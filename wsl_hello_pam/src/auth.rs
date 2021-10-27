use bindings::*;
use libc::{c_char, c_int};
use openssl;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, prelude::*, SeekFrom};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr;
use toml;
use toml::Value;
use uuid::Uuid;

#[no_mangle]
pub fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    flags: c_int,
    _: c_int,
    _: *mut *const c_char,
) -> c_int {
    authenticate_via_hello(pamh).unwrap_or_else(|err| {
        if (flags & PAM_SILENT) == 0 {
            println!("WSL Hello error: {}", err);
        }
        match err {
            HelloAuthenticationError::PublicKeyFileError(ref err)
                if err.kind() == io::ErrorKind::NotFound =>
            {
                PAM_USER_UNKNOWN
            }
            HelloAuthenticationError::AuthenticatorLaunchError(_) => PAM_AUTHINFO_UNAVAIL,
            HelloAuthenticationError::AuthenticatorConnectionError(_) => PAM_AUTHINFO_UNAVAIL,
            HelloAuthenticationError::AuthenticatorSignalled => PAM_AUTHINFO_UNAVAIL,
            _ => PAM_AUTH_ERR,
        }
    })
}

fn get_user(pamh: *mut pam_handle_t, prompt: Option<&str>) -> Result<Cow<str>, i32> {
    let mut c_user: *const c_char = ptr::null();
    let tmp_prompt_str: CString;
    let c_prompt = match prompt {
        Some(prompt_str) => {
            tmp_prompt_str = CString::new(prompt_str).unwrap();
            tmp_prompt_str.as_ptr()
        }
        None => ptr::null(),
    };
    let err;
    unsafe {
        err = pam_get_user(pamh, &mut c_user, c_prompt);
    }
    match err {
        PAM_SUCCESS => unsafe {
            let c_user_str = CStr::from_ptr(c_user);
            Ok(c_user_str.to_string_lossy())
        },
        err => Err(err),
    }
}

#[derive(Debug)]
enum ConfigError {
    Io(io::Error),
    Toml(toml::de::Error),
    MissingField(String),
    InvalidValueType(String),
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> ConfigError {
        ConfigError::Io(err)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> ConfigError {
        ConfigError::Toml(err)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConfigError::Io(ref ioerr) => write!(f, "{}", ioerr),
            ConfigError::Toml(_) => write!(f, "TOML format error"),
            ConfigError::MissingField(ref field) => write!(f, "field: '{}' is not found", field),
            ConfigError::InvalidValueType(ref field) => {
                write!(f, "field: '{}' has an invalid value type", field)
            }
        }
    }
}

fn get_authenticator_path() -> Result<String, ConfigError> {
    let mut config_file = File::open("/etc/pam_wsl_hello/config")?;
    let mut config = String::new();
    config_file.read_to_string(&mut config)?;

    let config_value = config.parse::<Value>()?;
    let authenticator_path = config_value
        .get("authenticator_path")
        .ok_or_else(|| ConfigError::MissingField("authenticator_path".to_owned()))?
        .as_str()
        .ok_or_else(|| ConfigError::InvalidValueType("authenticator_path".to_owned()))?;
    Ok(authenticator_path.to_owned())
}

fn get_win_mnt() -> Result<String, ConfigError> {
    let mut config_file = File::open("/etc/pam_wsl_hello/config")?;
    let mut config = String::new();
    config_file.read_to_string(&mut config)?;

    let config_value = config.parse::<Value>()?;
    let win_mnt = config_value
        .get("win_mnt")
        .ok_or_else(|| ConfigError::MissingField("win_mnt".to_owned()))?
        .as_str()
        .ok_or_else(|| ConfigError::InvalidValueType("win_mnt".to_owned()))?;
    Ok(win_mnt.to_owned())
}

#[derive(Debug)]
enum HelloAuthenticationError {
    GetUserError(i32),
    ConfigError(ConfigError),
    PublicKeyFileError(io::Error),
    Io(io::Error),
    InvalidPublicKey(openssl::error::ErrorStack),
    OpenSslError(openssl::error::ErrorStack),
    AuthenticatorLaunchError(io::Error),
    AuthenticatorConnectionError(io::Error),
    AuthenticatorSignalled,
    HelloAuthenticationFail(String),
    SignAuthenticationFail,
}

impl From<io::Error> for HelloAuthenticationError {
    fn from(err: io::Error) -> HelloAuthenticationError {
        HelloAuthenticationError::Io(err)
    }
}

impl From<ConfigError> for HelloAuthenticationError {
    fn from(err: ConfigError) -> HelloAuthenticationError {
        HelloAuthenticationError::ConfigError(err)
    }
}

impl fmt::Display for HelloAuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HelloAuthenticationError::ConfigError(ref err) => write!(f, "config error; {}", err),
            HelloAuthenticationError::PublicKeyFileError(ref err) => match err.kind() {
                io::ErrorKind::NotFound => {
                    write!(f, "cannot find the credential public key for this user")
                }
                _ => write!(f, "{}", err),
            },
            HelloAuthenticationError::Io(ref err) => write!(f, "{}", err),
            HelloAuthenticationError::InvalidPublicKey(_) => {
                write!(f, "the pem file of the public key is invalid")
            }
            HelloAuthenticationError::AuthenticatorLaunchError(ref err) => {
                write!(f, "cannot launch Windows Hello; {}", err)
            }
            HelloAuthenticationError::AuthenticatorConnectionError(ref err) => {
                write!(f, "cannot communicate with Windows Hello; {}", err)
            }
            HelloAuthenticationError::HelloAuthenticationFail(ref msg) => {
                write!(f, "authentication failed; {}", msg)
            }
            HelloAuthenticationError::SignAuthenticationFail => write!(
                f,
                "the result of signature verification of the credential is failure"
            ),
            ref err => write!(f, "internal error; {:?}", err),
        }
    }
}

fn authenticate_via_hello(pamh: *mut pam_handle_t) -> Result<i32, HelloAuthenticationError> {
    let user_name = get_user(pamh, None).map_err(HelloAuthenticationError::GetUserError)?;
    let credential_key_name = format!("pam_wsl_hello_{}", user_name);

    let mut hello_public_key_file = File::open(format!(
        "/etc/pam_wsl_hello/public_keys/{}.pem",
        credential_key_name
    ))
    .map_err(HelloAuthenticationError::PublicKeyFileError)?;
    let mut key_str = String::new();
    hello_public_key_file.read_to_string(&mut key_str)?;
    let hello_public_key = PKey::public_key_from_pem(key_str.as_bytes())
        .map_err(HelloAuthenticationError::InvalidPublicKey)?;

    let challenge = format!("pam_wsl_hello:{}:{}", user_name, Uuid::new_v4());

    let auth_res;
    let challenge_tmpfile_path = &format!("/tmp/{}", challenge);
    {
        // Since there seems to be a bug that C# applications cannot read from pipes on WSL,
        // we create a temporary file to redirect
        let mut challenge_tmpfile = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(challenge_tmpfile_path)?;
        challenge_tmpfile.write_all(challenge.as_bytes())?;
        challenge_tmpfile.seek(SeekFrom::Start(0))?;
        let challenge_tmpfile_in = unsafe { Stdio::from_raw_fd(challenge_tmpfile.as_raw_fd()) };

        let authenticator_path = get_authenticator_path()?;
        let authenticator = Command::new(&authenticator_path)
            .arg(credential_key_name)
            .current_dir(Path::new(&get_win_mnt()?))
            .stdin(challenge_tmpfile_in)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(HelloAuthenticationError::AuthenticatorLaunchError)?;

        auth_res = authenticator
            .wait_with_output()
            .map_err(HelloAuthenticationError::AuthenticatorConnectionError)?;
    }
    fs::remove_file(challenge_tmpfile_path)?;

    match auth_res.status.code() {
        Some(code) if code == 0 => { /* Success */ }
        Some(_) => {
            return Err(HelloAuthenticationError::HelloAuthenticationFail(
                String::from_utf8(auth_res.stdout)
                    .unwrap_or_else(|_| "invalid utf8 output".to_string()),
            ))
        }
        None => return Err(HelloAuthenticationError::AuthenticatorSignalled),
    }
    let signature = auth_res.stdout;

    let mut verifier = Verifier::new(MessageDigest::sha256(), &hello_public_key).unwrap();
    verifier
        .update(challenge.as_bytes())
        .map_err(HelloAuthenticationError::OpenSslError)?;

    match verifier
        .verify(&signature)
        .map_err(HelloAuthenticationError::OpenSslError)?
    {
        true => Ok(PAM_SUCCESS),
        false => Err(HelloAuthenticationError::SignAuthenticationFail),
    }
}
