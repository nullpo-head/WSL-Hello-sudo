#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use libc::{c_int, c_char};
use std::ffi::{CString, CStr};
use std::borrow::{Cow};
use std::ptr;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process::{Command, Stdio};
use std::os::unix::io::{AsRawFd, FromRawFd};
use openssl::sign::Verifier;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use bindings::*;
use toml::Value;
use uuid::Uuid;

extern crate libc;
extern crate openssl;
extern crate toml;
extern crate uuid;

pub mod bindings;


fn get_user(pamh: *mut pam_handle_t, prompt: Option<&str>) -> Result<Cow<str>, i32> {
    let mut c_user: *const c_char = ptr::null();
    let c_prompt = match prompt {
        Some(prompt_str) => CString::new(prompt_str).unwrap().as_ptr(),
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

fn get_authenticator_path() -> Result<String, ConfigError> {
    let mut config_file = File::open("/etc/pam_wsl_hello/config")?;
    let mut config = String::new();
    config_file.read_to_string(&mut config)?;

    let config_value = config.parse::<Value>()?;
    let authenticator_path = config_value.get("authenticator_path")
        .ok_or(ConfigError::MissingField("authenticator_path".to_owned()))?
        .as_str()
        .ok_or(ConfigError::InvalidValueType("authenticator_path".to_owned()))?;
    Ok(authenticator_path.to_owned())
}

#[derive(Debug)]
enum HelloAuthenticationError {
    GetUserError(i32),
    ConfigError(ConfigError),
    PublicKeyFileError(io::Error),
    Io(io::Error),
    InvalidPublicKey(openssl::error::ErrorStack),
    OpenSSLError(openssl::error::ErrorStack),
    AuthenticatorLaunchError(io::Error),
    AuthenticatorConnectionError(io::Error),
    AuthenticationFail(i32),
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

fn authenticate_via_hello(pamh: *mut pam_handle_t) -> Result<i32, HelloAuthenticationError> {

    let user_name = get_user(pamh, None).map_err(|e| HelloAuthenticationError::GetUserError(e))?;
    let credential_key_name = format!("pam_wsl_hello_{}", user_name);

    let mut hello_public_key_file = File::open(format!("/etc/pam_wsl_hello/public_keys/{}.pem", credential_key_name)).map_err(|io| HelloAuthenticationError::PublicKeyFileError(io))?;
    let mut key_str = String::new();
    hello_public_key_file.read_to_string(&mut key_str)?;
    let hello_public_key = PKey::public_key_from_pem(key_str.as_bytes()).map_err(|e| HelloAuthenticationError::InvalidPublicKey(e))?;

    let challenge = format!("pam_wsl_hello:{}:{}", user_name, Uuid::new_v4());

    // Since there seems to be a bug that C# applications cannot read from pipes on WSL,
    // we create a temporary file to redirect
    let challenge_tmpfile_path = &format!("/tmp/{}", challenge);
    {
        let mut challenge_tmpfile = File::create(challenge_tmpfile_path)?;
        challenge_tmpfile.write_all(challenge.as_bytes())?;
    }
    let challenge_tmpfile = File::open(challenge_tmpfile_path)?;
    let challenge_tmpfile_in = unsafe {Stdio::from_raw_fd(challenge_tmpfile.as_raw_fd())};

    let authenticator_path = get_authenticator_path()?;
    let authenticator = Command::new(&authenticator_path)
        .arg(credential_key_name)
        .current_dir("/mnt/c")
        .stdin(challenge_tmpfile_in)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| HelloAuthenticationError::AuthenticatorLaunchError(e))?;

    let output = authenticator
        .wait_with_output()
        .map_err(|e| HelloAuthenticationError::AuthenticatorConnectionError(e))?;
    match output.status.code() {
        Some(code) if code == 0 => {/* Success */},
        Some(code) => return Err(HelloAuthenticationError::AuthenticationFail(code)),
        None => return Err(HelloAuthenticationError::AuthenticationFail(1)),
    }
    let signature = output.stdout;

    let mut verifier = Verifier::new(MessageDigest::sha256(), &hello_public_key).unwrap();
    verifier.update(challenge.as_bytes()).map_err(|e| HelloAuthenticationError::OpenSSLError(e))?;

    match verifier.finish(&signature).map_err(|e| HelloAuthenticationError::OpenSSLError(e))? {
        true => Ok(PAM_SUCCESS),
        false => Err(HelloAuthenticationError::AuthenticationFail(1)),
    }
}

#[no_mangle]
pub fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    flags: c_int,
    _: c_int,
    _: *mut *const c_char,
) -> c_int {
    match authenticate_via_hello(pamh) {
        Ok(ok) => ok,
        Err(_) => 0,
    }
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_setcred(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_acct_mgmt(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_open_session(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_close_session(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_chauthtok(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}
