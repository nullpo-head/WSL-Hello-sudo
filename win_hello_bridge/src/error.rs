use std::fmt::Display;
use windows::Security::Credentials::KeyCredentialStatus;

#[derive(Debug)]
pub(crate) enum FailureReason {
    WindowsHelloNotSupported,
    CredentialExists,
    CredentialNotFound(String),
    DeviceLocked,
    Unknown,
    UserCancelled,
    PrefsPasswd,
    Other(windows::core::Error),
}

impl From<windows::core::Error> for FailureReason {
    fn from(e: windows::core::Error) -> Self {
        Self::Other(e)
    }
}

impl FailureReason {
    pub(crate) fn to_code(&self) -> i32 {
        match self {
            FailureReason::WindowsHelloNotSupported => 170, // Avoid reserved exit codes of UNIX
            FailureReason::CredentialExists => 171,
            FailureReason::CredentialNotFound(_) => 172,
            FailureReason::DeviceLocked => 173,
            FailureReason::Unknown => 175, // Skip 174 because the number should correspond to KeyCredentialStatus.Success if exists
            FailureReason::UserCancelled => 176,
            FailureReason::PrefsPasswd => 177,
            FailureReason::Other(_) => 178,
        }
    }

    pub(crate) fn from_credential_status(
        status: KeyCredentialStatus,
        key_name: &str,
    ) -> Result<(), Self> {
        match status {
            KeyCredentialStatus::Success => Ok(()),
            KeyCredentialStatus::CredentialAlreadyExists => Err(Self::CredentialExists),
            KeyCredentialStatus::NotFound => Err(Self::CredentialNotFound(key_name.to_string())),
            KeyCredentialStatus::SecurityDeviceLocked => Err(Self::DeviceLocked),
            KeyCredentialStatus::UnknownError => Err(Self::Unknown),
            KeyCredentialStatus::UserPrefersPassword => Err(Self::PrefsPasswd),
            KeyCredentialStatus::UserCanceled => Err(Self::UserCancelled),
            _ => unreachable!(),
        }
    }
}

impl Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FailureReason::WindowsHelloNotSupported => {
                "Windows Hello is not supported on this device."
            }
            FailureReason::CredentialExists => "The credential already exists, creation failed.",
            FailureReason::CredentialNotFound(name) => {
                return write!(f, "The credential '{}' does not exist.", name)
            }
            FailureReason::DeviceLocked => "The Windows Hello security device is locked",
            FailureReason::Unknown => "Unknown error.",
            FailureReason::UserCancelled => "The user cancelled.",
            FailureReason::PrefsPasswd => "The user prefers to enter a password. Aborted.",
            FailureReason::Other(e) => return Display::fmt(e, f),
        })
    }
}
