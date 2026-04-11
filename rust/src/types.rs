use core::fmt;
use std::{error::Error, os::raw::c_char};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GfrStatus {
    Success = 0,
    ErrorInvalidInput = -1, // invalid input (e.g., null pointers, invalid strings)
    ErrorKeygenFailed = -2, // key generation failed
    ErrorPasswordFailed = -3, // password setting failed
    ErrorArmorFailed = -4,  // conversion to ASCII Armor failed
    ErrorInternal = -5,     // internal conversion error (e.g., CString contains \0)
    ErrorPanic = -99,       // Rust internal panic
}

impl fmt::Display for GfrStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Just print the enum variant name for simplicity
        write!(f, "{:?}", self)
    }
}

impl Error for GfrStatus {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfrKeyAlgo {
    Unknown = 0,
    ED25519,
    CV25519,
    NISTP256,
    NISTP384,
    NISTP521,
    RSA2048,
    RSA3072,
    RSA4096,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfrSignMode {
    Inline = 0,
    ClearText = 1,
    Detached = 2,
}

#[repr(C)]
pub struct GfrKeyConfig {
    pub algo: GfrKeyAlgo,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_auth: bool,
}

#[repr(C)]
pub struct GfrSubkeyMetadataC {
    pub fpr: *mut c_char,
    pub key_id: *mut c_char,
    pub algo: GfrKeyAlgo,
    pub created_at: u32,
    pub has_secret: bool,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_auth: bool,
    pub can_certify: bool,
}

#[repr(C)]
pub struct GfrKeyMetadataC {
    pub fpr: *mut c_char,
    pub key_id: *mut c_char,
    pub user_id: *mut c_char,
    pub algo: GfrKeyAlgo,
    pub created_at: u32,
    pub has_secret: bool,

    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_auth: bool,
    pub can_certify: bool,

    pub subkeys: *mut GfrSubkeyMetadataC,
    pub subkey_count: usize,
}
