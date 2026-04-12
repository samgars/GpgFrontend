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
    ErrorNoKey = -6,        // required key not found for operation
    ErrorInvalidData = -7,  // data is not in expected format (e.g., not a valid OpenPGP message)
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

/// Status of an individual signature
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfrSignatureStatus {
    Valid = 0,        // The signature matches the payload and the public key
    BadSignature = 1, // The signature is mathematically invalid (payload tampered or wrong key)
    NoKey = 2,        // We don't have the public key required to verify this signature
    UnknownError = 3, // Other parsing or internal errors related to this signature
}

/// Verification result for a single signature found in the message
#[repr(C)]
pub struct GfrSignatureResultC {
    pub sig_type: GfrSignMode, // The type of signature (Inline, ClearText, Detached)
    pub issuer_fpr: *mut c_char, // The Fingerprint of the signer (if available, otherwise null)
    pub status: GfrSignatureStatus, // The verification status for this specific signature
    pub created_at: u32,       // Signature creation timestamp (Unix epoch)
    pub pub_algo: *mut c_char, // The algorithm used for this signature (if available)
    pub hash_algo: *mut c_char, // The hash algorithm used for this signature (if available)
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfrRecipientStatus {
    Success = 0, // Successfully decrypted using this key
    NoKey = 1,   // Key ID found, but we don't have the secret key to unlock it
    Error = 2,   // We have the key, but decryption failed (e.g., wrong password)
}

#[repr(C)]
pub struct GfrRecipientResultC {
    pub key_id: *mut c_char,
    pub pub_algo: *mut c_char,
    pub status: GfrRecipientStatus,
}

#[repr(C)]
pub struct GfrInvalidRecipientC {
    pub fpr: *mut c_char,
    pub reason: GfrStatus,
}

// Result structure for the encryption operation
#[repr(C)]
pub struct GfrEncryptResultC {
    pub data: *mut u8,
    pub data_len: usize,
    pub invalid_recipients: *mut GfrInvalidRecipientC,
    pub invalid_recipient_count: usize,
}

#[repr(C)]
pub struct GfrDecryptResultC {
    pub data: *mut u8,
    pub data_len: usize,
    pub filename: *mut c_char,
    pub recipients: *mut GfrRecipientResultC,
    pub recipient_count: usize,
}

/// The comprehensive result of a signing operation
#[repr(C)]
pub struct GfrSignResultC {
    pub data: *mut u8,
    pub data_len: usize,
    pub signatures: *mut GfrSignatureResultC,
    pub signature_count: usize,
}

/// The comprehensive result of a verification operation
#[repr(C)]
pub struct GfrVerifyResultC {
    // The underlying data (For ClearText/Inline, this is the extracted payload. For Detached, this might be null)
    pub data: *mut u8,
    pub data_len: usize,

    // The list of signatures found and evaluated
    pub signatures: *mut GfrSignatureResultC,
    pub signature_count: usize,

    // Helper flag: true if AT LEAST ONE signature is perfectly Valid
    pub is_verified: bool,
}
