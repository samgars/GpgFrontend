use crate::key::extract_public_key_internal;
use crate::keygen::{GeneratedKeys, create_key_internal};
use crate::types::{GfrKeyConfig, GfrKeyMetadataC, GfrStatus, GfrSubkeyMetadataC};
use log::LevelFilter;
use std::{
    ffi::{CStr, CString, c_char},
    panic::catch_unwind,
};

#[unsafe(no_mangle)]
pub extern "C" fn gfr_rust_hello() {
    println!(
        "Hello from Rust! (Rust Support Library version {})",
        env!("CARGO_PKG_VERSION")
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)) }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_init_logger() {
    let _ = env_logger::builder()
        .target(env_logger::Target::Stdout)
        .filter_level(LevelFilter::Debug)
        .try_init();
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_create_key_custom(
    user_id: *const c_char,
    pwd: *const c_char,
    key_config: GfrKeyConfig,
    s_key_configs: *const GfrKeyConfig,
    s_key_count: usize,
    o_s_key: *mut *mut c_char,
    o_p_key: *mut *mut c_char,
    o_fpr: *mut *mut c_char,
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<GeneratedKeys, GfrStatus> {
        if user_id.is_null()
            || pwd.is_null()
            || o_s_key.is_null()
            || o_p_key.is_null()
            || o_fpr.is_null()
        {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        let user_id_str = unsafe { CStr::from_ptr(user_id) }
            .to_str()
            .map_err(|_| GfrStatus::ErrorInvalidInput)?;

        let pwd_bytes = unsafe { CStr::from_ptr(pwd) }.to_bytes();
        let configs = unsafe { std::slice::from_raw_parts(s_key_configs, s_key_count) };

        let keys = create_key_internal(user_id_str, pwd_bytes, key_config, configs)?;

        Ok(keys)
    });

    match result {
        Ok(inner_result) => match inner_result {
            Ok(keys) => {
                let Ok(c_s) = CString::new(keys.secret) else {
                    return GfrStatus::ErrorInternal;
                };
                let Ok(c_p) = CString::new(keys.public) else {
                    return GfrStatus::ErrorInternal;
                };
                let Ok(c_f) = CString::new(keys.fingerprint) else {
                    return GfrStatus::ErrorInternal;
                };

                unsafe {
                    *o_s_key = c_s.into_raw();
                    *o_p_key = c_p.into_raw();
                    *o_fpr = c_f.into_raw();
                }
                GfrStatus::Success
            }

            Err(status) => status,
        },
        Err(_) => GfrStatus::ErrorPanic,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_extract_metadata(
    key_block: *const std::os::raw::c_char,
    out_metadata: *mut GfrKeyMetadataC,
) -> GfrStatus {
    let result = std::panic::catch_unwind(|| -> Result<(), GfrStatus> {
        // ... (null checks and string parsing same as before) ...
        let block_str = unsafe { CStr::from_ptr(key_block) }
            .to_str()
            .map_err(|_| GfrStatus::ErrorInvalidInput)?;
        let meta = crate::key::extract_metadata_internal(block_str)?;

        let c_fpr = CString::new(meta.fpr).map_err(|_| GfrStatus::ErrorInternal)?;
        let c_key_id = CString::new(meta.key_id).map_err(|_| GfrStatus::ErrorInternal)?;
        let c_user_id = CString::new(meta.user_id).map_err(|_| GfrStatus::ErrorInternal)?;

        // Convert the subkeys Vec into a C-compatible array
        let mut c_subkeys = Vec::with_capacity(meta.subkeys.len());
        for sub in meta.subkeys {
            c_subkeys.push(GfrSubkeyMetadataC {
                fpr: CString::new(sub.fpr)
                    .map_err(|_| GfrStatus::ErrorInternal)?
                    .into_raw(),
                key_id: CString::new(sub.key_id)
                    .map_err(|_| GfrStatus::ErrorInternal)?
                    .into_raw(),
                algo: sub.algo,
                created_at: sub.created_at,
                has_secret: sub.has_secret,
                can_sign: sub.can_sign,
                can_encrypt: sub.can_encrypt,
                can_auth: sub.can_auth,
                can_certify: sub.can_certify,
            });
        }

        // Prevent Rust from deallocating the vector backing array, transfer ownership to C
        let mut boxed_slice = c_subkeys.into_boxed_slice();
        let subkeys_ptr = boxed_slice.as_mut_ptr();
        let subkey_count = boxed_slice.len();
        std::mem::forget(boxed_slice); // Leak it deliberately to FFI

        unsafe {
            (*out_metadata).fpr = c_fpr.into_raw();
            (*out_metadata).key_id = c_key_id.into_raw();
            (*out_metadata).user_id = c_user_id.into_raw();
            (*out_metadata).algo = meta.algo;
            (*out_metadata).created_at = meta.created_at;
            (*out_metadata).has_secret = meta.has_secret;
            (*out_metadata).can_sign = meta.can_sign;
            (*out_metadata).can_encrypt = meta.can_encrypt;
            (*out_metadata).can_auth = meta.can_auth;
            (*out_metadata).can_certify = meta.can_certify;

            (*out_metadata).subkeys = subkeys_ptr;
            (*out_metadata).subkey_count = subkey_count;
        }

        Ok(())
    });

    match result {
        Ok(Ok(_)) => GfrStatus::Success,
        Ok(Err(e)) => e,
        Err(_) => GfrStatus::ErrorPanic,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_metadata(meta: *mut GfrKeyMetadataC) {
    if meta.is_null() {
        return;
    }

    unsafe {
        // 1. Free primary strings
        if !(*meta).fpr.is_null() {
            drop(CString::from_raw((*meta).fpr));
        }
        if !(*meta).key_id.is_null() {
            drop(CString::from_raw((*meta).key_id));
        }
        if !(*meta).user_id.is_null() {
            drop(CString::from_raw((*meta).user_id));
        }

        // 2. Free subkeys array and its internal strings
        if !(*meta).subkeys.is_null() && (*meta).subkey_count > 0 {
            // Reconstruct the slice so we can iterate
            let subkeys_slice =
                std::slice::from_raw_parts_mut((*meta).subkeys, (*meta).subkey_count);

            for sub in subkeys_slice.iter_mut() {
                if !sub.fpr.is_null() {
                    drop(CString::from_raw(sub.fpr));
                }
                if !sub.key_id.is_null() {
                    drop(CString::from_raw(sub.key_id));
                }
            }

            // Reconstruct the Box of the array itself to deallocate the array memory
            let array_ptr =
                std::ptr::slice_from_raw_parts_mut((*meta).subkeys, (*meta).subkey_count);
            drop(Box::from_raw(array_ptr));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_extract_public_key(
    secret_block: *const c_char,
    out_public_block: *mut *mut c_char,
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<(), GfrStatus> {
        // Null pointer check
        if secret_block.is_null() || out_public_block.is_null() {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        // Safely convert C string to Rust string slice
        let block_str = unsafe { CStr::from_ptr(secret_block) }
            .to_str()
            .map_err(|_| GfrStatus::ErrorInvalidInput)?;

        // Perform the extraction
        let pub_key_str = extract_public_key_internal(block_str)?;

        // Convert the result back to CString
        let c_pub = CString::new(pub_key_str).map_err(|_| GfrStatus::ErrorInternal)?;

        // Transfer ownership to C++
        unsafe {
            *out_public_block = c_pub.into_raw();
        }

        Ok(())
    });

    match result {
        Ok(Ok(_)) => GfrStatus::Success,
        Ok(Err(e)) => e,
        Err(_) => GfrStatus::ErrorPanic,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_encrypt_text(
    plaintext: *const c_char,
    pub_keys: *const *const c_char,
    pub_keys_count: usize,
    out_encrypted: *mut *mut c_char,
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<(), GfrStatus> {
        // Null pointer checks
        if plaintext.is_null() || pub_keys.is_null() || out_encrypted.is_null() {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        // Convert the plaintext C string to a Rust string slice
        let pt_str = unsafe { CStr::from_ptr(plaintext) }
            .to_str()
            .map_err(|_| GfrStatus::ErrorInvalidInput)?;

        // Convert the C array of strings into a Rust Vec<&str>
        let mut key_blocks = Vec::with_capacity(pub_keys_count);
        unsafe {
            let keys_slice = std::slice::from_raw_parts(pub_keys, pub_keys_count);
            for &key_ptr in keys_slice {
                if key_ptr.is_null() {
                    return Err(GfrStatus::ErrorInvalidInput);
                }
                let key_str = CStr::from_ptr(key_ptr)
                    .to_str()
                    .map_err(|_| GfrStatus::ErrorInvalidInput)?;
                key_blocks.push(key_str);
            }
        }

        // Perform the encryption
        let encrypted_text = crate::text::encrypt_text_internal(pt_str, &key_blocks)?;

        // Allocate a new CString for the result and transfer ownership to C++
        let c_encrypted = CString::new(encrypted_text).map_err(|_| GfrStatus::ErrorInternal)?;
        unsafe {
            *out_encrypted = c_encrypted.into_raw();
        }

        Ok(())
    });

    match result {
        Ok(Ok(_)) => GfrStatus::Success,
        Ok(Err(e)) => e,
        Err(_) => GfrStatus::ErrorPanic,
    }
}
