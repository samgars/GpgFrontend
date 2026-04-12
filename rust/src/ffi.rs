use crate::crypto::get_signature_issuers_internal;
use crate::key::extract_public_key_internal;
use crate::keygen::{GeneratedKeys, create_key_internal};
use crate::types::{
    GfrKeyConfig, GfrKeyMetadataC, GfrSignMode, GfrSignResultC, GfrSignatureResultC, GfrStatus,
    GfrSubkeyMetadataC, GfrVerifyResultC,
};
use log::LevelFilter;
use std::slice;
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
pub extern "C" fn gfr_crypto_free_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
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
    name: *const c_char,
    in_data: *const u8,
    in_len: usize,
    pub_keys: *const *const c_char,
    pub_keys_count: usize,
    ascii: bool,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<(), GfrStatus> {
        // Null pointer checks
        if name.is_null() || in_data.is_null() || pub_keys.is_null() || out_data.is_null() {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        let name_str = unsafe { CStr::from_ptr(name) }
            .to_str()
            .map_err(|_| GfrStatus::ErrorInvalidInput)?;

        // Convert the plaintext C string to a Rust string slice
        let data_slice = unsafe { slice::from_raw_parts(in_data, in_len) };

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
        let mut encrypted_bytes =
            crate::crypto::encrypt_text_internal(name_str, data_slice, &key_blocks, ascii)?;

        // 4. Prepare output: Allocate memory for the encrypted data and transfer ownership to C++
        encrypted_bytes.shrink_to_fit();
        let ptr = encrypted_bytes.as_mut_ptr();
        let len = encrypted_bytes.len();
        std::mem::forget(encrypted_bytes);

        unsafe {
            *out_data = ptr;
            *out_len = len;
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
pub extern "C" fn gfr_crypto_decrypt_data(
    in_data: *const u8,
    in_len: usize,
    secret_key: *const c_char,
    password: *const c_char,
    out_name: *mut *mut c_char,
    out_data: *mut *mut u8, // Output parameter for the decrypted bytes
    out_len: *mut usize,    // Output parameter for the length of decrypted bytes
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<(), GfrStatus> {
        // Null checks
        if in_data.is_null()
            || secret_key.is_null()
            || out_name.is_null()
            || out_data.is_null()
            || out_len.is_null()
        {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        // Parse inputs safely
        let data_slice = unsafe { slice::from_raw_parts(in_data, in_len) };
        let skey_str = unsafe { CStr::from_ptr(secret_key) }.to_str().unwrap_or("");

        // Password can be empty/null for unlocked keys
        let pwd_str = if password.is_null() {
            ""
        } else {
            unsafe { CStr::from_ptr(password) }.to_str().unwrap_or("")
        };

        // Perform decryption
        let (filename, mut decrypted_bytes) =
            crate::crypto::decrypt_internal(data_slice, skey_str, pwd_str)?;

        // Transfer string ownership to C
        let c_filename = CString::new(filename).unwrap_or_default();

        // Transfer bytes ownership to C (using exact capacity to avoid memory leaks)
        decrypted_bytes.shrink_to_fit();
        let ptr = decrypted_bytes.as_mut_ptr();
        let len = decrypted_bytes.len();
        std::mem::forget(decrypted_bytes); // Deliberate leak to FFI

        unsafe {
            *out_name = c_filename.into_raw();
            *out_data = ptr;
            *out_len = len;
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
pub extern "C" fn gfr_crypto_get_recipients(
    in_data: *const u8,
    in_len: usize,
    out_recipients: *mut *mut c_char,
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<(), GfrStatus> {
        if in_data.is_null() || out_recipients.is_null() {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        let data_slice = unsafe { slice::from_raw_parts(in_data, in_len) };
        let recipients_csv = crate::crypto::get_message_recipients_internal(data_slice)?;

        let c_str = CString::new(recipients_csv).map_err(|_| GfrStatus::ErrorInternal)?;
        unsafe {
            *out_recipients = c_str.into_raw();
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
pub extern "C" fn gfr_crypto_sign_data(
    name: *const c_char,
    in_data: *const u8,
    in_len: usize,
    secret_keys: *const *const c_char,
    passwords: *const *const c_char,
    signers_count: usize,
    mode: GfrSignMode,
    ascii: bool,
    out_result: *mut GfrSignResultC, // Replaced out_data/out_len with struct ptr
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<(), GfrStatus> {
        if name.is_null()
            || in_data.is_null()
            || secret_keys.is_null()
            || passwords.is_null()
            || out_result.is_null()
        {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("");
        let data_slice = unsafe { slice::from_raw_parts(in_data, in_len) };

        let mut skey_blocks = Vec::with_capacity(signers_count);
        let mut pwd_blocks = Vec::with_capacity(signers_count);

        unsafe {
            let sk_slice = slice::from_raw_parts(secret_keys, signers_count);
            let pwd_slice = slice::from_raw_parts(passwords, signers_count);

            for i in 0..signers_count {
                if sk_slice[i].is_null() || pwd_slice[i].is_null() {
                    return Err(GfrStatus::ErrorInvalidInput);
                }
                let sk_str = CStr::from_ptr(sk_slice[i])
                    .to_str()
                    .map_err(|_| GfrStatus::ErrorInvalidInput)?;
                let pw_str = CStr::from_ptr(pwd_slice[i])
                    .to_str()
                    .map_err(|_| GfrStatus::ErrorInvalidInput)?;

                skey_blocks.push(sk_str);
                pwd_blocks.push(pw_str);
            }
        }

        // Perform the multi-signature and get the structured report
        let mut internal_result = crate::crypto::sign_internal(
            name_str,
            data_slice,
            &skey_blocks,
            &pwd_blocks,
            mode,
            ascii,
        )?;

        // 1. Process the output payload (data)
        internal_result.data.shrink_to_fit();
        let data_ptr = internal_result.data.as_mut_ptr();
        let data_len = internal_result.data.len();
        std::mem::forget(internal_result.data); // Leak payload to C

        // 2. Process the signatures array
        let mut c_signatures = Vec::with_capacity(internal_result.signatures.len());
        for sig in internal_result.signatures {
            c_signatures.push(GfrSignatureResultC {
                sig_type: mode,
                issuer_fpr: CString::new(sig.fpr).unwrap_or_default().into_raw(),
                status: sig.status,
                created_at: sig.created_at,
                pub_algo: CString::new(sig.pub_algo).unwrap_or_default().into_raw(),
                hash_algo: CString::new(sig.hash_algo).unwrap_or_default().into_raw(),
            });
        }

        let mut boxed_sigs = c_signatures.into_boxed_slice();
        let sigs_ptr = boxed_sigs.as_mut_ptr();
        let sigs_count = boxed_sigs.len();
        std::mem::forget(boxed_sigs); // Leak array to C

        // 3. Populate the output struct safely
        unsafe {
            (*out_result).data = data_ptr;
            (*out_result).data_len = data_len;
            (*out_result).signatures = sigs_ptr;
            (*out_result).signature_count = sigs_count;
        }

        Ok(())
    });

    match result {
        Ok(Ok(_)) => GfrStatus::Success,
        Ok(Err(e)) => e,
        Err(_) => GfrStatus::ErrorPanic,
    }
}

/// Free the signature result memory
#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_sign_result(result: *mut GfrSignResultC) {
    if result.is_null() {
        return;
    }

    unsafe {
        // 1. Free the generated data buffer
        if !(*result).data.is_null() && (*result).data_len > 0 {
            let _ = Vec::from_raw_parts((*result).data, (*result).data_len, (*result).data_len);
        }

        // 2. Free the signatures array and its internal strings
        if !(*result).signatures.is_null() && (*result).signature_count > 0 {
            let sigs_slice =
                std::slice::from_raw_parts_mut((*result).signatures, (*result).signature_count);

            for sig in sigs_slice.iter_mut() {
                if !sig.issuer_fpr.is_null() {
                    drop(CString::from_raw(sig.issuer_fpr));
                }
                if !sig.pub_algo.is_null() {
                    drop(CString::from_raw(sig.pub_algo));
                }
                if !sig.hash_algo.is_null() {
                    drop(CString::from_raw(sig.hash_algo));
                }
            }

            // Free the array itself
            let array_ptr =
                std::ptr::slice_from_raw_parts_mut((*result).signatures, (*result).signature_count);
            drop(Box::from_raw(array_ptr));
        }

        // Zero out
        (*result).data = std::ptr::null_mut();
        (*result).data_len = 0;
        (*result).signatures = std::ptr::null_mut();
        (*result).signature_count = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_verify_data(
    in_data: *const u8,
    in_len: usize,
    sig_data: *const u8, // Only used if mode == 2 (Detached)
    sig_len: usize,      // Only used if mode == 2 (Detached)
    pub_keys: *const *const c_char,
    pub_keys_count: usize,
    mode: GfrSignMode,
    out_result: *mut GfrVerifyResultC, // Output parameter for the comprehensive result
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<(), GfrStatus> {
        if in_data.is_null() || out_result.is_null() {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        let data_slice = unsafe { slice::from_raw_parts(in_data, in_len) };
        let sig_slice = if !sig_data.is_null() && sig_len > 0 {
            unsafe { slice::from_raw_parts(sig_data, sig_len) }
        } else {
            &[]
        };

        let mut key_blocks = Vec::with_capacity(pub_keys_count);
        if !pub_keys.is_null() && pub_keys_count > 0 {
            unsafe {
                let keys_slice = slice::from_raw_parts(pub_keys, pub_keys_count);
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
        }

        // Call the updated internal function which now returns VerifyResultInternal
        let mut internal_result =
            crate::crypto::verify_internal(data_slice, sig_slice, &key_blocks, mode)?;

        // 1. Process the extracted payload (data)
        internal_result.data.shrink_to_fit();
        let data_ptr = internal_result.data.as_mut_ptr();
        let data_len = internal_result.data.len();
        std::mem::forget(internal_result.data); // Leak payload to C

        // 2. Process the signatures array
        let mut c_signatures = Vec::with_capacity(internal_result.signatures.len());
        for sig in internal_result.signatures {
            let c_fpr = CString::new(sig.fpr).unwrap_or_default().into_raw();
            let c_pub_algo = CString::new(sig.pub_algo).unwrap_or_default().into_raw();
            let c_hash_algo = CString::new(sig.hash_algo).unwrap_or_default().into_raw();

            c_signatures.push(GfrSignatureResultC {
                sig_type: sig.sig_type,
                issuer_fpr: c_fpr,
                status: sig.status,
                created_at: sig.created_at,
                pub_algo: c_pub_algo,
                hash_algo: c_hash_algo,
            });
        }

        let mut boxed_sigs = c_signatures.into_boxed_slice();
        let sigs_ptr = boxed_sigs.as_mut_ptr();
        let sigs_count = boxed_sigs.len();
        std::mem::forget(boxed_sigs); // Leak array to C

        // 3. Populate the output struct safely
        unsafe {
            (*out_result).data = data_ptr;
            (*out_result).data_len = data_len;
            (*out_result).signatures = sigs_ptr;
            (*out_result).signature_count = sigs_count;
            (*out_result).is_verified = internal_result.is_verified;
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
pub extern "C" fn gfr_crypto_get_signature_issuers(
    in_data: *const u8,
    in_len: usize,
    out_issuers: *mut *mut c_char,
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<(), GfrStatus> {
        if in_data.is_null() || out_issuers.is_null() {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        let data_slice = unsafe { std::slice::from_raw_parts(in_data, in_len) };
        let (_, issuers_csv) = get_signature_issuers_internal(data_slice)?;

        let c_str = CString::new(issuers_csv).map_err(|_| GfrStatus::ErrorInternal)?;
        unsafe {
            *out_issuers = c_str.into_raw();
        }
        Ok(())
    });

    match result {
        Ok(Ok(_)) => GfrStatus::Success,
        Ok(Err(e)) => e,
        Err(_) => GfrStatus::ErrorPanic,
    }
}

/// Free the verification result memory
#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_verify_result(result: *mut GfrVerifyResultC) {
    if result.is_null() {
        return;
    }

    unsafe {
        // 1. Free the extracted data buffer
        if !(*result).data.is_null() && (*result).data_len > 0 {
            let _ = Vec::from_raw_parts((*result).data, (*result).data_len, (*result).data_len);
        }

        // 2. Free the signatures array and its internal strings
        if !(*result).signatures.is_null() && (*result).signature_count > 0 {
            let sigs_slice =
                std::slice::from_raw_parts_mut((*result).signatures, (*result).signature_count);

            for sig in sigs_slice.iter_mut() {
                if !sig.issuer_fpr.is_null() {
                    drop(CString::from_raw(sig.issuer_fpr));
                }
                if !sig.pub_algo.is_null() {
                    drop(CString::from_raw(sig.pub_algo));
                }
                if !sig.hash_algo.is_null() {
                    drop(CString::from_raw(sig.hash_algo));
                }
            }

            // Free the array itself
            let array_ptr =
                std::ptr::slice_from_raw_parts_mut((*result).signatures, (*result).signature_count);
            drop(Box::from_raw(array_ptr));
        }

        // Zero out the struct to prevent double-free mistakes from the C side
        (*result).data = std::ptr::null_mut();
        (*result).data_len = 0;
        (*result).signatures = std::ptr::null_mut();
        (*result).signature_count = 0;
        (*result).is_verified = false;
    }
}
