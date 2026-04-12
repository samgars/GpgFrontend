use std::ffi::CString;

use crate::types::{
    GfrEncryptAndSignResultC, GfrEncryptMetadataC, GfrEncryptResultC, GfrSignMetadataC,
    GfrSignResultC,
};

/// Helper to free sign metadata
#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_sign_metadata(meta: *mut GfrSignMetadataC) {
    if meta.is_null() {
        return;
    }
    unsafe {
        if !(*meta).signatures.is_null() && (*meta).signature_count > 0 {
            let sigs_slice =
                std::slice::from_raw_parts_mut((*meta).signatures, (*meta).signature_count);
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
            let array_ptr =
                std::ptr::slice_from_raw_parts_mut((*meta).signatures, (*meta).signature_count);
            drop(Box::from_raw(array_ptr));
        }
        (*meta).signatures = std::ptr::null_mut();
        (*meta).signature_count = 0;
    }
}

/// Helper to free encrypt metadata
#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_encrypt_metadata(meta: *mut GfrEncryptMetadataC) {
    if meta.is_null() {
        return;
    }
    unsafe {
        if !(*meta).invalid_recipients.is_null() && (*meta).invalid_recipient_count > 0 {
            let recs_slice = std::slice::from_raw_parts_mut(
                (*meta).invalid_recipients,
                (*meta).invalid_recipient_count,
            );
            for rec in recs_slice.iter_mut() {
                if !rec.fpr.is_null() {
                    drop(CString::from_raw(rec.fpr));
                }
            }
            let array_ptr = std::ptr::slice_from_raw_parts_mut(
                (*meta).invalid_recipients,
                (*meta).invalid_recipient_count,
            );
            drop(Box::from_raw(array_ptr));
        }
        (*meta).invalid_recipients = std::ptr::null_mut();
        (*meta).invalid_recipient_count = 0;
    }
}

/// Free the encryption result memory
#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_encrypt_result(result: *mut GfrEncryptResultC) {
    if result.is_null() {
        return;
    }
    unsafe {
        // 1. Free the payload data
        if !(*result).data.is_null() && (*result).data_len > 0 {
            let _ = Vec::from_raw_parts((*result).data, (*result).data_len, (*result).data_len);
            (*result).data = std::ptr::null_mut();
            (*result).data_len = 0;
        }

        // 2. Delegate freeing metadata to our helper
        gfr_crypto_free_encrypt_metadata(&mut (*result).meta);
    }
}

/// Free the signature result memory
#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_sign_result(result: *mut GfrSignResultC) {
    if result.is_null() {
        return;
    }
    unsafe {
        // 1. Free the payload data
        if !(*result).data.is_null() && (*result).data_len > 0 {
            let _ = Vec::from_raw_parts((*result).data, (*result).data_len, (*result).data_len);
            (*result).data = std::ptr::null_mut();
            (*result).data_len = 0;
        }

        // 2. Delegate freeing metadata to our helper
        gfr_crypto_free_sign_metadata(&mut (*result).meta);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_free_encrypt_and_sign_result(result: *mut GfrEncryptAndSignResultC) {
    if result.is_null() {
        return;
    }
    unsafe {
        // 1. Free the payload data
        if !(*result).data.is_null() && (*result).data_len > 0 {
            let _ = Vec::from_raw_parts((*result).data, (*result).data_len, (*result).data_len);
            (*result).data = std::ptr::null_mut();
            (*result).data_len = 0;
        }

        // 2. Delegate freeing metadata to our helpers
        gfr_crypto_free_sign_metadata(&mut (*result).sign_meta);
        gfr_crypto_free_encrypt_metadata(&mut (*result).encrypt_meta);
    }
}
