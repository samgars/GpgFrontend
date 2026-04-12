/*
 * Copyright (C) 2021-2024 Saturneric <eric@bktus.com>
 *
 * This file is part of GpgFrontend.
 *
 * GpgFrontend is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GpgFrontend is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GpgFrontend. If not, see <https://www.gnu.org/licenses/>.
 *
 * The initial version of the source code is inherited from
 * the gpg4usb project, which is under GPL-3.0-or-later.
 *
 * All the source code of GpgFrontend was modified and released by
 * Saturneric <eric@bktus.com> starting on May 12, 2021.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

use crate::key::{export_merged_public_keys, extract_public_key_internal};
use crate::keygen::{GeneratedKeys, create_key_internal};
use crate::types::{
    GfrFreeCb, GfrKeyConfig, GfrKeyGenerateResult, GfrKeyMetadataC, GfrPasswordFetchCb, GfrStatus,
    GfrSubkeyMetadataC,
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
pub extern "C" fn gfr_init_logger() {
    let _ = env_logger::builder()
        .target(env_logger::Target::Stdout)
        .filter_level(LevelFilter::Debug)
        .try_init();
}

#[unsafe(no_mangle)]
pub extern "C" fn gfr_crypto_generate_key(
    user_id: *const c_char,
    key_config: GfrKeyConfig,
    s_key_configs: *const GfrKeyConfig,
    s_key_count: usize,
    fetch_pwd_cb: GfrPasswordFetchCb,
    free_cb: GfrFreeCb,
    o_result: *mut GfrKeyGenerateResult,
) -> GfrStatus {
    let result = catch_unwind(|| -> Result<GeneratedKeys, GfrStatus> {
        if user_id.is_null() || o_result.is_null() {
            return Err(GfrStatus::ErrorInvalidInput);
        }

        let user_id_str = unsafe { CStr::from_ptr(user_id) }
            .to_str()
            .map_err(|_| GfrStatus::ErrorInvalidInput)?;

        let configs = unsafe { std::slice::from_raw_parts(s_key_configs, s_key_count) };

        let keys = create_key_internal(
            user_id_str,
            key_config,
            configs,
            Some(fetch_pwd_cb),
            Some(free_cb),
        )?;

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
                    *o_result = GfrKeyGenerateResult {
                        secret_key: c_s.into_raw(),
                        public_key: c_p.into_raw(),
                        fingerprint: c_f.into_raw(),
                    };
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
pub unsafe extern "C" fn gfr_export_merged_public_keys(
    keys_ptr: *const *const c_char,
    keys_len: usize,
    out_armored_ptr: *mut *mut c_char,
) -> GfrStatus {
    // 1. Check for null pointers to prevent segmentation faults
    if keys_ptr.is_null() || out_armored_ptr.is_null() {
        return GfrStatus::ErrorInvalidInput;
    }

    // 2. Convert the C array of pointers into a Rust slice of pointers
    let c_str_ptrs = unsafe { slice::from_raw_parts(keys_ptr, keys_len) };
    let mut rust_strs = Vec::with_capacity(keys_len);

    // 3. Iterate through pointers, convert each to a Rust &str
    for &ptr in c_str_ptrs {
        if ptr.is_null() {
            return GfrStatus::ErrorInvalidInput;
        }

        match unsafe { CStr::from_ptr(ptr).to_str() } {
            Ok(s) => rust_strs.push(s),
            Err(_) => return GfrStatus::ErrorInvalidInput, // Fails if not valid UTF-8
        }
    }

    // 4. Call the core Rust function
    match export_merged_public_keys(&rust_strs) {
        Ok(armored_string) => {
            // 5. Convert the resulting Rust String into a null-terminated CString
            match CString::new(armored_string) {
                Ok(c_str) => {
                    // Transfer ownership of the memory to C (prevents Rust from dropping it)
                    unsafe { *out_armored_ptr = c_str.into_raw() };

                    // Assuming GfrStatus has a Success variant.
                    // If your enum uses a different name for success, adjust this.
                    GfrStatus::Success
                }
                // Handle cases where the output string somehow contains a null byte
                Err(_) => GfrStatus::ErrorArmorFailed,
            }
        }
        Err(status) => status, // Return the exact error status from the core function
    }
}
