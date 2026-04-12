use std::{
    io::{Cursor, Read},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::types::{GfrRecipientStatus, GfrSignMode, GfrSignatureStatus, GfrStatus};
use log::debug;
use pgp::{
    armor::Dearmor,
    composed::{
        ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, Message,
        MessageBuilder, SignedPublicKey, SignedSecretKey,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{Packet, PacketParser},
    ser::Serialize,
    types::{KeyDetails, Password},
};
use rand::thread_rng;

pub fn encrypt_text_internal(
    name: &str,
    data: &[u8],
    public_key_blocks: &[&str],
    ascii_armor: bool,
) -> Result<Vec<u8>, GfrStatus> {
    let mut rng = thread_rng();

    // 1. Initialize the builder with SEIPDv1 and AES256
    let mut builder = MessageBuilder::from_bytes(name.as_bytes().to_vec(), data.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    let mut has_recipient = false;

    // 2. Iterate through all provided recipient public key blocks
    for block in public_key_blocks {
        let (cert, _) =
            SignedPublicKey::from_string(block).map_err(|_| GfrStatus::ErrorInvalidInput)?;

        let mut added_for_this_cert = false;

        // 3. Dynamically find a valid encryption subkey
        for subkey in &cert.public_subkeys {
            if subkey.key.algorithm().can_encrypt() {
                builder
                    .encrypt_to_key(&mut rng, subkey)
                    .map_err(|_| GfrStatus::ErrorInternal)?;

                added_for_this_cert = true;
                has_recipient = true;
                break;
            }
        }

        // Fallback to primary key if no encryption subkeys are found
        if !added_for_this_cert && cert.primary_key.algorithm().can_encrypt() {
            builder
                .encrypt_to_key(&mut rng, &cert.primary_key)
                .map_err(|_| GfrStatus::ErrorInternal)?;
            has_recipient = true;
        }
    }

    if !has_recipient {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    // 4. If ASCII armor is requested, output armored string;
    if ascii_armor {
        let armored_str = builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .map_err(|_| GfrStatus::ErrorArmorFailed)?;
        return Ok(armored_str.as_bytes().to_vec());
    }

    // 5. If not ASCII armor, output raw bytes and convert to String (may not be valid UTF-8)
    let raw_str = builder
        .to_vec(&mut rng)
        .map_err(|_| GfrStatus::ErrorInternal)?;
    Ok(raw_str)
}

pub struct RecipientResultInternal {
    pub key_id: String, // PGP PKESK only exposes 16-char Key ID, not full Fingerprint
    pub pub_algo: String,
    pub status: GfrRecipientStatus,
}

pub struct DecryptResultInternal {
    pub data: Vec<u8>,
    pub filename: String,
    pub recipients: Vec<RecipientResultInternal>,
}

// Helper to sniff all intended recipients from the encrypted data
fn sniff_recipients(data: &[u8]) -> Vec<RecipientResultInternal> {
    let mut results = Vec::new();
    let mut dearmored = Vec::new();
    let _ = Dearmor::new(Cursor::new(data)).read_to_end(&mut dearmored);
    let payload = if dearmored.is_empty() {
        data
    } else {
        &dearmored
    };

    let parser = PacketParser::new(Cursor::new(payload));
    for packet_result in parser {
        if let Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) = packet_result {
            if let Ok(id) = pkesk.id() {
                let algo = if let Ok(algo_id) = pkesk.algorithm() {
                    algo_to_string_simple(algo_id)
                } else {
                    String::new()
                };
                results.push(RecipientResultInternal {
                    key_id: id.to_string(),
                    pub_algo: algo,
                    status: GfrRecipientStatus::NoKey, // Default to NoKey until proven otherwise
                });
            }
        }
    }
    results
}

pub fn decrypt_internal(
    encrypted_data: &[u8],
    secret_key_block: &str,
    password: &str,
) -> Result<DecryptResultInternal, GfrStatus> {
    // 1. Parse the provided secret key block
    let (skey, _) =
        SignedSecretKey::from_string(secret_key_block).map_err(|_| GfrStatus::ErrorInvalidInput)?;

    // 2. Sniff the intended recipients from the raw message
    let mut recipients = sniff_recipients(encrypted_data);

    // 3. Try parsing the encrypted data
    let parsed_message = if let Ok((msg, _)) = Message::from_armor(Cursor::new(encrypted_data)) {
        msg
    } else if let Ok(msg) = Message::from_bytes(encrypted_data) {
        msg
    } else {
        return Err(GfrStatus::ErrorInvalidInput);
    };

    // 4. Attempt to decrypt the message
    let pwd_fn = Password::from(password.as_bytes());
    let mut decrypted = parsed_message
        .decrypt(&pwd_fn, &skey)
        .map_err(|_| GfrStatus::ErrorInternal)?; // Fails if wrong key or wrong password

    // 5. If decryption is successful, update the recipient list status
    let primary_id = skey.primary_key.legacy_key_id().to_string();
    let subkey_ids: Vec<String> = skey
        .secret_subkeys
        .iter()
        .map(|s| s.key.legacy_key_id().to_string())
        .collect();

    for rec in &mut recipients {
        // Match either the primary key ID or any subkey ID
        if rec.key_id == primary_id || subkey_ids.contains(&rec.key_id) {
            rec.status = GfrRecipientStatus::Success;
        }
    }

    // 6. Decompress if necessary
    if decrypted.is_compressed() {
        decrypted = decrypted
            .decompress()
            .map_err(|_| GfrStatus::ErrorInternal)?;
    }

    // 7. Extract the original filename if the underlying packet is a LiteralData packet
    let mut filename = String::new();
    if let pgp::composed::Message::Literal { ref reader, .. } = decrypted {
        // Access the LiteralDataHeader first, then extract the filename
        let header = reader.data_header();
        filename = String::from_utf8_lossy(header.file_name()).to_string();
    }

    // 8. Extract the actual payload
    let payload = decrypted
        .as_data_vec()
        .map_err(|_| GfrStatus::ErrorInternal)?;

    Ok(DecryptResultInternal {
        data: payload,
        filename,
        recipients,
    })
}

pub fn get_message_recipients_internal(data: &[u8]) -> Result<String, GfrStatus> {
    let mut key_ids = Vec::new();

    // 1. Try to un-armor the data
    let mut dearmored = Vec::new();
    let mut dearmor_stream = Dearmor::new(Cursor::new(data));

    // Attempt to read. If it fails or finds no armor headers, 'dearmored' remains empty
    let _ = dearmor_stream.read_to_end(&mut dearmored);

    // If it's empty, it means the input is likely already binary (not ASCII armored)
    let payload = if dearmored.is_empty() {
        data
    } else {
        &dearmored
    };

    // 2. Parse the PGP packets sequentially
    let parser = PacketParser::new(Cursor::new(payload));

    for packet_result in parser {
        if let Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) = packet_result {
            // Safely unwrap the Result returned by pkesk.id()
            if let Ok(id) = pkesk.id() {
                // Now `id` is a reference to a KeyId, which can be safely converted to a String
                key_ids.push(id.to_string());
            }
        }
    }

    if key_ids.is_empty() {
        return Err(GfrStatus::ErrorInvalidInput); // Not a valid encrypted message
    }

    // Join them with commas for easy FFI transfer (e.g., "A1B2C3D4E5F6G7H8,8H7G6F5E4D3C2B1A")
    Ok(key_ids.join(","))
}

pub struct SignResultInternal {
    pub data: Vec<u8>,
    pub signatures: Vec<SignatureResultInternal>,
}

pub fn sign_internal(
    name: &str,
    data: &[u8],
    secret_key_blocks: &[&str],
    passwords: &[&str],
    mode: GfrSignMode,
    ascii_armor: bool,
) -> Result<SignResultInternal, GfrStatus> {
    if secret_key_blocks.len() != passwords.len() || secret_key_blocks.is_empty() {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    // Cleartext strictly requires valid UTF-8 string data
    if mode == GfrSignMode::ClearText && std::str::from_utf8(data).is_err() {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    // 1. Parse ALL secret keys first to ensure they live long enough
    let mut parsed_keys = Vec::with_capacity(secret_key_blocks.len());
    for block in secret_key_blocks {
        let (skey, _) =
            SignedSecretKey::from_string(block).map_err(|_| GfrStatus::ErrorInvalidInput)?;
        parsed_keys.push(skey);
    }

    let mut rng = thread_rng();
    let mut created_signatures = Vec::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    // Helper closure to record the signature info once created
    let mut record_sig = |fpr: String, algo: PublicKeyAlgorithm| {
        created_signatures.push(SignatureResultInternal {
            fpr,
            status: GfrSignatureStatus::Valid, // Always Valid for newly created signatures
            created_at: current_time,
            pub_algo: algo_to_string_simple(algo),
            hash_algo: "SHA512".to_string(), // Hardcoded SHA512 in builder.sign()
            sig_type: mode,
        });
    };

    // 2. Route the operation based on the selected mode
    match mode {
        // ---------------------------------------------------------
        // MODE 0: INLINE SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Inline => {
            let mut builder = MessageBuilder::from_bytes(name.as_bytes().to_vec(), data.to_vec());
            let mut at_least_one_signer = false;

            for i in 0..parsed_keys.len() {
                let skey = &parsed_keys[i];
                let mut added_for_this_key = false;

                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let pwd_fn = Password::from(passwords[i].as_bytes());
                        builder.sign(&subkey.key, pwd_fn, HashAlgorithm::Sha512);
                        record_sig(subkey.key.fingerprint().to_string(), subkey.key.algorithm());
                        added_for_this_key = true;
                        at_least_one_signer = true;
                        break;
                    }
                }

                if !added_for_this_key && skey.primary_key.algorithm().can_sign() {
                    let fallback_pwd = Password::from(passwords[i].as_bytes());
                    builder.sign(&skey.primary_key, fallback_pwd, HashAlgorithm::Sha512);
                    record_sig(
                        skey.primary_key.fingerprint().to_string(),
                        skey.primary_key.algorithm(),
                    );
                    at_least_one_signer = true;
                }
            }

            if !at_least_one_signer {
                return Err(GfrStatus::ErrorInvalidInput);
            }

            let final_data = if ascii_armor {
                builder
                    .to_armored_string(&mut rng, ArmorOptions::default())
                    .map_err(|_| GfrStatus::ErrorArmorFailed)?
                    .into_bytes()
            } else {
                builder
                    .to_vec(&mut rng)
                    .map_err(|_| GfrStatus::ErrorInternal)?
            };

            Ok(SignResultInternal {
                data: final_data,
                signatures: created_signatures,
            })
        }

        // ---------------------------------------------------------
        // MODE 1: CLEARTEXT SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::ClearText => {
            let text = std::str::from_utf8(data).unwrap().to_string();

            // Find the first valid signer and generate the cleartext message
            for i in 0..parsed_keys.len() {
                let skey = &parsed_keys[i];

                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let pwd = Password::from(passwords[i].as_bytes());
                        if let Ok(msg) =
                            CleartextSignedMessage::sign(&mut rng, &text, &subkey.key, &pwd)
                        {
                            record_sig(
                                subkey.key.fingerprint().to_string(),
                                subkey.key.algorithm(),
                            );
                            let out = msg
                                .to_armored_string(ArmorOptions::default())
                                .map_err(|_| GfrStatus::ErrorArmorFailed)?
                                .into_bytes();
                            return Ok(SignResultInternal {
                                data: out,
                                signatures: created_signatures,
                            });
                        }
                    }
                }

                if skey.primary_key.algorithm().can_sign() {
                    let pwd = Password::from(passwords[i].as_bytes());
                    if let Ok(msg) =
                        CleartextSignedMessage::sign(&mut rng, &text, &skey.primary_key, &pwd)
                    {
                        record_sig(
                            skey.primary_key.fingerprint().to_string(),
                            skey.primary_key.algorithm(),
                        );
                        let out = msg
                            .to_armored_string(ArmorOptions::default())
                            .map_err(|_| GfrStatus::ErrorArmorFailed)?
                            .into_bytes();
                        return Ok(SignResultInternal {
                            data: out,
                            signatures: created_signatures,
                        });
                    }
                }
            }

            Err(GfrStatus::ErrorInvalidInput)
        }

        // ---------------------------------------------------------
        // MODE 2: DETACHED SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Detached => {
            // Find the first valid signer and generate the detached signature
            for i in 0..parsed_keys.len() {
                let skey = &parsed_keys[i];

                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let pwd = Password::from(passwords[i].as_bytes());
                        if let Ok(sig) = DetachedSignature::sign_binary_data(
                            &mut rng,
                            &subkey.key,
                            &pwd,
                            HashAlgorithm::Sha512,
                            data,
                        ) {
                            record_sig(
                                subkey.key.fingerprint().to_string(),
                                subkey.key.algorithm(),
                            );
                            let out = if ascii_armor {
                                sig.to_armored_bytes(None.into())
                                    .map_err(|_| GfrStatus::ErrorArmorFailed)?
                            } else {
                                sig.to_bytes().map_err(|_| GfrStatus::ErrorInternal)?
                            };
                            return Ok(SignResultInternal {
                                data: out,
                                signatures: created_signatures,
                            });
                        }
                    }
                }

                if skey.primary_key.algorithm().can_sign() {
                    let pwd = Password::from(passwords[i].as_bytes());
                    if let Ok(sig) = DetachedSignature::sign_binary_data(
                        &mut rng,
                        &skey.primary_key,
                        &pwd,
                        HashAlgorithm::Sha512,
                        data,
                    ) {
                        record_sig(
                            skey.primary_key.fingerprint().to_string(),
                            skey.primary_key.algorithm(),
                        );
                        let out = if ascii_armor {
                            sig.to_armored_bytes(None.into())
                                .map_err(|_| GfrStatus::ErrorArmorFailed)?
                        } else {
                            sig.to_bytes().map_err(|_| GfrStatus::ErrorInternal)?
                        };
                        return Ok(SignResultInternal {
                            data: out,
                            signatures: created_signatures,
                        });
                    }
                }
            }

            Err(GfrStatus::ErrorInvalidInput)
        }
    }
}

pub struct VerifyResultInternal {
    pub data: Vec<u8>,
    pub is_verified: bool,
    pub signatures: Vec<SignatureResultInternal>,
}

pub struct SignatureResultInternal {
    pub fpr: String,
    pub status: GfrSignatureStatus,
    pub created_at: u32,
    pub pub_algo: String,
    pub hash_algo: String,
    pub sig_type: GfrSignMode,
}

fn cert_contains_issuer(cert: &SignedPublicKey, issuer_hex: &str) -> bool {
    if cert
        .primary_key
        .fingerprint()
        .to_string()
        .eq_ignore_ascii_case(issuer_hex)
    {
        return true;
    }
    for subkey in &cert.public_subkeys {
        if subkey
            .key
            .fingerprint()
            .to_string()
            .eq_ignore_ascii_case(issuer_hex)
        {
            return true;
        }
    }
    false
}

pub fn algo_to_string_simple(algo: PublicKeyAlgorithm) -> String {
    // Uses the derived Debug trait to get the variant name as a String
    format!("{:?}", algo)
}

fn sniff_signatures(data: &[u8], mode: GfrSignMode) -> Vec<SignatureResultInternal> {
    let mut results = Vec::new();
    let mut dearmored = Vec::new();
    let _ = Dearmor::new(Cursor::new(data)).read_to_end(&mut dearmored);
    let payload = if dearmored.is_empty() {
        data
    } else {
        &dearmored
    };

    let parser = PacketParser::new(Cursor::new(payload));
    for packet_result in parser {
        if let Ok(Packet::Signature(sig)) = packet_result {
            for issuer in sig.issuer_fingerprint() {
                let fpr = issuer.to_string();
                let (hash_algo_id, pub_algo_id) = if let Some(config) = sig.config() {
                    (
                        config.hash_alg.to_string(),
                        algo_to_string_simple(config.pub_alg),
                    )
                } else {
                    (String::new(), String::new())
                };
                if !results
                    .iter()
                    .any(|r: &SignatureResultInternal| r.fpr == fpr)
                {
                    results.push(SignatureResultInternal {
                        fpr: fpr,
                        status: GfrSignatureStatus::NoKey,
                        created_at: sig.created().map(|d| d.as_secs() as u32).unwrap_or(0),
                        pub_algo: pub_algo_id,
                        hash_algo: hash_algo_id,
                        sig_type: mode,
                    });
                }
            }
        }
    }
    results
}

pub fn verify_internal(
    data: &[u8],
    sig_data: &[u8], // Used only for Detached mode
    public_key_blocks: &[&str],
    mode: GfrSignMode,
) -> Result<VerifyResultInternal, GfrStatus> {
    // 1. Parse candidate public keys
    let mut certs = Vec::with_capacity(public_key_blocks.len());
    for block in public_key_blocks {
        if let Ok((cert, _)) = SignedPublicKey::from_string(block) {
            certs.push(cert);
        }
    }

    debug!(
        "Parsed {} public keys for verification, mode: {:?}",
        certs.len(),
        mode
    );

    match mode {
        // ---------------------------------------------------------
        // MODE 0: INLINE SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Inline => {
            let mut msg = if let Ok((m, _)) = Message::from_armor(Cursor::new(data)) {
                m
            } else if let Ok(m) = Message::from_bytes(data) {
                m
            } else {
                return Err(GfrStatus::ErrorInvalidInput);
            };

            // try to sniff signatures from the message packets first, to build
            // an initial list of issuers and their statuses
            let mut signatures = sniff_signatures(data, mode);
            let mut is_verified = false;

            for cert in &certs {
                // if verification succeeds with this cert, mark all matching
                // issuers as Valid; if it fails, mark them as BadSignature (but
                // only if we previously marked them as NoKey)
                if msg.verify(cert).is_ok() {
                    is_verified = true;
                    let mut found = false;

                    // Update the status of all signatures that match this
                    // cert's primary key or any of its subkeys
                    for sig in &mut signatures {
                        if cert_contains_issuer(cert, &sig.fpr) {
                            sig.status = GfrSignatureStatus::Valid;
                            found = true;
                        }
                    }

                    // If we found a matching issuer in the signatures, we would
                    // have updated its status to Valid.
                    if !found {
                        let fpr: String = cert.primary_key.fingerprint().to_string();
                        signatures.push(SignatureResultInternal {
                            fpr,
                            status: GfrSignatureStatus::Valid,
                            created_at: 0,
                            pub_algo: "None".to_string(),
                            hash_algo: "None".to_string(),
                            sig_type: mode,
                        });
                    }
                } else {
                    for sig in &mut signatures {
                        if cert_contains_issuer(cert, &sig.fpr)
                            && sig.status == GfrSignatureStatus::NoKey
                        {
                            sig.status = GfrSignatureStatus::BadSignature;
                        }
                    }
                }
            }

            let clear_data = msg.as_data_vec().map_err(|_| GfrStatus::ErrorInternal)?;
            Ok(VerifyResultInternal {
                data: clear_data,
                is_verified,
                signatures,
            })
        }

        // ---------------------------------------------------------
        // MODE 1: CLEARTEXT SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::ClearText => {
            debug!("Attempting to parse cleartext signed message for verification");

            let text_str = std::str::from_utf8(data).map_err(|_| GfrStatus::ErrorInvalidInput)?;
            let (msg, _) = CleartextSignedMessage::from_string(text_str)
                .map_err(|_| GfrStatus::ErrorInvalidInput)?;

            debug!(
                "Parsed cleartext signed message with {} signatures",
                msg.signatures().len()
            );

            let mut signatures = Vec::new();
            for sig in msg.signatures().into_iter() {
                for issuer in sig.issuer_fingerprint() {
                    let fpr: String = issuer.to_string();
                    let (hash_algo_id, pub_algo_id) = if let Some(config) = sig.config() {
                        (
                            config.hash_alg.to_string(),
                            algo_to_string_simple(config.pub_alg),
                        )
                    } else {
                        (String::new(), String::new())
                    };
                    if !signatures
                        .iter()
                        .any(|r: &SignatureResultInternal| r.fpr == fpr)
                    {
                        signatures.push(SignatureResultInternal {
                            fpr,
                            status: GfrSignatureStatus::NoKey,
                            created_at: sig.created().map(|d| d.as_secs() as u32).unwrap_or(0),
                            pub_algo: pub_algo_id,
                            hash_algo: hash_algo_id,
                            sig_type: mode,
                        });
                    }
                }
            }

            let mut is_verified = false;
            for cert in &certs {
                let is_cert_valid = msg.verify(cert).is_ok();
                for sig in &mut signatures {
                    if cert_contains_issuer(cert, &sig.fpr) {
                        sig.status = if is_cert_valid {
                            is_verified = true;
                            GfrSignatureStatus::Valid
                        } else {
                            GfrSignatureStatus::BadSignature
                        };
                    }
                }
            }

            let clear_data = msg
                .to_armored_bytes(ArmorOptions::default())
                .unwrap_or_default();
            Ok(VerifyResultInternal {
                data: clear_data,
                is_verified,
                signatures,
            })
        }

        // ---------------------------------------------------------
        // MODE 2: DETACHED SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Detached => {
            if sig_data.is_empty() {
                return Err(GfrStatus::ErrorInvalidInput);
            }

            let sig_msg =
                if let Ok((s, _)) = DetachedSignature::from_armor_single(Cursor::new(sig_data)) {
                    s
                } else if let Ok(s) = DetachedSignature::from_bytes(sig_data) {
                    s
                } else {
                    return Err(GfrStatus::ErrorInvalidInput);
                };

            // try to sniff signatures from the signature packets first, to build
            // an initial list of issuers and their statuses
            let mut signatures = sniff_signatures(sig_data, mode);
            let mut is_verified = false;

            for cert in &certs {
                let is_cert_valid = sig_msg.verify(cert, data).is_ok();
                for sig in &mut signatures {
                    if cert_contains_issuer(cert, &sig.fpr) {
                        sig.status = if is_cert_valid {
                            is_verified = true;
                            GfrSignatureStatus::Valid
                        } else {
                            GfrSignatureStatus::BadSignature
                        };
                    }
                }
            }

            // Detached verification doesn't extract plaintext, only confirms status
            Ok(VerifyResultInternal {
                data: Vec::new(),
                is_verified,
                signatures,
            })
        }
    }
}

pub fn get_signature_issuers_internal(data: &[u8]) -> Result<(String, String), GfrStatus> {
    let mut recipients = Vec::new();
    let mut issuers = Vec::new();

    // 1. First, attempt to parse as a Cleartext Signed Message
    if let Ok(text_str) = std::str::from_utf8(data) {
        if let Ok((msg, _)) = CleartextSignedMessage::from_string(text_str) {
            for sig in msg.signatures().into_iter() {
                for issuer in sig.issuer_key_id() {
                    issuers.push(issuer.to_string());
                }
            }
            // Cleartext messages only contain signatures, not encrypted recipients
            issuers.sort();
            issuers.dedup();
            return Ok((recipients.join(","), issuers.join(",")));
        }
    }

    // 2. Un-armor if necessary for standard encrypted or detached/inline signed data
    let mut dearmored = Vec::new();
    let _ = Dearmor::new(Cursor::new(data)).read_to_end(&mut dearmored);

    let payload = if dearmored.is_empty() {
        data
    } else {
        &dearmored
    };

    // 3. Parse standard PGP packets
    let parser = PacketParser::new(Cursor::new(payload));

    for packet_result in parser {
        if let Ok(packet) = packet_result {
            match packet {
                // Sniff Recipient (for Encryption)
                Packet::PublicKeyEncryptedSessionKey(pkesk) => {
                    if let Ok(id) = pkesk.id() {
                        recipients.push(id.to_string());
                    }
                }
                // Sniff Signer from OnePassSignature (Appears at the start of inline signatures)
                Packet::OnePassSignature(ops) => {
                    // Match on the version-specific enum to extract the identifier
                    match ops.version_specific() {
                        pgp::packet::OpsVersionSpecific::V3 { key_id } => {
                            // V3 OPS directly contains a KeyId
                            issuers.push(key_id.to_string());
                        }
                        pgp::packet::OpsVersionSpecific::V6 { fingerprint, .. } => {
                            // V6 OPS contains a 32-byte fingerprint. Format it safely as an uppercase HEX string.
                            let fp_str: String =
                                fingerprint.iter().map(|b| format!("{:02X}", b)).collect();
                            issuers.push(fp_str);
                        }
                        _ => {}
                    }
                }
                // Sniff Signer from Signature packet (Used in detached signatures or end of inline)
                Packet::Signature(sig) => {
                    for issuer in sig.issuer_key_id() {
                        issuers.push(issuer.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    // 4. Deduplicate the collected IDs to avoid repeating the same Key ID
    recipients.sort();
    recipients.dedup();

    issuers.sort();
    issuers.dedup();

    Ok((recipients.join(","), issuers.join(",")))
}
