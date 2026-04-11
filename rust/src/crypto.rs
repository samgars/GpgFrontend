use std::ascii;

use crate::types::GfrStatus;
use pgp::{
    composed::{ArmorOptions, Deserializable, Message, MessageBuilder, SignedPublicKey},
    crypto::sym::SymmetricKeyAlgorithm,
    types::KeyDetails,
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
