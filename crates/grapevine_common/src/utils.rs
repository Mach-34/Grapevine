use crate::{Fr, MAX_SECRET_CHARS, MAX_USERNAME_CHARS, SECRET_FIELD_LENGTH};
use std::error::Error;

/**
 * Generates a new stringified random bn254 field element
 *
 * @return - a stringified random field element
 */
#[cfg(not(target_family = "wasm"))]
pub fn random_fr() -> Fr {
    ff::Field::random(rand::rngs::OsRng)
}

#[cfg(target_family = "wasm")]
pub fn random_fr() -> Fr {
    // todo: implement random sampling for wasm
    let mut buf = [0u8; 31];
    getrandom::getrandom(&mut buf).unwrap();
    // convert to 32 bytes
    let mut fr_buf = [0u8; 32];
    fr_buf[0..buf.len()].copy_from_slice(&buf);
    fr_buf[31] = 0;
    // check valid fr
    Fr::from_repr(fr_buf).unwrap();
    // return hex string
    format!("0x{}", hex::encode(fr_buf))
}

/**
 * Converts a given word to array of 6 field elements
 * @dev split into 31-byte strings to fit in finite field and pad with 0's where necessary
 *
 * @param phrase - the string entered by user to compute hash for (will be length checked)
 * @return - array of 6 Fr elements
 */
pub fn convert_phrase_to_fr(
    phrase: &String,
) -> Result<[[u8; 32]; SECRET_FIELD_LENGTH], Box<dyn Error>> {
    // check
    if phrase.len() > MAX_SECRET_CHARS {
        return Err("Phrase must be <= 180 characters".into());
    }

    let mut chunks: [[u8; 32]; SECRET_FIELD_LENGTH] = Default::default();
    for i in 0..SECRET_FIELD_LENGTH {
        let start = i * 31;
        let end = (i + 1) * 31;
        let mut chunk: [u8; 32] = [0; 32];
        if start >= phrase.len() {
        } else if end > phrase.len() {
            chunk[1..(phrase.len() - start + 1)].copy_from_slice(&phrase.as_bytes()[start..]);
        } else {
            chunk[1..32].copy_from_slice(&phrase.as_bytes()[start..end]);
        }
        chunk.reverse();
        chunks[i] = chunk;
    }
    // format!("0x{}", hex::encode(chunk));
    Ok(chunks)
}

/**
 * Converts a given username to a field element
 *
 * @param username - the username to convert to utf8 and into field element
 * @return - the username serialied into the field element
 */
pub fn convert_username_to_fr(username: &String) -> Result<[u8; 32], Box<dyn Error>> {
    if username.len() > MAX_USERNAME_CHARS {
        return Err("Username must be <= 30 characters".into());
    }
    let mut bytes: [u8; 32] = [0; 32];
    bytes[1..(username.len() + 1)].copy_from_slice(&username.as_bytes()[..]);
    bytes.reverse();
    //    Ok(format!("0x{}", hex::encode(bytes)))
    Ok(bytes)
}