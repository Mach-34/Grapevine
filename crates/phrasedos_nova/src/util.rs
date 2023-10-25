use nova_snark::{provider, traits::Group, PublicParams};
use nova_scotia::F;
use std::env::current_dir;
use nova_scotia::{C1, C2};

use std::error::Error;
pub type G1 = provider::bn256_grumpkin::bn256::Point;
pub type G2 = provider::bn256_grumpkin::bn256::Point;
pub type Fr = F::<G1>;

pub const SECRET_FIELD_LENGTH: usize = 6;
pub const MAX_SECRET_CHARS: usize = 180;
pub const MAX_USERNAME_CHARS: usize = 30;
pub const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const EMPTY_SECRET: [&str; SECRET_FIELD_LENGTH] = [ZERO; SECRET_FIELD_LENGTH];

/**
 * Converts a given word to array of 6 field elements
 * @dev split into 31-byte strings to fit in finite field and pad with 0's where necessary
 *
 * @param phrase - the string entered by user to compute hash for (will be length checked)
 * @return - array of 6 Fr elements
 */
pub fn convert_phrase_to_felts(phrase: String) -> Result<[String; SECRET_FIELD_LENGTH], Box<dyn Error>> {
    // check
    if phrase.len() > MAX_SECRET_CHARS {
        return Err("Phrase must be <= 180 characters".into());
    }

    let mut chunks: [String; SECRET_FIELD_LENGTH] = Default::default();
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
        chunks[i] = format!("0x{}", hex::encode(chunk));
    }

    Ok(chunks)
}

/**
 * Converts a given username to a field element
 * 
 * @param username - the username to convert to utf8 and into field element
 * @return - the username serialied into the field element
 */
pub fn convert_username_to_felt(username: String) -> Result<String, Box<dyn Error>> {
    if username.len() > MAX_USERNAME_CHARS {
        return Err("Phrase must be <= 180 characters".into());
    }
    let mut bytes: [u8; 32] = [0; 32];
    bytes[1..(username.len() + 1)].copy_from_slice(&username.as_bytes()[..]);
    bytes.reverse();
    Ok(format!("0x{}", hex::encode(bytes)))
}

//https://github.com/dmpierre/zkconnect4/blob/86a129400647edc75a06f032bfb466186874c489/zkconnect4-nova-lib/src/lib.rs#L220
pub fn write_pp_file<G1, G2>(path: &str, pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>)
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let pp_serialized = serde_json::to_string(&pp).unwrap();
    std::fs::write(path, &pp_serialized).unwrap();
}

//https://github.com/dmpierre/zkconnect4/blob/86a129400647edc75a06f032bfb466186874c489/zkconnect4-nova-lib/src/lib.rs#L229C1-L238C2
pub fn read_pp_file<G1, G2>(path: &str) -> PublicParams<G1, G2, C1<G1>, C2<G2>>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let pp_file = std::fs::read_to_string(path).expect("Unable to read file");
    let pp: PublicParams<G1, G2, C1<G1>, C2<G2>> =
        serde_json::from_str(&pp_file).expect("Incorrect pp format");
    return pp;
}