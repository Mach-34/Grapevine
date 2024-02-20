use crate::{compat::ff_ce_to_le_bytes, utils::convert_username_to_fr};
use babyjubjub_rs::{Point, PrivateKey};
use num_bigint::{RandBigInt, ToBigInt};
use sha256::digest;
use sha3::{Digest, Sha3_256};

/**
 * Computes an AES-CBC-128 Key from a Baby Jub Jub shared secret
 *
 * @param sk - the private key in the ecdh shared secret
 * @param pk - the public key in the ecdh shared secret (ephemeral in practice)
 * @return - a tuple (AES Key, AES Iv) used to encrypt/ decrypt aes-cbc-128
 */
pub fn gen_aes_key(sk: PrivateKey, pk: Point) -> ([u8; 16], [u8; 16]) {
    // compute ecdh shared secret
    let shared_secret = pk.mul_scalar(&sk.scalar_key());
    // serialize for hash digest
    let secret_buffer = [shared_secret.x, shared_secret.y]
        .iter()
        .map(|el| ff_ce_to_le_bytes(el))
        .flatten()
        .collect::<Vec<u8>>();
    // compute sha256 hash of shared secret
    let hash = digest(&secret_buffer).as_bytes().to_vec();
    // split the hash into the aes key and aes iv
    let aes_key: [u8; 16] = hash[0..16].try_into().unwrap();
    let aes_iv: [u8; 16] = hash[16..32].try_into().unwrap();
    // return
    (aes_key, aes_iv)
}

/**
 * Generates a new private key as a 32 byte array
 *
 * @returns - the new private key
 */
pub fn new_private_key() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let sk_raw = rng.gen_biguint(1024).to_bigint().unwrap();
    let (_, sk_raw_bytes) = sk_raw.to_bytes_be();
    sk_raw_bytes[..32].try_into().unwrap()
}

/**
 * Computes the sha256 hash H |username, nonce| with last byte zeroed
 *
 * @param username - the username to hash
 * @param nonce - the nonce to hash
 * @return - the sha256 hash of the username and nonce
 */
pub fn nonce_hash(username: &String, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    // add username to hash buffer
    let username_bytes = convert_username_to_fr(username).unwrap();
    hasher.update(username_bytes);
    // add nonce to hash buffer
    let nonce_bytes = nonce.to_le_bytes();
    hasher.update(nonce_bytes);
    // compute sha256 hash
    let mut hash: [u8; 32] = hasher.finalize().into();
    // 0 the last byte to ensure it always falls within the prime field Fr
    hash[31] = 0;

    hash
}
