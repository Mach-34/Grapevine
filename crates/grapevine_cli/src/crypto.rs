use babyjubjub_rs::{Point, PrivateKey};
use ff::to_hex;
use num_bigint::BigInt;
use sha256::digest;

/**
 * Generates a new Baby Jubjub keypair
 *
 * @returns - the scalar representing the bjj private key
 */
pub fn gen_bjj_key() -> BigInt {
    return babyjubjub_rs::new_key().scalar_key();
}

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
        .map(|x| to_hex(x).as_bytes().to_vec())
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
