use crate::crypto::gen_aes_key;
use crate::Fr;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use babyjubjub_rs::{Point, PrivateKey, Signature};
use serde::{Deserialize, Serialize};
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/**
 * Encrypted version of an auth secret with the necessary info for the recipient to decrypt it
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthSignatureEncrypted {
    pub username: String,
    pub recipient: [u8; 32],
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 80],
}

/**
 * The confidential AuthSecret used when proving a degree of separation in Grapevine
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthSignature {
    pub username: String,
    #[serde(with = "serde_bytes")]
    pub auth_signature: [u8; 64], // compressed form of auth signature
}

impl AuthSignature {
    fn fmt_circom() {}
}

pub trait AuthSignatureEncryptedUser {
    /**
     * Create a new encrypted auth signature
     *
     * @param username - the username associated with this auth secret
     * @param auth_signature - the auth signature over user's pubkey
     * @param recipient- the bjj pubkey of the recipient of the auth secret
     * @returns - encrypted auth signature
     */
    fn new(username: String, auth_signature: Signature, recipient: Point) -> Self;

    /**
     * Decrypts an encrypted AuthSignature
     *
     * @param recipient - the private key of the recipient of the auth secret
     * @returns - the decrypted auth signature
     */
    fn decrypt(&self, recipient: PrivateKey) -> AuthSignature;
}

impl AuthSignatureEncryptedUser for AuthSignatureEncrypted {
    fn new(username: String, signature: Signature, recipient: Point) -> Self {
        // generate a new ephemeral keypair
        let ephm_sk = babyjubjub_rs::new_key();
        let ephm_pk = ephm_sk.public().compress();
        // compute the aes-cbc-128 key
        let (aes_key, aes_iv) = gen_aes_key(ephm_sk, recipient.clone());
        // encrypt the auth secret
        let plaintext = signature.compress();
        let mut buf = [0u8; 80];
        buf[..plaintext.len()].copy_from_slice(&plaintext);
        let ciphertext: [u8; 80] = Aes128CbcEnc::new(aes_key[..].into(), aes_iv[..].into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .try_into()
            .unwrap();
        // return the encrypted auth secret
        Self {
            username,
            recipient: recipient.compress(),
            ephemeral_key: ephm_pk,
            ciphertext: ciphertext,
        }
    }

    fn decrypt(&self, recipient: PrivateKey) -> AuthSignature {
        // compute the aes-cbc-128 key
        let ephm_pk = babyjubjub_rs::decompress_point(self.ephemeral_key).unwrap();
        let (aes_key, aes_iv) = gen_aes_key(recipient, ephm_pk);
        // decrypt the auth secret
        let mut buf = self.ciphertext;
        let auth_signature: [u8; 64] = Aes128CbcDec::new(aes_key[..].into(), aes_iv[..].into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .unwrap()
            .try_into()
            .unwrap();
        AuthSignature {
            username: self.username.clone(),
            auth_signature,
        }
    }
}

#[cfg(test)]
mod test {
    use num_bigint::{BigInt, Sign};
    use poseidon_rs::Poseidon;

    use super::*;
    use crate::compat::ff_ce_to_le_bytes;
    #[test]
    fn integrity_test() {
        // setup
        let username = String::from("JP4G");
        let sender_sk = babyjubjub_rs::new_key();
        let recipient_sk = babyjubjub_rs::new_key();
        let recipient_pk = recipient_sk.public();

        // hash recipient pubkey
        let poseidon = Poseidon::new();
        let hash = poseidon.hash(vec![recipient_pk.x, recipient_pk.y]).unwrap();

        // sign pubkey hash
        let msg = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_le_bytes(&hash));
        let auth_signature = sender_sk.sign(msg).unwrap();

        // create encrypted auth signature
        let encrypted_auth_signature =
            AuthSignatureEncrypted::new(username, auth_signature.clone(), recipient_pk);
        // decrypt the auth secret
        let decrypted_auth_secret = encrypted_auth_signature.decrypt(recipient_sk);
        // check that the auth secret is the same
        assert!(decrypted_auth_secret
            .auth_signature
            .eq(&auth_signature.compress()));
        println!("auth_secret_1 {:?}", auth_signature);
        println!("auth_secret_2 {:?}", decrypted_auth_secret.auth_signature);
    }

    #[test]
    fn serde_test() {
        // setup
        let username = String::from("JP4G");
        let sender_sk = babyjubjub_rs::new_key();
        let recipient_sk = babyjubjub_rs::new_key();
        let recipient_pk = recipient_sk.public();

        // hash recipient pubkey
        let poseidon = Poseidon::new();
        let hash = poseidon.hash(vec![recipient_pk.x, recipient_pk.y]).unwrap();

        // sign pubkey hash
        let msg = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_le_bytes(&hash));
        let auth_signature = sender_sk.sign(msg).unwrap();

        // create encrypted auth signature
        let encrypted_auth_signature =
            AuthSignatureEncrypted::new(username, auth_signature.clone(), recipient_pk);
        // serialize to json
        let json = serde_json::to_string(&encrypted_auth_signature).unwrap();
        // deserialize from json
        let deserialized = serde_json::from_str::<AuthSignatureEncrypted>(&json).unwrap();
        let decrypted_auth_signature = deserialized.decrypt(recipient_sk);
        // check that the auth secret is the same
        assert!(decrypted_auth_signature
            .auth_signature
            .eq(&auth_signature.compress()));
    }
}
