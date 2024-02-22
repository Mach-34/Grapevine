use crate::crypto::gen_aes_key;
use crate::Fr;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use babyjubjub_rs::{Point, PrivateKey};
use serde::{Deserialize, Serialize};
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/**
 * Encrypted version of an auth secret with the necessary info for the recipient to decrypt it
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthSecretEncrypted {
    pub username: String,
    pub recipient: [u8; 32],
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 48],
}

/**
 * The confidential AuthSecret used when proving a degree of separation in Grapevine
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthSecret {
    pub username: String,
    pub auth_secret: Fr,
}

pub trait AuthSecretEncryptedUser {
    /**
     * Create a new encrypted auth secret
     *
     * @param username - the username associated with this auth secret
     * @param auth_secret - the auth secret that is used by this username
     * @param recipient- the bjj pubkey of the recipient of the auth secret
     * @returns - encrypted auth secret
     */
    fn new(username: String, auth_secret: Fr, recipient: Point) -> Self;

    /**
     * Decrypts an encrypted AuthSecret
     *
     * @param recipient - the private key of the recipient of the auth secret
     * @returns - the decrypted auth secret
     */
    fn decrypt(&self, recipient: PrivateKey) -> AuthSecret;
}

impl AuthSecretEncryptedUser for AuthSecretEncrypted {
    fn new(username: String, auth_secret: Fr, recipient: Point) -> Self {
        // generate a new ephemeral keypair
        let ephm_sk = babyjubjub_rs::new_key();
        let ephm_pk = ephm_sk.public().compress();
        // compute the aes-cbc-128 key
        let (aes_key, aes_iv) = gen_aes_key(ephm_sk, recipient.clone());
        // encrypt the auth secret
        let plaintext = auth_secret.to_bytes();
        let mut buf = [0u8; 48];
        buf[..plaintext.len()].copy_from_slice(&plaintext);
        let ciphertext: [u8; 48] = Aes128CbcEnc::new(aes_key[..].into(), aes_iv[..].into())
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

    fn decrypt(&self, recipient: PrivateKey) -> AuthSecret {
        // compute the aes-cbc-128 key
        let ephm_pk = babyjubjub_rs::decompress_point(self.ephemeral_key).unwrap();
        let (aes_key, aes_iv) = gen_aes_key(recipient, ephm_pk);
        // decrypt the auth secret
        let mut buf = self.ciphertext;
        let ptr: [u8; 32] = Aes128CbcDec::new(aes_key[..].into(), aes_iv[..].into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .unwrap()
            .try_into()
            .unwrap();
        // convert the auth secret into an Fr
        let auth_secret = Fr::from_bytes(&ptr).unwrap();
        AuthSecret {
            username: self.username.clone(),
            auth_secret,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::random_fr;
    #[test]
    fn integrity_test() {
        // setup
        let auth_secret = random_fr();
        let username = String::from("JP4G");
        let recipient_sk = babyjubjub_rs::new_key();
        let recipient_pk = recipient_sk.public();
        // create encrypted auth secret
        let encrypted_auth_secret = AuthSecretEncrypted::new(username, auth_secret, recipient_pk);
        // decrypt the auth secret
        let decrypted_auth_secret = encrypted_auth_secret.decrypt(recipient_sk);
        // check that the auth secret is the same
        assert!(decrypted_auth_secret.auth_secret.eq(&auth_secret));
        println!("auth_secret_1 {:?}", auth_secret);
        println!("auth_secret_2 {:?}", decrypted_auth_secret.auth_secret);
    }

    #[test]
    fn serde_test() {
        // setup
        let auth_secret = random_fr();
        let username = String::from("JP4G");
        let recipient_sk = babyjubjub_rs::new_key();
        let recipient_pk = recipient_sk.public();
        // create encrypted auth secret
        let encrypted_auth_secret = AuthSecretEncrypted::new(username, auth_secret, recipient_pk);
        // serialize to json
        let json = serde_json::to_string(&encrypted_auth_secret).unwrap();
        // deserialize from json
        let deserialized = serde_json::from_str::<AuthSecretEncrypted>(&json).unwrap();
        let decrypted_auth_secret = deserialized.decrypt(recipient_sk);
        // check that the auth secret is the same
        assert!(decrypted_auth_secret.auth_secret.eq(&auth_secret));
    }
}
