use std::path::PathBuf;

use babyjubjub_rs::{Point, PrivateKey, Signature};
use grapevine_common::auth_secret::{AuthSecret, AuthSecretEncrypted, AuthSecretEncryptedUser};
use grapevine_common::compat::ff_ce_from_le_bytes;
use grapevine_common::utils::{convert_username_to_fr, random_fr};
use grapevine_common::Fr;
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GrapevineAccount {
    username: String,
    auth_secret: Fr,
    private_key: [u8; 32],
    nonce: u64,
}

impl GrapevineAccount {
    /**
     * Generates a new account
     *
     * @param username - the username to associate with this account
     * @returns - the new account with an autogenerated private key and auth secret
     */
    pub fn new(username: String) -> GrapevineAccount {
        let private_key = GrapevineAccount::new_private_key();
        let auth_secret = random_fr();
        GrapevineAccount {
            username,
            auth_secret,
            private_key,
            nonce: 0,
        }
    }

    /**
     * Reads an account saved to the filesystem
     */
    pub fn from_fs(path: PathBuf) -> Result<GrapevineAccount, serde_json::Error> {
        let account = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(&account)
    }

    pub fn username(&self) -> &String {
        &self.username
    }

    pub fn pubkey(&self) -> Point {
        PrivateKey::import(self.private_key.to_vec())
            .unwrap()
            .public()
    }

    pub fn private_key_raw(&self) -> &[u8; 32] {
        &self.private_key
    }

    pub fn private_key(&self) -> PrivateKey {
        PrivateKey::import(self.private_key.to_vec()).unwrap()
    }

    pub fn auth_secret(&self) -> &Fr {
        &self.auth_secret
    }

    pub fn encrypt_auth_secret(&self, recipient: Point) -> AuthSecretEncrypted {
        AuthSecretEncrypted::new(self.username.clone(), self.auth_secret.clone(), recipient)
    }

    pub fn decrypt_auth_secret(&self, message: AuthSecretEncrypted) -> AuthSecret {
        message.decrypt(self.private_key())
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

    pub fn sign_username(&self) -> Signature {
        let message = BigInt::from_bytes_le(
            Sign::Plus,
            &convert_username_to_fr(&self.username).unwrap()[..],
        );
        self.private_key().sign(message).unwrap()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_serialize() {
        let username = String::from("JP4G");
        let account = GrapevineAccount::new(username);
        let json = serde_json::to_string(&account).unwrap();
        let deserialized = serde_json::from_str::<GrapevineAccount>(&json).unwrap();
        let deserialized_key = hex::encode(deserialized.private_key);
        assert_eq!(deserialized_key, hex::encode(account.private_key));
    }
}
