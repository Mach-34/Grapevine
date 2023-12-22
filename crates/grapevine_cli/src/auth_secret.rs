use crate::crypto::gen_aes_key;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use babyjubjub_rs::{Point, PrivateKey};
use grapevine_circuits::Fr;
use serde::{
    de::{self, Visitor},
    ser, Deserialize, Deserializer, Serialize, Serializer,
};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/**
 * The AuthSecret as it exists at rest in the Grapevine Server
 * @notice: encrypted and must be decrypted by the right key
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthSecretEncrypted {
    pub username: String,
    pub recipient: [u8; 32],
    pub ephemeral_key: [u8; 32],
    #[serde(
        serialize_with = "serialize_ciphertext",
        deserialize_with = "deserialize_ciphertext"
    )]
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

impl AuthSecretEncrypted {
    /**
     * Create a new encrypted auth secret
     *
     * @param username - the username associated with this auth secret
     * @param auth_secret - the auth secret that is used by this username
     * @param recipient- the bjj pubkey of the recipient of the auth secret
     * @returns - encrypted auth secret
     */
    pub fn new(username: String, auth_secret: Fr, recipient: Point) -> AuthSecretEncrypted {
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
        AuthSecretEncrypted {
            username,
            recipient: recipient.compress(),
            ephemeral_key: ephm_pk,
            ciphertext: ciphertext,
        }
    }

    /**
     * Decrypts an encrypted AuthSecret
     *
     * @param recipient - the private key of the recipient of the auth secret
     * @returns - the decrypted auth secret
     */
    pub fn decrypt(&self, recipient: PrivateKey) -> AuthSecret {
        // compute the aes-cbc-128 key
        let ephm_pk = babyjubjub_rs::decompress_point(self.ephemeral_key).unwrap();
        let (aes_key, aes_iv) = gen_aes_key(recipient, ephm_pk);
        // decrypt the auth secret
        let mut buf = self.ciphertext;
        let pt: [u8; 32] = Aes128CbcDec::new(aes_key[..].into(), aes_iv[..].into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .unwrap()
            .try_into()
            .unwrap();
        // convert the auth secret into an Fr
        let auth_secret = Fr::from_bytes(&pt).unwrap();
        AuthSecret {
            username: self.username.clone(),
            auth_secret,
        }
    }
}

// Custom serializer for [u8; 48]
fn serialize_ciphertext<S>(data: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert the array to a slice and serialize it
    serializer.serialize_bytes(data)
}

fn deserialize_ciphertext<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
where
    D: Deserializer<'de>,
{
    struct ByteArrayVisitor;

    impl<'de> Visitor<'de> for ByteArrayVisitor {
        type Value = [u8; 48];

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte array of length 48")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut array = [0u8; 48];
            for (i, byte) in array.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            Ok(array)
        }
    }

    deserializer.deserialize_byte_buf(ByteArrayVisitor)
}

#[cfg(test)]
mod test {
    use super::*;
    use grapevine_circuits::utils::random_fr;
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
        println!("Json: {:#?}", json);
        // deserialize from json
        let deserialized = serde_json::from_str::<AuthSecretEncrypted>(&json).unwrap();
        let decrypted_auth_secret = deserialized.decrypt(recipient_sk);
        // check that the auth secret is the same
        assert!(decrypted_auth_secret.auth_secret.eq(&auth_secret));
    }
}
