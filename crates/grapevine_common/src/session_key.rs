use crate::compat::{ff_ce_from_le_bytes, ff_ce_to_le_bytes};
use crate::errors::GrapevineServerError;
use crate::utils::convert_username_to_fr;
use babyjubjub_rs::{PrivateKey, Signature};
use num_bigint::{BigInt, Sign};
use poseidon_rs::Poseidon;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct SessionKey {
    pub username: String,
    pub pubkey: [u8; 32],
    pub session_key: Uuid,
}

impl SessionKey {
    /**
     * Compute the poseidon hash of the session key
     * @notice - hash = H(username, pubkey.x, pubkey.y, uuid)
     *
     * @return - the poseidon hash of the session key
     */
    fn hash(&self) -> [u8; 32] {
        // convert username to ff_ce Fr field element
        let username_fr = ff_ce_from_le_bytes(convert_username_to_fr(&self.username).unwrap());
        // extract points from pubkey
        let pubkey = babyjubjub_rs::decompress_point(self.pubkey).unwrap();
        // convert the uuid into a field element
        let mut uuid_bytes = [0; 32];
        uuid_bytes[..16].copy_from_slice(&self.session_key.to_bytes_le());
        let uuid_fr = ff_ce_from_le_bytes(uuid_bytes);
        // compute the poseidon hash H(username, pubkey.x, pubkey.y, uuid)
        let poseidon = Poseidon::new();
        let hash = poseidon
            .hash(vec![username_fr, pubkey.x, pubkey.y, uuid_fr])
            .unwrap();
        // return converted hash
        ff_ce_to_le_bytes(&hash)
    }
}

pub trait Client {
    /**
     * Sign the hash of the session key with the given private key
     *
     * @param signer - the bjj private key to sign the session key hash with
     * @return - the signature over the session key hash
     */
    fn sign(&self, signer: PrivateKey) -> Signature;
}

impl Client for SessionKey {
    fn sign(&self, signer: PrivateKey) -> Signature {
        // compute the hash of the session key
        let hash = self.hash();
        // convert the hash into a bigint
        let msg = BigInt::from_bytes_le(Sign::Plus, &hash[..]);
        // sign the hash with the private key
        signer.sign(msg).unwrap()
    }
}

pub trait Server {
    /**
     * Creates a new session key
     * @notice - checks if signature is by the pubkey over the username as a field element
     *
     * @param username - the username to issue a session key for
     * @param pubkey - the public key associated with the username
     * @param signature - the signature over the username by pubkey
     * @returns - a new session key
     */
    fn new(
        username: String,
        pubkey: [u8; 32],
        signature: Signature,
    ) -> Result<SessionKey, GrapevineServerError>;

    /**
     * Verify the signature over the session key hash by the pubkey in the session key
     *
     * @param signature - the signature over the session key hash
     * @return - true if the signature is valid by the session key's pubkey, false otherwise
     */
    fn verify(&self, signature: Signature) -> Result<(), GrapevineServerError>;
}

impl Server for SessionKey {
    fn new(
        username: String,
        pubkey: [u8; 32],
        signature: Signature,
    ) -> Result<SessionKey, GrapevineServerError> {
        // convert the username to a field element then a bigint
        let username_fr = convert_username_to_fr(&username).unwrap();
        let msg = BigInt::from_bytes_le(Sign::Plus, &username_fr[..]);
        // decompress the pubkey
        let pubkey_decompressed = babyjubjub_rs::decompress_point(pubkey).unwrap();
        // verify the signature over the username by the pubkey
        match babyjubjub_rs::verify(pubkey_decompressed, signature, msg) {
            true => Ok(SessionKey {
                username,
                pubkey,
                session_key: Uuid::new_v4(),
            }),
            false => Err(GrapevineServerError::Signature(
                "Could not create new session key: error verifying signature by pubkey over username".to_string(),
            )),
        }
    }

    fn verify(&self, signature: Signature) -> Result<(), GrapevineServerError> {
        // compute the hash of the session key
        let hash = self.hash();
        // convert the hash into a bigint
        let msg = BigInt::from_bytes_le(Sign::Plus, &hash[..]);
        // decompress the pubkey inside the session key
        let pubkey = babyjubjub_rs::decompress_point(self.pubkey).unwrap();
        // verify the signature over the hash by the pubkey
        match babyjubjub_rs::verify(pubkey, signature, msg) {
            true => Ok(()),
            false => Err(GrapevineServerError::Signature(
                "Could not verify signature by pubkey over session key hash".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_uuid() {
        let id = Uuid::new_v4().to_bytes_le();
        println!("ID 1 {:?}", id);
        let mut id_2 = [0u8; 32];
        id_2[..16].copy_from_slice(&id);
        println!("ID 2 {:?}", id_2);
    }
}
