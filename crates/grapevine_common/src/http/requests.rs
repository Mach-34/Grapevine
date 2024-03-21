use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateUserRequest {
    pub username: String,
    pub pubkey: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct NewPhraseRequest {
//     pub proof: Vec<u8>,
//     #[serde(with = "serde_bytes")]
//     pub phrase_ciphertext: [u8; 192],
// }


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewPhraseRequest {
    #[serde(with = "serde_bytes")]
    pub hash: [u8; 32],
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetNonceRequest {
    pub username: String,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestProofCompressionRequest {
    pub proof: Vec<u8>,
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewRelationshipRequest {
    pub to: String,
    #[serde(with = "serde_bytes")]
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 48],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DegreeNProofRequest {
    pub proof: Vec<u8>,
    pub previous: String,
    pub degree: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Degree1ProofRequest {
    pub proof: Vec<u8>, // compressed proof
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 192], // encrypted phrase that the user can retrieve
    pub index: u32, // the index of the phrase to prove knowledge of
}
