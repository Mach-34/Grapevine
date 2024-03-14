use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateUserRequest {
    pub username: String,
    pub pubkey: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewPhraseRequest {
    pub proof: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub phrase_ciphertext: [u8; 192],
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
pub struct DegreeProofRequest {
    pub proof: Vec<u8>,
    pub previous: String,
    pub degree: u8,
}

pub struct RequestDriver {
    pub url: String,
}

impl RequestDriver {
    pub fn new(url: String) -> RequestDriver {
        RequestDriver { url }
    }

    // pub fn create_user(&self, request: CreateUserRequest) -> Result<(), reqwest::Error> {
    //     let client = reqwest::blocking::Client::new();
    //     client.post(&format!("{}/create_user", self.url))
    //         .json(&request)
    //         .send()
    //         .map(|_| ())
    // }

    // pub fn new_phrase(&self, request: NewPhraseRequest) -> Result<(), reqwest::Error> {
    //     let client = reqwest::blocking::Client::new();
    //     client.post(&format!("{}/new_phrase", self.url))
    //         .json(&request)
    //         .send()
    //         .map(|_| ())
    // }

    // pub fn test_proof_compression(&self, request: TestProofCompressionRequest) -> Result<(), reqwest::Error> {
    //     let client = reqwest::blocking::Client::new();
    //     client.post(&format!("{}/test_proof_compression", self.url))
    //         .json(&request)
    //         .send()
    //         .map(|_| ())
    // }

    // pub fn new_relationship(&self, request: NewRelationshipRequest) -> Result<(), reqwest::Error> {
    //     let client = reqwest::blocking::Client::new();
    //     client.post(&format!("{}/new_relationship", self.url))
    //         .json(&request)
    //         .send()
    //         .map(|_| ())
    // }

    // pub fn degree_proof(&self, request: DegreeProofRequest) -> Result<(), reqwest::Error> {
    //     let client = reqwest::blocking::Client::new();
    //     client.post(&format!("{}/degree_proof", self.url))
    //         .json(&request)
    //         .send()
    //         .map(|_| ())
    // }
}
