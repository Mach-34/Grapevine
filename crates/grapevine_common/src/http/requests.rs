use crate::auth_secret::AuthSecretEncrypted;
use crate::serde::{deserialize_byte_buf, serialize_byte_buf};
use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateUserRequest {
    pub username: String,
    pub pubkey: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    pub auth_secret: AuthSecretEncrypted,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewPhraseRequest {
    pub username: String,
    pub proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestProofCompressionRequest {
    pub proof: Vec<u8>,
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewRelationshipRequest {
    pub from: String,
    pub to: String,
    #[serde(with = "serde_bytes")]
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 48],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DegreeProofRequest {
    pub username: String,
    pub proof: Vec<u8>,
    pub previous: String,
    pub degree: u8,
}

pub struct RequestDriver {
    pub url: String
}

impl RequestDriver {
    pub fn new(url: String) -> RequestDriver {
        RequestDriver {
            url
        }
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