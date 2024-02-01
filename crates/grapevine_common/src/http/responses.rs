use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DegreeData {
    pub degree: u8,
    pub relation: Option<String>,
    pub originator: String,
    #[serde(with = "serde_bytes")]
    pub phrase_hash: [u8; 32],
}