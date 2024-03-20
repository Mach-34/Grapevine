use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DegreeData {
    pub phrase_index: u32,
    pub degree: u8,
    pub relation: Option<String>,
    pub preceding_relation: Option<String>,
    #[serde(with = "serde_bytes")]
    pub phrase_hash: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub secret_phrase: Option<[u8; 192]>
}
