use babyjubjub_rs::{Point, Signature, PrivateKey};
use serde::{Deserialize, Serialize};
use grapevine_common::crypto::pubkey_to_address;
use num_bigint::{BigInt, Sign};
use serde_json::{json, Value};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GrapevineInputs {
    nullifier: Option<Fr>,
    prover_pubkey: Point,
    relation_pubkey: Option<Point>,
    scope_signature: Signature,
    auth_signature: Option<Signature>
}

impl GrapevineInputs {

    /**
     * Generates the step private inputs for an identity step 
     * 
     * @param prover_key - the private key of the identity proof creator
     * @returns - the inputs for a circuit to prove an identity step
     */
    pub fn identity_step(prover_key: &PrivateKey) -> Self {
        // get the pubkey used by the prover
        let prover_pubkey = prover_key.public();
        // get the account address
        let address = pubkey_to_address(&pubkey);
        // sign the address
        let message = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_lse_bytes(&hash));
        let scope_signature = prover_key.sign(message).unwrap();
        // return the struct
        Self {
            nullifier: None,
            prover_pubkey,
            relation_pubkey: None,
            scope_signature,
            auth_signature: None
        }
    }

    /**
     * Generates the step private inputs for a degree step
     * 
     * @param prover_key - the private key of the degree proof creator
     * @param relation_pubkey - the pubkey of the user the prover is one degree from
     * @param relation_nullifier - the nullifier issued by the relation user
     * @param scope_address - the identity proof creator at the beginning of the proof chain
     * @returns - the inputs for a circuit to prove a degree step
     */
    pub fn degree_step(
        prover_key: &PrivateKey,
        relation_pubkey: &Point,
        relation_nullifier: &Fr,
        scope_address: &[u8; 32],
        auth_signature: &Signature,
    ) -> Self {
        // get the pubkey used by the prover
        let prover_pubkey = prover_key.public();
        // sign the scope address
        let message = BigInt::from_bytes_le(Sign::Plus, &scope_address);
        let scope_signature = prover_key.sign(message).unwrap();
        // return the struct
        Self {
            nullifier: Some(relation_nullifier),
            prover_pubkey,
            relation_pubkey: Some(relation_pubkey),
            scope_signature,
            auth_signature: Some(auth_signature)
        }
    }

    /**
     * Formats a given input struct for circom, including a chaff step
     * 
     * @returns input map for the given step + chaff step
     */
    pub fn fmt_circom(&self)-> [HashMap<String, Value>; 2] {
        // convert required inputs
        let prover_pubkey_input = pubkey_to_input(self.prover_pubkey);
        let scope_signature_input = sig_to_input(scope_signature);

        // convert optional inputs or assign random values
        let relation_pubkey_input = match relation_pubkey {
            Some(pubkey) => pubkey_to_input(pubkey),
            None => pubkey_to_input(&new_key().public()),
        };
        let auth_signature_input = match auth_signature {
            Some(signature) => sig_to_input(signature),
            None => sig_to_input(&random_signature()),
        };
        let relation_nullifier_input = match relation_nullifier {
            Some(nullifier) => convert_ff_to_ff_ce(nullifier).to_string(),
            None => format!("0x{}", hex::encode(random_fr().to_bytes()))
        };

        // build the input hashmaps
        let mut compute_step = HashMap::new();
        compute_step.insert("relation_pubkey".to_string(), json!(relation_pubkey_input));
        compute_step.insert("prover_pubkey".to_string(), json!(prover_pubkey_input));
        compute_step.insert("relation_nullifier".to_string(), json!(relation_nullifier_input));
        compute_step.insert("auth_signature".to_string(), json!(auth_signature_input));
        compute_step.insert("scope_signature".to_string(), json!(scope_signature_input));
    }

}

/**
 * Build a chaff step input map with random values assigned to the input advice
 *
 * @return - a hashmap containing the inputs for a chaff step
 */
fn chaff_step() -> HashMap<String, Value> {
    let mut samples: [String; 11] = [String::default(); 11];
    for i in 0..samples.len() {
        samples[i] = format!("0x{}", random_fr().to_bytes());
    }
    let mut chaff_step = HashMap::new();
    chaff_step.insert(
        "relation_pubkey".to_string(),
        json!([samples[0], samples[1]]),
    );
    chaff_step.insert("prover_pubkey".to_string(), json!([samples[2], samples[3]]));
    chaff_step.insert("relation_nullifier".to_string(), json!(samples[4]));
    chaff_step.insert(
        "auth_signature".to_string(),
        json!([samples[5], samples[6], samples[7]]),
    );
    chaff_step.insert(
        "scope_signature".to_string(),
        json!([samples[8], samples[9], samples[10]]),
    );

    chaff_step
}

/**
 * Converts a signature into the stringified circom inputs
 * @note annoying hackaronud until we figure out how to get it to line up
 *
 * @param sig - the siganture as Ff_ce bn254 Fr elements
 * @return the stringified signature
 */
fn sig_to_input(sig: &Signature) -> [String; 3] {
    // convert s to field element
    let mut s_bytes = sig.s.to_bytes_le().1;
    s_bytes.resize(32, 0);
    let s = ff_ce_from_le_bytes(s_bytes.try_into().unwrap());

    // serialize
    [
        sig.r_b8.x.into_repr().to_string(),
        sig.r_b8.y.into_repr().to_string(),
        s.into_repr().to_string(),
    ]
}

/**
 * Converts a Bjj point into the stringified circom inputs
 *
 * @param pubkey - the bjj point representing the pubkey
 * @return the stringified pubkey
 */
fn pubkey_to_input(pubkey: &Point) -> [String; 2] {
    [
        pubkey.x.into_repr().to_string(),
        pubkey.y.into_repr().to_string(),
    ]
}

/**
 * Generates a random signature by a random key
 *
 * @return - a meaningless signature that will not fail bjj point check
 */
fn random_signature() -> Signature {
    let key = new_key();
    let random_message = BigInt::from_bytes_le(Sign::Plus, random_fr().to_bytes());
    key.sign(random_message).unwrap()
}