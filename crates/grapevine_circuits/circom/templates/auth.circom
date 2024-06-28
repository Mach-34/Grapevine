pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/eddsaposeidon.circom";


// checks the authenticity of a given auth signature + scope signature
template BJJAddress() {
    signal input target_address; // the target scope address
    signal output address; // the bjj address of the target scope address

    // hash the pubkey
    component hasher = Poseidon(2);
    hasher.in <== pubkey;
    address <== hasher.out;
}

// Constrains the check of a BJJ pubkey to equal a given address
template CheckBJJAddress() {
    signal input pubkey[2];
    signal input address;
    signal enabled;

    // hash pubkey into address
    component hasher = Poseidon(2);
    hasher.in <== pubkey;

    // check equality if enabled
    component address_equality = ForceEqualIfEnabled();
    address_equality.in[0] <== hasher.out;
    address_equality.in[1] <== address;
    address_equality.enabled <== enabled;
    
}

// produces underlying auth message and checks signature over it
template AuthSigVerifier() {
    signal input pubkey[2]; // the pubkey of the signer (previous prover)
    signal input nullifier; // the nullifier issues from prev prover to current prover
    signal input prover_address; // the current prover's address
    signal input signature[3]; // the signature over auth message by pubkey ([R8.x, R8.y, s])
    signal input enabled; // whether or not to enforce the constraint

    // compute the auth message
    component auth_message = Poseidon(2);
    auth_message.in[0] <== nullifier;
    auth_message.in[1] <== prover_address;

    // verify the signature over the auth message
    component sig_verifier = EdDSAPoseidonVerifier();
    auth_sig_verifier.Ax <== pubkey[0];
    auth_sig_verifier.Ay <== pubkey[1];
    auth_sig_verifier.M <== auth_message.out;
    auth_sig_verifier.R8x <== signature[0];
    auth_sig_verifier.R8y <== signature[1];
    auth_sig_verifier.S <== signature[2];
    auth_sig_verifier.enabled <== enabled;
}

// checks the authenticity of a given scope signature (sig by current prover over scope address)
// a bit redundant but makes grapevine circuit more readable
template ScopeSigVerifier() {
    signal input pubkey[2];
    signal input scope_address;
    signal input signature[3];
    signal input enabled;

    // verify the signature over the auth message
    component sig_verifier = EdDSAPoseidonVerifier();
    auth_sig_verifier.Ax <== pubkey[0];
    auth_sig_verifier.Ay <== pubkey[1];
    auth_sig_verifier.M <== scope_address;
    auth_sig_verifier.R8x <== signature[0];
    auth_sig_verifier.R8y <== signature[1];
    auth_sig_verifier.S <== signature[2];
    auth_sig_verifier.enabled <== enabled;
}