pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// multiplexes signals according to whether this is a chaff step or not
template ChaffMux() {
    // inputs from step_in
    signal input degrees_of_separation;
    signal input given_phrase_hash;
    signal input given_degree_secret_hash;
    signal input is_chaff_step;
    // computed inputs from circuit
    signal input computed_phrase_hash;
    signal input computed_degree_secret_hash;
    // output formatted for step_out
    signal output out[4];

    // constrain is_chaff_step to be 0 or 1
    is_chaff_step * (is_chaff_step - 1) === 0;

    // mux 3 different inputs selected by is_chaff_step
    component mux = MultiMux1(3);
    mux.s <== is_chaff_step;

    // mux the degree of separation
    // if ! chaff step, increment degree of separation
    mux.c[0][0] <== degrees_of_separation + 1;
    mux.c[0][1] <== degrees_of_separation;

    // mux the secret hash
    // if ! chaff step, grab muxed hash output
    mux.c[1][0] <== computed_phrase_hash;
    mux.c[1][1] <== given_phrase_hash;

    // mux the username hash
    // if ! chaff step, grab the computed current username hash
    mux.c[2][0] <== computed_degree_secret_hash;
    mux.c[2][1] <== given_degree_secret_hash;

    // flip chaff step
    component flipped_chaff_step = IsZero();
    flipped_chaff_step.in <== is_chaff_step;

    // set step output
    out[0] <== mux.out[0];
    out[1] <== mux.out[1];
    out[2] <== mux.out[2];
    out[3] <== flipped_chaff_step.out;
}