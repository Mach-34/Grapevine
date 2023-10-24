mod util;

use std::{collections::HashMap, env::current_dir, time::Instant};
use nova_scotia::{
    circom::reader::load_r1cs,
    create_public_params,
    create_recursive_circuit,
    continue_recursive_circuit,
    FileLocation,
    F,
    S,
};
use util::{G1, G2, load_artifacts};

pub fn main() {}