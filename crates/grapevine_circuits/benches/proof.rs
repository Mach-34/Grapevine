use criterion::{criterion_group, criterion_main, Criterion};
use grapevine_circuits::nova::{
    continue_nova_proof, get_public_params, get_r1cs, nova_proof, verify_nova_proof,
};
use grapevine_circuits::utils::compress_proof;
use grapevine_circuits::{DEFAULT_PUBLIC_PARAMS_PATH, DEFAULT_R1CS_PATH, DEFAULT_WC_PATH};
use grapevine_common::utils::random_fr;
use grapevine_common::{Fr, NovaProof};
use std::env::current_dir;

fn benchmark(c: &mut Criterion) {
    // tracker for sizes of proofs
    let mut proof_sizes: [[usize; 2]; 7] = [[0, 0]; 7];
    // get proving artifacts
    let params_path = String::from("circom/artifacts/public_params.json");
    let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    let wc_path = current_dir()
        .unwrap()
        .join("circom/artifacts/grapevine_js/grapevine.wasm");
    let r1cs = get_r1cs(Some(r1cs_path));
    let public_params = get_public_params(Some(params_path));
    // build inputs
    let usernames: [String; 7] = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
    ]
    .iter()
    .map(|name| String::from(*name))
    .collect::<Vec<_>>()
    .try_into()
    .unwrap(); // assume degrees of connection will never be mroe than 7
    let phrase = String::from("I heard it through the grapevine");
    let auth_secrets: [Fr; 7] = std::array::from_fn(|_| random_fr());

    // benchmark degree 1 proof
    let current_usernames = vec![usernames[0].clone()];
    let current_auth_secrets = vec![auth_secrets[0].clone()];
    c.bench_function("degree 1 proof", |b| {
        b.iter(|| {
            nova_proof(
                wc_path.clone(),
                &r1cs,
                &public_params,
                &phrase,
                &current_usernames,
                &current_auth_secrets,
            )
            .unwrap()
        })
    });

    // prepare first degree proof & store sizing data
    let mut proof = nova_proof(
        wc_path.clone(),
        &r1cs,
        &public_params,
        &phrase,
        &current_usernames,
        &current_auth_secrets,
    )
    .unwrap();
    let uncompressed_size = serde_json::to_string(&proof)
        .unwrap()
        .as_bytes()
        .to_vec()
        .len();
    let compressed = compress_proof(&proof).len();
    proof_sizes[0] = [uncompressed_size, compressed];
    // benchmark degree 2 proof
    for i in 1..7 {
        // get inputs
        let z0_last = verify_nova_proof(&proof, &public_params, i * 2).unwrap().0;
        let current_usernames = usernames[i - 1..i + 1].to_vec();
        let current_auth_secrets = auth_secrets[i - 1..i + 1].to_vec();
        // benchmark the next iteration
        c.bench_function(format!("degree {} proof", i + 1).as_str(), |b| {
            b.iter(|| {
                continue_nova_proof(
                    &current_usernames,
                    &current_auth_secrets,
                    &mut proof.clone(),
                    z0_last.clone(),
                    wc_path.clone(),
                    &r1cs,
                    &public_params,
                )
                .unwrap()
            })
        });
        // prepare i degree proof and store sizing data
        continue_nova_proof(
            &current_usernames,
            &current_auth_secrets,
            &mut proof,
            z0_last,
            wc_path.clone(),
            &r1cs,
            &public_params,
        )
        .unwrap();
        let uncompressed_size = serde_json::to_string(&proof)
            .unwrap()
            .as_bytes()
            .to_vec()
            .len();
        let compressed = compress_proof(&proof).len();
        proof_sizes[i] = [uncompressed_size, compressed];
    }
    println!("Proof size benchmarks: ");
    for i in 0..proof_sizes.len() {
        println!(
            "Degree {}: uncompressed: {} bytes, compressed: {} bytes",
            i + 1,
            proof_sizes[i][0],
            proof_sizes[i][1]
        );
    }
}

/// RESULTS ///
/// TIME COMPLEXITY:
/// degree 1 proof          time:   [656.65 ms 672.54 ms 690.54 ms]
/// degree 2 proof          time:   [821.74 ms 839.84 ms 860.73 ms]
/// degree 3 proof          time:   [827.24 ms 834.92 ms 844.82 ms]
/// degree 4 proof          time:   [829.25 ms 837.45 ms 845.54 ms]
/// degree 5 proof          time:   [830.29 ms 837.36 ms 844.50 ms]
/// degree 6 proof          time:   [910.51 ms 975.62 ms 1.0427 s]
/// degree 7 proof          time:   [865.17 ms 906.53 ms 954.73 ms]
/// SPACE COMPLEXITY:
/// Degree 1: uncompressed: 2636747 bytes, compressed: 821232 bytes
/// Degree 2: uncompressed: 3635789 bytes, compressed: 1158725 bytes
/// Degree 3: uncompressed: 3775192 bytes, compressed: 1213468 bytes
/// Degree 4: uncompressed: 3804644 bytes, compressed: 1296345 bytes
/// Degree 5: uncompressed: 3816699 bytes, compressed: 1468022 bytes
/// Degree 6: uncompressed: 3816407 bytes, compressed: 1595677 bytes
/// Degree 7: uncompressed: 3820269 bytes, compressed: 1644215 bytes


criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark
}
criterion_main!(benches);
