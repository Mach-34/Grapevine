use lazy_static::lazy_static;
use rocket::route::Route;
mod proof;
mod user;

lazy_static! {
    pub(crate) static ref USER_ROUTES: Vec<Route> = routes![
        user::create_user,
        user::add_relationship,
        user::get_user,
        user::get_pubkey,
        user::get_all_degrees
    ];
    pub(crate) static ref PROOF_ROUTES: Vec<Route> = routes![
        proof::create_phrase,
        proof::degree_proof,
        proof::get_available_proofs,
        // proof::get_proof_chain,
        proof::get_proof_with_params,
        proof::get_pipeline_test
    ];
}
