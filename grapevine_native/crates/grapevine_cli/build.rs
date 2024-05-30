use dotenv::dotenv;
use std::env;

fn main() {
    dotenv().ok();

    // try to load from env
    let server_url = env::var("GRAPEVINE_SERVER").unwrap_or("https://grapevine.mach34.space".to_string());
    println!("cargo:rustc-env=SERVER_URL={}", server_url);
}