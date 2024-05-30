use dotenv::dotenv;
use std::env;

fn main() {
    dotenv().ok();

    let mongodb_uri = env::var("MONGODB_URI").unwrap_or("mongodb://localhost:27017".to_string());
    println!("cargo:rustc-env=MONGODB_URI={}", mongodb_uri);
    let database_name = env::var("DATABASE_NAME").unwrap_or("grapevine".to_string());
    println!("cargo:rustc-env=DATABASE_NAME={}", database_name);
}