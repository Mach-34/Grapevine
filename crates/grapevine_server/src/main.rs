#[macro_use]
extern crate rocket;
use rocket::config::Config;
use rocket::serde::{json::Json, Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

pub(crate) mod routes;



#[tokio::main]
async fn main() {
    // create config for http server

    // Initialize logger
    tracing_subscriber::fmt::init();

    // Define warp filter to serve files from static dir
    rocket::build()
        .mount("/", routes![health])
        .launch()
        .await
        .unwrap();
}

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}
