use crate::errors::GrapevineCLIError;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::requests::CreateUserRequest;
use reqwest::{Client, StatusCode};

pub const SERVER_URL: &str = "http://localhost:8000";

/**
 * Makes an HTTP Request to create a new user
 *
 * @param body - the CreateUserRequest data to provide as the body of the http request
 * @returns - Ok if 201, or the error type otherwise
 */
pub async fn create_user_req(body: CreateUserRequest) -> Result<(), GrapevineServerError> {
    let url = format!("{}/user/create", SERVER_URL);
    let client = Client::new();
    let res = client.post(&url).json(&body).send().await.unwrap();
    match res.status() {
        StatusCode::CREATED => return Ok(()),
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}
