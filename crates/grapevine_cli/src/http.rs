use grapevine_common::http::requests::CreateUserRequest;
use crate::errors::GrapevineCLIError;
use reqwest::{Client, StatusCode};

pub const SERVER_URL: &str = "http://localhost:8000";

/**
 * Makes an HTTP Request to create a new user
 *
 * @param body - the CreateUserRequest data to provide as the body of the http request
 * @returns - Ok if 201, or the error type otherwise
 */
pub async fn create_user_req(body: CreateUserRequest) -> Result<(), GrapevineCLIError> {
    let url = format!("{}/user/create", SERVER_URL);
    let client = Client::new();
    let res = client.post(&url).json(&body).send().await.unwrap();
    match res.status() {
        StatusCode::CREATED => {
            Ok(())
        },
        // StatusCode::CONFLICT => {
            
        // }

        StatusCode::BAD_REQUEST => {
            println!("Error: username {} already exists", &body.username);
            Ok(())
        }
        _ => {
            let text = res.status().to_string();
            println!("Error: {}", text);
            Err(GrapevineCLIError::ServerError(text))
        }
    }
}