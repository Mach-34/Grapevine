use rocket::{catcher::Catcher, request::Request};

#[derive(Responder)]
enum CustomResponder {
    #[response(status = 200)]
    Ok(String),
    #[response(status = 400)]
    BadRequest(String),
    #[response(status = 401)]
    Unauthorized(String),
    #[response(status = 401)]
    NotFound(String),
    #[response(status = 500)]
    UnknownError(String),
}

pub struct ErrorMessage(pub Option<String>);

#[catch(400)]
pub fn bad_request(req: &Request) -> CustomResponder {
    match req.local_cache(|| ErrorMessage(None)) {
        ErrorMessage(Some(msg)) => CustomResponder::BadRequest(msg.to_string()),
        ErrorMessage(None) => {
            CustomResponder::Unauthorized("Unknown bad request error has occurred".to_string())
        }
    }
}

#[catch(401)]
pub fn unauthorized(req: &Request) -> CustomResponder {
    match req.local_cache(|| ErrorMessage(None)) {
        ErrorMessage(Some(msg)) => CustomResponder::Unauthorized(msg.to_string()),
        ErrorMessage(None) => {
            CustomResponder::Unauthorized("Unknown authorization error has occurred".to_string())
        }
    }
}

#[catch(404)]
pub fn not_found(req: &Request) -> CustomResponder {
    match req.local_cache(|| ErrorMessage(None)) {
        ErrorMessage(Some(msg)) => CustomResponder::BadRequest(msg.to_string()),
        ErrorMessage(None) => CustomResponder::Unauthorized("Asset not found".to_string()),
    }
}
