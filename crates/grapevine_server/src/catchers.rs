use rocket::request::Request;

// TODO: Rename to GrapvineServerError?
#[derive(Responder)]
pub enum GrapevineResponder {
    // #[response(status = 200)]
    // Ok(String),
    #[response(status = 201)]
    Created(String),
    #[response(status = 400)]
    BadRequest(String),
    #[response(status = 401)]
    Unauthorized(String),
    #[response(status = 404)]
    NotFound(String),
    #[response(status = 409)]
    Conflict(String),
    #[response(status = 413)]
    TooLarge(String),
    #[response(status = 501)]
    NotImplemented(String),
    // #[response(status = 500)]
    // UnknownError(String),
}

pub struct ErrorMessage(pub Option<String>);

#[catch(400)]
pub fn bad_request(req: &Request) -> GrapevineResponder {
    match req.local_cache(|| ErrorMessage(None)) {
        ErrorMessage(Some(msg)) => GrapevineResponder::BadRequest(msg.to_string()),
        ErrorMessage(None) => {
            GrapevineResponder::BadRequest("Unknown bad request error has occurred".to_string())
        }
    }
}

#[catch(401)]
pub fn unauthorized(req: &Request) -> GrapevineResponder {
    match req.local_cache(|| ErrorMessage(None)) {
        ErrorMessage(Some(msg)) => GrapevineResponder::Unauthorized(msg.to_string()),
        ErrorMessage(None) => {
            GrapevineResponder::Unauthorized("Unknown authorization error has occurred".to_string())
        }
    }
}

#[catch(404)]
pub fn not_found(req: &Request) -> GrapevineResponder {
    match req.local_cache(|| ErrorMessage(None)) {
        ErrorMessage(Some(msg)) => GrapevineResponder::NotFound(msg.to_string()),
        ErrorMessage(None) => GrapevineResponder::NotFound("Asset not found".to_string()),
    }
}
