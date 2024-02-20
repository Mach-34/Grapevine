use grapevine_common::errors::GrapevineServerError;
use rocket::{
    http::ContentType,
    request::Request,
    response::{self, Responder, Response},
    serde::json::Json,
};
use serde::{Deserialize, Serialize};

// TODO: Rename to GrapvineServerError?

#[derive(Responder)]
pub enum GrapevineResponse {
    #[response(status = 201)]
    Created(String),
    #[response(status = 400)]
    BadRequest(ErrorMessage),
    #[response(status = 401)]
    Unauthorized(ErrorMessage),
    #[response(status = 404)]
    NotFound(String),
    #[response(status = 409)]
    Conflict(ErrorMessage),
    #[response(status = 413)]
    TooLarge(String),
    #[response(status = 500)]
    InternalError(ErrorMessage),
    #[response(status = 501)]
    NotImplemented(String),
}

// #[catch(400)]
// pub fn bad_request(req: &Request) -> GrapevineResponse {
//     match req.local_cache(|| ErrorMessage(None)) {
//         ErrorMessage(Some(err)) => {
//             let x = GrapevineServerError::Signature(("".to_string(), 0));
//             let y = x.into();
//             GrapevineResponse::BadRequest(ErrorMessage(Some(err.clone())))
//         }
//         ErrorMessage(None) => {
//             GrapevineResponse::BadRequest(ErrorMessage(Some(GrapevineServerError::InternalError)))
//         }
//     }
// }

// #[catch(401)]
// pub fn unauthorized(req: &Request) -> Response {
//     match req.local_cache(|| ErrorMessage(None)) {
//         ErrorMessage(Some(msg)) => Response::Unauthorized(msg.to_string()),
//         ErrorMessage(None) => {
//             Response::Unauthorized("Unknown authorization error has occurred".to_string())
//         }
//     }
// }

// #[catch(404)]
// pub fn not_found(req: &Request) -> Response {
//     match req.local_cache(|| ErrorMessage(None)) {
//         ErrorMessage(Some(msg)) => Response::NotFound(msg.to_string()),
//         ErrorMessage(None) => Response::NotFound("Asset not found".to_string()),
//     }
// }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorMessage(pub Option<GrapevineServerError>, pub Option<u64>);

impl<'r> Responder<'r, 'static> for ErrorMessage {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        let body = match self.0.is_some() {
            true => Json(self.0.unwrap()),
            false => Json(GrapevineServerError::InternalError),
        };
        let mut res = Response::build_from(body.respond_to(req)?);
        // optionally add nonce to header
        if self.1.is_some() {
            res.raw_header("X-Nonce", self.1.unwrap().to_string());
        };
        res.header(ContentType::JSON).ok()
    }
}
