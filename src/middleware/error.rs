use actix_web::{error, http::StatusCode, HttpResponse};
use derive_more::{Display, Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientErrorMessage {
    status_code: String,
    msg: String,
}

#[derive(Debug, Serialize, Deserialize, Display, Error)]
pub enum ServerResponseError {
    #[display(fmt = "INTERNAL_SERVER_ERROR")]
    InternalError,

    #[display(fmt = "BAD_HEADER_DATA")]
    BadHeaderData,

    #[display(fmt = "BAD_CLIENT_DATA")]
    BadRequest,

    #[display(fmt = "USER_NOT_FOUND")]
    NotFound,

    #[display(fmt = "USER_ALREADY_EXIST")]
    AlreadyExist,

    #[display(fmt = "USER_FORBIDDEN")]
    FORBIDDEN,

    #[display(fmt = "USER_REQUEST_TIMEOUT")]
    RequestTimeout,
}

impl error::ResponseError for ServerResponseError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ClientErrorMessage {
            status_code: self.status_code().to_string(),
            msg: self.to_string(),
        })
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            ServerResponseError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            ServerResponseError::BadRequest => StatusCode::BAD_REQUEST,
            ServerResponseError::NotFound => StatusCode::NOT_FOUND,
            ServerResponseError::BadHeaderData => StatusCode::FORBIDDEN,
            ServerResponseError::AlreadyExist => StatusCode::CONFLICT,
            ServerResponseError::FORBIDDEN => StatusCode::FORBIDDEN,
            ServerResponseError::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
        }
    }
}
