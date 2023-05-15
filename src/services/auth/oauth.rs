extern crate jsonwebtoken as jwt;
use std::str::FromStr;

use crate::{middleware::error::ServerResponseError, models::User};
use actix_web::{
    http::header::ContentType,
    post,
    web::{self, Json},
    HttpRequest, HttpResponse,
};
use bson::doc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    msg: String,
}

#[post("/signin/Oauth/google")]
pub async fn signin_google(
    serverState: web::Data<crate::AppState>,
    data: Json<User>,
) -> Result<HttpResponse, ServerResponseError> {
    Ok(HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(Response {
            msg: String::from_str("Hello World!").unwrap(),
        }))
}

#[post("/signin/Oauth/facebook")]
pub async fn signin_facebook(
    serverState: web::Data<crate::AppState>,
    data: Json<User>,
) -> Result<HttpResponse, ServerResponseError> {
    Ok(HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(Response {
            msg: String::from_str("Hello World!").unwrap(),
        }))
}

