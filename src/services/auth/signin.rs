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
pub struct Credentials {
    pub email: String,
    pub password: String,
}

impl Credentials {
    pub fn hash_password(&mut self) {
        self.password = base16::encode_lower(&self.password);
    }
}

#[post("/signin")]
pub async fn signin(
    server_state: web::Data<crate::AppState>,
    mut data: Json<Credentials>,
) -> Result<HttpResponse, ServerResponseError> {
    data.hash_password();
    let resposne: Result<Option<User>, ServerResponseError> =
        match server_state.container.collection.find_one(&data).await {
            Ok(user) => Ok(user),
            Err(_) => Err(ServerResponseError::NotFound),
        };
    Ok(HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(resposne.ok()))
}
