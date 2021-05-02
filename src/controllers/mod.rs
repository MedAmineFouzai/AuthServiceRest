extern crate jsonwebtoken as jwt;
use crate::helper::mailer::emailer::{send_email_for_password_reset, send_user_login_account};
use crate::middleware::error::UserCustomResponseError;
use bson::Document;
use futures::stream::StreamExt;
use jwt::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
mod schema;
use actix_web::{
    delete, get, post, put,
    web::{self, Json},
    HttpRequest, HttpResponse,
};
use schema::{
    AuthResponseModel, DeleteByUserId, EmailModel, Role, SendAccountModel, TokenPayload,
    UpdateUserInfo, UpdateUserPassword, UserDeserializeModel, UserId, UserLoginModel, UserModel,
    UserResponseModel,
};

#[post("auth/signup")]
pub async fn signup(
    app_data: web::Data<crate::AppState>,
    user_data: Json<UserModel>,
) -> Result<HttpResponse, UserCustomResponseError> {
    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
        match serde_json::from_str::<UserModel>(&user_data) {
            Ok(user) => Ok(user),
            Err(serde_error) => Err(serde_error.into()),
        }
    }) {
        Ok(user_data) => Ok(
            match app_data
                .container
                .user
                .find_one_by_email(&user_data.email)
                .await
            {
                Ok(dcoument) => match dcoument.unwrap_or(Document::new()) {
                    user_dcoument => {
                        if !user_dcoument.is_empty() {
                            Err(UserCustomResponseError::AlreadyExist)
                        } else {
                            match app_data
                                .container
                                .user
                                .insert_one(|mut user_data: UserModel| -> UserModel {
                                    user_data.hash_password();
                                    user_data
                                }(user_data))
                                .await
                            {
                                Ok(user_id) => {
                                    match user_id.inserted_id.as_object_id() {
                                        Some(object_id) => {
                                            match app_data
                                                .container
                                                .user
                                                .find_one_by_id(&object_id.to_string())
                                                .await
                                            {
                                                Ok(user_document) => {
                                                    if user_document != None {
                                                        match bson::from_document::<UserDeserializeModel>(user_document.unwrap_or(Document::new()))
                                                    {
                                        Ok(user_deserialize_model) => {
                                            Ok(HttpResponse::Ok().json(AuthResponseModel {
                                                token: encode(
                                                    &Header::default(),
                                                    &TokenPayload {
                                                        id: user_deserialize_model._id.to_string(),
                                                        role: user_deserialize_model.role.clone(),
                                                    },
                                                    &EncodingKey::from_secret("secret".as_ref()),
                                                )
                                                .unwrap(),
                                                user: UserResponseModel::build_user(user_deserialize_model),
                                            }))
                                        }
                                        Err(_bson_de_error) => {Err(UserCustomResponseError::InternalError)}
                                    }
                                                    } else {
                                                        Err(UserCustomResponseError::NotFound)
                                                    }
                                                }
                                                Err(_mongodb_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        }
                                        None => Err(UserCustomResponseError::InternalError),
                                    }
                                }
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            }
                        }
                    }
                },

                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            },
        ),
        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
    }?
}

#[post("auth/login")]
pub async fn login(
    app_data: web::Data<crate::AppState>,
    user_data: Json<UserLoginModel>,
) -> Result<HttpResponse, UserCustomResponseError> {
    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
        match serde_json::from_str::<UserLoginModel>(&user_data) {
            Ok(user) => Ok(user),
            Err(serde_error) => Err(serde_error.into()),
        }
    }) {
        Ok(user_data) => Ok(
            match app_data
                .container
                .user
                .find_one(|mut user_data: UserLoginModel| -> UserLoginModel {
                    user_data.hash_password();
                    user_data
                }(user_data))
                .await
                .and_then(|document: Option<Document>| {
                    let user_document: Document = match document {
                        Some(document) => document,
                        None => Document::new(),
                    };
                    Ok(user_document)
                }) {
                Ok(document) => match document {
                    document => {
                        if !document.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(document) {
                                Ok(user_deserialize_model) => {
                                    Ok(HttpResponse::Ok().json(AuthResponseModel {
                                        token: encode(
                                            &Header::default(),
                                            &TokenPayload {
                                                id: user_deserialize_model._id.to_string(),
                                                role: user_deserialize_model.role.clone(),
                                            },
                                            &EncodingKey::from_secret("secret".as_ref()),
                                        )
                                        .unwrap(),
                                        user: UserResponseModel::build_user(user_deserialize_model),
                                    }))
                                }
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::NotFound)
                        }
                    }
                },
                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            },
        ),
        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
    }?
}

#[get("/all")]
pub async fn get_all_users(
    req: HttpRequest,
    app_data: web::Data<crate::AppState>,
) -> Result<HttpResponse, UserCustomResponseError> {
    let basic_auth_header: Result<TokenData<TokenPayload>, UserCustomResponseError> =
        match req.headers().get("Authorization") {
            Some(header) => match header
                .to_str()
                .and_then(|token: &str| Ok(token.replace("Bearer ", "")))
            {
                Ok(token) => match decode::<TokenPayload>(
                    &token,
                    &DecodingKey::from_secret("secret".as_ref()),
                    &Validation {
                        validate_exp: false,
                        ..Default::default()
                    },
                ) {
                    Ok(token_payload) => Ok(token_payload),
                    Err(_jwt_error) => Err(UserCustomResponseError::BadHeaderData),
                },
                Err(_to_str_error) => Err(UserCustomResponseError::BadHeaderData),
            },
            None => Err(UserCustomResponseError::BadHeaderData),
        };

    match basic_auth_header {
        Ok(token) => {
            let token: TokenPayload = token.claims;
            let validation_data: Result<UserResponseModel, UserCustomResponseError> = match app_data
                .container
                .user
                .find_one_by_id(&token.id)
                .await
                .and_then(|document| {
                    let user_document: Document = match document {
                        Some(document) => document,
                        None => Document::new(),
                    };
                    Ok(user_document)
                }) {
                Ok(document) => match document {
                    document => {
                        if !document.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(document) {
                                Ok(user_deserialize_model) => {
                                    Ok(UserResponseModel::build_user(user_deserialize_model))
                                }
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::BadHeaderData)
                        }
                    }
                },
                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            };

            match validation_data?.role {
                Role::Admin => match app_data.container.user.find_all().await {
                    Ok(cursor) => {
                        let users: Vec<UserResponseModel> = cursor
                            .map(|document| {
                                let user_deserialize_model =
                                    bson::from_document::<UserDeserializeModel>(match document {
                                        Ok(user_document) => match user_document {
                                            user_document => user_document,
                                        },
                                        Err(_mongodb_error) => bson::Document::new(),
                                    })
                                    .unwrap();
                                UserResponseModel::build_user(user_deserialize_model)
                            })
                            .collect()
                            .await;
                        Ok(HttpResponse::Ok().json(users))
                    }
                    Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                },
                Role::Client => Err(UserCustomResponseError::NotAllowed),
                Role::Developer => Err(UserCustomResponseError::NotAllowed),
                Role::ProductOwner => match app_data.container.user.find_all_users().await {
                    Ok(cursor) => {
                        let users: Vec<UserResponseModel> = cursor
                            .map(|document| {
                                let user_deserialize_model =
                                    bson::from_document::<UserDeserializeModel>(match document {
                                        Ok(user_document) => match user_document {
                                            user_document => user_document,
                                        },
                                        Err(_mongodb_error) => bson::Document::new(),
                                    })
                                    .unwrap();
                                UserResponseModel::build_user(user_deserialize_model)
                            })
                            .collect()
                            .await;
                        Ok(HttpResponse::Ok().json(users))
                    }
                    Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                },
            }
        }
        Err(basic_auth_header_error) => Err(basic_auth_header_error.into()),
    }
}

#[post("/get")]
pub async fn get_user_by_id(
    req: HttpRequest,
    app_data: web::Data<crate::AppState>,
    user_data: Json<UserId>,
) -> Result<HttpResponse, UserCustomResponseError> {
    let basic_auth_header = match req.headers().get("Authorization") {
        Some(header) => match header
            .to_str()
            .and_then(|token| Ok(token.replace("Bearer ", "")))
        {
            Ok(token) => match decode::<TokenPayload>(
                &token,
                &DecodingKey::from_secret("secret".as_ref()),
                &Validation {
                    validate_exp: false,
                    ..Default::default()
                },
            ) {
                Ok(token_payload) => Ok(token_payload),
                Err(_jwt_error) => Err(UserCustomResponseError::BadHeaderData),
            },
            Err(_to_str_error) => Err(UserCustomResponseError::BadHeaderData),
        },
        None => Err(UserCustomResponseError::BadHeaderData),
    };

    match basic_auth_header {
        Ok(token) => {
            let token: TokenPayload = token.claims;
            let validation_data:Result<UserResponseModel, UserCustomResponseError> = match app_data
                .container
                .user
                .find_one_by_id(&token.id)
                .await
                .and_then(|document:Option<Document>| {
                    let user_document:Document = match document {
                        Some(document) => document,
                        None => Document::new(),
                    };
                    Ok(user_document)
                }) {
                Ok(document) => match document {
                    document => {
                        if !document.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(document) {
                                Ok(user_deserialize_model) => {
                                    Ok(UserResponseModel::build_user(user_deserialize_model))
                                }
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::BadHeaderData)
                        }
                    }
                },
                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            };

            match validation_data?.role {
                Role::Admin => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UserId>(&user_data) {
                            Ok(user_id) => Ok(user_id),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(user_id) => Ok(
                            match app_data
                                .container
                                .user
                                .find_one_by_id(&user_id.id)
                                .await
                                .and_then(|document:Option<Document>| {
                                    let user_dcoument:Document = match document {
                                        Some(document) => document,
                                        None => Document::new(),
                                    };
                                    Ok(user_dcoument)
                                }) {
                                Ok(document) => match document {
                                    document => {
                                        if !document.is_empty() {
                                            match bson::from_document::<UserDeserializeModel>(
                                                document,
                                            ) {
                                                Ok(user_deserialize_model) => Ok(HttpResponse::Ok(
                                                )
                                                .json(UserResponseModel::build_user(
                                                    user_deserialize_model,
                                                ))),
                                                Err(_bson_de_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        } else {
                                            Err(UserCustomResponseError::NotFound)
                                        }
                                    }
                                },
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            },
                        ),
                        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
                    }?
                }

                Role::Client => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UserId>(&user_data) {
                            Ok(user_id) => Ok(user_id),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(user_id) => Ok(
                            match app_data
                                .container
                                .user
                                .find_one_by_id(&user_id.id)
                                .await
                                .and_then(|document:Option<Document>| {
                                    let user_document:Document = match document {
                                        Some(document) => document,
                                        None => Document::new(),
                                    };
                                    Ok(user_document)
                                }) {
                                Ok(document) => match document {
                                    document => {
                                        if !document.is_empty() {
                                            match bson::from_document::<UserDeserializeModel>(
                                                document,
                                            ) {
                                                Ok(user_deserialize_model) => {
                                                    let user:UserResponseModel = UserResponseModel::build_user(user_deserialize_model);
                                                    if token.id == user.id {
                                                        Ok(HttpResponse::Ok().json(user))
                                                    } else {
                                                        Err(UserCustomResponseError::NotAllowed)
                                                    }
                                                }
                                                Err(_bson_de_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        } else {
                                            Err(UserCustomResponseError::NotFound)
                                        }
                                    }
                                },
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            },
                        ),
                        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
                    }?
                }

                Role::Developer => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UserId>(&user_data) {
                            Ok(user_id) => Ok(user_id),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(user_id) => Ok(
                            match app_data
                                .container
                                .user
                                .find_one_by_id(&user_id.id)
                                .await
                                .and_then(|document| {
                                    Ok(match document {
                                        Some(doc) => doc,
                                        None => bson::Document::new(),
                                    })
                                }) {
                                Ok(result) => match result {
                                    result => {
                                        if !result.is_empty() {
                                            match bson::from_document::<UserDeserializeModel>(
                                                result,
                                            ) {
                                                Ok(user_deserialize_model) => {
                                                    let user:UserResponseModel = UserResponseModel::build_user(user_deserialize_model);
                                                    if token.id == user.id {
                                                        Ok(HttpResponse::Ok().json(user))
                                                    } else {
                                                        Err(UserCustomResponseError::NotAllowed)
                                                    }
                                                }
                                                Err(_bson_de_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        } else {
                                            Err(UserCustomResponseError::NotFound)
                                        }
                                    }
                                },
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            },
                        ),
                        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
                    }?
                }

                Role::ProductOwner => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UserId>(&user_data) {
                            Ok(user_id) => Ok(user_id),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(user_id) => Ok(
                            match app_data
                                .container
                                .user
                                .find_one_by_id(&user_id.id)
                                .await
                                .and_then(|document:Option<Document>| {
                                    Ok(match document {
                                        Some(doc) => doc,
                                        None => bson::Document::new(),
                                    })
                                }) {
                                Ok(document) => match document {
                                    document => {
                                        if !document.is_empty() {
                                            match bson::from_document::<UserDeserializeModel>(
                                                document,
                                            ) {
                                                Ok(user_deserialize_model) => {
                                                    let user:UserResponseModel = UserResponseModel::build_user(user_deserialize_model);
                                                    if token.id == user.id {
                                                        Ok(HttpResponse::Ok().json(user))
                                                    } else {
                                                        Err(UserCustomResponseError::NotAllowed)
                                                    }
                                                }
                                                Err(_bson_de_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        } else {
                                            Err(UserCustomResponseError::NotFound)
                                        }
                                    }
                                },
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            },
                        ),
                        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
                    }?
                }
            }
        }
        Err(basic_auth_header_error) => Err(basic_auth_header_error.into()),
    }
}

#[delete("/delete")]
pub async fn delete_user(
    req: HttpRequest,
    app_data: web::Data<crate::AppState>,
    mut user_data: Json<DeleteByUserId>,
) -> Result<HttpResponse, UserCustomResponseError> {
    let basic_auth_header:Result<TokenData<TokenPayload>, UserCustomResponseError> = match req.headers().get("Authorization") {
        Some(header) => match header
            .to_str()
            .and_then(|token| Ok(token.replace("Bearer ", "")))
        {
            Ok(token) => match decode::<TokenPayload>(
                &token,
                &DecodingKey::from_secret("secret".as_ref()),
                &Validation {
                    validate_exp: false,
                    ..Default::default()
                },
            ) {
                Ok(token_payload) => Ok(token_payload),
                Err(_jwt_error) => Err(UserCustomResponseError::BadHeaderData),
            },
            Err(_to_str_error) => Err(UserCustomResponseError::BadHeaderData),
        },
        None => Err(UserCustomResponseError::BadHeaderData),
    };

    match basic_auth_header {
        Ok(token) => {
            user_data.hash_password();
            let token: TokenPayload = token.claims;
            let validation_data: UserResponseModel= match app_data
                .container
                .user
                .find_one_by_id_and_pass(&token.id, &user_data.password)
                .await
                .and_then(|document:Option<Document>| {
                   Ok(match document {
                        Some(document) => document,
                        None => Document::new(),
                    })
                }) {
                Ok(document) => match document {
                    document => {
                        if !document.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(document) {
                                Ok(user_deserialize_model) => Ok(UserResponseModel::build_user(user_deserialize_model)),
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::BadHeaderData)
                        }
                    }
                },
                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            }?;

            match validation_data.role {
                Role::Admin => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<DeleteByUserId>(&user_data) {
                            Ok(user_data) => Ok(user_data),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(user_data) => Ok(
                            match app_data
                                .container
                                .user
                                .delete_one(&user_data.id)
                                .await
                                .and_then(|document:Option<Document>| {
                                    Ok(match document {
                                        Some(doc) => doc,
                                        None => bson::Document::new(),
                                    })
                                   
                                }) {
                                Ok(document) => match document {
                                    document => {
                                        if !document.is_empty() {
                                            match bson::from_document::<UserDeserializeModel>(
                                                document,
                                            ) {
                                                Ok(user_deserialize_model) => Ok(HttpResponse::Ok()
                                                    .json(UserResponseModel::build_user(user_deserialize_model))),
                                                Err(_bson_de_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        } else {
                                            Err(UserCustomResponseError::NotFound)
                                        }
                                    }
                                },
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            },
                        ),
                        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
                    }?
                }
                Role::Client => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<DeleteByUserId>(&user_data) {
                            Ok(user_id) => Ok(user_id),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(user_id) =>{

                            if token.id==user_id.id {
                                Ok(
                                match app_data
                                .container
                                .user
                                .delete_one(&user_id.id)
                                .await
                                .and_then(|document| {
                                    let user = match document {
                                        Some(doc) => doc,
                                        None => bson::Document::new(),
                                    };
                                    Ok(user)
                                }) {
                                Ok(result) => match result {
                                    result => {
                                        if !result.is_empty() {
                                            match bson::from_document::<UserDeserializeModel>(
                                                result,
                                            ) {
                                                Ok(user) => Ok(HttpResponse::Ok()
                                                    .json(UserResponseModel::build_user(user))),
                                                Err(_bson_de_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        } else {
                                            Err(UserCustomResponseError::NotFound)
                                        }
                                    }
                                },
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            })
                            }else {
                                Err(UserCustomResponseError::NotAllowed)
                            }

                        },
                        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
                    }?
                }
                Role::Developer => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<DeleteByUserId>(&user_data) {
                            Ok(user) => Ok(user),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(user_id) => {

                            if token.id==user_id.id {
                                Ok(
                                match app_data
                                .container
                                .user
                                .delete_one(&user_id.id)
                                .await
                                .and_then(|document| {
                                    let user = match document {
                                        Some(doc) => doc,
                                        None => bson::Document::new(),
                                    };
                                    Ok(user)
                                }) {
                                Ok(result) => match result {
                                    result => {
                                        if !result.is_empty() {
                                            match bson::from_document::<UserDeserializeModel>(
                                                result,
                                            ) {
                                                Ok(user) => Ok(HttpResponse::Ok()
                                                    .json(UserResponseModel::build_user(user))),
                                                Err(_bson_de_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        } else {
                                            Err(UserCustomResponseError::NotFound)
                                        }
                                    }
                                },
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            })
                            }else {
                                Err(UserCustomResponseError::NotAllowed)
                            }

                        },
                        Err(_serde_json_error) => Err(UserCustomResponseError::BadClientData),
                    }?
                }
                Role::ProductOwner => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<DeleteByUserId>(&user_data) {
                            Ok(user) => Ok(user),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(user_id) =>{

                            if token.id==user_id.id {
                                Ok(
                                match app_data
                                .container
                                .user
                                .delete_one(&user_id.id)
                                .await
                                .and_then(|document| {
                                    let user = match document {
                                        Some(doc) => doc,
                                        None => bson::Document::new(),
                                    };
                                    Ok(user)
                                }) {
                                Ok(result) => match result {
                                    result => {
                                        if !result.is_empty() {
                                            match bson::from_document::<UserDeserializeModel>(
                                                result,
                                            ) {
                                                Ok(user) => Ok(HttpResponse::Ok()
                                                    .json(UserResponseModel::build_user(user))),
                                                Err(_bson_de_error) => {
                                                    Err(UserCustomResponseError::InternalError)
                                                }
                                            }
                                        } else {
                                            Err(UserCustomResponseError::NotFound)
                                        }
                                    }
                                },
                                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
                            })
                            }else {
                                Err(UserCustomResponseError::BadClientData)
                            }

                        },
                        Err(_serde_json_error) => Err(UserCustomResponseError::NotAllowed),
                    }?
                }
            }
        }
        Err(basic_auth_header_error) => Err(basic_auth_header_error.into()),
    }
}

#[put("/update/info")]
pub async fn update_user_info(
    req: HttpRequest,
    app_data: web::Data<crate::AppState>,
    user_data: Json<UpdateUserInfo>,
) -> Result<HttpResponse, UserCustomResponseError> {
    let basic_auth_header = match req.headers().get("Authorization") {
        Some(header) => match header
            .to_str()
            .and_then(|token| Ok(token.replace("Bearer ", "")))
        {
            Ok(token) => match decode::<TokenPayload>(
                &token,
                &DecodingKey::from_secret("secret".as_ref()),
                &Validation {
                    validate_exp: false,
                    ..Default::default()
                },
            ) {
                Ok(token_payload) => Ok(token_payload),
                Err(_jwt_error) => Err(UserCustomResponseError::BadHeaderData),
            },
            Err(_to_str_error) => Err(UserCustomResponseError::BadHeaderData),
        },
        None => Err(UserCustomResponseError::BadHeaderData),
    };

    match basic_auth_header {
        Ok(token) => {
            let token: TokenPayload = token.claims;
            let validation_data = match app_data
                .container
                .user
                .find_one_by_id(&token.id)
                .await
                .and_then(|document| {
                    let user = match document {
                        Some(doc) => doc,
                        None => bson::Document::new(),
                    };
                    Ok(user)
                }) {
                Ok(result) => match result {
                    result => {
                        if !result.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(result) {
                                Ok(user) => Ok(UserResponseModel::build_user(user)),
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::BadHeaderData)
                        }
                    }
                },
                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            };

            match validation_data?.role {
                Role::Admin => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UpdateUserInfo>(&user_data) {
                            Ok(user) => Ok(user),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(update_result) => Ok(app_data
                            .container
                            .user
                            .update_one(&update_result.id, update_result.user_info)
                            .await),
                        Err(_serialization_error) => Err(UserCustomResponseError::BadHeaderData),
                    }
                    .and_then(|response| {
                        match bson::from_document::<UserDeserializeModel>(
                            response
                                .unwrap_or(Some(Document::new()))
                                .unwrap_or(Document::new()),
                        ) {
                            //change this one
                            Ok(user) => {
                                Ok(HttpResponse::Ok().json(UserResponseModel::build_user(user)))
                            }
                            Err(_bson_de_error) => Err(UserCustomResponseError::NotFound),
                        }
                    })
                }
                Role::Client => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UpdateUserInfo>(&user_data) {
                            Ok(user) => Ok(user),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(update_result) => {
                            if update_result.id == token.id {
                                Ok(app_data
                                    .container
                                    .user
                                    .update_one(&update_result.id, update_result.user_info)
                                    .await)
                            } else {
                                Err(UserCustomResponseError::NotAllowed)
                            }
                        }
                        Err(_serialization_error) => Err(UserCustomResponseError::BadHeaderData),
                    }
                    .and_then(|response| {
                        match bson::from_document::<UserDeserializeModel>(
                            response
                                .unwrap_or(Some(Document::new()))
                                .unwrap_or(Document::new()),
                        ) {
                            //change this one
                            Ok(user) => {
                                Ok(HttpResponse::Ok().json(UserResponseModel::build_user(user)))
                            }
                            Err(_bson_de_error) => Err(UserCustomResponseError::NotFound),
                        }
                    })
                }
                Role::ProductOwner => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UpdateUserInfo>(&user_data) {
                            Ok(user) => Ok(user),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(update_result) => {
                            if update_result.id == token.id {
                                Ok(app_data
                                    .container
                                    .user
                                    .update_one(&update_result.id, update_result.user_info)
                                    .await)
                            } else {
                                Err(UserCustomResponseError::NotAllowed)
                            }
                        }
                        Err(_serialization_error) => Err(UserCustomResponseError::BadHeaderData),
                    }
                    .and_then(|response| {
                        match bson::from_document::<UserDeserializeModel>(
                            response
                                .unwrap_or(Some(Document::new()))
                                .unwrap_or(Document::new()),
                        ) {
                            //change this one
                            Ok(user) => {
                                Ok(HttpResponse::Ok().json(UserResponseModel::build_user(user)))
                            }
                            Err(_bson_de_error) => Err(UserCustomResponseError::NotFound),
                        }
                    })
                }
                Role::Developer => {
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UpdateUserInfo>(&user_data) {
                            Ok(user) => Ok(user),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(update_result) => {
                            if update_result.id == token.id {
                                Ok(app_data
                                    .container
                                    .user
                                    .update_one(&update_result.id, update_result.user_info)
                                    .await)
                            } else {
                                Err(UserCustomResponseError::NotAllowed)
                            }
                        }
                        Err(_serialization_error) => Err(UserCustomResponseError::BadHeaderData),
                    }
                    .and_then(|response| {
                        match bson::from_document::<UserDeserializeModel>(
                            response
                                .unwrap_or(Some(Document::new()))
                                .unwrap_or(Document::new()),
                        ) {
                            //change this one
                            Ok(user) => {
                                Ok(HttpResponse::Ok().json(UserResponseModel::build_user(user)))
                            }
                            Err(_bson_de_error) => Err(UserCustomResponseError::NotFound),
                        }
                    })
                }
            }

            // if validation_data.is_ok() {
            //     let update_result =
            //         match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
            //             match serde_json::from_str::<UpdateUserInfo>(&user_data) {
            //                 Ok(user) => Ok(user),
            //                 Err(e) => Err(e.into()),
            //             }
            //         }) {
            //             Ok(update_result) => Ok(app_data
            //                 .container
            //                 .user
            //                 .update_one(&update_result.id, update_result.user_info)
            //                 .await),
            //             Err(_serialization_error) => Err(UserCustomResponseError::BadHeaderData),
            //         }
            //         .and_then(|response| {
            //             match bson::from_document::<UserDeserializeModel>(
            //                 response
            //                     .unwrap_or(Some(Document::new()))
            //                     .unwrap_or(Document::new()),
            //             ) {
            //                 //change this one
            //                 Ok(user) => {
            //                     Ok(HttpResponse::Ok().json(UserResponseModel::build_user(user)))
            //                 }
            //                 Err(_bson_de_error) => Err(UserCustomResponseError::NotFound),
            //             }
            //         });
            //     update_result
            // } else {
            //     Err(UserCustomResponseError::BadHeaderData)
            // }
        }
        Err(basic_auth_header_error) => Err(basic_auth_header_error.into()),
    }
}

#[put("/update/password")]
pub async fn update_user_password(
    req: HttpRequest,
    app_data: web::Data<crate::AppState>,
    user_data: Json<UpdateUserPassword>,
) -> Result<HttpResponse, UserCustomResponseError> {
    let basic_auth_header = match req.headers().get("Authorization") {
        Some(header) => match header
            .to_str()
            .and_then(|token| Ok(token.replace("Bearer ", "")))
        {
            Ok(token) => match decode::<TokenPayload>(
                &token,
                &DecodingKey::from_secret("secret".as_ref()),
                &Validation {
                    validate_exp: false,
                    ..Default::default()
                },
            ) {
                Ok(token_payload) => Ok(token_payload),
                Err(_jwt_error) => Err(UserCustomResponseError::BadHeaderData),
            },
            Err(_to_str_error) => Err(UserCustomResponseError::BadHeaderData),
        },
        None => Err(UserCustomResponseError::BadHeaderData),
    };

    match basic_auth_header {
        Ok(token) => {
            let token: TokenPayload = token.claims;
            let validation_data = match app_data
                .container
                .user
                .find_one_by_id(&token.id)
                .await
                .and_then(|document| {
                    let user = match document {
                        Some(doc) => doc,
                        None => bson::Document::new(),
                    };
                    Ok(user)
                }) {
                Ok(result) => match result {
                    result => {
                        if !result.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(result) {
                                Ok(user) => Ok(UserResponseModel::build_user(user)),
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::BadHeaderData)
                        }
                    }
                },
                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            };

            if validation_data.is_ok() {
                let update_result =
                    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
                        match serde_json::from_str::<UpdateUserPassword>(&user_data) {
                            Ok(user) => Ok(user),
                            Err(e) => Err(e.into()),
                        }
                    }) {
                        Ok(mut update_result) => {
                            update_result.set_password.hash_password();
                            Ok(app_data
                                .container
                                .user
                                .update_password(
                                    &update_result.id,
                                    &update_result.set_password.new_password,
                                )
                                .await)
                        }
                        Err(_serialization_error) => Err(UserCustomResponseError::BadHeaderData),
                    }
                    .and_then(|response| {
                        match bson::from_document::<UserDeserializeModel>(
                            response.unwrap().unwrap_or(Document::new()),
                        ) {
                            //change this one
                            Ok(user) => {
                                Ok(HttpResponse::Ok().json(UserResponseModel::build_user(user)))
                            }
                            Err(_bson_de_error) => Err(UserCustomResponseError::NotFound),
                        }
                    });
                update_result
            } else {
                Err(UserCustomResponseError::BadHeaderData)
            }
        }
        Err(basic_auth_header_error) => Err(basic_auth_header_error.into()),
    }
}

#[post("auth/reset")]
pub async fn reset_password(
    app_data: web::Data<crate::AppState>,
    user_data: Json<EmailModel>,
) -> Result<HttpResponse, UserCustomResponseError> {
    println!("user_data: {:?}", user_data);
    let result = match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
        match serde_json::from_str::<EmailModel>(&user_data) {
            Ok(user) => Ok(user),
            Err(e) => Err(e.into()),
        }
    }) {
        Ok(email_object) => {
            match app_data
                .container
                .user
                .find_one_by_email(&email_object.email)
                .await
            {
                Ok(result) => match result.unwrap_or(bson::Document::new()) {
                    result => {
                        if !result.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(result) {
                                Ok(user) => Ok(UserResponseModel::build_user(user)),
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::NotFound)
                        }
                    }
                },

                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            }
        }
        Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
    };
    match result {
        Ok(user) => {
            send_email_for_password_reset(
                &format!("{} {}", &user.first_name, &user.last_name),
                &format!("http://localhost:3000/recover-account?code={}", &user.id),
                &user.email,
            )
            .await?;
            Ok(HttpResponse::Ok().json(user))
        }
        Err(e) => Err(e.into()),
    }
}

#[put("auth/reset/confirm")]
pub async fn confirm_reset_user_password(
    app_data: web::Data<crate::AppState>,
    user_data: Json<UpdateUserPassword>,
) -> Result<HttpResponse, UserCustomResponseError> {
    match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
        match serde_json::from_str::<UpdateUserPassword>(&user_data) {
            Ok(user) => Ok(user),
            Err(e) => Err(e.into()),
        }
    }) {
        Ok(mut update_result) => {
            update_result.set_password.hash_password();
            Ok(app_data
                .container
                .user
                .update_password(&update_result.id, &update_result.set_password.new_password)
                .await)
        }
        Err(_serialization_error) => Err(UserCustomResponseError::BadHeaderData),
    }
    .and_then(|response| {
        match bson::from_document::<UserDeserializeModel>(
            response.unwrap().unwrap_or(Document::new()),
        ) {
            //change this one
            Ok(user) => Ok(HttpResponse::Ok().json(UserResponseModel::build_user(user))),
            Err(_bson_de_error) => Err(UserCustomResponseError::NotFound),
        }
    })
}

#[post("auth/send/account")]
pub async fn send_user_account(
    app_data: web::Data<crate::AppState>,
    user_data: Json<SendAccountModel>,
) -> Result<HttpResponse, UserCustomResponseError> {
    println!("user_data: {:?}", user_data);
    let accoun_object = user_data.clone();
    let result = match serde_json::to_string(&user_data.into_inner()).and_then(|user_data| {
        match serde_json::from_str::<SendAccountModel>(&user_data) {
            Ok(user) => Ok(user),
            Err(e) => Err(e.into()),
        }
    }) {
        Ok(account_object) => {
            match app_data
                .container
                .user
                .find_one_by_email(&account_object.email)
                .await
            {
                Ok(result) => match result.unwrap_or(bson::Document::new()) {
                    result => {
                        if !result.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(result) {
                                Ok(user) => Ok(UserResponseModel::build_user(user)),
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::NotFound)
                        }
                    }
                },

                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            }
        }
        Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
    };
    match result {
        Ok(user) => {
            send_user_login_account(
                &format!("{} {}", &user.first_name, &user.last_name),
                &accoun_object.password,
                &accoun_object.role,
                &user.email,
            )
            .await?;
            Ok(HttpResponse::Ok().json(user))
        }
        Err(e) => Err(e.into()),
    }
}

#[post("auth/verfiyToken")]
pub async fn verfiy_Token(
    req: HttpRequest,
    app_data: web::Data<crate::AppState>,
    user_data: Json<SendAccountModel>,
) -> Result<HttpResponse, UserCustomResponseError> {
    let basic_auth_header = match req.headers().get("Authorization") {
        Some(header) => match header
            .to_str()
            .and_then(|token| Ok(token.replace("Bearer ", "")))
        {
            Ok(token) => match decode::<TokenPayload>(
                &token,
                &DecodingKey::from_secret("secret".as_ref()),
                &Validation {
                    validate_exp: false,
                    ..Default::default()
                },
            ) {
                Ok(token_payload) => Ok(token_payload),
                Err(_jwt_error) => Err(UserCustomResponseError::BadHeaderData),
            },
            Err(_to_str_error) => Err(UserCustomResponseError::BadHeaderData),
        },
        None => Err(UserCustomResponseError::BadHeaderData),
    };

    match basic_auth_header {
        Ok(token) => {
            let token: TokenPayload = token.claims;
            match app_data
                .container
                .user
                .find_one_by_id(&token.id)
                .await
                .and_then(|document| {
                    let user = match document {
                        Some(doc) => doc,
                        None => bson::Document::new(),
                    };
                    Ok(user)
                }) {
                Ok(result) => match result {
                    result => {
                        if !result.is_empty() {
                            match bson::from_document::<UserDeserializeModel>(result) {
                                Ok(user) => {
                                    Ok(HttpResponse::Ok().json(UserResponseModel::build_user(user)))
                                }
                                Err(_bson_de_error) => Err(UserCustomResponseError::InternalError),
                            }
                        } else {
                            Err(UserCustomResponseError::BadHeaderData)
                        }
                    }
                },
                Err(_mongodb_error) => Err(UserCustomResponseError::InternalError),
            }
        }
        Err(e) => Err(e.into()),
    }
}
