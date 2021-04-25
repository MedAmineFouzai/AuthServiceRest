use actix_web::{error, http::StatusCode, HttpResponse};
use derive_more::{Display, Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    status_code: String,
    msg: String,
}

#[derive(Debug, Display, Error)]
pub enum UserCustomResponseError {
    #[display(fmt = "internal error !")]
    InternalError,
    #[display(fmt = "Bad Header Data Forbidden !")]
    BadHeaderData,

    #[display(fmt = "Bad Client Data !")]
    BadClientData,

    #[display(fmt = "User not Found!")]
    NotFound,

    #[display(fmt = "User Already Exist!")]
    AlreadyExist,

    #[display(fmt = "User not Allowed!")]
    NotAllowed,
    // #[display(fmt = "Timeout !")]
    // Timeout,
}

impl error::ResponseError for UserCustomResponseError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorResponse {
            status_code: self.status_code().to_string(),
            msg: self.to_string(),
        })
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            UserCustomResponseError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            UserCustomResponseError::BadClientData => StatusCode::BAD_REQUEST,
            UserCustomResponseError::NotFound => StatusCode::NOT_FOUND,
            UserCustomResponseError::BadHeaderData => StatusCode::FORBIDDEN,
            UserCustomResponseError::AlreadyExist => StatusCode::CONFLICT,
            UserCustomResponseError::NotAllowed => StatusCode::FORBIDDEN,
        }
    }
}

// use actix_web::{web, App, Error, HttpResponse, HttpServer, ResponseError};
// use derive_more::Display; // naming it clearly for illustration purposes
// use rand::{
//     distributions::{Distribution, Standard},
//     thread_rng, Rng,
// };

// #[derive(Debug, Display)]
// pub enum CustomError {
//     #[display(fmt = "Custom Error 1")]
//     CustomOne,
//     #[display(fmt = "Custom Error 2")]
//     CustomTwo,
//     #[display(fmt = "Custom Error 3")]
//     CustomThree,
//     #[display(fmt = "Custom Error 4")]
//     CustomFour,
// }

// impl Distribution<CustomError> for Standard {
//     fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CustomError {
//         match rng.gen_range(0, 4) {
//             0 => CustomError::CustomOne,
//             1 => CustomError::CustomTwo,
//             2 => CustomError::CustomThree,
//             _ => CustomError::CustomFour,
//         }
//     }
// }

// /// Actix web uses `ResponseError` for conversion of errors to a response
// impl ResponseError for CustomError {
//     fn error_response(&self) -> HttpResponse {
//         match self {
//             CustomError::CustomOne => {
//                 println!("do some stuff related to CustomOne error");
//                 HttpResponse::Forbidden().finish()
//             }

//             CustomError::CustomTwo => {
//                 println!("do some stuff related to CustomTwo error");
//                 HttpResponse::Unauthorized().finish()
//             }

//             CustomError::CustomThree => {
//                 println!("do some stuff related to CustomThree error");
//                 HttpResponse::InternalServerError().finish()
//             }

//             _ => {
//                 println!("do some stuff related to CustomFour error");
//                 HttpResponse::BadRequest().finish()
//             }
//         }
//     }
// }

// /// randomly returns either () or one of the 4 CustomError variants
// async fn do_something_random() -> Result<(), CustomError> {
//     let mut rng = thread_rng();

//     // 20% chance that () will be returned by this function
//     if rng.gen_bool(2.0 / 10.0) {
//         Ok(())
//     } else {
//         Err(rand::random::<CustomError>())
//     }
// }

// async fn do_something() -> Result<HttpResponse, Error> {
//     do_something_random().await?;

//     Ok(HttpResponse::Ok().body("Nothing interesting happened. Try again."))
// }

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     std::env::set_var("RUST_LOG", "actix_web=info");
//     env_logger::init();

//     HttpServer::new(move || {
//         App::new()
//             .service(web::resource("/something").route(web::get().to(do_something)))
//     })
//     .bind("127.0.0.1:8088")?
//     .run()
//     .await
// }
