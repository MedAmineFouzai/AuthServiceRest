mod confirm_email;
mod forget_password;
mod oauth;
mod signin;
mod signup;
use actix_web::web::ServiceConfig;

pub fn load_auth_services(cfg: &mut ServiceConfig) {
    cfg.service(signup::signup)
        .service(signin::signin)
        .service(forget_password::forget_password)
        .service(confirm_email::confirm_email)
        .service(oauth::signin_facebook)
        .service(oauth::signin_google);
}
