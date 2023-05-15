use actix_web::{get, http::header::ContentType, HttpResponse};
use chrono::Utc;
#[get("/health")]
pub async fn get_health_status() -> HttpResponse {
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(format!("Healthy! At:{}", Utc::now().timestamp()))
}
