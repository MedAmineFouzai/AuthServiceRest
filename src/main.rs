mod controllers;
mod helper;
mod middleware;
mod models;
use actix_web::{
    web::{scope, ServiceConfig},
    App, HttpServer,
};
use std::net::{SocketAddr, ToSocketAddrs};

use load_dotenv::load_dotenv;
use middleware::{
    cors_middelware::init_cors,
    logging_middelware::{get_subscriber, init_subscriber},
};
use models::UserCollection;
use mongodb::{options::ClientOptions, Client, Collection};
use std::env;
use tracing_actix_web::TracingLogger;

pub struct CollectionContainer {
    #[allow(dead_code)]
    user: UserCollection,
}
impl CollectionContainer {
    pub fn new(user: UserCollection) -> CollectionContainer {
        CollectionContainer { user }
    }
}

pub struct AppState {
    #[allow(dead_code)]
    container: CollectionContainer,
}

async fn establish_connection() -> Collection {
    load_dotenv!();
    let client_options = ClientOptions::parse(env!("USER_DATABASE_URL"))
        .await
        .unwrap();
    let client = Client::with_options(client_options).unwrap();
    let db = client.database(env!("USER_DATABASE"));
    db.collection(env!("USER_COLLECTION"))
}

pub fn init_services(cfg: &mut ServiceConfig) {
    cfg.service(controllers::signup)
        .service(controllers::login)
        .service(controllers::get_all_users)
        .service(controllers::delete_user)
        .service(controllers::update_user_info)
        .service(controllers::update_user_password)
        .service(controllers::reset_password)
        .service(controllers::confirm_reset_user_password)
        .service(controllers::get_user_by_id);
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let subscriber = get_subscriber("app".into(), "info".into());
    init_subscriber(subscriber);
    let port:u16= env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse().expect("PORT must be a number");
 

    let user_collection = establish_connection().await;
    println!("🚀 Server ready at http://127.0.0.1:8080");
    HttpServer::new(move || {
        let collection_container =
            CollectionContainer::new(UserCollection::new(user_collection.clone()));

        App::new()
            .wrap(init_cors())
            .wrap(TracingLogger)
            .data(AppState {
                container: collection_container,
            })
            .service(scope("/api/v1/users/").configure(init_services))
    })
    .bind(("0.0.0.0".to_string(),port))?
    .run()
    .await
}
