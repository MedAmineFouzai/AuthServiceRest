mod helper;
mod middleware;
mod models;
mod services;
use actix_web::{
    web::{scope, Data},
    App, HttpServer,
};
use bson::doc;
use load_dotenv::load_dotenv;
use middleware::{get_health_status, init_cors};
use models::{User, UserCollection};
use mongodb::{options::ClientOptions, Client};
use services::{load_auth_services, load_user_services};
use std::env;

#[derive(Clone)]
pub struct Container {
    collection: UserCollection,
}

impl Container {
    pub fn new(collection: UserCollection) -> Container {
        Container { collection }
    }
}

pub struct AppState {
    #[allow(dead_code)]
    container: Container,
}

async fn establish_connection() -> Option<UserCollection> {
    load_dotenv!();
    Client::with_options(
        match ClientOptions::parse(env!("USER_DATABASE_URL")).await.ok() {
            Some(client_options) => client_options,
            None => panic!("Couldn't Parse Client Options"),
        },
    )
    .and_then(|client| Ok(client.database(env!("USER_DATABASE"))))
    .ok()
    .and_then(|database| {
        println!("established connection");
        Some(UserCollection::new(
            database.collection::<User>(env!("USER_COLLECTION")),
        ))
    })
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let container = Container::new(
        establish_connection()
            .await
            .expect("Failed to create connection"),
    );
    HttpServer::new(move || {
        App::new()
            .wrap(init_cors())
            // .wrap(TracingLogger)
            .app_data(Data::new(AppState {
                container: Container {
                    collection: container.collection.clone(),
                },
            }))
            .service(scope("/auth").configure(load_auth_services))
            .service(scope("/user").configure(load_user_services))
            .service(get_health_status)
    })
    .bind((
        "0.0.0.0".to_string(),
        env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .expect("PORT MUST BE A NUMBER"),
    ))?
    .run()
    .await
}
