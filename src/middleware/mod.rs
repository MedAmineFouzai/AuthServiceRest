pub mod cors;
pub mod error;
pub mod logging;
pub mod health;
pub use cors::cors_middelware::init_cors;
pub use error::ServerResponseError;
pub use logging::logging_middelware;
pub use health::get_health_status;

//add validators unknown for me how much long it takes still !

//add reset password check for smtp libery still ! front end needs to manage some stuff

// confirm signup !front end needs to manage some stuff

// add Oauth hard still !

// Link to GateWay easy not that hard after one day of hard work
