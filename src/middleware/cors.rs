pub mod cors_middelware {
    use actix_cors::Cors;
    pub fn init_cors() -> Cors {
        Cors::default()
            .allow_any_origin()
            .allow_any_header()
            .allow_any_method()
            .supports_credentials()
    }
}
