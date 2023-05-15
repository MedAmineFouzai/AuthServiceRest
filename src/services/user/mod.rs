mod create_user;
mod delete_user;
mod find_all_users;
mod find_user;
mod update_user;
use actix_web::web::ServiceConfig;

pub fn load_user_services(cfg: &mut ServiceConfig) {
    cfg.service(create_user::create_user)
        .service(delete_user::delete_user)
        .service(find_all_users::find_all_users)
        .service(find_user::find_user)
        .service(update_user::update_user);
}
