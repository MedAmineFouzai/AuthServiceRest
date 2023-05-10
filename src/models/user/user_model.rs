
use serde::{self, Deserialize, Serialize};
use super::user_phone_model::Phone;
use super::user_address_model::Address;
use super::user_role_model::Role;
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone: Phone,
    pub address: Address,
    pub role: Role,
}
