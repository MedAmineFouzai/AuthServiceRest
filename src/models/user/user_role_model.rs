use serde::{self, Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Role {
    ADMIN,
    CLIENT,
    PRODUCTOWNER,
    DEVELOPER,
}
impl FromStr for Role {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Role, Self::Err> {
        match input {
            "ADMIN" | "admin" | "Admin" => Ok(Role::ADMIN),
            "CLIENT" | "client" | "Client" => Ok(Role::CLIENT),
            "PRODUCTOWNER" | "productowner" | "ProductOwner" => Ok(Role::PRODUCTOWNER),
            "DEVELOPER" | "developer" | "Developer" => Ok(Role::DEVELOPER),
            _ => Err("UNKNOWN"),
        }
    }
}
