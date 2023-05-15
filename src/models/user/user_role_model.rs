use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};
use std::{fmt, str::FromStr};

#[derive(Debug, Serialize, Clone)]
pub enum Role {
    ADMIN,
    CLIENT,
    PRODUCTOWNER,
    DEVELOPER,
    UNKNOWN,
}
impl FromStr for Role {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Role, Self::Err> {
        match input {
            "ADMIN" | "admin" | "Admin" => Ok(Role::ADMIN),
            "CLIENT" | "client" | "Client" => Ok(Role::CLIENT),
            "PRODUCTOWNER" | "productowner" | "ProductOwner" => Ok(Role::PRODUCTOWNER),
            "DEVELOPER" | "developer" | "Developer" => Ok(Role::DEVELOPER),
            _ => Ok(Role::UNKNOWN),
        }
    }
}

struct RoleVisitor;

impl<'de> Visitor<'de> for RoleVisitor {
    type Value = Role;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(
            "Expected Role In (ADMIN | CLIENT | PRODUCTOWNER |  DEVELOPER) : fallback => UNKNOWN",
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Role::from_str(value).unwrap_or_else(|_| Role::UNKNOWN))
    }
}

impl<'de> Deserialize<'de> for Role {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(RoleVisitor)
    }
}
