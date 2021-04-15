use bson::oid::ObjectId;
use pwhash::bcrypt::{self, BcryptSetup, BcryptVariant};
use serde::{self, Deserialize, Serialize};

use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct UserId {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PhoneModel {
    pub prefix: String,
    pub number: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasswordModel {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserInfo {
    pub email: String,
    pub phone: PhoneModel,
    pub address: AddressModel,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EmailModel {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AddressModel {
    pub place: String,
    pub city: String,
    pub zip: String,
    pub country: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateUserInfo {
    pub id: String,
    pub user_info: UserInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateUserPassword {
    pub id: String,
    pub set_password: PasswordModel,
}

impl PasswordModel {
    pub fn hash_password(&mut self) {
        self.new_password = bcrypt::hash_with(
            BcryptSetup {
                variant: Some(BcryptVariant::V2a),
                salt: Some("delta"),
                cost: Some(4),
            },
            &self.new_password,
        )
        .unwrap();
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Role {
    Admin,
    User,
    ProductOwner,
    Developer,
}

impl FromStr for Role {
    type Err = ();

    fn from_str(input: &str) -> Result<Role, Self::Err> {
        match input {
            "Admin" => Ok(Role::Admin),
            "User" => Ok(Role::User),
            "ProductOwner" => Ok(Role::ProductOwner),
            "Developer" => Ok(Role::Developer),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserDeserializeModel {
    pub _id: ObjectId,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone: PhoneModel,
    pub address: AddressModel,
    pub active: bool,
    pub role: Role,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponseModel {
    pub id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone: PhoneModel,
    pub address: AddressModel,
    pub active: bool,
    pub role: Role,
}

impl UserResponseModel {
    pub fn build_user(user: UserDeserializeModel) -> UserResponseModel {
        UserResponseModel {
            id: user._id.to_string(),
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            phone: user.phone,
            address: user.address,
            active: user.active,
            role: user.role,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserModel {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub phone: PhoneModel,
    pub address: AddressModel,
    pub active: bool,
    pub role: Role,
}

impl UserModel {
    pub fn hash_password(&mut self) {
        self.password = bcrypt::hash_with(
            BcryptSetup {
                variant: Some(BcryptVariant::V2a),
                salt: Some("delta"),
                cost: Some(4),
            },
            &self.password,
        )
        .unwrap();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    pub id: String,
    pub role: Role,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginModel {
    email: String,
    password: String,
}

impl UserLoginModel {
    pub fn hash_password(&mut self) {
        self.password = bcrypt::hash_with(
            BcryptSetup {
                variant: Some(BcryptVariant::V2a),
                salt: Some("delta"),
                cost: Some(4),
            },
            &self.password,
        )
        .unwrap();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponseModel {
    pub user: UserResponseModel,
    pub token: String,
}
