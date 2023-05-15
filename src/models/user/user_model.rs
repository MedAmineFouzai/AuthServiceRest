
use bson::oid::ObjectId;
use serde::{self, Deserialize, Serialize, Serializer};
use super::user_phone_model::Phone;
use super::user_address_model::Address;
use super::user_role_model::Role;

pub fn serialize_object_id<S>(object_id: &Option<ObjectId>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match object_id {
      Some(ref object_id) => serializer.serialize_some(object_id.to_string().as_str()),
      None => serializer.serialize_none()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(serialize_with = "serialize_object_id")]
    pub _id:Option<ObjectId>,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub phone: Phone,
    pub address: Address,
    pub role: Role,
}

impl User {

    pub fn hash_password(&mut self) {
        self.password =  base16::encode_lower(&self.password);
    }
}