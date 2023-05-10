use serde::{self, Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Address {
    pub place: String,
    pub city: String,
    pub zip: String,
    pub country: String,
}
