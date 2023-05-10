use serde::{self, Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Phone {
    pub prefix: String,
    pub number: String,
}
