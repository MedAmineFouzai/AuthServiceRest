pub mod user;
use std::{str::FromStr, fmt::Debug};

pub use user::user_model::User;

use bson::{doc, oid::ObjectId, Document};
use mongodb::{
    error::Error,
    options::{FindOneAndUpdateOptions, ReturnDocument},
    results::InsertOneResult,
    Collection, Cursor,
};

#[derive(Debug, Clone)]
pub struct UserCollection {
    collection: Collection<User>,
}

impl UserCollection {
    pub fn new(collection: Collection<User>) -> UserCollection {
        UserCollection { collection }
    }

    pub async fn find_one<T>(&self, document: T) -> Result<Option<User>, Error>
    where
        T: serde::Serialize + Debug,
    {
        println!("{:?}",document);
        let query = match bson::to_bson(&document) {
            Ok(bson_document) => match bson_document.as_document() {
                Some(document) => document.clone(),
                None => Document::new(),
            },
            _ => Document::new(),
        };
        dbg!(&query);

        return self.collection.find_one(query, None).await;
    }

    pub async fn find_all(&self, query: Document) -> Result<Cursor<User>, Error> {
        Ok(self.collection.find(query, None).await?)
    }

    pub async fn insert_one<T>(&self, document: User) -> Result<InsertOneResult, Error>
    where
        T: serde::Serialize,
    {
        Ok(self.collection.insert_one(document, None).await?)
    }

    pub async fn delete_one(&self, user_id: &str) -> Result<Option<User>, Error> {
        Ok(self
            .collection
            .find_one_and_delete(
                doc! {
                "_id":match ObjectId::from_str(user_id){
                    Ok(user_id)=>user_id,
                    Err(_)=>ObjectId::new()
                }                   },
                None,
            )
            .await?)
    }

    pub async fn update_one<T>(
        &self,
        user_id: &str,
        document: Document,
    ) -> Result<Option<User>, Error>
    where
        T: serde::Serialize,
    {
        Ok(self
            .collection
            .find_one_and_update(
                doc! {
                    "_id":match ObjectId::from_str(user_id){
                        Ok(user_id)=>user_id,
                        Err(_)=>ObjectId::new()
                    }
                },
                doc! {
                      "$set":document
                },
                Some(
                    FindOneAndUpdateOptions::builder()
                        .return_document(ReturnDocument::After)
                        .build(),
                ),
            )
            .await?)
    }
}
