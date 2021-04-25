use bson::{doc, oid::ObjectId, Document};
use mongodb::{
    error::Error,
    options::{FindOneAndUpdateOptions, ReturnDocument},
    results::InsertOneResult,
    Collection, Cursor,
};

#[derive(Debug, Clone)]
pub struct UserCollection {
    collection: Collection,
}

impl UserCollection {
    pub fn new(collection: Collection) -> UserCollection {
        UserCollection { collection }
    }

    pub async fn find_one<T>(&self, document: T) -> Result<Option<Document>, Error>
    where
        T: serde::Serialize,
    {
        Ok(self
            .collection
            .find_one(
                bson::to_bson(&document)
                    .unwrap()
                    .as_document()
                    .unwrap()
                    .clone(),
                None,
            )
            .await?)
    }
    

 
    pub async fn find_all(&self) -> Result<Cursor, Error> {
        Ok(self.collection.find(None, None).await?)
    }

    pub async fn find_all_users(&self) -> Result<Cursor, Error> {
        Ok(self
            .collection
            .find(
                doc! {
                    "role":"Client"
                },
                None,
            )
            .await?)
    }

    pub async fn insert_one<T>(&self, document: T) -> Result<InsertOneResult, Error>
    where
        T: serde::Serialize,
    {
        Ok(self
            .collection
            .insert_one(
                bson::to_bson(&document)
                    .unwrap()
                    .as_document()
                    .unwrap()
                    .clone(),
                None,
            )
            .await?)
    }

    pub async fn delete_one(&self, user_id: &str) -> Result<Option<Document>, Error> {
        Ok(self
            .collection
            .find_one_and_delete(
                doc! {
                "_id":ObjectId::with_string(user_id).unwrap()
                    },
                None,
            )
            .await?)
    }

    pub async fn update_one<T>(&self, user_id: &str, document: T) -> Result<Option<Document>, Error>
    where
        T: serde::Serialize,
    {
        Ok(self
            .collection
            .find_one_and_update(
                doc! {
                    "_id":ObjectId::with_string(user_id).unwrap()
                },
                doc! {
                      "$set":bson::to_bson(&document)
                        .unwrap()
                        .as_document()
                        .unwrap()
                        .clone()

                },
                Some(
                    FindOneAndUpdateOptions::builder()
                        .return_document(ReturnDocument::After)
                        .build(),
                ),
            )
            .await?)
    }
    // pub async fn update_email(
    //     &self,
    //     user_id: &str,
    //     email: &str,
    // ) -> Result<Option<Document>, Error> {
    //     Ok(self
    //         .collection
    //         .find_one_and_update(
    //             doc! {
    //                 "_id":ObjectId::with_string(user_id).unwrap()
    //             },
    //             doc! {
    //                   "$set":{
    //                     "email":email

    //                 },
    //             },
    //             Some(
    //                 FindOneAndUpdateOptions::builder()
    //                     .return_document(ReturnDocument::After)
    //                     .build(),
    //             ),
    //         )
    //         .await?)
    // }

    pub async fn update_password(
        &self,
        user_id: &str,
        password: &str,
    ) -> Result<Option<Document>, Error> {
        Ok(self
            .collection
            .find_one_and_update(
                doc! {
                    "_id":ObjectId::with_string(user_id).unwrap()
                },
                doc! {
                      "$set":{
                        "password":password

                    },
                },
                None,
            )
            .await?)
    }

    pub async fn find_one_by_id(&self, id: &str) -> Result<Option<Document>, Error> {
        Ok(self
            .collection
            .find_one(
                doc! {
                    "_id":ObjectId::with_string(id).unwrap()
                },
                None,
            )
            .await?)
    }

    pub async fn find_one_and_id_and_pass(&self, id: &str,password:&str) -> Result<Option<Document>, Error> {
        Ok(self
            .collection
            .find_one(
                doc! {
                    "_id":ObjectId::with_string(id).unwrap(),
                    "password":password
                },
                None,
            )
            .await?)
    }

    pub async fn deactivate_user(
        &self,
        user_id: &str,
        state: &bool,
    ) -> Result<Option<Document>, Error> {
        Ok(self
            .collection
            .find_one_and_update(
                doc! {
                    "_id":ObjectId::with_string(user_id).unwrap()
                },
                doc! {
                      "$set":{
                        "active":state

                    },
                },
                Some(
                    FindOneAndUpdateOptions::builder()
                        .return_document(ReturnDocument::After)
                        .build(),
                ),
            )
            .await?)
    }

    pub async fn find_one_by_email(&self, email: &str) -> Result<Option<Document>, Error> {
        Ok(self
            .collection
            .find_one(
                doc! {
                    "email":email
                },
                None,
            )
            .await?)
    }
}
