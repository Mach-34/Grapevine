use crate::models::user::User;
use crate::{DATABASE, MONGODB_URI};
use grapevine_common::errors::GrapevineServerError;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::options::{ClientOptions, FindOneOptions, ServerApi, ServerApiVersion};
use mongodb::{Client, Collection};

pub struct GrapvineMongo {
    users: Collection<User>,
}

impl GrapvineMongo {
    pub async fn init() -> Self {
        let mut client_options = ClientOptions::parse(MONGODB_URI).await.unwrap();
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);
        let client = Client::with_options(client_options).unwrap();
        let db = client.database(DATABASE);
        let users = db.collection("users");
        Self { users }
    }

    pub async fn increment_nonce(&self, username: &str) {
        let filter = doc! { "username": username };
        let update = doc! { "$inc": { "nonce": 1 } };
        self.users
            .update_one(filter, update, None)
            .await
            .expect("Error incrementing nonce");
    }

    pub async fn get_nonce(&self, username: &str) -> u64 {
        // Verify user existence
        let filter = doc! { "username": username };
        let user = self.users.find_one(filter, None).await.unwrap();
        match user {
            Some(user) => user.nonce,
            None => 0,
        }
    }

    pub async fn get_user(&self, username: String) -> Option<User> {
        let filter = doc! { "username": username };
        self.users.find_one(filter, None).await.unwrap()
    }

    /**
     * Insert a new user into the database
     * @notice - assumes username and pubkey auth checks were already performed
     *
     * @param user - the user to insert into the database
     * @returns - an error if the user already exists, or Ok otherwise
     */
    pub async fn create_user(&self, user: User) -> Result<ObjectId, GrapevineServerError> {
        // check if the username exists already in the database
        let query = doc! { "username": &user.username };
        let options = FindOneOptions::builder()
            .projection(doc! {"_id": 1})
            .build();
        // let x = user.clone().username;
        match self.users.find_one(query, options).await.unwrap() {
            Some(_) => return Err(GrapevineServerError::UserExists(user.username.clone())),
            None => (),
        };

        // insert the user into the collection
        Ok(self
            .users
            .insert_one(user, None)
            .await
            .unwrap()
            .inserted_id
            .as_object_id()
            .unwrap())
    }
}
