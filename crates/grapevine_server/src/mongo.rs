use crate::{DATABASE, MONGODB_URI};
use futures::stream::StreamExt;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::models::user::{Connection, User};
use mongodb::bson::{self, doc, oid::ObjectId, Binary};
use mongodb::options::{ClientOptions, FindOneOptions, ServerApi, ServerApiVersion, AggregateOptions};
use mongodb::{Client, Collection};

pub struct GrapevineDB {
    users: Collection<User>,
    auth_secrets: Collection<AuthSecretEncrypted>,
}

impl GrapevineDB {
    pub async fn init() -> Self {
        let mut client_options = ClientOptions::parse(MONGODB_URI).await.unwrap();
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);
        let client = Client::with_options(client_options).unwrap();
        let db = client.database(DATABASE);
        let users = db.collection("users");
        let auth_secrets = db.collection("auth_secrets");
        Self { users, auth_secrets }
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

    /**
     * Queries the DB for documents where username OR pubkey matches an existing document
     * @dev used in user creation. If true, then fail to create the user
     *
     * @param username - the username to check for existence
     * @param pubkey - the pubkey to check
     * @returns - true or false if [username, pubkey] exists in d
     */
    pub async fn check_creation_params(
        &self,
        username: &String,
        pubkey: &[u8; 32],
    ) -> Result<[bool; 2], GrapevineServerError> {
        // Verify user existence
        let pubkey_binary = Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: pubkey.to_vec(),
        };
        let query = doc! {
            "$or": [
                { "username": username },
                { "pubkey": pubkey_binary }
            ]
        };
        let mut cursor = self.users.find(query, None).await.unwrap();
        let mut found = [false; 2];
        while let Some(result) = cursor.next().await {
            match result {
                Ok(user) => {
                    // Check if the username matches
                    if &user.username == username {
                        found[0] = true;
                    }
                    // Check if the pubkey matches
                    if &user.pubkey == pubkey {
                        found[1] = true;
                    }
                }
                Err(e) => return Err(GrapevineServerError::MongoError(String::from("todo"))),
            }
        }

        Ok(found)
    }

    pub async fn get_user(&self, username: String) -> Option<User> {
        let filter = doc! { "username": username };
        let projection = doc! { "connections": 0 };
        let find_options = FindOneOptions::builder()
            .projection(projection)
            .build();
        self.users.find_one(filter, Some(find_options)).await.unwrap()
    }

    /**
     * Insert a new user into the database
     * @notice - assumes username and pubkey auth checks were already performed
     *
     * @param user - the user to insert into the database
     * @param auth_secret - the encrypted auth secret used by this user
     * @returns - an error if the user already exists, or Ok otherwise
     */
    pub async fn create_user(&self, user: User, auth_secret: AuthSecretEncrypted) -> Result<ObjectId, GrapevineServerError> {
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
        let uuid = self
            .users
            .insert_one(&user, None)
            .await
            .unwrap()
            .inserted_id
            .as_object_id()
            .unwrap();

        // add the encrypted note to the user's
        println!("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        _ = self.add_encrypted_auth_secret(&user.username, &auth_secret).await.unwrap();

        Ok(uuid)
    }

    pub async fn add_encrypted_auth_secret(
        &self,
        recipient: &String,
        auth_secret: &AuthSecretEncrypted,
    ) -> Result<ObjectId, GrapevineServerError> {
        //todo: optionally pass in oid to not make query to check if user exists
        // ensure the recipient exists in the database
        println!("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        let query = doc! { "username": recipient };
        let options = FindOneOptions::builder()
            .projection(doc! {"_id": 1})
            .build();
        let uuid = match self.users.find_one(query, options).await.unwrap() {
            Some(user) => user.id.unwrap(),
            None => return Err(GrapevineServerError::UserDoesNotExist(recipient.clone())),
        };
        println!("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX, {:?}", uuid);

        // create the encrypted auth secret
        let auth_secret_id = self
            .auth_secrets
            .insert_one(auth_secret, None)
            .await
            .unwrap()
            .inserted_id
            .as_object_id()
            .unwrap();
        println!("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        // add the encrypted auth secret to the user's list of encrypted auth secrets
        let connections = Connection {
            user: uuid,
            auth_secret: auth_secret_id,
        };
        
        let query = doc! { "id": uuid }; 
        let update = doc! { "$push": { "connections": bson::to_bson(&connections).unwrap()} };
        self.users.update_one(query, update, None).await.unwrap();
        println!("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");

        Ok(auth_secret_id)
    }
}
