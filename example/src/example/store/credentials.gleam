import glasskeys.{type Credential, Credential}
import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import storail.{type Collection, type Config, type StorailError}

pub type CredentialStore {
  CredentialStore(
    config: Config,
    credentials: Collection(StoredCredential),
    users: Collection(StoredUser),
    user_id_index: Collection(String),
  )
}

pub type CredentialError {
  StorageError(StorailError)
  NotFound
}

pub type User {
  User(username: String, user_id: BitArray, credentials: List(Credential))
}

pub type StoredCredential {
  StoredCredential(
    id: String,
    public_key: String,
    sign_count: Int,
    username: String,
    user_id: String,
  )
}

pub type StoredUser {
  StoredUser(username: String, user_id: String, credential_ids: List(String))
}

pub fn new(storage_path: String) -> CredentialStore {
  let config = storail.Config(storage_path: storage_path)

  CredentialStore(
    config: config,
    credentials: storail.Collection(
      name: "credentials",
      to_json: credential_to_json,
      decoder: credential_decoder(),
      config: config,
    ),
    users: storail.Collection(
      name: "users",
      to_json: user_to_json,
      decoder: user_decoder(),
      config: config,
    ),
    user_id_index: storail.Collection(
      name: "user_id_index",
      to_json: json.string,
      decoder: decode.string,
      config: config,
    ),
  )
}

/// Save a new credential after registration
pub fn save(
  store: CredentialStore,
  username: String,
  user_id: BitArray,
  credential: Credential,
) -> Result(Nil, StorailError) {
  let cred_id_b64 = bit_array.base64_url_encode(credential.id, False)
  let user_id_b64 = bit_array.base64_url_encode(user_id, False)
  let pub_key_b64 = bit_array.base64_url_encode(credential.public_key, False)

  let stored_cred =
    StoredCredential(
      id: cred_id_b64,
      public_key: pub_key_b64,
      sign_count: credential.sign_count,
      username: username,
      user_id: user_id_b64,
    )

  let cred_key = storail.key(store.credentials, cred_id_b64)
  use _ <- result.try(storail.write(cred_key, stored_cred))

  let user_key = storail.key(store.users, username)
  use existing_user <- result.try(storail.optional_read(user_key))

  let updated_user = case existing_user {
    Some(user) ->
      StoredUser(..user, credential_ids: [cred_id_b64, ..user.credential_ids])
    None ->
      StoredUser(username: username, user_id: user_id_b64, credential_ids: [
        cred_id_b64,
      ])
  }

  use _ <- result.try(storail.write(user_key, updated_user))

  let index_key = storail.key(store.user_id_index, user_id_b64)
  storail.write(index_key, username)
}

/// Check if a user exists
pub fn user_exists(store: CredentialStore, username: String) -> Bool {
  storail.key(store.users, username)
  |> storail.exists
  |> result.unwrap(False)
}

/// Get user by username (reconstructs credentials from storage)
pub fn get_user(store: CredentialStore, username: String) -> Result(User, Nil) {
  let user_key = storail.key(store.users, username)
  use stored_user: StoredUser <- result.try(
    storail.read(user_key)
    |> result.replace_error(Nil),
  )

  use user_id <- result.try(bit_array.base64_url_decode(stored_user.user_id))

  let credentials =
    stored_user.credential_ids
    |> list.filter_map(fn(cred_id) {
      let cred_key = storail.key(store.credentials, cred_id)
      case storail.read(cred_key) {
        Ok(stored) -> stored_to_credential(stored)
        Error(_) -> Error(Nil)
      }
    })

  Ok(User(
    username: stored_user.username,
    user_id: user_id,
    credentials: credentials,
  ))
}

/// Get user by credential ID (for authentication)
pub fn get_user_by_credential_id(
  store: CredentialStore,
  credential_id: BitArray,
) -> Result(User, Nil) {
  let cred_id_b64 = bit_array.base64_url_encode(credential_id, False)
  let cred_key = storail.key(store.credentials, cred_id_b64)

  use stored_cred: StoredCredential <- result.try(
    storail.read(cred_key)
    |> result.replace_error(Nil),
  )

  get_user(store, stored_cred.username)
}

/// Get user by user_id (for discoverable credentials)
pub fn get_user_by_user_id(
  store: CredentialStore,
  user_id: BitArray,
) -> Result(User, Nil) {
  let user_id_b64 = bit_array.base64_url_encode(user_id, False)
  let index_key = storail.key(store.user_id_index, user_id_b64)

  use username <- result.try(
    storail.read(index_key)
    |> result.replace_error(Nil),
  )

  get_user(store, username)
}

/// Update credential (after authentication, to update sign_count)
pub fn update(
  store: CredentialStore,
  _username: String,
  credential: Credential,
) -> Result(Nil, CredentialError) {
  let cred_id_b64 = bit_array.base64_url_encode(credential.id, False)
  let pub_key_b64 = bit_array.base64_url_encode(credential.public_key, False)
  let cred_key = storail.key(store.credentials, cred_id_b64)

  use existing <- result.try(
    storail.optional_read(cred_key)
    |> result.map_error(StorageError),
  )

  case existing {
    Some(stored) -> {
      let updated =
        StoredCredential(
          ..stored,
          sign_count: credential.sign_count,
          public_key: pub_key_b64,
        )
      storail.write(cred_key, updated)
      |> result.map_error(StorageError)
    }
    None -> Error(NotFound)
  }
}

fn credential_to_json(cred: StoredCredential) -> json.Json {
  json.object([
    #("id", json.string(cred.id)),
    #("public_key", json.string(cred.public_key)),
    #("sign_count", json.int(cred.sign_count)),
    #("username", json.string(cred.username)),
    #("user_id", json.string(cred.user_id)),
  ])
}

fn user_to_json(user: StoredUser) -> json.Json {
  json.object([
    #("username", json.string(user.username)),
    #("user_id", json.string(user.user_id)),
    #("credential_ids", json.array(user.credential_ids, json.string)),
  ])
}

fn credential_decoder() -> decode.Decoder(StoredCredential) {
  use id <- decode.field("id", decode.string)
  use public_key <- decode.field("public_key", decode.string)
  use sign_count <- decode.field("sign_count", decode.int)
  use username <- decode.field("username", decode.string)
  use user_id <- decode.field("user_id", decode.string)
  decode.success(StoredCredential(
    id: id,
    public_key: public_key,
    sign_count: sign_count,
    username: username,
    user_id: user_id,
  ))
}

fn user_decoder() -> decode.Decoder(StoredUser) {
  use username <- decode.field("username", decode.string)
  use user_id <- decode.field("user_id", decode.string)
  use credential_ids <- decode.field(
    "credential_ids",
    decode.list(decode.string),
  )
  decode.success(StoredUser(
    username: username,
    user_id: user_id,
    credential_ids: credential_ids,
  ))
}

fn stored_to_credential(stored: StoredCredential) -> Result(Credential, Nil) {
  use id <- result.try(bit_array.base64_url_decode(stored.id))
  use public_key <- result.try(bit_array.base64_url_decode(stored.public_key))
  Ok(Credential(
    id: id,
    public_key: public_key,
    sign_count: stored.sign_count,
    user_verified: False,
  ))
}
