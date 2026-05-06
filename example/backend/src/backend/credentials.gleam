//// Credential store backed by trove.

import glasslock
import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/result
import gleam/string
import trove
import trove/codec

type StoredUser {
  StoredUser(
    username: String,
    user_id: BitArray,
    credentials: List(StoredCredential),
  )
}

type StoredCredential {
  StoredCredential(
    id: BitArray,
    public_key_bytes: BitArray,
    sign_count: Int,
    transports: List(glasslock.Transport),
  )
}

fn to_stored(user: User) -> StoredUser {
  StoredUser(
    username: user.username,
    user_id: user.user_id,
    credentials: list.map(user.credentials, to_stored_credential),
  )
}

fn to_stored_credential(credential: glasslock.Credential) -> StoredCredential {
  StoredCredential(
    id: credential.id,
    public_key_bytes: glasslock.encode_public_key(credential.public_key),
    sign_count: credential.sign_count,
    transports: credential.transports,
  )
}

fn from_stored(stored: StoredUser) -> Result(User, Nil) {
  use credentials <- result.try(list.try_map(
    stored.credentials,
    from_stored_credential,
  ))
  Ok(User(username: stored.username, user_id: stored.user_id, credentials:))
}

fn from_stored_credential(
  stored: StoredCredential,
) -> Result(glasslock.Credential, Nil) {
  glasslock.parse_public_key(stored.public_key_bytes)
  |> result.replace_error(Nil)
  |> result.map(fn(public_key) {
    glasslock.Credential(
      id: stored.id,
      public_key:,
      sign_count: stored.sign_count,
      transports: stored.transports,
    )
  })
}

// term_to_binary round-trips nested records (User -> Credential ->
// AuthenticatorTransport) without per-field encoders.
fn user_codec() -> codec.Codec(User) {
  codec.Codec(
    encode: fn(user) { term_encode(to_stored(user)) },
    decode: fn(bits) {
      use stored <- result.try(term_decode(bits))
      from_stored(stored)
    },
  )
}

pub type Store {
  Store(
    db: trove.Db(String, String),
    users: trove.Keyspace(String, User),
    credential_index: trove.Keyspace(String, String),
    user_id_index: trove.Keyspace(String, String),
  )
}

pub type User {
  User(
    username: String,
    user_id: BitArray,
    credentials: List(glasslock.Credential),
  )
}

const trove_timeout = 5000

pub fn open(storage_path: String) -> Result(Store, trove.OpenError) {
  let config =
    trove.Config(
      path: storage_path,
      key_codec: codec.string(),
      value_codec: codec.string(),
      key_compare: string.compare,
      auto_compact: trove.AutoCompact(min_dirt: 1000, min_dirt_factor: 0.25),
      auto_file_sync: trove.AutoSync,
      call_timeout: trove_timeout,
    )
  use db <- result.try(trove.open(config))
  let users =
    trove.keyspace(
      db,
      name: "users",
      key_codec: codec.string(),
      value_codec: user_codec(),
      key_compare: string.compare,
    )
  let credential_index =
    trove.keyspace(
      db,
      name: "credential_index",
      key_codec: codec.string(),
      value_codec: codec.string(),
      key_compare: string.compare,
    )
  let user_id_index =
    trove.keyspace(
      db,
      name: "user_id_index",
      key_codec: codec.string(),
      value_codec: codec.string(),
      key_compare: string.compare,
    )
  Ok(Store(db:, users:, credential_index:, user_id_index:))
}

pub fn close(store: Store) -> Nil {
  trove.close(store.db)
}

pub fn get_user(store: Store, username: String) -> Result(User, Nil) {
  trove.get_in(store.db, keyspace: store.users, key: username)
  |> result.replace_error(Nil)
}

pub fn get_user_by_credential_id(
  store: Store,
  credential_id: BitArray,
) -> Result(User, Nil) {
  trove.get_in(
    store.db,
    keyspace: store.credential_index,
    key: bit_array.base64_url_encode(credential_id, False),
  )
  |> result.replace_error(Nil)
  |> result.try(get_user(store, _))
}

pub fn get_user_by_user_id(
  store: Store,
  user_id: BitArray,
) -> Result(User, Nil) {
  trove.get_in(
    store.db,
    keyspace: store.user_id_index,
    key: bit_array.base64_url_encode(user_id, False),
  )
  |> result.replace_error(Nil)
  |> result.try(get_user(store, _))
}

pub type SaveError {
  UsernameTaken
  CredentialIdTaken
  UserIdTaken
}

pub fn save(
  store: Store,
  username: String,
  user_id: BitArray,
  credential: glasslock.Credential,
) -> Result(Nil, SaveError) {
  let cred_key = bit_array.base64_url_encode(credential.id, False)
  let uid_key = bit_array.base64_url_encode(user_id, False)

  trove.transaction(store.db, timeout: trove_timeout, callback: fn(tx) {
    use <- bool.guard(
      when: trove.tx_has_key_in(tx, keyspace: store.users, key: username),
      return: trove.Cancel(result: Error(UsernameTaken)),
    )
    use <- bool.guard(
      when: trove.tx_has_key_in(
        tx,
        keyspace: store.credential_index,
        key: cred_key,
      ),
      return: trove.Cancel(result: Error(CredentialIdTaken)),
    )
    use <- bool.guard(
      when: trove.tx_has_key_in(tx, keyspace: store.user_id_index, key: uid_key),
      return: trove.Cancel(result: Error(UserIdTaken)),
    )

    let tx =
      tx
      |> trove.tx_put_in(
        keyspace: store.users,
        key: username,
        value: User(username:, user_id:, credentials: [credential]),
      )
      |> trove.tx_put_in(
        keyspace: store.credential_index,
        key: cred_key,
        value: username,
      )
      |> trove.tx_put_in(
        keyspace: store.user_id_index,
        key: uid_key,
        value: username,
      )
    trove.Commit(tx: tx, result: Ok(Nil))
  })
}

pub fn update(
  store: Store,
  user: User,
  credential: glasslock.Credential,
) -> Nil {
  let updated_user =
    User(..user, credentials: replace_credential(user.credentials, credential))
  trove.put_in(
    store.db,
    keyspace: store.users,
    key: user.username,
    value: updated_user,
  )
}

fn replace_credential(
  credentials: List(glasslock.Credential),
  updated: glasslock.Credential,
) -> List(glasslock.Credential) {
  list.map(credentials, fn(cred) {
    case cred.id == updated.id {
      True -> updated
      False -> cred
    }
  })
}

@external(erlang, "backend_ffi", "term_encode")
fn term_encode(term: a) -> BitArray

@external(erlang, "backend_ffi", "term_decode")
fn term_decode(bits: BitArray) -> Result(a, Nil)
