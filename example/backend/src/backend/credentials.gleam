//// Credential store backed by trove.

import glasslock
import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import trove
import trove/codec

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
      value_codec: term_codec(),
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
    use <- guard_unique(tx, store.users, username, UsernameTaken)
    use <- guard_unique(tx, store.credential_index, cred_key, CredentialIdTaken)
    use <- guard_unique(tx, store.user_id_index, uid_key, UserIdTaken)

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

fn guard_unique(
  tx: trove.Tx(String, String),
  keyspace: trove.Keyspace(String, v),
  key: String,
  conflict: SaveError,
  proceed: fn() ->
    trove.TransactionResult(String, String, Result(Nil, SaveError)),
) -> trove.TransactionResult(String, String, Result(Nil, SaveError)) {
  case trove.tx_has_key_in(tx, keyspace:, key:) {
    True -> trove.Cancel(result: Error(conflict))
    False -> proceed()
  }
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

fn term_codec() -> codec.Codec(a) {
  codec.Codec(encode: term_encode, decode: term_decode)
}

@external(erlang, "backend_ffi", "term_encode")
fn term_encode(term: a) -> BitArray

@external(erlang, "backend_ffi", "term_decode")
fn term_decode(bits: BitArray) -> Result(a, Nil)
