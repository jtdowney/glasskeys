import glasskeys/authentication
import glasskeys/registration
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/otp/actor
import gleam/time/duration
import gleam/time/timestamp

const session_ttl_seconds = 300.0

pub type SessionStore =
  Subject(Message)

pub type SessionData {
  RegistrationSession(
    username: String,
    user_id: BitArray,
    verifier: registration.Challenge,
  )
  AuthenticationSession(verifier: authentication.Challenge)
}

type StoredSession {
  StoredSession(data: SessionData, created_at: timestamp.Timestamp)
}

pub opaque type Message {
  Set(session_id: String, data: SessionData)
  Get(session_id: String, reply: Subject(Result(SessionData, Nil)))
  Delete(session_id: String)
}

type State =
  Dict(String, StoredSession)

pub fn start() -> Result(SessionStore, actor.StartError) {
  let started =
    actor.new(dict.new())
    |> actor.on_message(handle_message)
    |> actor.start

  case started {
    Ok(started) -> Ok(started.data)
    Error(e) -> Error(e)
  }
}

fn handle_message(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    Set(session_id, data) -> {
      let now = timestamp.system_time()
      let stored = StoredSession(data: data, created_at: now)
      let state = dict.insert(state, session_id, stored)
      actor.continue(state)
    }

    Get(session_id, reply) -> {
      let #(state, result) = case dict.get(state, session_id) {
        Ok(stored) -> {
          let now = timestamp.system_time()
          let age =
            timestamp.difference(stored.created_at, now)
            |> duration.to_seconds()
          case age >. session_ttl_seconds {
            True -> #(dict.delete(state, session_id), Error(Nil))
            False -> #(state, Ok(stored.data))
          }
        }
        Error(_) -> #(state, Error(Nil))
      }
      process.send(reply, result)
      actor.continue(state)
    }

    Delete(session_id) -> {
      let state = dict.delete(state, session_id)
      actor.continue(state)
    }
  }
}

pub fn set(store: SessionStore, id: String, data: SessionData) -> Nil {
  actor.send(store, Set(id, data))
}

pub fn get(store: SessionStore, id: String) -> Result(SessionData, Nil) {
  actor.call(store, waiting: 1000, sending: fn(reply) { Get(id, reply) })
}

pub fn delete(store: SessionStore, id: String) -> Nil {
  actor.send(store, Delete(id))
}
