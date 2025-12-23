import example/router
import example/store/credentials
import example/store/sessions
import example/web.{Context}
import gleam/erlang/process
import mist
import simplifile
import wisp
import wisp/wisp_mist

pub fn main() {
  wisp.configure_logger()

  let assert Ok(priv) = simplifile.current_directory()
  let priv = priv <> "/priv/static"
  let storage_path = priv <> "/../storage"

  let cred_store = credentials.new(storage_path)
  let assert Ok(session_store) = sessions.start()

  let ctx =
    Context(
      origin: "http://localhost:8000",
      rp_id: "localhost",
      priv: priv,
      credential_store: cred_store,
      session_store: session_store,
    )

  let handler = fn(req) { router.handle_request(req, ctx) }
  let secret_key_base = wisp.random_string(64)

  let assert Ok(_) =
    wisp_mist.handler(handler, secret_key_base)
    |> mist.new
    |> mist.port(8000)
    |> mist.start

  process.sleep_forever()
}
