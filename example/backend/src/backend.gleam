import backend/credentials
import backend/router
import backend/sessions
import backend/web
import gleam/erlang/process
import mist
import wisp
import wisp/wisp_mist

pub fn main() {
  wisp.configure_logger()

  let assert Ok(session_store) = sessions.start()
  let assert Ok(credential_store) = credentials.open("priv/storage")

  let ctx =
    web.Context(
      sessions: session_store,
      credentials: credential_store,
      rp_id: "localhost",
      rp_name: "Glasslock Example",
      origins: ["http://localhost:1234", "http://localhost:5173"],
    )

  let handler = router.handle_request(_, ctx)
  let assert Ok(_) =
    handler
    |> wisp_mist.handler(wisp.random_string(64))
    |> mist.new
    |> mist.port(3000)
    |> mist.start

  process.sleep_forever()
}
