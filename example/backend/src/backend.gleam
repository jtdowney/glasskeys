import backend/credentials
import backend/router
import backend/web
import gleam/erlang/process
import gleam/result
import mist
import wisp
import wisp/wisp_mist

pub fn main() {
  wisp.configure_logger()

  let priv_dir = wisp.priv_directory("backend") |> result.unwrap("priv")
  let assert Ok(credential_store) = credentials.open(priv_dir <> "/storage")

  let ctx =
    web.Context(
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
