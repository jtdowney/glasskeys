import backend/credentials
import backend/router
import backend/web
import envoy
import gleam/erlang/process
import gleam/list
import gleam/result
import gleam/string
import mist
import wisp
import wisp/wisp_mist

const default_rp_id = "localhost"

const default_rp_name = "Glasslock Example"

const default_origins = "http://localhost:1234,http://localhost:5173"

pub fn main() {
  wisp.configure_logger()

  let priv_dir = wisp.priv_directory("backend") |> result.unwrap("priv")
  let assert Ok(credential_store) = credentials.open(priv_dir <> "/storage")

  let origins =
    envoy.get("ORIGINS") |> result.unwrap(default_origins) |> parse_origins
  let assert [_, ..] = origins
    as "ORIGINS must contain at least one non-empty origin"

  let ctx =
    web.Context(
      credentials: credential_store,
      rp_id: envoy.get("RP_ID") |> result.unwrap(default_rp_id),
      rp_name: envoy.get("RP_NAME") |> result.unwrap(default_rp_name),
      origins:,
    )

  let secret_key =
    envoy.get("SECRET_KEY") |> result.unwrap(wisp.random_string(64))

  let handler = router.handle_request(_, ctx)
  let assert Ok(_) =
    handler
    |> wisp_mist.handler(secret_key)
    |> mist.new
    |> mist.port(3000)
    |> mist.start

  process.sleep_forever()
}

fn parse_origins(raw: String) -> List(String) {
  raw
  |> string.split(",")
  |> list.map(string.trim)
  |> list.filter(fn(value) { value != "" })
}
