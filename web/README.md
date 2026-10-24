# enigma-web

A separate, local web client for the Rust Enigma engine. **Currently implemented:
server scaffold, embedded placeholder page, authenticated status route and persisted
engine path/version validation.** Transform execution and the bilingual machine UI
remain planned in T4–T5 of `odd/tasks/enigma-web-client.md`.

## Build and run

Requires Go 1.24 or newer; standard library only. From the repository root:

```sh
cd web
go build -o enigma-web ./cmd/enigma-web
./enigma-web
```

The server binds `127.0.0.1`, prints its full token-bearing URL to stdout, then opens
it in the browser (`xdg-open` on Linux, `open` on macOS, or `rundll32
url.dll,FileProtocolHandler` on Windows). If opening fails, it prints a manual-open
hint to stderr and keeps serving. Ctrl+C gracefully stops the server.

| Flag | Default | Effect |
| --- | --- | --- |
| `--port <n>` | `0` | Port from 0–65535; 0 selects a free port. |
| `--no-browser` | off | Print the URL without launching a browser (headless/tests). |
| `--help` | | Show command help. |

For example: `./enigma-web --no-browser --port 8080`. Open the printed URL manually.
The executable includes the page; it needs no static files in its working directory.

## Security and routes

- IPv4 loopback only, never `0.0.0.0`. `Host` must be exactly `127.0.0.1:<port>` or
  `localhost:<port>`; any other value receives 403.
- Every non-GET/HEAD request requires an `Origin` exactly equal to
  `http://127.0.0.1:<port>` or `http://localhost:<port>`. Missing/foreign origins
  receive 403, before authentication or routing. No cross-origin access is enabled.
- Each run generates 32 cryptographically random bytes, encoded as hex in the URL.
  `GET /?token=<correct token>` sets the host-only `enigma_token_<port>` session cookie (the port is in the name because browser cookies ignore ports)
  (`Path=/`, `HttpOnly`, `SameSite=Strict`) and redirects with 303 to `/`, removing
  the token from the address bar. The cookie is not `Secure` because this is local
  HTTP. Invalid tokens do not set a cookie. Bootstrap responses are not cached and
  responses use `Referrer-Policy: no-referrer`.
- Every `/api/...` request requires that cookie, checked in constant time, otherwise
  401 with `{"error":"unauthorized"}`. API responses use JSON and `Cache-Control:
  no-store`. Static content is public on the allowed hosts.
- `GET /api/status` returns 200 with `{"ok":true}`. Other methods, after the security
  checks, receive 405 (`Allow: GET`); unknown authenticated API routes receive 404.

Keep the printed URL private: any local program holding the token can use the API.
This is a local browser boundary, not isolation from other processes on your machine.

## Engine setup and compatibility

Use the absolute path to the installed Rust `enigma` executable, not its directory
or the Go `enigma-web` binary. For a local release build, that is the repository's
`target/release/enigma`; installed binaries can be located with `command -v enigma`
on Unix. No PATH lookup, shell expansion, or shell invocation is used by the server.
Only configure an executable you trust: probing `--version` executes that program.

All engine routes have the same cookie authentication and Host/Origin guards as
`/api/status`:

| Route | Result |
| --- | --- |
| `GET /api/engine` | 200 with the saved path, revalidated on every request; missing config means not configured. |
| `POST /api/engine` | Body `{"path":"/absolute/path/to/enigma"}`; 200 validates and atomically saves, 400 rejects without changing saved config. |

Other methods return 405 (`Allow: GET, POST`). Requests must contain one JSON object
with a string `path`, no unknown fields, and at most 16 KiB. Responses have this shape:

```json
{"configured":true,"path":"/absolute/path/to/enigma","version":"0.1.0","protocol":1,"compatible":true,"error":null,"supported":[{"version":"0.1.0","protocol":1}]}
```

An unconfigured response has `configured:false`, empty path/version, protocol 0,
`compatible:false`, and `error:null`. POST responses describe the attempted candidate,
not the previous saved path; GET describes what is saved, including when it becomes
invalid. Rejected JSON has empty candidate fields. Errors are objects with stable
`code` and a short English `message`; the future page can translate the codes.

| Code | Meaning |
| --- | --- |
| `invalid_request` | Missing/wrong path field, malformed/oversized JSON, extra fields or trailing JSON. |
| `not_absolute` | Path is not absolute. |
| `not_found` | File does not exist. |
| `not_executable` | Path is not a regular executable file, or metadata cannot be read. |
| `not_enigma` | Failed execution/nonzero exit, unparsable version output, or stdout above 4096 bytes. |
| `unsupported_version` | Parsed engine/protocol pair is not supported. Also includes `error.found` and `error.supported` version/protocol objects. |
| `timeout` | Version probe exceeded its five-second deadline. |
| `internal_error` | Config read/parse/save failed (HTTP 500). |

Version stdout must be exactly two lines: `enigma <version>` and
`protocol version <n>` (a final newline is optional). Stderr is discarded. Probes
have a five-second timeout and a 100 ms pipe-drain limit, so inherited output pipes
cannot hold the request open indefinitely. Supported pairs are exact, not minimums:
**engine 0.1.0, protocol 1**. Older and newer engines are refused. To support another
engine, test its CLI/protocol contract, update the single `supported` list in
`internal/engine/engine.go` plus tests and this document, then release the web client.

The saved JSON is `{"path":"..."}` in `enigma-web/config.json` under Go's
`os.UserConfigDir()` (normally `$XDG_CONFIG_HOME` or `~/.config` on Linux,
`~/Library/Application Support` on macOS, `%AppData%` on Windows). A newly created
config directory uses 0700; the config file uses 0600. Saves write a same-directory
temporary file, sync and close it, then rename atomically. A missing file is normal;
corrupt or unreadable config is reported, not silently discarded. Existing parent
directory permissions are left unchanged.

For tests/headless smoke checks only, set **`ENIGMA_WEB_CONFIG`** to a temporary
config-file path before launching the binary. This overrides the user config location;
no new command-line flag is exposed. Tests inject their own config path and create
fake engines under `t.TempDir()`. The optional real-engine test skips if the release
binary is absent. `Server.ValidatedEnginePath(ctx)` is the reusable boundary for
future jobs: it reloads and revalidates, never returning an invalid cached path.

## Test

From `web/`:

```sh
go vet ./... && go test ./...
gofmt -l .
```

The formatting check should print nothing. HTTP tests use `net/http/httptest` without
opening a browser or network listener.

## Architecture and next steps

- `cmd/enigma-web/`: flags, loopback listener, browser launcher and shutdown.
- `internal/server/`: testable HTTP security boundary and routes.
- `internal/engine/`: bounded version probing, exact compatibility gate and atomic config persistence.
- `static/`: embedded page (currently a placeholder).

The future machine page will build a request only on explicit start and run
`enigma --events - --request -` as a child process, reading JSONL events from
`docs/protocol.md` §4. Engine path/version validation follows §8. The engine stays
in `crates/`; it has no web listener and is never linked into this Go binary.
