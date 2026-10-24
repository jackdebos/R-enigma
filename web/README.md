# enigma-web

A separate, local web client for the Rust Enigma engine. **Currently implemented:
server scaffold, embedded placeholder page and authenticated status route.** Engine
path/version validation, transform execution and the bilingual machine UI are planned
in T3–T5 of `odd/tasks/enigma-web-client.md`; this scaffold does not run the engine yet.

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
- `static/`: embedded page (currently a placeholder).

The future machine page will build a request only on explicit start and run
`enigma --events - --request -` as a child process, reading JSONL events from
`docs/protocol.md` §4. Engine path/version validation will follow §8. The engine stays
in `crates/`; it has no web listener and is never linked into this Go binary.
