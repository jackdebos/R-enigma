# enigma-web

A separate, local web client for the Rust Enigma engine. The embedded bilingual
machine page configures Enigma I, M3, M4, Railway, G-312, G-260, KD and the
I/M3 UKW-D variants and starts encryption or decryption
explicitly, using the separately installed Rust engine. No framework, build step,
CDN, external font, image, or JavaScript package installation is needed.

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
  `localhost:<port>`. Only when listening on port 80, the browser's port-less
  `127.0.0.1` and `localhost` forms are also accepted; other values receive 403.
- Every non-GET/HEAD request requires an `Origin` exactly equal to
  `http://127.0.0.1:<port>` or `http://localhost:<port>`. Missing/foreign origins
  receive 403, before authentication or routing. Only on port 80,
  `http://127.0.0.1` and `http://localhost` are also accepted. Port-less forms
  remain forbidden on every other port. No cross-origin access is enabled.
- Each run generates 32 cryptographically random bytes, encoded as hex in the URL.
  `GET /?token=<correct token>` sets the host-only `enigma_token_<port>` session cookie (the port is in the name because browser cookies ignore ports)
  (`Path=/`, `HttpOnly`, `SameSite=Strict`) and redirects with 303 to `/`, removing
  the token from the address bar. The cookie is not `Secure` because this is local
  HTTP. Invalid tokens do not set a cookie. Bootstrap responses are not cached and
  responses use `Referrer-Policy: no-referrer`.
- Every response includes `X-Content-Type-Options: nosniff` and a self-only Content
  Security Policy (no inline scripts/styles, no framing, no external resources).
  The page uses same-origin fetches with the session cookie.
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
`target/release/enigma`; installed binaries can be located with `which enigma`
on Linux/macOS or `where enigma` on Windows. No PATH lookup, shell expansion, or shell invocation is used by the server.
Only configure an executable you trust: probing `--version` executes that program.

All engine routes have the same cookie authentication and Host/Origin guards as
`/api/status`:

| Route | Result |
| --- | --- |
| `GET /api/engine` | 200 with the remembered startup/save validation result; missing config at startup means not configured. |
| `POST /api/engine` | Body `{"path":"/absolute/path/to/enigma"}`; 200 validates and atomically saves, 400 rejects without changing saved config. |

Other methods return 405 (`Allow: GET, POST`). Requests must contain one JSON object
with a string `path`, no unknown fields, and at most 16 KiB. Responses have this shape:

```json
{"configured":true,"path":"/absolute/path/to/enigma","version":"0.3.0","protocol":1,"compatible":true,"error":null,"supported":[{"version":"0.3.0","protocol":1}]}
```

An unconfigured response has `configured:false`, empty path/version, protocol 0,
`compatible:false`, and `error:null`. POST responses describe the attempted candidate,
not the previous saved path; GET describes the remembered state. Failed saves leave
both that state and the saved config unchanged. Rejected JSON has empty candidate fields. Errors are objects with stable
`code` and a short English `message`; the page translates the codes.

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
**engine 0.3.0, protocol 1**. The page advertises Railway and G catalog IDs
introduced in 0.3.0, so 0.2.0 is no longer supported (even though its I/M3/M4
requests remain compatible). Engine 0.1.0 also lacks the distinct-wheel constraint. Older and newer
engines are refused. To support another engine, test its CLI/protocol contract, update the single `supported` list in
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
fake engines under `t.TempDir()`. Optional real-engine tests use `ENIGMA_TEST_BIN`
(an absolute path to engine 0.3.0) and skip with a message when unset or unavailable.
`Server.ValidatedEnginePath(ctx)` is the reusable boundary for jobs: it uses the remembered startup/save validation result without probing or
re-reading the config. Startup validates the saved engine once, before printing
the URL; missing or invalid configuration does not prevent the server starting,
and the page shows that state. Only saving a path probes `--version` again.
GET and transform-path lookups do not wait for an in-progress save probe.
Replacing the engine (or editing its saved config) requires a restart or saving
the path again to refresh compatibility state.

## Machine catalog and transform

These routes use the same cookie authentication and Host/Origin guards:

- `GET /api/machines`: `{"models":[{"id":"enigma-i","definition_id":"enigma-i","reflectors":["B","C"],"slots":[{"id":"left","allowed_wheels":["I","II","III","IV","V"]},...],"plugboard":true},...]}`.
  Models are `enigma-i`, `enigma-m3`, `enigma-m4`, `enigma-railway`,
  `enigma-g312`, `enigma-g260`, `enigma-i-ukwd`, `enigma-m3-ukwd`, and
  `enigma-kd`. The UKW-D models have `rewirable_reflector:true`, reflector `D`,
  and no editable reflector position/ring. KD has `plugboard:false` and the same
  fixed ETW as Railway/G. KD uses the FRA wiring; its attribution to Mil Amt is
  uncertain. `enigma-m3-ukwd` also represents M4 with UKW-D in M3 mode (no Greek
  wheel). Railway/G have `plugboard:false`,
  `settable_reflector:true`, reflector `UKW`, and `fixed_slots` containing
  `{"id":"etw","wheel":"ETW","ring":"A","position":"A"}`. The fixed ETW is
  not shown in either editable form and is inserted by the server. Editable slots are in definition order,
  **excluding the separately selected reflector**: left/middle/right for I and M3;
  greek/left/middle/right for M4. M3/M4 moving slots admit I–VIII; M4 Greek admits
  Beta/Gamma and its reflectors are Thin-B/Thin-C. Sources are
  `docs/historical-catalog.md` and `crates/enigma-core/catalog/*.json`.
- `POST /api/transform`: explicitly starts one transform; no automatic jobs or
  persisted machine state. Other methods return 405 with `Allow: GET` or `POST`.

Example body (all members required, no unknown fields, maximum 1 MiB):

```json
{"model":"enigma-i","reflector":"B","slots":[{"id":"left","wheel":"I","ring":"A","position":"A"},{"id":"middle","wheel":"II","ring":"A","position":"A"},{"id":"right","wheel":"III","ring":"A","position":"A"}],"plugboard":[],"text":"HELLO"}
```

Railway/G transform bodies additionally require `reflector_ring` and
`reflector_position` (uppercase A–Z), and `plugboard:[]`. Attack bodies accept
these same reflector fields with `null` meaning search A–Z; omitted fields also
mean unknown on these models. I/M3/M4 omit both fields and keep reflector A/A.
Railway's reflector is settable but stationary; G's is settable and moves.
ETW must not be supplied in `slots`: it is always inserted at A/A. Cable editors
and cable-count settings are hidden for models without a plugboard.

Slots must follow catalog order; rings/positions and disjoint plugboard endpoints
must be uppercase A–Z. The server inserts the reflector slot (A/A for I/M3/M4),
uses bundled definition IDs and direction `encrypt` (these reflected machines are
reciprocal, so the same operation also decrypts from the same initial settings).
It does not impose distinct-wheel or historical operational-key restrictions that
the engine catalog does not enforce.

### UKW-D wiring

For `enigma-i-ukwd`, `enigma-m3-ukwd` and `enigma-kd`, enter exactly 12
space-separated, disjoint uppercase wiring pairs covering all 24 free contacts.
The notation selector defaults to **German**. It converts a valid wiring when
changed; invalid input is preserved for correction. Validation blocks submission
and explains missing pairs, repeated contacts, malformed pairs and forbidden
contacts in Spanish or English. The permanent pair must never be entered.

The mapping is BP `ABCDEFGHIJKLMNOPQRSTUVWXYZ` → German
`A-ZXWVUTSRQPON-MLKIHGFEDCB`: BP B/O are the unlabeled permanent contacts;
German has no J/Y. For example:

```text
BP:     AZ CX DW EV FU GT HS IR JQ KP LN MY
German: AB ZD XE WF VG UH TI SK RL QM PN OC
```

The browser converts to BP before sending `reflector_pairs:[["A","Z"],...]`
in the transform or known-wiring attack body. The server validates the BP key
again and inserts it as `pairs` in the engine's reflector configuration. Neither
German notation nor notation-selector state reaches the engine. UKW-D position
and ring are always inserted as A/A, not editable. KD additionally fixes ETW
A/A and hides all plugboard controls; its attack cap is `max_pairs:0`.

**Text rule:** the text is sent to the engine exactly as typed; nothing is uppercased,
removed or replaced. The bundled machines use the 26 uppercase letters A–Z, so the
engine rejects lowercase letters, spaces, digits, punctuation and any other symbol with
`invalid_text` before any work starts. Converting text (for example to uppercase) is
always an explicit user action on the page, never automatic.
Empty text is allowed. Each request starts from the supplied initial positions.

The server uses the remembered compatible engine path and runs it directly,
without a shell, as `enigma --events - --request -`. If the engine disappears or
changes after validation, transform attempts simply report the existing process
or protocol error (for example `engine_failed`), without another version probe. Transform execution has a ten-second deadline,
4 MiB stdout and 64 KiB stderr limits, plus a 100 ms inherited-pipe drain limit.
No report file is produced. Successful responses are HTTP 200:

```json
{"output":"ILBDA","events":[{"event":"started","protocol_version":1,"seq":1,"ts":"..."},{"event":"output","protocol_version":1,"seq":2,"ts":"...","output":"ILBDA"},{"event":"done","protocol_version":1,"seq":3,"ts":"...","reason":"completed"}]}
```

Events are retained whole, including any future additional state fields. Current
protocol v1 transform events expose **no final rotor positions or machine state**.
The engine is not modified and the server does not simulate stepping.

Failures have `{"error":{"code":"...","message":"..."}}`:

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed, oversized or incomplete body, wrong types, unknown fields or trailing JSON. |
| 400 | `unknown_model` | Model is not in the bundled catalog. |
| 400 | `invalid_component` | Invalid reflector, slot order/count, wheel, ring, position or plugboard. |
| 409 | `engine_not_configured` | Configure an engine first. |
| 409 | `engine_incompatible` | Remembered startup validation failed; message explains why. |
| 500 | `internal_error` | Startup configuration could not be read or request could not be built. |
| 422 | engine code, e.g. `invalid_text` | Engine error code/message passed through verbatim; also includes available location/expected/hint and events. |
| 502 | `engine_failed` | Failed process, excessive output, invalid JSONL or missing terminal/output events. |
| 502 | `timeout` | Transform deadline exceeded or request cancelled. |

## Attack preview

`POST /api/attack/preview` builds a search request and estimate only: it never
runs or requires a configured engine, writes files, or starts an attack. It uses
the same cookie and Host/Origin guards; other methods return 405 (`Allow: POST`).
The body is one strict JSON object, at most 1 MiB, with no unknown or duplicate
members. All members below are required except `settings`; `null` explicitly
marks an unknown reflector, wheel, ring or position. Slots follow catalog order.
Text is copied unchanged, including invalid engine symbols.

```json
{"model":"enigma-i","reflector":"B","slots":[{"id":"left","wheel":"I","ring":"A","position":"A"},{"id":"middle","wheel":"II","ring":"A","position":"A"},{"id":"right","wheel":"III","ring":"A","position":null}],"plugboard":{"known":[],"search":true},"text":"ABCDEF","settings":{"threads":2}}
```

Success returns `{"request":{...},"outer_keys":"26","threads":2,
"backend":"cpu","gpu_usage":100,"estimate_seconds":0.0014238362068965517,"resources":[{"measure":"sinkov_trigram",
"file":"enigma1941-trigram.json","builtin":"enigma1941-trigram"}]}`.
The request uses protocol 1 and bundled models. Unknowns enumerate complete catalog
wheel domains or A–Z rings/positions. By default `settings.distinct_wheels` is
`true` (also when absent). The builder adds
`"constraints":{"distinct_wheels":["left","middle","right"]}` to `job.space`
for Enigma I, M3 and M4; M4's Greek wheel has a separate domain and is not named.
Known wheels also participate. Repeated orders are skipped, and both `outer_keys`
and the estimate use the exact filtered count (for example 1,054,560 instead of
2,197,000 for Enigma I with unknown wheels/positions and known rings).
Set `settings.distinct_wheels:false` to omit the constraint and restore the previous
request bytes and product count, including repeats. If known wheels already repeat,
the default preview rejects the input with `invalid_settings` at
`settings/distinct_wheels`; choose different wheels, mark one unknown, or turn the
setting off. The builder never changes the input.
Railway/G attacks require `plugboard:{"known":[],"search":false}` and at least
one unknown key dimension. Their engine request still uses the required attack
plugboard branch with A–Z `symbols` and `max_pairs:0`; a supplied nonzero
`settings.max_pairs` is rejected. Reflector rings/positions participate in preview
counts just like rotor dimensions.

UKW-D attacks also offer **Unknown UKW-D wiring / Cableado UKW-D desconocido**.
This sends `search_reflector:true` without `reflector_pairs`. The builder fixes
reflector D/A/A, adds `{"id":"reflector","pairs":{"kind":"attack"}}` to
`job.space.slots`, and sends `job.attack.reflector_starts`. The starts control
allows 1–1000000 (default 8); more starts improve recovery chances but cost time,
and do not guarantee recovery. Wiring alone is a valid unknown dimension.
Only hill climb is offered for unknown wiring; partial exhaustion and crib
attack are unavailable, with a visible explanation. Optional finishing stages
keep the recovered wiring fixed.

**GPU choice:** unknown-wiring search explicitly blocks GPU, rather than silently
switching to CPU. A visible notice asks the user to select CPU; preview, start
and resume reject GPU with `backend_unavailable` at `settings/backend`, message
`GPU backend unavailable: the UKW-D wiring search runs on the CPU only`.
Known-wiring attacks keep GPU available. `settings.reflector_starts` is forbidden
for known wiring or non-UKW-D machines. The approximate duration scales with the
starts count, but is not a calibrated UKW-D benchmark.

Known plugboard pairs are fixed; all remaining letters are mutable. With
`search:false`, the pair cap equals the known pair count. A fully known key with
no plugboard search is rejected; a full 13-pair board has no mutable letters and
is also rejected.

Optional settings (the page exposes the method, crib and distinct wheels directly; other settings are in Advanced):

| Setting | Default / allowed values |
| --- | --- |
| `distinct_wheels` | `true`; boolean. `false` also tries repeated wheels. |
| `method` | `hill_climb` (empty start), `partial_exhaustion`, or CPU-only `bombe` (crib attack). |
| `crib` | Required for bombe only: one nonempty plaintext fragment, sent exactly as typed; A–Z only (lowercase and spaces are rejected at `settings/crib`), no longer than the ciphertext. No `start`/`seeds` are sent. |
| `crib_position` | Bombe only: optional nonnegative 0-based integer; omitted tries every admissible position. Out-of-range/crashing fixed positions and no admissible position are rejected before launch. |
| `seeds` | PE only: omitted selects all empty/single-pair seeds; an array selects seeds touching those unique uppercase mutable letters. |
| `initial_measure`, `final_measure` | `ic`, `sinkov_trigram`. Measures: `ic`, `entropy`, `sinkov_monogram` through `sinkov_hexagram`, `trie`. |
| `stages` | `[{"pass":"reswapping","measure":"sinkov_trigram"},{"pass":"measure","measure":"sinkov_trigram"}]`; `[]` disables stages. Each pass occurs at most once. |
| Stage fields | `reswapping`/`measure`: optional `measure` (defaults `sinkov_trigram`/`ic`); `trie`: optional `base_measure` (otherwise carries the previous score). |
| `switch_pairs`, `backtrack_pairs` | 7, 5; each 0–13. |
| `max_pairs` | 13 when searching; between known pair count and 13. |
| `hold` | 5; 1–1000. |
| `threads` | Half the logical CPUs, at least one; explicit values 1–256. Returned separately, not embedded in the engine request. |
| `backend` | `cpu` (default) or `gpu`; host setting, not part of the engine request. Bombe + GPU is rejected with `backend_unavailable` at `settings/backend` before launch, including resume. |
| `gpu_usage` | Integer 1–100, default 100; validated and used only with GPU. |
| `tables` | Measure-to-absolute-file-path map; own files override built-ins. Only used resource measures are allowed. |

Built-ins supply German 1941 bigrams/trigrams; see `internal/tables/NOTICE.md`
for provenance and licence. Other Sinkov measures and trie need an own table.
Own paths must resolve to regular files of at most 64 MiB. Preview checks metadata,
not table contents. Resources return `own` instead of `builtin` for own sources;
engine paths remain relative (`own-<measure>.json` or `<builtin id>.json`). The
attack runner copies/writes these resources before execution. Own files must follow
[engine JSON v1 scoring resources](../docs/scoring-resources.md); convert n-grams
with `python3 e2e/recovery/ngrams.py convert --help` from the repository root.

The approximate duration is `outer_keys × 0.004235 seconds × (PE ? 20 : 1)
× text_letters / 232 / threads` (ASCII letters counted without changing text).
The basis is our engine's U-264 design B: 74.4 seconds / 17576 keys, one thread,
Ryzen 5 2600. PE's factor is heuristic; hardware, text, stages and hold affect
actual time. This is guidance, not a completion guarantee.

Rejections return HTTP 400 with `{"error":{"code":"...","message":"...",
"field":"settings/hold"}}`; `field` is a body path (empty for whole-body errors).
Codes are `invalid_request` (JSON/schema/size), `unknown_model`,
`invalid_component` (catalog/key facts), `invalid_settings` (advanced settings or
own-file metadata), `missing_table` (required resource unavailable), and
`nothing_to_search` (no unknown key dimension).

## Attacks

The attack API runs one background child process at a time, independently of the
browser tab. Configure a compatible engine first. These JSON routes have the same
authentication, Host/Origin guards and `Cache-Control: no-store` as other APIs:

| Route | Result |
| --- | --- |
| `GET /api/attack` | 200 with `{"attack":null}` or the latest attack view. Poll about once a second. |
| `POST /api/attack` | The exact preview body; builds and starts an attack, returning 202 with `{"attack":{...}}`. |
| `POST /api/attack/cancel` | Creates this run's empty cancel marker; 202 with the current view. Cancellation takes effect at an engine safe boundary. |
| `POST /api/attack/resume` | Continues the latest resumable attack, with a new run number; optional `{"backend":"gpu","gpu_usage":50}` chooses host settings for this resume; 202 with the view. Empty body/`{}` retains saved host settings. |

Wrong methods return 405 with `Allow: GET, POST` for `/api/attack` and `Allow: POST`
for cancel/resume. Builder rejections match preview (400). Conflicts use 409 codes:
`attack_running`, `attack_not_running`, `attack_not_resumable`,
`engine_not_configured` or `engine_incompatible`. Storage failures use 500
`internal_error`.

The view includes `id`, `status`, `created_at` (UTC), absolute `directory`, original
`input` object, `outer_keys`, `threads`, `backend`, `gpu_usage`, `estimate_seconds`, `outers_selected`,
latest progress `counters` and `elapsed_ms`, complete `result` event, `error`
(`code`, `message`), `stderr` (at most 64 KiB per run), `resumable` and `runs`.
Unobserved event fields are null. Engine counter/time fields remain decimal strings.
States are `running`, `completed` (`completed` or `outer_slice_end`), `cancelled`,
`failed` (engine error, invalid stream or unsuccessful/incomplete process), and
`interrupted` (a saved running attack found after restart). Only cancelled or
interrupted attacks with a regular `checkpoint.json` are resumable. Cancel requests
do not mark a job cancelled until the engine emits its terminal event and exits.

Storage is an `attacks` directory beside the configured config file (including the
`ENIGMA_WEB_CONFIG` override), normally `<UserConfigDir>/enigma-web/attacks/`.
New root/job directories use 0700, web-created files 0600. Each job ID is UTC
`YYYYMMDDTHHMMSSZ-<8 random hex>` and gets a new, exclusively created directory:

```text
attacks/<id>/
  input.json                 exact HTTP request body
  request.json               exact builder-produced engine request
  enigma1941-trigram.json     built-in resources, when required
  own-<measure>.json          own resources copied byte-for-byte (maximum 64 MiB)
  state.json                 atomically persisted status and metadata
  events.jsonl               engine stdout JSONL without valid progress, appended across runs
  checkpoint.json            engine-owned checkpoint
  cancel-1                   empty marker, only when cancellation is requested
  report-1.txt               engine report; later runs use report-2.txt, etc.
```

The engine runs directly, without a shell or attack deadline, in the job directory:
`enigma --events - --request request.json --checkpoint checkpoint.json --cancel-file
cancel-1 --threads <n> --report report-1.txt`. Resume substitutes `--resume` for
`--checkpoint` and increments the cancel/report numbers, leaving old markers intact.
GPU appends `--backend gpu --gpu-usage <n>`; CPU leaves this command byte-for-byte
unchanged, with no backend flags. Neither setting enters the engine request or
checkpoint identity, so supported attacks can resume across backends.
If a resume cannot launch the engine, the attack keeps its previous status, run count
and resumability, and the view's `error` explains the launch failure. A start body is
read before the attack state is locked, so a slow client never delays status polls.
Own resources are rechecked during copying; text is never normalized. Stdout lines
are bounded to 64 MiB; an invalid/excessive stream fails the attack. Valid `progress`
events only update the live view polled by the page and are not written to
`events.jsonl` (a long attack emits hundreds of thousands of them); every other line,
including an invalid `progress`, is logged byte for byte. While an attack runs,
`state.json` is also saved at most every 5 seconds when progress arrives, so after a
crash it holds counters and elapsed time at most about 5 seconds old. The first
failed periodic save stops further periodic saves; the final save still reports
errors. Logs written by earlier versions, which contain every progress event, are
still read. Restart keeps the counters and elapsed time from whichever of
`state.json` and the log has the larger elapsed time. Restart loads
the newest readable job ID and rebuilds observations from its log; a saved `running`
state is persisted as `interrupted`. A newer directory whose `state.json` or
`input.json` is missing or unreadable (for example one left by a failed start) is
named on stderr and skipped, never repaired or deleted, so it cannot stop enigma-web
from starting.

On SIGINT/Ctrl+C or SIGTERM, enigma-web requests cancellation and waits up to 30
seconds for the attack to checkpoint and exit before shutting down HTTP. On Linux,
parent death also sends SIGTERM to the child for a safe stop; other platforms have
no parent-death hook. No hard cancellation latency is promised. Files are never
deleted by enigma-web: only `state.json` is atomically replaced by the web client;
the engine updates its own checkpoint as specified in protocol §6. Failed state
writes may leave `state-*.tmp` artifacts for manual inspection. Remove unwanted
attack directories manually only when no process is using them.

The Attack view below exposes these routes without requiring hand-written JSON.

## Machine page

- Choose Spanish or English in the header. The initial language follows the browser
  (`es*` selects Spanish, otherwise English); a selection is saved in localStorage
  when browser storage is available. Changing language preserves the current form.
- Save the full executable path in the engine panel. Its status shows the compatible
  engine and protocol versions, or explains the error (including found/supported
  versions). Until a compatible engine is connected, a friendly notice replaces the
  machine controls. A rejected candidate does not replace an already saved engine.
- Choose the model, reflector and one wheel, ring and start position for each slot.
  Slots follow catalog order, including the Greek wheel on M4. The small `?` buttons
  show short explanations while hovered or focused (Tab, or a tap on touch screens)
  and hide them when the pointer or focus leaves or on Escape, including the
  distinction between ring and position.
  Each CSS letter window shows only its chosen **initial** position: no animation,
  stepping simulation, or final rotor state is implied.
- Add or remove plugboard pairs using the two letter selectors. Used letters cannot
  be reused, and the page shows the pair count (up to 13).
- Type a message and press **Start / Comenzar**. Typing never starts a request.
  Invalid characters are listed individually with 1-based Unicode code-point
  positions (not UTF-16 offsets); spaces, tabs and line breaks have visible labels.
  Nothing is sent if any character is outside A–Z. If lowercase is present,
  **Convert to uppercase / Pasar a mayúsculas** explicitly changes the textarea,
  but does not send it. Review it and press Start again; accents or other remaining
  symbols are still rejected. No automatic trimming or normalization occurs.
- The result is shown exactly as returned in a read-only text area with a Copy
  button. A static lamp marks the last output letter. If clipboard access is denied,
  select the result and copy it manually. Engine rejections show a translated
  explanation and the engine's original message; other failures have friendly copy.

## Attack page

Use the **Machine / Máquina** and **Attack / Ataque** header buttons to switch
views. The selection is saved in localStorage, independently of the language.
The engine panel and compatibility notice are shared; switching views or languages
keeps both forms and the machine result intact.

- Choose a model, reflector and each slot's wheel, ring and starting position.
  **Unknown / No lo sé** sends JSON `null` for that value. Slots follow catalog
  order, including the Greek wheel on M4. Initially the wheels and A rings are
  known, positions are unknown, and plugboard search is checked. Add known cable
  pairs with the same disjoint-letter editor as the machine page; **Search the
  rest of the plugboard** keeps those pairs fixed and searches the free letters.
- Paste ciphertext exactly as published. Offending characters and their 1-based
  Unicode positions are listed immediately; Start is disabled until they are
  resolved. **Convert to uppercase** changes the text only when pressed. No
  trimming, automatic uppercasing, removal or normalization occurs.
- Changes request a preview after roughly 300 ms, never starting the engine.
  The preview shows grouped outer-key counts and an approximate duration in
  seconds, minutes, hours or days, with warnings above one hour and 24 hours.
  The reference-computer estimate is not a guarantee; the running panel shows
  observed elapsed time. **Distinct wheels (as on the real machine) / Rotores
  distintos (como en la máquina real)** is checked by default. Its `?` explains
  that the real machine had one copy of each wheel, so orders like II-II-IV are
  skipped for a faster search. Toggling it refreshes the count and estimate;
  unchecking also tries repeated wheels, with a visible explanation. Errors show
  translated guidance, server message and field.
- **Advanced** starts collapsed. Except for the explicit method/backend choices, untouched settings are omitted so the server
  supplies the recommended defaults: hill climb; initial `ic`, final
  `sinkov_trigram`; reswapping then measure stages on `sinkov_trigram`; 13 maximum
  pairs, switching 7, backtracking 5, hold 5 and half the logical CPUs. Every
  parameter has a `?` explanation, including the usually unhelpful left-ring
  search and how many best candidates hold retains.
- The method selector offers HC, PE and **Crib attack (bombe) / Ataque con crib**.
  Choosing bombe shows one crib field and an optional 0-based position. The crib follows
  the ciphertext's exact-text rule: it is sent as typed, never uppercased or stripped
  of spaces automatically; an uppercase button appears when it has lowercase letters,
  and offending symbols (spaces included) are listed and block starting. The server
  rejects them with `invalid_settings` at `settings/crib` (position errors at
  `settings/crib_position`). A warning below 14 letters does not block starting. The bombe estimate counts the
  scrambler rows and crib tests per setting; finishing climbs on stops are not included,
  so short cribs with many stops take longer than shown. Choosing bombe sets
  the right ring unknown and every other ring (including M4 Greek) to A; these remain
  editable in Advanced. Loading saved input preserves its ring choices. Choosing
  bombe selects CPU and disables the GPU option; direct GPU API requests are rejected,
  never silently changed to CPU. The summary reports crib text, positions count,
  settings and stops, and every finalist shows its crib position. HC/PE results are unchanged.
- Advanced exposes PE seeds (all or touching chosen letters), initial/final
  scores (`ic`, `entropy`, Sinkov monogram through hexagram, `trie`), optional
  reswapping/measure/dictionary stages and their scores, pair thresholds, hold and
  threads, plus CPU (default) / GPU selection next to threads. GPU alone shows
  **GPU usage (%) / Uso de GPU (%)**, an integer 1–100, default 100. Lower usage
  keeps the screen smoother but takes longer; results do not change. Backend and
  usage persist with the other advanced settings and saved input. Resume uses the
  current form's backend and usage. Unavailable GPUs (`backend_unavailable`) and
  unsupported GPU attacks (`unsupported_job`) show translated guidance and the
  engine's reason; there is no silent CPU fallback. Empty numeric fields use defaults. Each table-based score in use gets
  an absolute own-file path field; bigrams/trigrams have included German 1941
  tables, other Sinkov scores and trie require own files. Hints explain engine
  JSON v1 n-gram/dictionary files and `e2e/recovery/ngrams.py convert` for bomm txt
  n-grams. **Show request JSON** displays the preview request read-only.
- Only **Start attack** posts to `/api/attack`. It is disabled for invalid text,
  preview errors, pending estimates, unavailable engine or an already running
  attack. Opening the page or Attack view fetches the latest attack once. While
  running, the visible Attack view polls every second; switching away or hiding
  the browser tab stops polling. The engine continues independently.
- The last-attack panel shows translated status, outer-key progress with one
  decimal percent, completed evaluations, elapsed HH:MM:SS and extrapolated ETA
  (`--:--:--` until one outer completes). **Cancel** requests a safe stop and
  checkpoint; cancelled/interrupted attacks with a checkpoint offer **Resume**.
  Failures include translated guidance, the engine message and collapsible
  stderr. The report/checkpoint directory is always shown for a saved attack.
  **Load this setup** explicitly fills the form from the saved original input;
  it never starts an attack or overwrites the form automatically.
- UKW-D candidates show their found wiring in both BP and German notation,
  using the engine's winning `configuration.slots[].pairs`. Other machines'
  transform and attack result displays are unchanged.
- Ranked results use `result.hold` (or `best` as fallback), showing measured score
  and measure ID, full reflector/slot key in configuration order, complete
  plugboard and plaintext in blocks of five. Each plaintext has a Copy button.
  Cancelled results are labelled partial. No results are invented before the
  engine supplies them.

All page copy and hints live in `static/i18n/{es,en}.json` with matching keys.
`static/logic.js` contains DOM-free validation, request building and dictionary
lookup with an English fallback. The server embeds only runtime assets; Node test
files, package metadata and Go source are not served.

## Test

From `web/`:

```sh
go vet ./... && go test ./...
gofmt -l .
```

To include real-engine tests (including preview count versus
`started.outers_selected`), build engine 0.3.0 with `cargo build --release`
from the repository root, then run from `web/`:

```sh
ENIGMA_TEST_BIN="$(cd .. && pwd)/target/release/enigma" go test ./...
```

The formatting check should print nothing. HTTP tests use `net/http/httptest` without
opening a browser or network listener. Tests verify every runtime asset's content
type, security headers on success and rejection paths, and dictionary key parity
with no empty translations.

From the repository root, with Node 24 or newer (no npm install):

```sh
node --test web/static/
```

`static/package.json` declares ES modules and points the directory runner at
`logic.test.mjs`; it has no dependencies and is not embedded. The tests cover text
validation, lowercase detection, disjoint plugboard pairs, unmodified request
building for each model, language selection and dictionary fallback. Attack tests
also cover unknown-to-null conversion, changed-only advanced settings, exact text,
saved-input round trips, duration unit boundaries, decimal-string progress and
ETA, hold/best extraction and five-symbol grouping. Browser end-to-end checks are
separate; Node tests need no DOM, browser, framework or packages.

Optional Railway and UKW-D browser smoke (requires Google Chrome at `/usr/bin/google-chrome`):

```sh
# From the repository root, after cargo build --release:
(cd web && go build -o ../target/enigma-web ./cmd/enigma-web)
node web/e2e/wwii.mjs
```

This transforms the independent Railway vector and starts a 26-key attack through
page controls, comparing preview and engine counts. It then enters the L26 Enigma I
UKW-D vector in German notation and compares the web output with the real CLI and
external fixture; runs a small unknown-wiring KD attack to completion; and checks
both result notations, explicit GPU blocking, fixed ETW/reflector controls,
hidden plugboard controls, Spanish rerendering and script/CSP errors. The script
prints and removes its fresh system-temp scratch directory. `ENIGMA_WEB_BIN` and
`ENIGMA_TEST_BIN` can point to temporary web/engine build outputs instead of the
default `target/enigma-web` and `target/release/enigma`.

`e2e/differential.mjs` compares separately built base/current web binaries using
`ENIGMA_BASE_WEB_BIN`, `ENIGMA_WEB_BIN` and `ENIGMA_TEST_BIN`. It checks real-engine
I/M3/M4/Railway/G transform HTTP response bytes (including events, unmodified),
new-field rejections on sibling models, empty stderr and clean server exits.
It does not read Git history; prepare the base checkout/build outside the test.
Both scripts keep config, attack artifacts and Chrome profiles outside the repository.

## Architecture and next steps

- `cmd/enigma-web/`: flags, loopback listener, browser launcher and shutdown.
- `internal/server/`: testable HTTP security boundary and routes.
- `internal/engine/`: bounded version probing, exact compatibility gate and atomic config persistence.
- `static/`: embedded HTML, one stylesheet, ES modules and Spanish/English dictionaries.

The machine page calls the transform endpoint only on explicit start.
The server reads JSONL events from `docs/protocol.md` §4; engine path/version
validation follows §8. The engine stays
in `crates/`; it has no web listener and is never linked into this Go binary.
