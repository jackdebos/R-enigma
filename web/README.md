# enigma-web

Local web interface for the Enigma engine (Stage 2). It is a separate program from the
Rust engine: install the `enigma` CLI first, then run `enigma-web` to open the
interface in your browser. The engine itself has no web code and no listener.

## How it works

- `enigma-web` serves a small page (HTML, CSS and JavaScript embedded in the binary)
  on `127.0.0.1` only and opens it in your browser.
- When you press the start button, it builds a protocol request from the form and runs
  `enigma --events - --request -` as a child process, reading the JSONL events of
  `docs/protocol.md` §4. It never links the engine library.
- You enter the path to your `enigma` executable on the page. `enigma-web` runs
  `enigma --version` and accepts only the engine versions it supports
  (`docs/protocol.md` §8). A newer or older engine requires a matching `enigma-web`.
- The interface is available in Spanish and English.

## Security

The server listens on the loopback address only, requires a random per-run token that
is part of the URL it opens, and rejects requests whose `Host` or `Origin` is not its
own loopback address. Other programs and other computers cannot use it.

## Layout

- `web/` Go module for the `enigma-web` server.
- `web/static/` the embedded page.

Routes, build and test commands are documented here as they are implemented
(`odd/tasks/enigma-web-client.md`).
