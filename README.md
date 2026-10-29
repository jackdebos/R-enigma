# R-enigma

[Español](README.es.md)

A universal Enigma simulator and cryptanalysis engine in Rust, with a local web
client in Go. Every machine is configuration data over one generic engine, and
attacks are deterministic: the same request gives the same result for any thread
count and on CPU or GPU.

## Features

- **Machines:** Enigma I, M3, M4, Railway, G-312, G-260, KD, and Enigma I/M3 with
  the rewirable UKW-D reflector. Wirings come from cited historical sources.
- **Attacks:** hill climbing and partial exhaustion over the plugboard, chained
  reswapping/measure/dictionary stages, a hold list of best keys, crib dragging with
  a bombe, and UKW-D wiring search.
- **Scoring:** index of coincidence, Shannon entropy, Sinkov n-grams and weighted
  dictionaries, all in exact fixed point.
- **Runs:** multithreaded, cancellable, with checkpoints and resume. An optional
  GPU backend (wgpu) gives exactly the same results as the CPU.
- **Web client:** a bilingual (English/Spanish) local page for transforms and
  attacks, with no framework or build step.

## Quick start

Requires Rust 1.97 or newer, and Go 1.24 or newer for the web client.

```sh
cargo install --path crates/enigma-cli   # installs the `enigma` command
```

Save this request as `request.json`:

```json
{
  "protocol_version": 1,
  "machine": {"definition": {"kind": "bundled", "id": "enigma-i"}},
  "job": {
    "kind": "transform",
    "configuration": {
      "slots": [
        {"id": "reflector", "wheel": "B", "position": "A", "ring": "A"},
        {"id": "left", "wheel": "I", "position": "A", "ring": "A"},
        {"id": "middle", "wheel": "II", "position": "A", "ring": "A"},
        {"id": "right", "wheel": "III", "position": "A", "ring": "A"}
      ],
      "plugboard": []
    },
    "text": "AAAAA",
    "direction": "encrypt"
  }
}
```

```sh
enigma --no-report request.json   # prints BDZGO
enigma --help                     # threads, GPU backend, checkpoints, events
```

Web client:

```sh
cd web
go build -o enigma-web ./cmd/enigma-web
./enigma-web   # opens the page; point it at the absolute path of `enigma`
```

## Documentation

| Document | Contents |
| --- | --- |
| [docs/protocol.md](docs/protocol.md) | Requests, events, CLI, checkpoints: the engine contract |
| [docs/search-passes.md](docs/search-passes.md) | Plugboard attacks, chained stages, hold list, UKW-D search |
| [docs/crib-attack.md](docs/crib-attack.md) | Crib dragging and the bombe |
| [docs/scoring-resources.md](docs/scoring-resources.md) | Scoring measures and external n-gram/dictionary files |
| [docs/historical-catalog.md](docs/historical-catalog.md) | Bundled machines and their sources |
| [web/README.md](web/README.md) | Web client |
| [crates/enigma-gpu/README.md](crates/enigma-gpu/README.md) | GPU backend |
| [e2e/](e2e/) | Parity checks against bomm and the recovery benchmark |

## Tests

```sh
cargo test --workspace
cd web && go test ./...
```

## Credits

- Developed with [Gentle Shell](https://github.com/Gentleman-Programming/gentle-shell).
  Thanks to [Gentleman Programming](https://gentlemanprogramming.com/) (Alan Buscaglia)
  and its community of contributors.
- [bomm](https://github.com/ffraenz/bomm) by Fränz Friederes (MIT) is the
  differential reference for this engine and the source of its built-in 1941
  frequency tables.
- Those tables derive from 1941 Enigma message decrypts published by Frode Weierud,
  [CryptoCellar](https://cryptocellar.org/bgac/keyofE.html). Thanks to Frode Weierud
  for granting permission to use these tables.
- Machine wirings and reference vectors come from Crypto Museum, Daniel Palloks'
  Universal Enigma and other sources cited in
  [docs/historical-catalog.md](docs/historical-catalog.md).

## License

[MIT](LICENSE). Third-party data keeps its own terms; see
[web/internal/tables/NOTICE.md](web/internal/tables/NOTICE.md).
