# R-enigma

[English](README.md)

Un simulador universal de Enigma y motor de criptoanálisis en Rust, con un
cliente web local en Go. Cada máquina es una configuración sobre un único motor
genérico, y los ataques son deterministas: la misma solicitud da el mismo
resultado con cualquier cantidad de hilos y en CPU o GPU.

## Características

- **Máquinas:** Enigma I, M3, M4, Railway, G-312, G-260, KD, y Enigma I/M3 con el
  reflector recableable UKW-D. Los cableados provienen de fuentes históricas citadas.
- **Ataques:** hill climbing y exhaustión parcial sobre el tablero de conexiones,
  etapas encadenadas de reswapping/medida/diccionario, una lista de mejores claves,
  crib dragging con bombe, y búsqueda del cableado de la UKW-D.
- **Puntuación:** índice de coincidencia, entropía de Shannon, n-gramas de Sinkov y
  diccionarios ponderados, todo en punto fijo exacto.
- **Ejecución:** multihilo, cancelable, con checkpoints y reanudación. Un backend GPU
  opcional (wgpu) da exactamente los mismos resultados que la CPU.
- **Cliente web:** una página local bilingüe (inglés/español) para cifrar y atacar,
  sin frameworks ni paso de compilación del frontend.

## Inicio rápido

Requiere Rust 1.97 o superior, y Go 1.24 o superior para el cliente web.

```sh
cargo install --path crates/enigma-cli   # instala el comando `enigma`
```

Guardá esta solicitud como `request.json`:

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
enigma --no-report request.json   # imprime BDZGO
enigma --help                     # hilos, backend GPU, checkpoints, eventos
```

Cliente web:

```sh
cd web
go build -o enigma-web ./cmd/enigma-web
./enigma-web   # abre la página; indicale la ruta absoluta de `enigma`
```

## Documentación

La documentación técnica está en inglés.

| Documento | Contenido |
| --- | --- |
| [docs/protocol.md](docs/protocol.md) | Solicitudes, eventos, CLI, checkpoints: el contrato del motor |
| [docs/search-passes.md](docs/search-passes.md) | Ataques al tablero, etapas encadenadas, lista de claves, búsqueda UKW-D |
| [docs/crib-attack.md](docs/crib-attack.md) | Crib dragging y la bombe |
| [docs/scoring-resources.md](docs/scoring-resources.md) | Medidas de puntuación y archivos externos de n-gramas/diccionarios |
| [docs/historical-catalog.md](docs/historical-catalog.md) | Máquinas incluidas y sus fuentes |
| [web/README.md](web/README.md) | Cliente web |
| [crates/enigma-gpu/README.md](crates/enigma-gpu/README.md) | Backend GPU |
| [e2e/](e2e/) | Comparaciones contra bomm y benchmark de recuperación |

## Tests

```sh
cargo test --workspace
cd web && go test ./...
```

## Créditos

- [bomm](https://github.com/ffraenz/bomm), de Fränz Friederes (MIT), es la
  referencia diferencial de este motor y la fuente de sus tablas de frecuencias
  de 1941 incluidas.
- Esas tablas derivan de descifrados de mensajes Enigma de 1941 publicados por
  Frode Weierud, [CryptoCellar](https://cryptocellar.org/bgac/keyofE.html).
- Los cableados y vectores de referencia provienen de Crypto Museum, el Universal
  Enigma de Daniel Palloks y otras fuentes citadas en
  [docs/historical-catalog.md](docs/historical-catalog.md).

## Licencia

[MIT](LICENSE). Los datos de terceros conservan sus propios términos; ver
[web/internal/tables/NOTICE.md](web/internal/tables/NOTICE.md).
