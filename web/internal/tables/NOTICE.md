# Built-in scoring tables

`enigma1941-bigram.json` and `enigma1941-trigram.json` are the bomm frequency tables
`e2e/bomm/frequencies/enigma1941-{bigram,trigram}.txt` (byte-for-byte copies of
`data/frequencies/` in bomm commit `aeb2f2bf00dfdee68e972f90ae7e83b387b188e9`,
https://github.com/ffraenz/bomm), converted to the engine JSON v1 n-gram format.
bomm's README credits raw 1941 Enigma message decrypt tables published by Frode
Weierud, CryptoCellar (https://cryptocellar.org/bgac/keyofE.html); no separate data
licence is stated. bomm is distributed under the MIT License below.

Regenerate from the repository root (then write each file compact, with no
whitespace and one final newline):

```sh
python3 e2e/recovery/ngrams.py convert e2e/bomm/frequencies/enigma1941-bigram.txt --order 2 --json-out <dir>/enigma1941-bigram.json
python3 e2e/recovery/ngrams.py convert e2e/bomm/frequencies/enigma1941-trigram.txt --order 3 --json-out <dir>/enigma1941-trigram.json
```

| File | SHA-256 |
| --- | --- |
| `enigma1941-bigram.json` | `873e29907b9112513856f4b0c6ce8180ac1001df8b108b4bdb0194fe1013655d` |
| `enigma1941-trigram.json` | `0a2706c75bb3b3696bd1af96a1971bf6186e37c0be20c645398c6faeeb4db132` |

## bomm licence

```text
MIT License

Copyright (c) 2023 Fränz Friederes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
