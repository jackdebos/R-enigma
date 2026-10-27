# Historical Enigma catalog evidence

This note separates historical claims from the catalog's JSON representation. Bundled
catalog entries are key-free structural definitions, not daily keys or operational
instructions. No rotor order, displayed position, ring setting, plugboard, or active key
is supplied by a definition.

## Sources

- David Hamer, “Enigma Rotor Wiring” and displayed turnover table:
  <https://enigmamuseum.com/rotwirg.htm>. Used for the A–Z rotor/reflector wiring
  tables, the listed turnover letters (including two positions for VI–VIII), Beta and
  Gamma wiring, and UKW B/C and UKW Thin-B/Thin-C wiring. Gamma is copied from Hamer's
  table as `FSOKANUERHMBTIYCWLQPZXVGJD`; a conflicting search-result snippet is not used.
- Crypto Museum, [Enigma I](https://www.cryptomuseum.com/crypto/enigma/i/): the rotor
  selection discussion (three rotors selected from I–V after 1938), UKW B/C options,
  and the entry wheel's alphabet wiring.
- Crypto Museum, [Enigma M3](https://www.cryptomuseum.com/crypto/enigma/m3/): the rotor
  selection discussion (three from I–VIII), UKW B/C options, and identity entry-wheel
  alphabet.
- Crypto Museum, [Enigma M4](https://www.cryptomuseum.com/crypto/enigma/m4/): the
  three moving wheels selected from I–VIII, Greek Beta/Gamma wheel position at the
  left of them, its non-moving and non-interchangeable relationship to the moving
  wheels, and UKW Thin-B/Thin-C options; the entry-wheel alphabet is identity.
- Crypto Museum, [How Enigma works](https://www.cryptomuseum.com/crypto/enigma/working.htm):
  rotor movement occurs before the electrical path; the fast wheel steps on every
  keypress, the middle wheel double-steps at its turnover, and the left wheel advances
  when the middle wheel is at turnover.

The sources above establish component facts and mechanical behavior. The slot IDs,
allowed-wheel arrays, and declarative rule encoding below are this project's
representation of those facts, not historical labels or a claim that a period operator
used every structurally representable combination. The NSA catalog PDF was not fetched
because of its size limit and is not cited as supporting evidence.

## Catalog mappings

- `enigma-i` contains rotors I–V and UKW B/C. The three rotor slots accept I–V;
  the reflector slot accepts B/C. This represents the Crypto Museum Enigma I rotor and
  reflector choices without imposing operational restrictions on an order.
- `enigma-m3` contains rotors I–VIII and UKW B/C. Its three moving slots accept I–VIII;
  the reflector accepts B/C.
- `enigma-i-ukwd` retains Enigma I's I–V rotors and stepping, replacing B/C
  with the rewirable UKW-D (`D`); CM-D documents Luftwaffe use from January 1944.
- `enigma-m3-ukwd` retains M3's I–VIII rotors and stepping, replacing B/C
  with UKW-D (`D`), as documented by CM-D. It also represents M4 in M3 mode:
  UKW-D replaces both UKW-B and the Greek wheel, so there is no Greek slot.
  Both entries use BP contact notation with `BO` permanently wired and require
  exactly 12 free pairs in the transform key. The historical reflector setting is
  position A, ring A; other settings are representable but non-historical.
  For German-sheet conversion see **UKW-D facts** below. The original I/M3
  catalog bytes are unchanged. UKW-D search remains pending (T10/T11).
- `enigma-m4` contains rotors I–VIII, Beta/Gamma, and UKW Thin-B/Thin-C. Its moving
  slots accept I–VIII; a separate fixed `role: "rotor"` Greek slot admits Beta/Gamma
  and is not treated as an entry wheel. The leftmost reflector admits only Thin-B/C.
  Beta/Gamma are modeled as fixed and have no turnover positions.
- `enigma-railway`, `enigma-g312`, and `enigma-g260` each contain I/II/III,
  UKW and ETW. Their left-to-right slots are `reflector`, `left`, `middle`,
  `right`, `etw`; each moving rotor slot accepts I/II/III. The rightmost ETW is
  a fixed `role: "rotor"` slot with structural wheel `ETW`, using the inverse
  QWERTZ keyboard-to-rotor map below. Configure its position and ring as A/A;
  other representable settings are non-historical. The reflector admits UKW and
  has settable position and ring: it is fixed in Railway but movable in both G
  entries. Railway uses military double stepping; G uses the nested pre-step
  carry rules below, including reflector motion and no double step. No active
  position or ring is supplied by these definitions. `enigma-g228` is deferred
  because its published rotor-II wiring is invalid and its attribution disputed;
  no corrected wiring is guessed. See **WWII additions** for sources and vectors.
- In the existing I/M3/M4 definitions, the entry/ETW wheel is not represented as a slot. Although the cited sources identify
  its alphabet wiring (identity for M3/M4), this engine's generic slot traversal would
  treat a slot as a position/ring-configurable wheel; using a slot for the ETW would
  therefore need additional traversal semantics to guarantee a fixed identity mapping.
  Omitting the separate ETW slot is a representation boundary, not a claim that the
  physical machine lacked one.
- The triple-rotor stepping rules encode the sourced mechanism with simultaneous
  pre-keypress conditions: the right slot always advances; the middle advances when
  either the right wheel is at turnover or the middle wheel is at turnover; the left
  advances at middle-wheel turnover. Unioning those targets makes the middle advance
  only once when both conditions hold, matching the double-step behavior. M4's fixed
  Greek wheel is excluded from all advance targets.
- None of the definitions applies naval daily-key, wheel-order, or other operational
  restrictions. The definitions express component admissibility and mechanics, not a
  historical operational key.

## Exact sourced wiring details used

The I/M3/M4 JSON files use the A–Z order and wire permutations as printed in Hamer's rotor
wiring table. Turnover positions are the displayed letters in Hamer's turnover table:
I Q, II E, III V, IV J, V Z, and VI–VIII Z and M. The M4 Greek wiring strings are
Beta `LEYJVCNIXWPBQMDRTAKZGFUHOS` and Gamma
`FSOKANUERHMBTIYCWLQPZXVGJD`, copied from that same table. The reflector permutations
are the listed UKW B/C and Thin-B/Thin-C table entries. The catalog parser validates
these JSON definitions using the same strict schema and structural checks as custom
embedded definitions; their bundled status does not bypass validation.

## WWII additions

Railway, G-312 and G-260 are bundled as of engine 0.3.0. KD remains planned
for T12, after UKW-D support; its data below is evidence, not a bundled entry.
This section covers S5/S6/S9; the
ETW and G stepping representation follows S7/S8. The fixture contains external
ciphertexts, not output of this repository's engine. G-228 remains blocked by an
invalid sourced rotor-II permutation; do not manufacture a corrected wiring.

### Sources and reconciliation status

The source labels below are URLs, not claims that all authors independently
measured a machine. Crypto Museum and Toledo share some upstream researchers
(Reuvers, Hamer, Weierud); two publications agreeing is not two independent
physical measurements. Palloks is an independent implementation, not independent
archival confirmation of each wiring.

- **CM-W**: Crypto Museum, [wiring tables](https://www.cryptomuseum.com/crypto/enigma/wiring.htm),
  sections G-228, G-260, G-312, KD, Railway and technical drawings.
- **CM-G**: [Enigma G](https://www.cryptomuseum.com/crypto/enigma/g/index.htm),
  cogwheel mechanism, driven reflector and network-specific wiring tables.
- **CM-R**: [Railway](https://www.cryptomuseum.com/crypto/enigma/k/railway.htm),
  recovered versus original wiring, K438 measurement and non-moving reflector.
- **CM-KD**: [KD](https://www.cryptomuseum.com/crypto/enigma/k/kd.htm),
  FRA machine, nine notches, UKW-D and Mil Amt uncertainty.
- **CM-D**: [UKW-D](https://www.cryptomuseum.com/crypto/enigma/ukwd/index.htm),
  rewiring, fixed contacts and German/BP notation.
- **Toledo**: CJ Odenthal, [configuration tables](https://www.math.utoledo.edu/~codenth/Cryptanalysis/python/enigma/enigma_configs.py)
  and [simulator](https://www.math.utoledo.edu/~codenth/Cryptanalysis/python/enigma/enigma.py).
  G-312 cites Hamer's measurement on 20 October 1998, supplied 16 May 2004;
  G-260 cites Reuvers and Weierud; Railway cites CSG's 2004 simulator.
- **Palloks**: Daniel Palloks, [Universal Enigma v2.6.2](https://people.physik.hu-berlin.de/~palloks/js/enigma/enigma-u_v262_en.html),
  inline `walze[]`, `ukw[]`, presets and cipher/stepping functions.

| Entry | Source status | Resolution for this feature |
|---|---|---|
| Railway | CM-W + Toledo agree on the S6 strings and N/E/Y; Palloks preset 10 agrees | Use that explicitly identified BP-equivalent parameterization, not Palloks preset 11 (original wiring) |
| G-312 | CM-W/CM-G + Toledo agree; Palloks preset 17 agrees on equipment | Dual-publication wiring agreement; simulator stepping disagreement below |
| G-260 | CM-W/CM-G + Toledo agree; Palloks preset 16 agrees on equipment | Dual-publication wiring agreement; simulator stepping disagreement below |
| G-228 (Green/Grün) | CM-W/CM-G only; absent from Toledo and Palloks presets | Single historical source; III confirmed in both CM table and drawing index, but II is invalid as printed |
| KD (FRA) | CM-W/CM-KD only historically; absent from Toledo; Palloks preset 13 reproduces it | Single historical source, not independently confirmed Mil Amt wiring |
| UKW-D | CM-D + CM-KD/CM-W; Palloks independently implements contact conversion | Same publisher for historical claims; simulator agreement does not establish independent archival provenance |

### Exact wiring strings and conventions

Each rotor string maps right-side A–Z input contacts to left-side output contacts.
Reflector strings are full A–Z involutions. All five machines have no plugboard.
Their shared sourced ETW string is `QWERTZUIOASDFGHJKPYXCVBNML`.
**Its direction is opposite the keyboard-to-rotor mapping**: keyboard A enters
contact J, not Q. On entry use its inverse
`JWULCMNOHPQZYXIRADKEGVBTSF`; on exit use QWERTZ. Toledo explicitly uses
`~Permutation("QWERTZUIOASDFGHJKPYXCVBNML")`; Palloks `etq` is the inverse.
The bundled rightmost ETW rotor slot uses that inverse as its forward map:
the engine traverses it forward on entry and in reverse on exit. Historical ETW position/ring
are A/A; other representable settings are non-historical. I/M3/M4 are unchanged.

Turnovers below are **displayed pre-step letters**, not the physical notch
column and not the next displayed letter. This matches the existing catalog.
Rings do not shift these displayed turnover sets. I/II/III identify wheel
numbers, never fixed left/middle/right slots; vector orders are left to right.

| Machine | Wheel | Wiring | Displayed turnover |
|---|---|---|---|
| Railway | I | `JGDQOXUSCAMIFRVTPNEWKBLZYH` | `N` |
| Railway | II | `NTZPSFBOKMWRCJDIVLAEYUXHGQ` | `E` |
| Railway | III | `JVIUBHTCDYAKEQZPOSGXNRMWFL` | `Y` |
| Railway | UKW | `QYHOGNECVPUZTFDJAXWMKISRBL` | none |
| G-312 | I | `DMTWSILRUYQNKFEJCAZBPGXOHV` | `SUVWZABCEFGIKLOPQ` |
| G-312 | II | `HQZGPJTMOBLNCIFDYAWVEUSRKX` | `STVYZACDFGHKMNQ` |
| G-312 | III | `UQNTLSZFMREHDPXKIBVYGJCWOA` | `UWXAEFHKMNR` |
| G-312 | UKW | `RULQMZJSYGOCETKWDAHNBXPVIF` | none |
| G-260 | I | `RCSPBLKQAUMHWYTIFZVGOJNEXD` | `SUVWZABCEFGIKLOPQ` |
| G-260 | II | `WCMIBVPJXAROSGNDLZKEYHUFQT` | `STVYZACDFGHKMNQ` |
| G-260 | III | `FVDHZELSQMAXOKYIWPGCBUJTNR` | `UWXAEFHKMNR` |
| G-260 | UKW | `IMETCGFRAYSQBZXWLHKDVUPOJN` | none |
| G-228 | I | `JDZLYKXVOUCMRAGTSBIWQHPENF` | `SUVWZABCEFGIKLOPQ` |
| G-228 | II (invalid source) | `SKQXFDVNGMUETJBRZLAHYWIODP` | `STVYZACDFGHKMNQ` |
| G-228 | III | `GRMKJBSAIXHWDQUYOEZVPNLFCT` | `UWXAEFHKMNR` |
| G-228 | UKW | `RULQMZJSYGOCETKWDAHNBXPVIF` | none |
| KD | I | `VEZIOJCXKYDUNTWAPLQGBHSFMR` | `SUYAEHLNQ` |
| KD | II | `HGRBSJZETDLVPMQYCXAOKINFUW` | `SUYAEHLNQ` |
| KD | III | `NWLHXGRBYOJSAZDVTPKFQMEUIC` | `SUYAEHLNQ` |
| KD | UKW-D (one FRA setting, BP notation) | `KOTVPNLMJIAGHFBEWYXCZDQSRU` | none |

**G-228 discrepancy:** CM-W's G-228 table, CM-G's corresponding table and
CM-W's drawing index Ch.15 Tz 125c all print III as
`GRMKJBSAIXHWDQUYOEZVPNLFCT`. The drawing index attributes I/II/III to
Ch.15 Tz 125a/b/c (1939) and the Green reflector to Ch.15 Tz 115 (1936).
This checks the published transcription/index, not an independently inspected
original drawing. More importantly, II in the table and Ch.15 Tz 125b index
has D twice and no C (26 characters, only 25 distinct contacts). Toledo's
permutation validator rejects it. No G-228 vector is claimed and no correction
is guessed. The attribution itself is also contested: Weierud's
[overview of Enigma G wiring data](https://cryptocellar.org/enigma/e-prod-history/overview-of-enigma-g.pdf)
lists "G 227 – G 228 — Germany, OKW/Ag WNV/Fu II b, special wiring GD,
(10.07.1943)", and GD as UKW Ch 15 Tz 115 with I–III Ch 15 Tz 123 a–c, not
Tz 125. G-228 is deferred until corrected primary evidence exists.

**Railway caveat:** CM-W labels its S6 table original, while Palloks labels the
same electrical strings BP wiring without correction (preset 10); preset 11
uses `EVLPKUDJHTGSZFRABWYICOXNMQ`, `HXMQKGJTSCZFLBERNAWYIDOVPU`,
`JHDBSKYPZNMVXURECLIGQOAWTF`, UKW `DNSAJQIPGEXRWBVHFLCZYOMKUT`
and Y/E/N. Do not mix those keys with the fixture. CM-R records original wiring
measured from K438 in 2023. CM-W explains BP-recovered and original wiring are
equivalent with appropriate ring adjustments, and I/III turnover differences
arose from BP misidentification, not German swapping of alphabet rings;
see Philip Marks, Cryptologia 39 (2015), issue 1. The fixture deliberately pins
S6/Toledo/Palloks-10 conventions; it is not a recovered historical daily key.
Railway has standard military double stepping and a settable, ring-adjustable,
non-moving reflector. CM-R explicitly rejects Friedman's moving-UKW claim.

**G mechanics:** CM-G describes cogwheel stepping “like the odometer of a car”,
“No double-stepping anomaly”, and a driven UKW that moves during encipherment.
The wheel notch counts are 17/15/11 for I/II/III. Both rotor rings and reflector
ring/position are settable; Toledo explicitly says “Settable UKW, UKW also has
ring setting” and “UKW also rotates”. The S8 encoding evaluates all turnovers
before motion: right always, middle iff right at turnover, left iff right AND
middle, reflector iff right AND middle AND left. A middle notch alone cannot
advance the left wheel. Palloks `engage_gear` implements this nested carry.

**KD caveat (verbatim, CM-KD):**
> This wiring might be identical to the first three rotors of the Enigma KD used by Mil Amt during WWII, but this is currently uncertain.

KD has standard Enigma stepping, nine turnovers per wheel and UKW-D; Mil Amt
had six rotors, only these three are documented. The FRA UKW wiring is one
explicit key, not a fixed KD structural reflector. In the simulator KD's UKW-D
is fixed at A/A, not ring/position adjustable.

**UKW-D facts:** CM-D documents 12 patch cables with BP `BO` permanently wired;
the German index omits J and Y. Against BP `ABCDEFGHIJKLMNOPQRSTUVWXYZ`, the
German contact labels are `A-ZXWVUTSRQPON-MLKIHGFEDCB` (hyphens are the fixed
contacts, not free letters). German labeling runs counterclockwise, BP clockwise.
To convert a German key sheet, replace each endpoint by the BP letter at the
same index in these two strings, then supply the 12 converted free pairs;
the two hyphens correspond to the permanent BP `BO` pair and are not supplied.
The engine accepts BP symbols only; it does not silently convert German labels.
CM-D describes Luftwaffe Enigma I use from 1 January 1944, M3/M4 variants (in
M4 replacing UKW-B plus Beta), and KD. Luftwaffe rewiring was every 7–12 days;
CM-KD says Mil Amt changed rotor order/rings daily and Grundstellung, **probably
also** UKW-D wiring, every three weeks. Preserve that qualification.

### Independent vectors and reproduction

`crates/enigma-cli/tests/fixtures/wwii_reference_vectors.json` is an array of
four vectors. Every vector records the complete key, plaintext, Palloks
ciphertext, Toledo ciphertext, agreement flag and provenance. All use wheel
order III–II–I, rings F/C/P, and 114 letters of normalized German text (spaces
removed, X separator); none is a historical intercept. G-228 is intentionally
absent, not silently substituted with another network's wiring.

| Machine | UKW ring/position | Rotor start L/M/R | External result |
|---|---|---|---|
| Railway | D/J | K/D/M | Toledo and Palloks agree |
| G-312 | D/J | U/S/A | Palloks reference; Toledo disagrees |
| G-260 | D/J | U/S/A | Palloks reference; Toledo disagrees |
| KD | A/A, fixed | K/Q/S | Both agree; Toledo custom configuration |

Railway's first three post-step states (UKW,L,M,R) are `JKDN`, `JKEO`,
`JLFP`: the middle wheel steps twice consecutively. G begins `KVTB`, `KWUC`,
`KWVD`, `KWVE` in Palloks: the first key advances the reflector J→K and the
long text encounters multiple notches. Toledo instead gives `KVTB`, `KWUC`,
`LWVD`, `LXVE`. Its `__step1` uses independently tested `turnSets/holdSets`
rather than nested carries: at the third key it advances UKW even though the
left wheel III's displayed W is not a turnover. Neither simulator was changed
to force agreement. Palloks matches the sourced cog mechanism and S8; Toledo
is **not** a second confirming G oracle. Both alternate ciphertexts are retained.

Notation mapping:

- Fixture rotor arrays and Toledo wheel strings run slow-to-fast (left-to-right).
  Toledo's four-character ring/key strings prepend UKW; D/F/C/P and J/U/S/A
  therefore mean `DFCP` and `JUSA`. A=0 internally; rings A=01, B=02, etc.
- Palloks wheel indices 1/2/3 mean right/middle/left, **not historical wheel
  numbers**. The harness reverses fixture arrays, uses 0 for UKW, and converts
  rings to zero-based offsets. Displayed positions remain A–Z; electrical
  displacement is position minus ring, including UKW. ETW is inverse-QWERTZ
  on entry in both simulators; its fixture ring/position stay A/A.
- Palloks uses walze 26–28 / UKW 13 for Railway (preset 10), 52–54 / UKW 9
  for G-312, 49–51 / UKW 11 for G-260, and 40–42 for KD. KD receives the
  full FRA BP involution directly; no German-label string is mistaken for a
  BP permutation. Toledo has no KD preset, so its unchanged public simulator
  receives the documented rotors/turnovers, inverse ETW and fixed FRA UKW.
- G-228 was attempted as a custom Toledo configuration and rejected before
  encryption. A simulator accepting the non-bijective II string would not
  constitute valid independent evidence.

Downloads live only in ignored `target/wwii-ref/dl/`; reproducibility tools live
in `target/wwii-ref/tools/`. No downloaded program is run in `dl/`. `prepare.py`
ports Toledo's Python-2 syntax, eager map/range, types aliases, reduce import
and integer division without changing cipher logic. No lib2to3 is available
on this Python 3.13 host, so the compatibility conversions are explicit.
It extracts only named Palloks cipher/stepping helpers; `effRot` loses its
DOM-only status-display assignment. The JS harness supplies state, not stepping
or enciphering logic. The extracted code retains Palloks attribution and terms.

Run from the repository root (Python isolated mode; no bytecode caches):

```sh
python3 -I -B target/wwii-ref/tools/prepare.py target/wwii-ref/dl target/wwii-ref/tools
python3 -I -B target/wwii-ref/tools/seed.py target/wwii-ref/keys.json
python3 -I -B target/wwii-ref/tools/toledo.py target/wwii-ref/tools target/wwii-ref/keys.json
node target/wwii-ref/tools/palloks.js target/wwii-ref/tools/palloks-core.js target/wwii-ref/dl/page.html target/wwii-ref/keys.json
```

The seed contains only keys and documented custom equipment, never ciphertext.
Both runners return ciphertext plus per-letter position traces. Repeat each
runner twice and compare its outputs byte-for-byte; compare ciphertexts between
implementations separately (G disagreements are expected and documented).
Source reconciliation and fixture collection are passive documentation/data work;
the bundled catalog behavior is separately covered by core and CLI vector tests.
