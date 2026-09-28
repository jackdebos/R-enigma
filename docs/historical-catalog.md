# Historical Enigma catalog evidence

This note separates historical claims from the catalog's JSON representation. The three
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
- `enigma-m4` contains rotors I–VIII, Beta/Gamma, and UKW Thin-B/Thin-C. Its moving
  slots accept I–VIII; a separate fixed `role: "rotor"` Greek slot admits Beta/Gamma
  and is not treated as an entry wheel. The leftmost reflector admits only Thin-B/C.
  Beta/Gamma are modeled as fixed and have no turnover positions.
- The entry/ETW wheel is not represented as a slot. Although the cited sources identify
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

The JSON files use the A–Z order and wire permutations as printed in Hamer's rotor
wiring table. Turnover positions are the displayed letters in Hamer's turnover table:
I Q, II E, III V, IV J, V Z, and VI–VIII Z and M. The M4 Greek wiring strings are
Beta `LEYJVCNIXWPBQMDRTAKZGFUHOS` and Gamma
`FSOKANUERHMBTIYCWLQPZXVGJD`, copied from that same table. The reflector permutations
are the listed UKW B/C and Thin-B/Thin-C table entries. The catalog parser validates
these JSON definitions using the same strict schema and structural checks as custom
embedded definitions; their bundled status does not bypass validation.
