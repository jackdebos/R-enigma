#!/usr/bin/env python3
"""Standalone recovery-benchmark n-gram builder (Python 3, standard library)."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import string
import sys
import unicodedata

DIGITS = ("NULL", "EINS", "ZWO", "DREI", "VIER", "FUENF", "SECHS", "SIEBEN", "ACHT", "NEUN")
UMLAUTS = str.maketrans({"Ä": "AE", "Ö": "OE", "Ü": "UE", "ẞ": "SS"})
MAX_COUNT = 2**64 - 1


def militarize(text):
    """Fold German/Latin letters and turn non-letter runs into word boundaries."""
    # Compose first so decomposed umlauts retain German AE/OE/UE spelling.
    text = unicodedata.normalize("NFC", text).upper().translate(UMLAUTS)
    text = unicodedata.normalize("NFKD", text)
    pieces = []
    for char in text:
        if unicodedata.category(char).startswith("M"):
            continue
        if "A" <= char <= "Z":
            pieces.append(char)
        elif "0" <= char <= "9":
            pieces.append(" " + DIGITS[int(char)] + " ")
        else:
            pieces.append(" ")
    return "X".join("".join(pieces).split())


def count_grams(text, order):
    counts = Counter(text[index:index + order] for index in range(len(text) - order + 1))
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def bomm_text(entries):
    width = max((len(str(count)) for _, count in entries), default=1)
    return "".join(f"{gram.lower()}  {count:>{width}}\n" for gram, count in entries)


def resource_json(entries, order):
    return json.dumps({
        "resource_version": 1,
        "kind": "ngram",
        "alphabet": list(string.ascii_uppercase),
        "order": order,
        "entries": [{"gram": list(gram.upper()), "count": count} for gram, count in entries],
    }, indent=2) + "\n"


def parse_bomm(text, order, source):
    """Validate bomm records; preserve their order as the CLI fixture adapter does."""
    entries = []
    seen = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        context = f"{source}: line {line_number}"
        fields = line.split()
        if len(fields) != 2:
            raise ValueError(f"{context}: expected a gram and count")
        gram, raw_count = fields
        if not re.fullmatch(rf"[a-z]{{{order}}}", gram):
            raise ValueError(f"{context}: expected exactly {order} lowercase ASCII letters")
        if gram in seen:
            raise ValueError(f"{context}: duplicate gram: {gram}")
        # Strip leading zeros before conversion to avoid Python's int-string limit.
        digits = raw_count.lstrip("0") or "0"
        if (not re.fullmatch(r"[0-9]+", raw_count) or len(digits) > 20
                or not 0 < int(digits) <= MAX_COUNT):
            raise ValueError(f"{context}: count must be a positive u64 decimal integer")
        seen.add(gram)
        entries.append((gram, int(digits)))
    return entries


def read_input(name):
    return sys.stdin.read() if name == "-" else Path(name).read_text(encoding="utf-8")


def write_outputs(outputs, force, inputs):
    """Preflight all paths before creating any output, including with --force."""
    seen = set()
    input_paths = [Path(name) for name in inputs if name != "-"]
    for path, _ in outputs:
        resolved = path.resolve()
        if resolved in seen:
            raise ValueError(f"duplicate output path: {path}")
        # Compare file identity, not names: hard links share one inode.
        if path.exists() and any(path.samefile(source) for source in input_paths):
            raise ValueError(f"output would replace input: {path}")
        seen.add(resolved)
        if (path.exists() or path.is_symlink()) and not force:
            raise ValueError(f"output exists (use --force): {path}")
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f"output must be a regular file: {path}")
        if not path.parent.is_dir():
            raise ValueError(f"output directory does not exist: {path.parent}")
    for path, content in outputs:
        # Exclusive create also protects against a new file racing the preflight.
        with path.open("w" if force else "x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    modes = cli.add_subparsers(dest="mode", required=True)
    build = modes.add_parser("build", help="militarize UTF-8 text and count overlapping n-grams")
    build.add_argument("inputs", nargs="*", metavar="FILE", help="UTF-8 files, in order; default: stdin (-)")
    build.add_argument("--bomm-out", type=Path, help="write lowercase grams and aligned counts")
    build.add_argument("--json-out", type=Path, help="write engine JSON v1 resource")
    build.add_argument("--text-out", type=Path, help="write militarized text with a final newline")
    build.add_argument("--print-text", action="store_true", help="also print militarized text to stdout")
    convert = modes.add_parser("convert", help="convert an existing bomm txt table to engine JSON v1")
    convert.add_argument("input", nargs="?", default="-", metavar="FILE", help="bomm txt table; default: stdin (-)")
    convert.add_argument("--json-out", type=Path, required=True, help="write engine JSON v1 resource")
    for mode in (build, convert):
        mode.add_argument("--order", type=int, choices=range(1, 7), required=True, help="n-gram length (1..6)")
        mode.add_argument("--force", action="store_true", help="allow replacing existing output files (never inputs)")
    return cli


def main():
    args = parser().parse_args()
    try:
        outputs = []
        if args.mode == "build":
            if not (args.bomm_out or args.json_out or args.text_out or args.print_text):
                raise ValueError("choose --bomm-out, --json-out, --text-out or --print-text")
            inputs = args.inputs or ["-"]
            if inputs.count("-") > 1:
                raise ValueError("stdin (-) may appear only once")
            # File boundaries are separators too; n-grams span the resulting X.
            stream = militarize("\n".join(read_input(name) for name in inputs))
            entries = count_grams(stream, args.order)
            if args.bomm_out:
                outputs.append((args.bomm_out, bomm_text(entries)))
            if args.text_out:
                outputs.append((args.text_out, stream + "\n"))
        else:
            inputs = [args.input]
            source = "stdin" if args.input == "-" else args.input
            entries = parse_bomm(read_input(args.input), args.order, source)
        if args.json_out:
            outputs.append((args.json_out, resource_json(entries, args.order)))
        write_outputs(outputs, args.force, inputs)
        if args.mode == "build" and args.print_text:
            print(stream)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
