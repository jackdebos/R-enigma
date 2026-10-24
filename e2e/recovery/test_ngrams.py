"""Public-CLI tests; all generated data lives in temporary directories."""

import json
from pathlib import Path
import string
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("ngrams.py")
REFERENCE = SCRIPT.parent.parent / "bomm/frequencies/enigma1941-trigram.txt"


class NgramsCLI(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="enigma-ngrams-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def run_cli(self, *args, text=""):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *map(str, args)],
            input=text, text=True, encoding="utf-8", capture_output=True,
        )

    def success(self, result, stdout=""):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, stdout)
        self.assertEqual(result.stderr, "")

    def test_militarization(self):
        cases = [
            ("Größe 12, Übung.", "GROESSEXEINSXZWOXUEBUNG"),
            (" äöü ÄÖÜ ßẞ!", "AEOEUEXAEOEUEXSSSS"),
            ("Café, naïve\n déjà-vu!", "CAFEXNAIVEXDEJAXVU"),
            ("Cafe\u0301 a\u0308 O\u0308 u\u0308", "CAFEXAEXOEXUE"),
            ("A0123456789B", "AXNULLXEINSXZWOXDREIXVIERXFUENFXSECHSXSIEBENXACHTXNEUNXB"),
            (" -- A\t...\nB / C -- ", "AXBXC"),
            ("123", "EINSXZWOXDREI"),
            ("---", ""),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.success(self.run_cli("build", "--order", 3, "--print-text", text=text), expected + "\n")

    def test_counting_formats_and_print_text(self):
        bomm, resource, stream = [self.root / name for name in ("table.txt", "table.json", "stream.txt")]
        self.success(self.run_cli(
            "build", "--order", 2, "--bomm-out", bomm, "--json-out", resource,
            "--text-out", stream, "--print-text", text="ABABA",
        ), "ABABA\n")
        self.assertEqual(bomm.read_text(), "ab  2\nba  2\n")
        self.assertEqual(stream.read_text(), "ABABA\n")
        self.assertEqual(json.loads(resource.read_text()), {
            "resource_version": 1, "kind": "ngram", "alphabet": list(string.ascii_uppercase),
            "order": 2, "entries": [
                {"gram": ["A", "B"], "count": 2},
                {"gram": ["B", "A"], "count": 2},
            ],
        })

    def test_bomm_count_width_and_order(self):
        output = self.root / "table.txt"
        self.success(self.run_cli("build", "--order", 1, "--bomm-out", output, text="B" * 12 + "AA"))
        self.assertEqual(output.read_text(), "b  12\na   2\n")

    def test_orders_one_through_six(self):
        output = self.root / "table.txt"
        for order in range(1, 7):
            with self.subTest(order=order):
                self.success(self.run_cli("build", "--order", order, "--bomm-out", output, "--force", text="AAAAAA"))
                self.assertEqual(output.read_text(), f"{'a' * order}  {7 - order}\n")

    def test_multiple_files_are_separated(self):
        first, second = self.root / "one.txt", self.root / "two.txt"
        first.write_text("Ä", encoding="utf-8")
        second.write_text("B", encoding="utf-8")
        self.success(self.run_cli("build", first, second, "--order", 2, "--print-text"), "AEXB\n")

    def test_reference_conversion(self):
        output = self.root / "reference.json"
        self.success(self.run_cli("convert", REFERENCE, "--order", 3, "--json-out", output))
        resource = json.loads(output.read_text())
        self.assertEqual(set(resource), {"resource_version", "kind", "alphabet", "order", "entries"})
        self.assertEqual(resource["resource_version"], 1)
        self.assertEqual(resource["kind"], "ngram")
        self.assertEqual(resource["alphabet"], list(string.ascii_uppercase))
        self.assertEqual(resource["order"], 3)
        self.assertEqual(len(resource["entries"]), 3514)
        self.assertEqual(sum(entry["count"] for entry in resource["entries"]), 17694)
        self.assertEqual(resource["entries"][0], {"gram": ["E", "I", "N"], "count": 194})
        expected = [{"gram": list(gram.upper()), "count": int(count)}
                    for gram, count in (line.split() for line in REFERENCE.read_text().splitlines())]
        self.assertEqual(resource["entries"], expected)

    def test_conversion_from_stdin(self):
        output = self.root / "table.json"
        self.success(self.run_cli("convert", "--order", 2, "--json-out", output, text="ab  12\nba   2\n"))
        self.assertEqual(json.loads(output.read_text())["entries"], [
            {"gram": ["A", "B"], "count": 12}, {"gram": ["B", "A"], "count": 2},
        ])

    def test_invalid_table_leaves_outputs_unchanged(self):
        output = self.root / "existing.json"
        output.write_text("sentinel")
        cases = [
            ("abc\n", "expected a gram and count"),
            ("ABC 2\n", "expected exactly 3 lowercase ASCII letters"),
            ("ab 2\n", "expected exactly 3 lowercase ASCII letters"),
            ("abc -1\n", "count must be a positive u64 decimal integer"),
            ("abc 0\n", "count must be a positive u64 decimal integer"),
            ("abc 18446744073709551616\n", "count must be a positive u64 decimal integer"),
            ("abc 2\nabc 3\n", "duplicate gram: abc"),
        ]
        for text, message in cases:
            with self.subTest(text=text):
                result = self.run_cli("convert", "--order", 3, "--json-out", output, "--force", text=text)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                line = 2 if "duplicate" in message else 1
                self.assertEqual(result.stderr, f"error: stdin: line {line}: {message}\n")
                self.assertEqual(output.read_text(), "sentinel")

    def test_overwrite_refusal_and_force(self):
        for mode in ("build", "convert"):
            with self.subTest(mode=mode):
                output = self.root / "existing.json"
                output.write_text("sentinel")
                args = [mode, "--order", 2, "--json-out", output]
                text = "ABAB" if mode == "build" else "ab 2\nba 1\n"
                result = self.run_cli(*args, text=text)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, f"error: output exists (use --force): {output}\n")
                self.assertEqual(output.read_text(), "sentinel")
                self.success(self.run_cli(*args, "--force", text=text))
                self.assertEqual(json.loads(output.read_text())["entries"][0], {"gram": ["A", "B"], "count": 2})

    def test_preflight_all_outputs(self):
        fresh, existing = self.root / "fresh.txt", self.root / "existing.json"
        existing.write_text("sentinel")
        result = self.run_cli("build", "--order", 2, "--bomm-out", fresh, "--json-out", existing, text="AB")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"error: output exists (use --force): {existing}\n")
        self.assertFalse(fresh.exists())
        self.assertEqual(existing.read_text(), "sentinel")

    def test_help(self):
        for args in (("--help",), ("build", "--help"), ("convert", "--help")):
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertIn("--help", result.stdout)


if __name__ == "__main__":
    unittest.main()
