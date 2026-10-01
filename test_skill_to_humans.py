#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_skill_to_humans.py — Tests for the Decode Engine v1.1 (SPEC sections 5, 8, 9).

Spec section 9 rule (sealed addendum): all fixtures are crafted LOCALLY with
BENIGN payloads only:
  - canonical keyword: parapluie
  - secondary keyword: canari
  - test URL: https://example.org/c?d= (RFC 2606 reserved domain)
No real malicious sample is ever fetched from the Internet. Decoded content is
never executed.
"""

import ast
import base64
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(DIRECTORY))

import skill_to_humans as engine

# --- Canonical section 9 values ---
WORD = "parapluie"
WORD2 = "canari"
TEST_URL = "https://example.org/c?d="

WORD_B64 = base64.b64encode(WORD.encode("utf-8")).decode("ascii")    # cGFyYXBsdWll
WORD2_B64 = base64.b64encode(WORD2.encode("utf-8")).decode("ascii")  # Y2FuYXJp
WORD_HEX = WORD.encode("utf-8").hex()                                # bare hex
WORD2_HEX_X = "".join("\\x%02x" % b for b in WORD2.encode("utf-8"))  # \xNN
WORD2_UESC = "".join("\\u%04x" % ord(c) for c in WORD2)              # \uNNNN
WORD2_PCT = "".join("%%%02X" % b for b in WORD2.encode("utf-8"))     # %NN


def zw_encode(word):
    """F1b: word -> UTF-8 bits -> ZWSP(0)/ZWNJ(1) run."""
    return "".join("\u200b" if bit == "0" else "\u200c"
                   for octet in word.encode("utf-8")
                   for bit in format(octet, "08b"))


def tags_encode(word):
    """F1c: ASCII word -> Unicode tags U+E0000+codepoint."""
    return "".join(chr(0xE0000 + ord(c)) for c in word)


LEGIT = (
    "---\n"
    "name: legit-demo-skill\n"
    "description: Small demo skill with no hidden content.\n"
    "---\n"
    "\n"
    "# Demo skill\n"
    "\n"
    "## Usage\n"
    "\n"
    "This skill helps draft structured summaries.\n"
    "\n"
    "- Step 1: read the provided document.\n"
    "- Step 2: produce a three-point outline.\n"
    "- Step 3: write the final summary in English.\n"
    "\n"
    "See the documentation at https://example.org/docs for details.\n"
)


def build_fixtures():
    """Build all fixtures in memory (no external read)."""
    return {
        "fixture_f1_invisibles.md":
            "The keyword is para\u200bpluie, the second one is ca\u00adnari."
            " Final\u2060 note.\ufeff\n",
        "fixture_f1b_binary_zw.md":
            "An ordinary-looking line. " + zw_encode(WORD) + " End of line.\n",
        "fixture_f1c_tags.md":
            "The weather is nice. " + tags_encode(WORD2) + " Lovely day.\n",
        "fixture_f2_bidi.md":
            "The hidden word displays as: \u202e" + WORD[::-1] + "\u202c — end.\n",
        "fixture_f3_homoglyphs.md":
            "The p\u0430r\u0430pluie is open, the can\u0430ri sings.\n",
        "fixture_f4_base64.md":
            "Documented block: eval $(echo \"" + WORD2_B64 + "\" | base64 -d)\n"
            "Standalone blob: " + WORD_B64 + "\n",
        "fixture_f4_hex_escapes.md":
            "Bare hex: " + WORD_HEX + "\n"
            "Escaped hex: " + WORD2_HEX_X + "\n"
            "Escapes: " + WORD2_UESC + "\n"
            "Percents: " + WORD2_PCT + "\n",
        "fixture_f5_url.md":
            "Badge: ![b](" + TEST_URL + WORD2_B64 + ")\n"
            "Link: [x](https://example.org/c?data=" + WORD_HEX + ")\n",
        "fixture_multicouche.md":
            "Cover text. " + tags_encode(
                base64.b64encode(zw_encode(WORD).encode("utf-8")).decode("ascii")
            ) + " Tail.\n",
        "fixture_legit.md": LEGIT,
    }


class DecodeEngineTest(unittest.TestCase):
    """One fixture per family + nested + legit skill (spec sections 5, 8)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.outputs = {}
        for name, content in build_fixtures().items():
            p = cls.root / name
            p.write_text(content, encoding="utf-8")
            text, notes = engine.read_file(p)
            rendered, ctx = engine.render_text(text)
            cls.outputs[name] = engine.full_output(name, rendered, ctx, notes)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # --- Correct reveal per family (section 8.1) ---

    def test_f1_isolated_invisibles(self):
        s = self.outputs["fixture_f1_invisibles.md"]
        for marker in ("[U+200B]", "[U+00AD]", "[U+2060]", "[U+FEFF]"):
            self.assertIn(marker, s)
        self.assertIn("para[U+200B]pluie", s)

    def test_f1b_binary_zw(self):
        s = self.outputs["fixture_f1b_binary_zw.md"]
        self.assertIn('⟦BINARY-ZW → "parapluie"⟧', s)
        self.assertNotIn("\u200b", s.split("=== REVEAL SUMMARY ===")[0])

    def test_f1c_tags(self):
        s = self.outputs["fixture_f1c_tags.md"]
        self.assertIn('⟦TAGS → "canari"⟧', s)

    def test_f2_bidi(self):
        s = self.outputs["fixture_f2_bidi.md"]
        self.assertIn("⟦BIDI U+202C,U+202E", s)
        self.assertIn('logical order = "The hidden word displays as: eiulparap', s)
        self.assertIn('display = "The hidden word displays as: parapluie', s)

    def test_f3_homoglyphs(self):
        s = self.outputs["fixture_f3_homoglyphs.md"]
        self.assertIn("⟦HOMOGLYPH: Cyrillic \u0430 U+0430 -> 'a'⟧", s)
        self.assertIn("⟦HOMOGLYPH: Cyrillic \u0430 U+0430 -> 'a'⟧", s)

    def test_f5_url_json_escaped_slashes(self):
        """v1.2: https:\/\/... (valid JSON escape) must be detected.
        Raw file bytes contain ONE backslash per slash; the engine must
        reveal the URL data anyway."""
        brut = '{"endpoint": "https:\\/\\/example.org\\/c?d=' + WORD2_B64 + '"}'
        p = self.root / "fixture_f5b_url_json_escapes.md"
        p.write_text(brut, encoding="utf-8")
        text, notes = engine.read_file(p)
        rendered, ctx = engine.render_text(text)
        self.assertIn('⟦URL-DATA → d = "canari" (base64-decoded)⟧', rendered)

    def test_f4_eval_echo_escaped_quotes(self):
        """v1.1: eval $(echo \"...\" | base64 -d) with JSON-escaped quotes —
        the blob must be revealed despite the backslashes."""
        note = 'eval $(echo "' + WORD2_B64 + '" | base64 -d)'
        p = self.root / "fixture_f4b_eval_echo_json.md"
        p.write_text(json.dumps({"provenance_note": note}, ensure_ascii=False),
                     encoding="utf-8")
        text, notes = engine.read_file(p)
        rendered, ctx = engine.render_text(text)
        self.assertIn('⟦BASE64 → "canari" (from eval-echo)⟧', rendered)

    def test_f4_base64(self):
        s = self.outputs["fixture_f4_base64.md"]
        self.assertIn('⟦BASE64 → "canari" (from eval-echo)⟧', s)
        self.assertIn('⟦BASE64 → "parapluie"⟧', s)

    def test_f4_hex_and_escapes(self):
        s = self.outputs["fixture_f4_hex_escapes.md"]
        self.assertIn('⟦HEX → "parapluie"⟧', s)
        self.assertIn('⟦HEX → "canari" (from \\\\xNN escapes)⟧', s)
        self.assertIn('⟦U-ESC → "canari"⟧', s)
        self.assertIn('⟦URL-ENC → "canari"⟧', s)

    def test_f5_url_exfil(self):
        s = self.outputs["fixture_f5_url.md"]
        self.assertIn('⟦URL-DATA → d = "canari" (base64-decoded)⟧', s)
        self.assertIn('⟦URL-DATA → data = "parapluie" (hex-decoded)⟧', s)

    def test_nested_three_layers(self):
        """Section 8.6: ZW-binary -> base64 -> tags, all three layers revealed."""
        s = self.outputs["fixture_multicouche.md"]
        for label in ("TAGS", "BASE64", "BINARY-ZW"):
            self.assertIn(label, s)
        self.assertIn("parapluie", s)

    def test_legit_no_false_positive(self):
        """Section 8.2: no annotation on a known-legit skill."""
        s = self.outputs["fixture_legit.md"]
        self.assertNotIn("⟦", s)
        self.assertNotIn("[U+", s)
        self.assertIn("Techniques found: 0", s)

    # --- Cross-cutting criteria (sections 8.3 to 8.6) ---

    def test_forbidden_words_absent(self):
        """Section 8.4: \bsafe\b, malicious, dangerous, suspicious — word
        boundary (the contract phrase contains 'safety', a distinct word)."""
        pattern = re.compile(r"\b(safe|malicious|dangerous|suspicious)\b", re.IGNORECASE)
        for name, s in self.outputs.items():
            self.assertIsNone(pattern.search(s), "forbidden word in %s" % name)

    def test_not_covered_block_and_contract_phrase(self):
        for name, s in self.outputs.items():
            self.assertIn(engine.NOT_COVERED, s)
            self.assertIn(engine.CONTRACT_PHRASE, s)

    def test_stdlib_only_imports(self):
        """Section 8.5: AST parsing of the engine's imports, stdlib whitelist."""
        allowed = {"argparse", "base64", "binascii", "json", "re", "sys",
                   "unicodedata", "urllib", "pathlib", "tempfile", "time",
                   "ast", "unittest"}
        tree = ast.parse((DIRECTORY / "skill_to_humans.py").read_text(
            encoding="utf-8"))
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        self.assertTrue(modules <= allowed,
                        "imports outside whitelist: %s" % (modules - allowed))

    def test_determinism(self):
        """Section 5: same input -> same output, byte for byte."""
        content = build_fixtures()["fixture_multicouche.md"]
        r1, _ = engine.render_text(content)
        r2, _ = engine.render_text(content)
        self.assertEqual(r1, r2)

    def test_utf16_bom_normalized(self):
        """Section 3.1 / 5: UTF-16 with BOM detected, normalized, reported."""
        p = self.root / "fixture_utf16.md"
        p.write_text(build_fixtures()["fixture_f1c_tags.md"], encoding="utf-16")
        text, notes = engine.read_file(p)
        self.assertTrue(any("UTF-16" in n for n in notes))
        rendered, _ = engine.render_text(text)
        self.assertIn('⟦TAGS → "canari"⟧', rendered)

    def test_performance_50kb(self):
        """Section 8.3: < 1 s on a 50 KB skill."""
        big = (LEGIT * (50 * 1024 // len(LEGIT) + 1))[:50 * 1024]
        start = time.perf_counter()
        engine.render_text(big)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0, "too slow: %.3f s" % elapsed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
