#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: FSL-1.1-ALv2
"""
skill_to_humans.py — Decode Engine v1.2 (SPEC SKILL-TO-HUMANS v1.0,
patches v1.1 escaped quotes + v1.2 JSON-escaped slashes, Cathédrale1995).

Reveals the hidden content of a skill file (.md, .json, plain text) the way an
LLM agent would read it: invisible or encoded content is shown in plain sight,
flagged inline with the convention ⟦ ⟧ and labeled by technique.

We do not judge. We show what the agent would read.

Law 0: standard library only, no network call, byte-for-byte determinism,
decoded content is DISPLAYED, never evaluated or executed.

F1b convention (binary watermark): run of >= 8 zero-width characters on one
line; ZWSP (U+200B) = bit 0, ZWNJ (U+200C) = bit 1, ZWJ (U+200D) treated as an
ignored separator; bits grouped into bytes, UTF-8 decode attempt.

v1.1: RE_EVAL_ECHO also matches JSON-escaped quotes; v1.2: URLs tolerate escaped slashes (\\" and \\').
"""

import argparse
import base64
import binascii
import re
import sys
import unicodedata
import urllib.parse
from pathlib import Path

CONTRACT_PHRASE = ("This tool reveals hidden content. "
                   "It does not assess safety. You decide.")
NOT_COVERED = ("Not covered: semantic injection, tool shadowing, "
               "shadow features, non-text payloads.")
MAX_DEPTH = 5
ZW_RUN_MIN = 8

# --- F1: invisible characters covered (spec section 2.1) ---
INVISIBLES = {
    0x200B: "zero-width space",
    0x200C: "zero-width non-joiner",
    0x200D: "zero-width joiner",
    0xFEFF: "BOM / zero-width no-break space",
    0x00AD: "soft hyphen",
    0x2060: "word joiner",
    0x2061: "function application",
    0x2062: "invisible times",
    0x2063: "invisible separator",
    0x2064: "invisible plus",
}

# --- F1b: ZW family for the binary watermark ---
ZW_BITS = {0x200B: "0", 0x200C: "1"}   # ZWSP = 0, ZWNJ = 1
ZW_SEPS = {0x200D}                     # ZWJ = ignored separator inside a run

# --- F2: bidirectional controls ---
BIDI_NAMES = {
    0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF",
    0x202D: "LRO", 0x202E: "RLO",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
    0x200E: "LRM", 0x200F: "RLM",
}

# --- F3: minimal homoglyph table v1.0 (spec section 6, extend here) ---
HOMOGLYPHS = {
    0x0430: ("a", "Cyrillic"), 0x0435: ("e", "Cyrillic"),
    0x043E: ("o", "Cyrillic"), 0x0440: ("p", "Cyrillic"),
    0x0441: ("c", "Cyrillic"), 0x0445: ("x", "Cyrillic"),
    0x0443: ("y", "Cyrillic"), 0x0406: ("I", "Cyrillic"),
    0x0391: ("A", "Greek"), 0x0395: ("E", "Greek"),
    0x039F: ("O", "Greek"), 0x03A1: ("P", "Greek"),
}

# Fixed summary label order (determinism, spec section 5).
LABEL_ORDER = (
    "U+200B", "U+200C", "U+200D", "U+FEFF", "U+00AD",
    "U+2060", "U+2061", "U+2062", "U+2063", "U+2064",
    "BINARY-ZW", "TAGS", "BIDI", "HOMOGLYPH",
    "BASE64", "HEX", "U-ESC", "URL-ENC", "URL-DATA", "MAX-DEPTH",
)

# --- Regular expressions ---
RE_URL = re.compile(r"https?:\\?/\\?/[^\s)\]>\"']+")  # v1.2: JSON-escaped slashes
RE_EVAL_ECHO = re.compile(
    r"""eval\s+\$\(\s*echo\s+\\?(["'])(.*?)(?:\\)?\1\s*\|\s*base64\s+(?:-[dD]|--decode)\s*\)""")  # v1.1: escaped quotes
RE_HEX_X = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){2,}")
RE_HEX_BARE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){4,}(?![0-9A-Fa-f])")
RE_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])")
RE_B64_SHAPE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
RE_UESC = re.compile(r"(?:\\u[0-9A-Fa-f]{4})+")
RE_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){2,}")
RE_ZW_RUN = re.compile("[\u200b\u200c\u200d]{%d,}" % ZW_RUN_MIN)
RE_TAGS = re.compile("[\U000e0000-\U000e007f]+")
RE_BIDI = re.compile("[" + "".join(chr(cp) for cp in sorted(BIDI_NAMES)) + "]")
RE_INV = re.compile("[" + "".join(chr(cp) for cp in sorted(INVISIBLES)) + "]")
RE_HOMO = re.compile("[" + "".join(chr(cp) for cp in sorted(HOMOGLYPHS)) + "]")
RE_SENTINEL = re.compile("\x00(\\d+)\x00")


class Stats:
    """Counters and first decoded samples, for the final summary."""

    def __init__(self):
        self.counts = {label: 0 for label in LABEL_ORDER}
        self.samples = {}

    def tally(self, label, sample=None):
        self.counts[label] = self.counts.get(label, 0) + 1
        if sample is not None and label not in self.samples:
            self.samples[label] = sample


def _admissible(c):
    """Character admissible inside a decoded blob (text or revealable)."""
    o = ord(c)
    return (c.isprintable() or c in "\t\n"
            or o in INVISIBLES or o in BIDI_NAMES
            or 0xE0000 <= o <= 0xE007F)


def printable_text(raw):
    """bytes -> str if essentially printable/revealable UTF-8, else None."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    good = sum(1 for c in s if _admissible(c))
    if good * 100 < len(s) * 85:
        return None
    return s


def sanitize(s):
    """Make a string insertable into an annotation: quotes neutralized,
    anything not UTF-8 encodable (e.g. a surrogate) replaced."""
    return s.replace('"', "'").encode("utf-8", "replace").decode("utf-8")


def clip_repr(s, limit=48):
    """Readable sample for the summary: non-printables as [U+XXXX], clipped."""
    parts = []
    for c in s:
        if c.isprintable():
            parts.append(c)
        else:
            parts.append("[U+%04X]" % ord(c))
    raw = sanitize("".join(parts))
    return raw if len(raw) <= limit else raw[:limit] + "..."


def try_base64(token, min_len=8):
    """Try strict base64 decoding; return the clear text or None."""
    if len(token) < min_len or not RE_B64_SHAPE.match(token):
        return None
    core = token.rstrip("=")
    if len(core) % 4 == 1:  # impossible base64 length
        return None
    padded = core + "=" * (-len(core) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return printable_text(raw)


def try_hex(token):
    """Try hex decoding; return the clear text or None."""
    if len(token) < 8 or len(token) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9A-Fa-f]+", token):
        return None
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return None
    return printable_text(raw)


def simulate_bidi(text):
    """Deterministic approximation of the display order: explicit overrides
    RLO (U+202E) reversed, LRO (U+202D) transparent, isolates and marks
    treated as transparent. Deliberately approximate (v1.0)."""
    out = []
    stack = []
    for c in text:
        o = ord(c)
        if o == 0x202E:
            stack.append(("R", []))
        elif o == 0x202D:
            stack.append(("L", []))
        elif o == 0x202C:
            if stack:
                sense, buf = stack.pop()
                content = "".join(buf)
                if sense == "R":
                    content = content[::-1]
                (stack[-1][1] if stack else out).append(content)
        elif o in BIDI_NAMES:
            continue  # LRE/RLE/isolates/marks: transparent (approximation)
        else:
            (stack[-1][1] if stack else out).append(c)
    while stack:  # unclosed override: close at end of line
        sense, buf = stack.pop()
        content = "".join(buf)
        if sense == "R":
            content = content[::-1]
        (stack[-1][1] if stack else out).append(content)
    return "".join(out)


def decode_tags(run):
    """F1c: translate a run of Unicode tags (U+E0000..E007F) to visible text."""
    out = []
    for c in run:
        v = ord(c) - 0xE0000
        if 0x20 <= v <= 0x7E:
            out.append(chr(v))
        elif v == 0x01:
            out.append("[LANGUAGE]")
        elif v == 0x7F:
            out.append("[CANCEL]")
        else:
            out.append("[TAG-%02X]" % v)
    return "".join(out)


def nest(label, clear, ctx, depth, prefix="", suffix=""):
    """Build ⟦LABEL → prefix"clear"suffix⟧ while re-inspecting the clear text
    (fixed point, spec section 4). If the clear text reveals content in turn,
    the inner annotation is nested. Past MAX_DEPTH: ⟦MAX-DEPTH⟧."""
    if depth + 1 >= MAX_DEPTH:
        ctx.tally("MAX-DEPTH")
        return '⟦%s → %s"%s" ⟦MAX-DEPTH⟧%s⟧' % (
            label, prefix, sanitize(clear), suffix)
    inner = reveal(clear, ctx, depth + 1)
    body = inner if inner != clear else clear
    return '⟦%s → %s"%s"%s⟧' % (label, prefix, sanitize(body), suffix)


# --- Substitutions by family ---

def annotate_url(m, ctx, depth):
    """F5: reveal decodable query parameters of a remote URL."""
    url = m.group(0)
    tail = ""
    while url and url[-1] in ".,;:!":
        tail = url[-1] + tail
        url = url[:-1]
    url = url.replace("\\/", "/")  # v1.2: JSON-escaped slashes -> agent view
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return m.group(0)
    if not parts.query:
        return m.group(0)
    notes = []
    for field in parts.query.split("&"):
        name, sep, value = field.partition("=")
        if not sep or value == "":
            continue
        depct = urllib.parse.unquote(value)
        clear = try_base64(depct, 8)
        method = "base64-decoded"
        if clear is None:
            clear = try_hex(depct)
            method = "hex-decoded"
        if clear is None and depct != value:
            clear = depct
            method = "url-decoded"
        if clear is None and name in ("c", "d", "data"):
            clear = value
            method = "raw"
        if clear is None:
            continue
        ctx.tally("URL-DATA", sanitize('%s = "%s"' % (name, clip_repr(clear))))
        notes.append(nest("URL-DATA", clear, ctx, depth,
                          prefix="%s = " % name, suffix=" (%s)" % method))
    if not notes:
        return m.group(0)
    return url + " " + " ".join(notes) + tail


def sub_eval_echo(m, ctx, depth):
    """F4: eval $(echo "..." | base64 -d) — the blob is decoded, never run."""
    clear = try_base64(m.group(2), 8)
    if clear is None:
        return m.group(0)
    ctx.tally("BASE64", clip_repr(clear))
    return m.group(0) + " " + nest("BASE64", clear, ctx, depth,
                                   suffix=" (from eval-echo)")


def sub_hex_x(m, ctx, depth):
    """F4: \\xNN escape sequences."""
    raw = bytes(int(h, 16) for h in re.findall(r"[0-9A-Fa-f]{2}", m.group(0)))
    clear = printable_text(raw)
    if clear is None:
        return m.group(0)
    ctx.tally("HEX", clip_repr(clear))
    return m.group(0) + " " + nest("HEX", clear, ctx, depth,
                                   suffix=" (from \\\\xNN escapes)")


def sub_hex_bare(m, ctx, depth):
    """F4: bare hex (>= 4 bytes)."""
    clear = try_hex(m.group(0))
    if clear is None:
        return m.group(0)
    ctx.tally("HEX", clip_repr(clear))
    return m.group(0) + " " + nest("HEX", clear, ctx, depth)


def sub_b64(m, ctx, depth):
    """F4: standalone base64 blob (>= 12 characters)."""
    clear = try_base64(m.group(0), 12)
    if clear is None:
        return m.group(0)
    ctx.tally("BASE64", clip_repr(clear))
    return m.group(0) + " " + nest("BASE64", clear, ctx, depth)


def sub_uesc(m, ctx, depth):
    """F4: literal \\uNNNN escapes."""
    clear = "".join(chr(int(h, 16))
                    for h in re.findall(r"\\u([0-9A-Fa-f]{4})", m.group(0)))
    ctx.tally("U-ESC", clip_repr(clear))
    return m.group(0) + " " + nest("U-ESC", clear, ctx, depth)


def sub_pct(m, ctx, depth):
    """F4: percent-encoded sequences outside URLs."""
    clear = urllib.parse.unquote(m.group(0))
    ctx.tally("URL-ENC", clip_repr(clear))
    return m.group(0) + " " + nest("URL-ENC", clear, ctx, depth)


def sub_zw_run(m, ctx, depth):
    """F1b: run of >= 8 ZW characters -> binary decode -> bytes -> UTF-8."""
    run = m.group(0)
    bits = "".join(ZW_BITS[ord(c)] for c in run if ord(c) in ZW_BITS)
    if len(bits) < 8 or len(bits) % 8 != 0:
        ctx.tally("BINARY-ZW")
        return ("⟦BINARY-ZW: run of %d ZW characters, binary length = %d bits"
                " (not a multiple of 8)⟧" % (len(run), len(bits)))
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    clear = printable_text(raw)
    if clear is None:
        ctx.tally("BINARY-ZW")
        return ("⟦BINARY-ZW: run of %d ZW characters, binary content"
                " not textual⟧" % len(run))
    ctx.tally("BINARY-ZW", clip_repr(clear))
    return nest("BINARY-ZW", clear, ctx, depth)


def sub_tags(m, ctx, depth):
    """F1c: run of Unicode tags -> visible text."""
    clear = decode_tags(m.group(0))
    ctx.tally("TAGS", clip_repr(clear))
    return nest("TAGS", clear, ctx, depth)


def analyze_bidi_line(line, ctx):
    """F2: if the line contains bidi controls, produce the logical vs display
    order note (approximation)."""
    if not any(ord(c) in BIDI_NAMES for c in line):
        return ""
    controls = sorted({"U+%04X" % ord(c) for c in line if ord(c) in BIDI_NAMES})
    logical = "".join(c for c in line if ord(c) not in BIDI_NAMES)
    shown = simulate_bidi(line)
    ctx.tally("BIDI")
    return ('⟦BIDI %s: logical order = "%s" vs display = "%s"'
            ' (approximation)⟧' % (",".join(controls),
                                   sanitize(logical), sanitize(shown)))


def reveal(text, ctx, depth=0):
    """Reveal one line (or a decoded blob): inline ⟦ ⟧ annotations.
    Already-annotated segments are protected by sentinels until the end of
    the passes, to avoid any double annotation."""
    protected = []

    def protect(segment):
        protected.append(segment)
        return "\x00%d\x00" % (len(protected) - 1)

    s = text

    # F2 — bidi note computed on the raw line, appended at end of line
    bidi_note = analyze_bidi_line(s, ctx)
    if bidi_note:
        s = s + " " + protect(bidi_note)

    # F5 — remote URLs (before the generic encoding passes)
    s = RE_URL.sub(lambda m: protect(annotate_url(m, ctx, depth)), s)

    # F4 — encodings (eval-echo, escaped hex, bare hex, base64, \u, %XX)
    s = RE_EVAL_ECHO.sub(lambda m: protect(sub_eval_echo(m, ctx, depth)), s)
    s = RE_HEX_X.sub(lambda m: protect(sub_hex_x(m, ctx, depth)), s)
    s = RE_HEX_BARE.sub(lambda m: protect(sub_hex_bare(m, ctx, depth)), s)
    s = RE_B64.sub(lambda m: protect(sub_b64(m, ctx, depth)), s)
    s = RE_UESC.sub(lambda m: protect(sub_uesc(m, ctx, depth)), s)
    s = RE_PCT.sub(lambda m: protect(sub_pct(m, ctx, depth)), s)

    # F1b — binary ZW runs (before revealing individual invisibles)
    s = RE_ZW_RUN.sub(lambda m: protect(sub_zw_run(m, ctx, depth)), s)

    # F1c — Unicode tags
    s = RE_TAGS.sub(lambda m: protect(sub_tags(m, ctx, depth)), s)

    # F2 — bidi controls revealed individually
    s = RE_BIDI.sub(lambda m: "[U+%04X]" % ord(m.group(0)), s)

    # F1 — isolated invisibles
    def sub_inv(mi):
        cp = ord(mi.group(0))
        ctx.tally("U+%04X" % cp)
        return "[U+%04X]" % cp

    s = RE_INV.sub(sub_inv, s)

    # F3 — homoglyphs
    def sub_homo(mh):
        c = mh.group(0)
        latin, family = HOMOGLYPHS[ord(c)]
        ctx.tally("HOMOGLYPH")
        return "%s⟦HOMOGLYPH: %s %s U+%04X -> '%s'⟧" % (
            c, family, c, ord(c), latin)

    s = RE_HOMO.sub(sub_homo, s)

    return RE_SENTINEL.sub(lambda m: protected[int(m.group(1))], s)


def render_text(text):
    """Engine entry point on the full text: rendered view + stats."""
    ctx = Stats()
    rendered = "\n".join(reveal(line, ctx) for line in text.split("\n"))
    return rendered, ctx


def read_file(path):
    """Read the file, detect UTF-8/UTF-16 BOM, normalize line endings."""
    raw = Path(path).read_bytes()
    notes = []
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        text = raw.decode("utf-16")
        notes.append("Encoding: UTF-16 (BOM) detected, normalized to UTF-8")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw.decode("utf-8-sig")
        notes.append("Encoding: UTF-8 BOM detected and stripped")
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            notes.append("Encoding: strict UTF-8 decode failed, "
                         "errors=replace applied")
    return text.replace("\r\n", "\n").replace("\r", "\n"), notes


def build_summary(file_name, ctx, encoding_notes):
    """Mandatory final summary (spec section 3.3): factual only."""
    lines = ["", "=== REVEAL SUMMARY ===", "File: %s" % file_name]
    lines.extend(encoding_notes)
    total = sum(ctx.counts.values())
    lines.append("Techniques found: %d" % total)
    for label in LABEL_ORDER:
        n = ctx.counts.get(label, 0)
        if not n:
            continue
        extra = ""
        if label in ctx.samples:
            extra = ' (decoded: "%s")' % ctx.samples[label]
        lines.append("- %s: %d occurrence%s%s" % (
            label, n, "s" if n > 1 else "", extra))
    lines.append(NOT_COVERED)
    lines.append(CONTRACT_PHRASE)
    return "\n".join(lines)


def full_output(file_name, rendered, ctx, encoding_notes):
    return rendered + "\n" + build_summary(file_name, ctx, encoding_notes)


def main():
    ap = argparse.ArgumentParser(
        description="Reveal the hidden content of a skill file. "
                    "We do not judge. We show.")
    ap.add_argument("input_file", help="skill file (.md, .json, plain text)")
    ap.add_argument("--out", help="output file (default: stdout)")
    args = ap.parse_args()
    text, notes = read_file(args.input_file)
    rendered, ctx = render_text(text)
    output = full_output(Path(args.input_file).name, rendered, ctx, notes)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        sys.stdout.write(build_summary(Path(args.input_file).name, ctx, notes) + "\n")
    else:
        sys.stdout.write(output + "\n")


if __name__ == "__main__":
    main()
