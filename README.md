# 🪞 SKILL-TO-HUMANS — Decode Engine v1.0

**Reveal what the agent would read. You decide what it means.**

A small, deterministic, zero-dependency Python tool that renders a skill file
(`.md`, `.json`, or plain text) the way an LLM agent would actually read it —
with every hidden layer peeled, shown in plain sight, and labeled by
technique. For **human eyes only**.

---

## Why this exists

Skills, MCP servers and agent config files are distributed as innocent-looking
text. But text can carry more than the eye sees: invisible Unicode, reordered
bidirectional runs, binary watermarks, nested encodings. The agent reads the
*logical* content; you read the *rendered* content. When those two differ,
you are not reviewing the same document your agent is about to execute.

This tool closes that gap. It does not protect you. It **shows you**.

## What it does — and what it does not do

**It does:**
- Render the file with hidden content revealed, inline, labeled by technique
- Decode nested layers iteratively until nothing new is found (fixed point, max depth 5)
- Produce a factual summary of what was found, where

**It does not:**
- ❌ Deliver any safety verdict. **The output never says "safe" or "malicious".**
- ❌ Assess, score, or rank files
- ❌ Execute, evaluate, or transmit anything it decodes — payloads are *displayed*, never run
- ❌ Cover every attack class (see [Coverage](#coverage))

> **Security is at the judgment of each user.** This tool is a mirror, not a
> guardian. A clean-looking reveal does not mean a clean file: legitimate-looking
> instructions can still be harmful, and hidden characters are not inherently
> evil (some are typography, some are localization). Look, think, decide.

## Demo

Input (looks like one harmless line):

```
Texte de couverture. 󠀴󠁯󠃌󠀴󠁯󠃍󠀴󠁯󠃍󠀴󠁯󠃍󠀴󠁯󠃌󠀴󠁯󠃌󠀴󠁯󠃌󠀴󠁯󠃌󠀴󠁯󠃍󠀴󠁯󠃌󠀴󠁯󠃍󠀴󠁯󠃍󠀴󠁯󠃍󠀴󠁯󠃌󠀴󠁯󠃌󠀴󠁯󠃍󠀴󠁯󠃌󠀴󠁯󠃌󠀴󠁯󠃍󠀴󠁯󠃌󠀴󠁯󠃍󠀴󠁯󠃌 Suite.
```

Output (what the mirror shows):

```
Texte de couverture. ⟦TAGS → "4oCL4oCM4oCM4oCL4oCM4oCL4oCL..." ⟦BASE64 → '⟦BINARY-ZW → 'parapluie'⟧'⟧"⟧ Suite.

=== REVEAL SUMMARY ===
File: fixture_multicouche.md
- TAGS: 1 occurrence (decoded: "4oCL4oCM...")
- BASE64: 1 occurrence (decoded: "⟦BINARY-ZW → 'parapluie'⟧")
- BINARY-ZW: 1 occurrence (decoded: "parapluie")
Techniques found: 3
Not covered: semantic injection, tool shadowing, shadow features, non-text payloads.
This tool reveals hidden content. It does not assess safety. You decide.
```

Three nested invisible layers — Unicode Tags → Base64 → binary zero-width
watermark — peeled to the fixed point. Test payloads are benign by design
(canonical words: `parapluie`, `canari`; reserved domain `example.org`).

## Usage

```bash
python skill_to_humans.py path/to/skill.md              # render to stdout
python skill_to_humans.py path/to/skill.md --out report.txt
```

```python
import skill_to_humans as m
texte, notes = m.lire_fichier("skill.md")
rendu, ctx = m.moteur(texte)
print(m.sortie_complete("skill.md", rendu, ctx, notes))
```

## Coverage

| Family | Techniques revealed | Status |
|---|---|---|
| Invisible Unicode | ZWSP, ZWNJ, ZWJ, BOM, soft hyphen, U+2060–U+2064 | ✅ |
| Binary watermarks | ZWSP/ZWNJ runs encoding hidden bits | ✅ |
| Unicode Tags | U+E0000–U+E007F (invisible ASCII twins) | ✅ |
| Bidirectional controls | U+202A–U+202E, U+2066–U+2069, LRM/RLM — logical vs displayed order | ✅ (approximation, labeled as such) |
| Homoglyphs | Greek/Cyrillic lookalikes | ✅ |
| Encoded payloads | base64, hex (raw & `\xNN`), `\uNNNN` escapes, percent-encoding, `eval $(echo ... | base64 -d)` | ✅ |
| Markdown exfiltration | remote URLs with decodable query data | ✅ |

**Not covered — and deliberately so:**
- *Semantic injection* — harmful instructions written in plain, visible text
- *Tool shadowing / context poisoning* — duplicate tool names, poisoned tool outputs
- *Shadow features* — divergence between code and description
- *Non-text payloads* — steganography in images or binaries

These families require judgment calls, and judgment is **your** job, not the
tool's. The output prints this list on every run, so the boundary is never hidden.


## Known limitations

Transparency cuts both ways: here is what the mirror does **not** catch yet.
This list is part of the product, not a footnote.

- **JSON escaping in general** — valid JSON can escape characters (`\"`, `\/`),
  and each escape is a potential hiding place. Since v1.2 both known forms are
  normalized before detection (escaped quotes in `eval $(echo ...)` since v1.1,
  escaped slashes in URLs since v1.2). New escape tricks may still appear:
  the fixed-point loop is the architecture, and issues are welcome.
  run the engine.
- **Bidi display order** — the logical-vs-display reconstruction is an
  approximation (explicit overrides only). Each BIDI note is labeled
  `(approximation)` so you always know.
- **Anything in the [not covered](#coverage) list above** — repeated on every
  run, by design.

Found a gap? Open an issue. The best demos of this tool so far are the
limitations it revealed about itself.

## Guarantees

- **Standard library only.** No dependency, no network call. Auditable by reading one file.
- **Deterministic.** Same input → same output, byte for byte. Run it twice, diff nothing.
- **Never executes decoded content.** Payloads are displayed, never `eval`'d.
- **Honest approximations.** Where the render is an approximation (bidi display order), the annotation says so.

## Hosted API

Don't want to run Python? A hosted version with a free tier is available:
self-host here for free, or use the API if you'd rather not think about it.
*(link coming)*

## Tests

```bash
python -m unittest test_skill_to_humans -v
```

18 tests: one per covered family, a three-layer nested fixture, a known-legit
skill (zero false positives), determinism, stdlib-only audit (AST),
performance (<1 s on 50 KB), and the two regression locks added by the
project's own demos (v1.1 JSON-escaped quotes, v1.2 JSON-escaped slashes).
All test payloads are locally crafted and benign.

## Credits & license

- **Antoine Couet** — Cathédrale1995 Research Initiative (architecture & specs)
- **Kimi K 2.6 Thinking** — research synthesis & spec co-authorship
- **K3** — implementation

Code: **Apache 2.0**. Specs & docs: CC BY 4.0.

*On ne juge pas. On montre ce que l'agent lirait.*
