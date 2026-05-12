# Methodology

How the scanner works, how each detection class was chosen, and the
limits of static analysis.

## Pipeline

For each piece of agent-facing text (an MCP tool description, a SKILL.md
body, an agent.md file), the scanner runs 26 independent detection passes
plus a tier classifier. Each pass has clear regex / heuristic signatures
and emits a list of hit records. The tier classifier combines those into
one of four outputs:

| Tier | Meaning |
|---|---|
| `TIER_1_VULN` | A strict-bar vulnerability fired. Schema mismatch, explicit consent bypass, coerced FS write, hidden Unicode + instructions, indirect injection, shell exec, credentials, conversation exfiltration, persistence, priv-esc. |
| `TIER_2_PATTERN` | A documented attack pattern fired but no strict-vuln signal. Imperative density, tool commandeering, excessive scope claims. |
| `TIER_3_WEAK` | One weak signal, manual review warranted. |
| `CLEAN` | Nothing fired. |

A composite severity score (0-100) accumulates per-hit weight by class
severity. Scores ≥ 30 with multiple class hits are the high-confidence
named-vendor set.

## Why each class was added

Every detection class traces to published security research. Numbered
references in `src/skill_audit/detectors.py` cite the originating paper
or advisory.

* **A. Hidden character injection** — Invariant Labs 2025 (the original
  Tool Poisoning Attack); Embrace The Red, *Scary Agent Skills*
  (Feb 2026, the "Unicode-Tag" thresholds we use).
* **B. Homoglyphs** — same lineage; the latin-ratio gate prevents
  false positives on multilingual servers.
* **C. Encoded payloads** — arXiv 2601.17548 §M1.3 ("Encoding
  Obfuscation").
* **D. Instruction tags** — `<SYSTEM>`, `<IMPORTANT>`, role tags from
  Invariant Labs' canonical examples.
* **E. Imperatives + J. caps density** — observed pattern across the
  May 2026 ecosystem rescan; high frequency in published descriptions.
* **F. Schema-vs-description mismatch** — the CircleCI pattern from
  the May 2026 rescan; 64 cases in the public corpus.
* **G. Consent bypass + H. Coerced write** — Skyramp-MCP pattern.
* **I. Tool commandeering** — desktop-commander variants.
* **AA. Line Jumping** — Trail of Bits, *Jumping the line* (April 2025).
  The single most important class for an MCP scanner; treat tool
  descriptions as instructions, not metadata.
* **BB. ANSI escape** — Mindgard AnsiEscaped attack library (2026).
* **CC. Conversation-history exfiltration** — Trail of Bits, *How
  MCP servers can steal your conversation history* (April 2025).
* **DD. Lethal Trifecta** — Simon Willison (compositional, not in this
  scanner yet; lives at the install / manifest layer).
* **EE. OAuth confused deputy** — MCP spec security guidance, 2026.
* **FF. Promptware C2** — Rehberger, *Agent Commander* (March 2026).
* The remaining classes (K through Z) come from OWASP Top 10 for
  Agentic Applications, OWASP LLM Top 10, the Vulnerable MCP Project
  taxonomy, and the May 2026 ecosystem rescan.

## The PII detector is intentionally narrow

A common mistake in scanners of this kind is flagging every tool that
accepts an `email` or `phone` parameter as a privacy issue. That's
noise. The scanner here flags only the **canonical suspicious set**:

* The Invariant `sidenote` pattern (undocumented context-soliciting
  fields).
* Explicit prompt or conversation capture (`originalUserMessage`,
  `conversation_history`, `system_prompt`, etc.).
* Secrets passed as arguments (`api_key`, `access_token`,
  `private_key`, etc. — these should come via env, not tool args).
* Explicit high-sensitivity PII (`ssn`, `credit_card`, `cvv`,
  `passport`, `private_key`, `iban`).

Common fields (`email`, `phone`, `address`, `name`) are not flagged
on their own. They only contribute to a finding when paired with other
suspicious signals.

This is a deliberate precision-over-recall trade. The May 2026 rescan's
high-confidence set is 30 multi-class TIER_1 findings; the noisy version
of the same scanner would have produced 1,959.

## Limits

* **Static is a lower bound.** Many attacks require an LLM judge to
  flag with high precision. The original invisible-ink scan pairs this
  static layer with Kimi K2.6 / Claude Haiku for ambiguous cases.
* **Tier classification is heuristic.** Findings with severity score
  ≥ 30 with multiple class hits are the high-confidence set; lower
  scores warrant manual review. The published writeup uses the strict
  multi-class TIER_1 subset, not the full TIER_1 count.
* **Pseudonymization is editorial, not technical.** The scanner outputs
  full server identifiers in its JSON; the writeup chooses to anonymize.
* **The corpus changes.** Tool descriptions are published, updated, and
  withdrawn. Pin a hash on first scan if you want to detect drift.
* **Line Jumping is the most over-fired class** in practice. The strict
  bar (≥ 3 second-person imperatives) is tuned to keep the false-positive
  rate manageable, but it still catches some legitimate tool docs that
  use *"You can also..."* style. Manual triage of TIER_1 Line Jumping
  findings is recommended before any disclosure.

## Cross-reference with the runtime defense

Static scanning catches the patterns at write-time. Runtime adjudication
catches the residue — the behaviors that pass schema validation but
exceed user intent. The companion repo at
[mcp-line-jumping-demo](https://github.com/manumarri-sudo/mcp-line-jumping-demo)
demonstrates both layers side-by-side: a deliberately-poisoned MCP
server and a guarded version wrapped with the
[adjudicator](https://github.com/manumarri-sudo/adjudicator) Haiku-judge
layer.

## Reproducibility

```bash
# 1. install
git clone https://github.com/manumarri-sudo/skill-audit-2026
cd skill-audit-2026
uv venv && uv pip install -e ".[dev]"

# 2. run the test suite (12 tests, deterministic)
pytest -q

# 3. scan your own corpus
python -c "
import json
from skill_audit import scan
text = open('your-tool-description.txt').read()
schema = json.load(open('your-tool-schema.json'))  # optional
print(scan(text, input_schema=schema))
"
```

For corpus-level scans (walking a directory of MCP servers each with a
`tools.json`), see the scripts in this repo's `scripts/` directory.
