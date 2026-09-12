# Methodology

The scanner applies 30 local heuristic detection categories to supplied text and optional input schemas. It does not execute that text, call a model, connect to a server, or test whether an instruction succeeds.

## Implementation and interpretation

`src/skill_audit/detectors.py` contains the detector functions, the `CLASS_SEVERITY` catalogue and the classifier. Findings retain the category and matched text for human review.

| Output | Interpretation |
|---|---|
| `TIER_1_VULN` | At least one strict-tier heuristic fired. Despite the legacy label, an exploit has not been established. |
| `TIER_2_PATTERN` | Pattern signals fired without a strict-tier finding. |
| `TIER_3_WEAK` | A nonzero score remains without a stronger classification. |
| `CLEAN` | No configured scoring signal fired; safety has not been established. |

The severity score accumulates weighted matches and is capped at 100. The general weights are critical 10, high 5, medium 2 and low 1, with category-specific caps and exceptions in the classifier. Tier selection depends on the finding categories, not simply on a numeric threshold. Neither the weights nor the tier names are calibrated probabilities.

Some thresholds reduce obvious noise: a single consent-bypass match stays a pattern signal, line-jumping needs at least three matched imperatives for its strict tier, and ordinary contact fields such as email or phone do not by themselves trigger the narrow PII-name detector. These choices can still produce both false positives and false negatives.

## Research background

These primary sources explain the broader attack surface; they do not validate this scanner's accuracy or its individual weights:

* [Invariant Labs, Tool Poisoning Attacks, April 1, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) describes attacks using instructions embedded in tool descriptions, including cross-tool influence.
* [Trail of Bits, Jumping the line, April 21, 2025](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/) examines malicious descriptions that influence an agent before the advertised tool is invoked.
* [MCP tools specification, June 18, 2025](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) describes tool definitions, input schemas and the tools/list exchange.

Historical project drafts included corpus counts and vendor-level interpretations. The original corpus and adjudication records are not included here, and those older claims are not reproduced or established by this release. Current documentation describes the shipped scanner and avoids treating static matches as evidence of successful attacks.

## Coverage limits

* Pattern matching can miss instructions expressed in an unfamiliar way and flag legitimate operational documentation.
* A description/schema discrepancy does not establish what a server's runtime handler enforces, and a prompt-capture parameter is not proof of unauthorized exfiltration.
* The corpus runner skips malformed or unreadable tool files and records that raise scan errors. Its output cannot attest that every record was examined.
* Findings contain the supplied text and server identifiers. Treat saved results as sensitive whenever the input is sensitive.
* Tests establish behavior for selected inputs, not ecosystem-wide precision, recall or exploitability.

## Reproduce the local checks

```bash
git clone https://github.com/manumarri-sudo/skill-audit-2026
cd skill-audit-2026
uv venv
uv pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

For a directory containing server folders with `tools.json`, run:

```bash
.venv/bin/python scripts/scan.py /path/to/servers --out findings.json
```

Review skipped or malformed inputs separately before using corpus totals in research.
