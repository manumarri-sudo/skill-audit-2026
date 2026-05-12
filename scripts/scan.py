"""Walk a directory tree of MCP servers (each with a `tools.json`) and
scan every tool description with the comprehensive detector.

This is the corpus-level runner. For per-string scanning, use the
`skill_audit.scan` function directly:

    from skill_audit import scan
    result = scan(description_text, input_schema=optional_dict)

Usage:
    python scripts/scan.py /path/to/servers/ --out findings.json

Where /path/to/servers/ is a directory whose immediate children are
server directories, each containing a `tools.json` with shape:
    {"tools": [{"name": ..., "description": ..., "inputSchema": ...}, ...]}
or just `[{"name": ..., "description": ..., "inputSchema": ...}, ...]`.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from skill_audit import scan, CLASS_SEVERITY


def iter_tools(root: Path):
    """Yield (server_id, tool_dict) pairs from every tools.json under root."""
    for server_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        tj = server_dir / "tools.json"
        if not tj.exists():
            continue
        try:
            data = json.load(open(tj))
        except Exception:
            continue
        tools = data.get("tools") if isinstance(data, dict) else data
        if not isinstance(tools, list):
            continue
        for t in tools:
            if isinstance(t, dict):
                yield server_dir.name, t


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=Path, help="Directory whose children are server dirs.")
    ap.add_argument("--out", type=Path, default=Path("findings.json"))
    args = ap.parse_args()

    if not args.root.exists() or not args.root.is_dir():
        sys.exit(f"error: {args.root} not a directory")

    t0 = time.time()
    findings: list[dict[str, Any]] = []
    by_tier: Counter = Counter()
    by_class: Counter = Counter()
    n_tools = 0

    for server_id, tool in iter_tools(args.root):
        desc = tool.get("description", "") or ""
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        if not desc:
            continue
        n_tools += 1
        try:
            result = scan(desc, input_schema=schema)
        except Exception:
            continue
        by_tier[result["tier"]] += 1
        for c in result["vuln_classes"]:
            by_class[c] += 1
        for c in result["pattern_signals"]:
            by_class[c] += 1
        if result["tier"] in ("TIER_1_VULN", "TIER_2_PATTERN"):
            findings.append({
                "server_id": server_id,
                "tool_name": tool.get("name", "?"),
                "tier": result["tier"],
                "vuln_classes": result["vuln_classes"],
                "pattern_signals": result["pattern_signals"],
                "severity_score": result["severity_score"],
                "description": desc[:1500],
            })

    findings.sort(key=lambda x: -x["severity_score"])

    args.out.write_text(json.dumps({
        "meta": {
            "n_tools_scanned": n_tools,
            "duration_s": round(time.time() - t0, 1),
            "scanned_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "by_tier": dict(by_tier),
        "by_class": dict(by_class),
        "findings": findings,
    }, indent=2))

    print(f"scanned {n_tools:,} tools in {time.time() - t0:.1f}s", file=sys.stderr)
    print(f"by tier:", file=sys.stderr)
    for k, v in by_tier.most_common():
        print(f"  {k:<16} {v:>6,}", file=sys.stderr)
    print(f"\ntop attack classes:", file=sys.stderr)
    for c, n in by_class.most_common(15):
        sev = CLASS_SEVERITY.get(c, ("?", False))[0]
        print(f"  {c:<28} sev={sev:<8} n={n:>6,}", file=sys.stderr)
    print(f"\nwrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
