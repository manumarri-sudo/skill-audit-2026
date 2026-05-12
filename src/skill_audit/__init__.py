"""skill_audit — comprehensive static scanner for MCP / agent / skill text.

Public API:

    from skill_audit import scan, CLASS_SEVERITY

    result = scan(description_text, input_schema=optional_dict)
    # result['tier'] in {'TIER_1_VULN','TIER_2_PATTERN','TIER_3_WEAK','CLEAN'}

The detector covers 26 attack classes from the 2026 MCP / agent security
literature: OWASP Top 10 for Agentic Applications, Trail of Bits Line Jumping,
Invariant Labs Tool Poisoning, Rehberger's aid scanner thresholds.

Open source. Methodology in docs/METHODOLOGY.md.
"""
from .detectors import (
    scan_comprehensive as scan,
    CLASS_SEVERITY,
    SEV_WEIGHT,
)

__version__ = "0.1.0"
__all__ = ["scan", "CLASS_SEVERITY", "SEV_WEIGHT"]
