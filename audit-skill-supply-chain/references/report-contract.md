# Skill Supply Chain Audit Report Contract

## JSON contract

Emit stable UTF-8 JSON without timestamps or arbitrary numeric risk scores. Include at least:

```json
{
  "schema_version": "1.0",
  "target": {},
  "coverage": {},
  "capability_manifest": {},
  "declaration_analysis": {},
  "findings": [],
  "correlations": [],
  "scanner_verdict": "",
  "verdict_reasons": [],
  "limitations": []
}
```

Use only target-relative evidence paths. Never include the target's absolute path. Keep inventory and finding order deterministic.

Each finding must contain:

- `rule_id`
- `title`
- `severity`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- `confidence`: `LOW`, `MEDIUM`, or `HIGH`
- `category`
- `evidence`
- `explanation`
- `remediation`

Each evidence item must contain a relative `path`, `line` or `byte_offset`, a redacted minimum `snippet`, and a named `detection` method. Do not output raw bidi controls or complete credentials.

The capability manifest is a Skill-oriented inventory, not an SPDX or CycloneDX claim. Record files, hashes when read within limits, inferred types, Python imports, endpoints, and normalized capabilities with evidence.

## Verdict contract

- `BLOCK`: High-confidence critical chain, including credential exfiltration, download-execute, concealed persistence, or dangerous out-of-scope execution.
- `REVIEW`: Risky capability or suspicious behavior may be legitimate but requires human confirmation.
- `INCONCLUSIVE`: Limits, unreadable material, parse failures, missing critical metadata, or unknown binary content prevent a complete assessment.
- `ALLOW`: Complete scan with no unresolved high/critical issue or declared-capability mismatch.

`ALLOW` means only that no blocking evidence was found in the supplied fully scanned material. It is not a guarantee of safety.

Use exit code `0` for `ALLOW`, `1` for `REVIEW`/`INCONCLUSIVE`, `2` for `BLOCK`, and `3` for input or scanner errors.

## Markdown contract

Render these sections in order:

1. Final Verdict
2. Scan Coverage
3. Declared Purpose
4. Observed Capability Manifest
5. Declared vs Observed
6. Risk Findings
7. Dangerous Correlations
8. Installation or Use Recommendation
9. Limitations

Separate facts, correlations, and missing evidence. Retain deterministic scanner findings during any later semantic review; never silently delete or downgrade them.
