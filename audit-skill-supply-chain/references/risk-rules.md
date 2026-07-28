# Skill Supply Chain Risk Rules

## Contents

- Evidence model
- ASC-001 through ASC-013
- Correlation and verdict guidance
- OWASP Agentic Top 10 mapping

## Evidence model

Keep four questions separate: what capability exists, whether it matches the declared purpose, whether it is concealed, and whether multiple facts form a dangerous chain. A match is an indicator, not proof of malicious intent. Use only relative paths and masked minimum snippets.

### ASC-001 — Broad trigger or instruction hierarchy override

- Risk: The Skill claims unrelated requests or attempts to replace higher-priority instructions.
- Detection: Broad frontmatter phrases or explicit ignore/override/authority language in any target text.
- False positives: Security examples, quoted attack strings, and defensive documentation.
- Severity: `MEDIUM`; raise to `HIGH` when an operative instruction targets system/developer authority.
- Confidence: High for explicit imperative override text; low for generic broad wording.
- Evidence: Frontmatter field or relative file line containing a masked minimum indicator.
- Remediation: Narrow the trigger and remove instruction-precedence claims.
- Do not conclude from: A generic description or quoted example alone.
- OWASP: ASI01, ASI06 when the text is intended to redirect an agent.

### ASC-002 — Hidden Unicode controls

- Risk: Bidirectional, zero-width, BOM-in-body, or other controls can conceal or reorder content.
- Detection: U+202A–U+202E, U+2066–U+2069, U+200B–U+200D, U+FEFF outside the leading BOM, or unreasonable control characters.
- False positives: Intentional multilingual layout tests and generated fixtures.
- Severity: `HIGH` for bidi controls, otherwise `MEDIUM`.
- Confidence: High for exact code-point detection.
- Evidence: Relative path, line/column or byte offset, and code point name; never raw bidi text.
- Remediation: Remove the character or document a narrowly justified need.
- Do not conclude from: A BOM at the beginning of a UTF-8 text file.
- OWASP: ASI04, ASI06.

### ASC-003 — Suspected encoding, obfuscation, or hidden payload

- Risk: Encoded or transformed content can hide commands, prompts, or executables.
- Detection: Long structured encoding indicators, encoded PowerShell, or decoding immediately connected to execution.
- False positives: Test vectors, hashes, signatures, and ordinary serialized data.
- Severity: `MEDIUM`; raise when correlated with execution.
- Confidence: High only when structure and use corroborate the indicator.
- Evidence: Encoding kind, location, masked preview, and connected capability.
- Remediation: Replace opaque content with reviewed source or document and verify the transformation.
- Do not conclude from: Alphanumeric appearance, one Base64-like word, or encoding alone.
- OWASP: ASI04, ASI05.

### ASC-004 — Undeclared external communication

- Risk: Code can contact an endpoint outside the declared purpose or permission boundary.
- Detection: Network APIs or commands in executable content when the Skill does not declare network use, plus discovered external endpoints.
- False positives: Documentation, mocked endpoints, and declared integrations.
- Severity: `HIGH` for observed undeclared communication; `MEDIUM` for unknown endpoint scope.
- Confidence: High for AST calls or executable command rules; low for URLs in prose.
- Evidence: Capability evidence, declaration text, and masked endpoint.
- Remediation: Remove the call or declare exact endpoints, data classes, and approval boundaries.
- Do not conclude from: A URL, imported network module, or declared network use alone.
- OWASP: ASI02, ASI04.

### ASC-005 — Credential, token, environment, or sensitive-directory access

- Risk: The Skill can read secrets or locations likely to contain them.
- Detection: Environment access, credential-shaped keys, private-key or cloud/config paths, and known credential APIs.
- False positives: Synthetic tests, variable-name validation, and local configuration needed for a declared integration.
- Severity: `HIGH`; `MEDIUM` for generic environment access without a sensitive key.
- Confidence: High for direct AST/file-path evidence.
- Evidence: Capability and masked key/path category, never a full value.
- Remediation: Minimize access, use explicit inputs, and document least-privilege handling.
- Do not conclude from: The word “token” in prose.
- OWASP: ASI03, ASI04.

### ASC-006 — Sensitive-source to external-send chain

- Risk: Credentials or sensitive files can be exfiltrated.
- Detection: `credentials.read` plus `network.upload` with compatible file or data-flow context.
- False positives: A declared authentication exchange that never sends the secret as payload.
- Severity: `CRITICAL`.
- Confidence: High when both capabilities occur in the same executable file or data-flow expression.
- Evidence: Both source and send locations and the correlation rationale.
- Remediation: Block installation, remove the chain, rotate exposed credentials, and require independent review.
- Do not conclude from: Credential access or network use in isolation.
- OWASP: ASI02, ASI03, ASI04.

### ASC-007 — Dynamic execution, dangerous deserialization, or download-then-execute

- Risk: Unreviewed bytes or text can become code.
- Detection: Dynamic execution APIs, `pickle.loads`/`marshal.loads`, encoded interpreter commands, or download followed by process/dynamic execution.
- False positives: Build tools, controlled plugin systems, and documented local subprocess use.
- Severity: `HIGH`; `CRITICAL` for a high-confidence download-execute chain.
- Confidence: High for AST call pairs or explicit same-line command chains.
- Evidence: Download/deserialization and execution locations.
- Remediation: Remove dynamic execution, verify content integrity, pin provenance, and separate download from reviewed execution.
- Do not conclude from: `subprocess`, `curl`, or an interpreter name alone.
- OWASP: ASI05.

### ASC-008 — Deletion or persistence

- Risk: The Skill can destroy data or survive beyond the requested run.
- Detection: Delete APIs, recursive removal, registry Run keys, scheduled tasks, cron, or startup writes.
- False positives: Declared cleanup of scoped temporary files and legitimate deployment automation.
- Severity: `HIGH`; `CRITICAL` when hidden or aimed outside a reviewed scope.
- Confidence: High for AST calls and explicit executable command matches.
- Evidence: Relative location, capability, and operation category.
- Remediation: Remove persistence; scope cleanup to explicit temporary paths and require approval.
- Do not conclude from: A cleanup example in documentation.
- OWASP: ASI02, ASI03, ASI05.

### ASC-009 — Symlink, traversal, or out-of-scope access

- Risk: Reads, writes, or execution can escape the reviewed directory.
- Detection: Symbolic links, parent traversal, absolute sensitive paths, or path resolution combined with write/execute.
- False positives: Documented relative navigation and benign symlinks in development fixtures.
- Severity: `MEDIUM`; `HIGH` when traversal combines with write or execution.
- Confidence: High for filesystem metadata and literal traversal in executable content.
- Evidence: Link metadata or normalized relative source location; redact absolute targets.
- Remediation: Reject links, constrain paths to an approved root, and verify containment before access.
- Do not conclude from: `..` in prose or a link alone.
- OWASP: ASI02, ASI04.

### ASC-010 — Extension/header mismatch or disguised binary

- Risk: Executable or archive bytes can masquerade as a document, image, or source file.
- Detection: Compare extensions with MZ/PE, ELF, ZIP, PDF, PNG, JPEG, and Gzip signatures.
- False positives: Polyglots, embedded test fixtures, and valid ZIP-based office formats.
- Severity: `HIGH`.
- Confidence: High for an unambiguous signature mismatch.
- Evidence: Relative path, size, SHA-256, detected header, and claimed extension.
- Remediation: Quarantine the file, verify provenance, and use the correct extension after review.
- Do not conclude from: Extension alone or an unknown file header.
- OWASP: ASI04, ASI05.

### ASC-011 — Unpinned or unverifiable external dependency

- Risk: Mutable versions or unclear sources can change after review.
- Detection: Install commands or dependency declarations lacking exact versions or integrity metadata.
- False positives: Local editable installs, operating-system packages, or manifests with lock files inspected elsewhere.
- Severity: `MEDIUM`.
- Confidence: High for explicit unpinned declarations; lower when a lock file may supply integrity.
- Evidence: Package declaration or install command location.
- Remediation: Pin exact versions and record a trusted source and hashes/lock file.
- Do not conclude from: The presence of a package manager alone.
- OWASP: ASI04.

### ASC-012 — Declared purpose conflicts with observed capability

- Risk: Reviewers authorize a narrower behavior than the code can perform.
- Detection: Explicit offline/read-only/local-only claims that conflict with network, write, delete, execution, or persistence capabilities.
- False positives: Test fixtures, optional disabled code, and inaccurate but non-malicious documentation.
- Severity: `HIGH`.
- Confidence: High only with an explicit declaration and deterministic capability evidence.
- Evidence: Both declaration and capability locations.
- Remediation: Remove the capability or update the declaration and permission boundary for renewed review.
- Do not conclude from: Missing documentation alone; report the gap separately.
- OWASP: ASI02, ASI04.

### ASC-013 — Approval or safety bypass request

- Risk: The Skill attempts to suppress authorization, permission confirmation, or higher-level safeguards.
- Detection: Explicit instructions to skip approval, disable safeguards, or act without confirmation.
- False positives: Defensive examples and policy tests.
- Severity: `HIGH`.
- Confidence: High for imperative instructions outside a clearly marked example.
- Evidence: Relative text location and matched bypass category.
- Remediation: Remove the instruction and restore explicit approvals.
- Do not conclude from: Discussion of approval systems without a bypass instruction.
- OWASP: ASI01, ASI03.

## Correlation and verdict guidance

- Correlate sensitive access plus upload as exfiltration.
- Correlate download plus process or dynamic execution as download-execute.
- Correlate hidden instructions plus persistence/high-privilege behavior as concealed persistence.
- Correlate traversal plus write/execute as out-of-scope execution.
- Correlate a disguised binary plus execution reference as concealed execution.
- Keep `BLOCK` when a blocking chain exists even if other coverage is incomplete.
- Prefer `REVIEW` for isolated dangerous capabilities with plausible legitimate uses.
- Prefer `INCONCLUSIVE` when limits, parse failures, unreadable files, or unknown binaries leave material content unexamined.
