---
description: Critical-first source code security audit of a repo, archive, installer/binary, or browser extension with evidence and deliverables
---
Load the `code-review` skill and follow it exactly.

Input: $ARGUMENTS

Resolve the input before reviewing:
- GitHub/Git URL → clone, record the commit hash, audit that checkout.
- Local directory or source file → audit it in place.
- Bare project name (e.g. `karpenter-provider-aws`) → use the local directory if present, otherwise resolve the repository and state the owner/repo chosen.
- `.zip`/`.tar`/`.7z`/`.jar`/`.whl`/`.apk` → list entries first, then extract into an isolated workspace.
- `.exe`/`.msi`/`.deb`/`.rpm`/Electron app → static extraction only (7z/innoextract/pyinstxtractor/asar); never execute the binary.
- Chrome Web Store URL → extract the extension ID, download the CRX, strip the header, and audit `manifest.json` plus scripts.
- No input → ask for a repository URL, path, archive, or extension URL before starting.

Then:
1. Describe the repository discovery and the Critical-severity areas you are about to investigate.
2. Begin examining the actual source immediately — do not reply with a generic security checklist.
3. Work in severity order (Critical → High → Medium → Low), tracing attacker-controlled input to security-sensitive sinks.
4. Check hardcoded credentials, internal endpoints, and information disclosure.
5. Validate safely and label unproven items INCONCLUSIVE rather than guessing.
6. Produce `security_audit_report.md`, `security_findings.json`, and `audit_coverage.md` in the audit workspace, with patches and regression tests in separate directories for confirmed findings.

Read-only analysis of the target; no exploitation of external systems, no credential reuse, no destructive testing.
