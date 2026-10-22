---
description: Validate Nuclei findings, separate template-level from target-level false positives, and build the global ignore list
---
Load the `nuclei` skill and follow it exactly.

Input (scan output file, target list, or a single target): $ARGUMENTS

If the input is a path to existing Nuclei output, parse it as-is and use targeted re-tests instead of re-running the full scan. If it is a target list or single target, run the scan with JSONL output as described in Phase 0. If no input is given, ask for the scan output path or target scope, then continue.
