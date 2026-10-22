---
description: Analyze IIS Shortscan output, filter ASP.NET defaults, reconstruct and validate 8.3 short names
---
Load the `iis` skill and follow it exactly.

Input (httpx.txt path, existing Shortscan output, or a single target URL): $ARGUMENTS

If the input is existing Shortscan output, preserve it and parse it as-is; do not rescan unless validation requires JSON. If it is an httpx.txt file, run the Shortscan pipeline from Phase 0 once and keep the raw output. If it is a single URL, scan only that target. If no input is given, ask for the Shortscan output, httpx.txt, or target URL, then continue.

Produce the Phase 11 report and update `shortscan_ignore.txt` only with confirmed framework/default patterns.
