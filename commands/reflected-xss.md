---
description: Hunt reflected XSS — map reflections, classify encoding, prove execution with the dialog trio in a real browser
---
Load the `reflected-xss` skill (id `reflected`) and follow it exactly.

Target (URL, host, or existing crawl output): $ARGUMENTS

Resolve the input before testing:
- Full URL with parameters → start there and keep the existing query names.
- Bare host/domain → enumerate reflection points first (query params, search, redirect/UTM params, error pages, 404 path echo), then test.
- Existing crawl/httpx output → take the URLs from it; do not rescan.
- No input → ask for a target URL or scope before starting.

Then:
1. Send one canary per parameter (`aaa"bbb'ccc<ddd>eee&fff`) and classify the encoder before spending payloads. Full entity encoding (`&amp;` `&quot;` `&#039;` `&lt;` `&gt;`) means skip that parameter — see HTML-Entity Encoding for the three exceptions.
2. Use a unique random marker, and check the baseline response for it first — a marker that appears without your input is a false positive.
3. Prove execution in a real browser with the dialog trio: `alert(1)` → `confirm(1)` → `prompt(1)`, substituting a unique number when the page carries decoy payloads. Handle the dialog explicitly and never leave it blocking the tab.
4. Report only what executes: payload, exact URL, reflection context, encoder observed, and the dialog that fired. `&lt;script&gt;` in the response is not a finding.
