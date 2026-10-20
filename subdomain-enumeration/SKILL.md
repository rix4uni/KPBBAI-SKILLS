---
name: subdomain-enumeration
description: Subdomain enumeration using Subfinder and SubDog for discovery, followed by a mandatory naabu port scan of every discovered host and a mandatory httpx probe of every naabu-confirmed host. Optionally crawls with katana and urlflux when the user asks for URL crawling. Use when the user asks to discover subdomains with these tools, or asks to enumerate a domain's subdomains and their open ports. Covers passive hostname discovery plus active port scanning, HTTP probing, and conditional URL crawling — not takeover checks or vulnerability testing.
---

# Subdomain Enumeration

Collect publicly discoverable hostnames for one exact root domain using only `subfinder` and `subdog`, then port-scan every discovered host with `naabu`, then probe every naabu-confirmed host with `httpx`.

Subdomain discovery is passive; the naabu port scan and httpx probe that follow it are active and are required final steps, not optional extras. Do not invoke any other reconnaissance or enumeration tool. The single exception is URL crawling: when the user asks for URL crawling, run both `katana` and `urlflux` against the httpx output. Standard shell utilities may be used only to create files, normalize output, filter the exact domain, deduplicate, sort, and count results.

Report hostnames as passive discoveries unless naabu has actually confirmed them live. httpx is used only to probe the naabu-confirmed hosts, not to discover new ones. Do not add takeover or vulnerability conclusions.

## Workflow

Set the target without a scheme, port, path, or wildcard:

```bash
TARGET="example.com"
ESCAPED_TARGET="example\\.com"
OUTDIR="./recon/$TARGET"
TMPDIR="$OUTDIR/.tmp"
mkdir -p "$TMPDIR"
```

Check that all four required tools are available:

```bash
command -v subfinder subdog naabu httpx
```

Run Subfinder:

```bash
echo "$TARGET" | subfinder -duc -silent -all | unew "$TMPDIR/subfinder.raw"
```

Run SubDog:

```bash
echo "$TARGET" | subdog --silent --source all | unew "$TMPDIR/subdog.raw"
```

Merge, normalize, scope-filter, and deduplicate their output:

```bash
cat "$TMPDIR/subfinder.raw" "$TMPDIR/subdog.raw" \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/\.$//' \
  | grep -aE "^([A-Za-z0-9_-]+\\.)*$ESCAPED_TARGET$" \
  | unew "$OUTDIR/allsubs.txt"
```

Count the final results:

```bash
wc -l "$OUTDIR/allsubs.txt"
```

Port scan every discovered host with naabu. This step is required — do not skip it or present results before it completes:

```bash
cat "$OUTDIR/allsubs.txt" | naabu -duc -silent | unew "$OUTDIR/naabu.txt"
```

Count the live hosts naabu confirmed:

```bash
wc -l "$OUTDIR/naabu.txt"
```

Probe every naabu-confirmed host with httpx. This step is required — always run this exact command, do not skip it:

```bash
cat "$OUTDIR/naabu.txt" | httpx -duc -silent -nc -sc -title -cl -ct | sort -t'[' -k3,3nr | unew -el -i "$OUTDIR/httpx.txt"
```

Count the httpx-probed hosts:

```bash
wc -l "$OUTDIR/httpx.txt"
```
