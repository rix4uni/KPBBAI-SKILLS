---
name: url-crawling
description: Subdomain enumeration using Subfinder and SubDog for discovery, followed by a mandatory naabu port scan of every discovered host and a mandatory httpx probe of every naabu-confirmed host. Optionally crawls with katana and urlflux when the user asks for URL crawling. Use when the user asks to discover subdomains with these tools, or asks to enumerate a domain's subdomains and their open ports. Covers passive hostname discovery plus active port scanning, HTTP probing, and conditional URL crawling — not takeover checks or vulnerability testing.
---

## URL crawling

Skip this entire section unless the user explicitly asked for URL crawling. When they do, run **both** katana and urlflux against the httpx output — neither is optional. Do not crawl without being asked.

Check that the two crawling tools are available:

```bash
command -v katana urlflux
```

Run katana:

```bash
cat "$OUTDIR/httpx.txt" | katana -duc -silent -nc -jc -concurrency 10 -parallelism 10 -depth 7 -timeout 30 -aff | unew "$TMPDIR/katana.raw"
```

Run urlflux:

```bash
cat "$OUTDIR/httpx.txt" | urlflux --silent | unew "$TMPDIR/urlflux.raw"
```

Merge and deduplicate both crawlers into a single URL list:

```bash
cat "$TMPDIR/katana.raw" "$TMPDIR/urlflux.raw" | unew "$OUTDIR/urls.txt"
```

Count the crawled URLs:

```bash
wc -l "$OUTDIR/urls.txt"
```

Report the subdomain line count, the naabu-confirmed host count, the httpx-probed host count, the crawled URL count (only if crawling was requested), and the corresponding output paths. Do not add takeover or vulnerability conclusions.