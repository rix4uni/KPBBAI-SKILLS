---
name: url-crawling
description: Crawl URLs from an existing subdomain-enumeration run using katana and urlflux. Use when the user explicitly asks to crawl URLs, collect endpoints, or discover paths from a prior enumeration's httpx output. Requires an existing httpx.txt from a subdomain-enumeration run; merges and deduplicates both crawlers' output into a single URL list. Covers katana and urlflux invocation, deduplication, and the crawl count report — not subdomain discovery, port scanning, takeover checks, or vulnerability testing.
metadata:
  opencode/slash: "true"
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