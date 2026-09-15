# Dorker

A dependency-free Google and DuckDuckGo query builder inspired by [jinouchi/dorker](https://github.com/jinouchi/dorker). This is an original implementation.

## Use

Open `index.html` in a browser. Enter domains, optional exact phrases, and optional file extensions. Generate and review queries, then open individual search links. Copy the full list or download it as text.

- **Combined:** one query per domain, with OR groups for terms and file types.
- **Granular:** one query per domain × term × file type combination.
- Blank terms or file types impose no restriction for that field.
- Commas and newlines separate entries; commas inside phrases are not supported.
- Full website URLs are normalized to their hostname.
- A maximum of 500 queries prevents accidental oversized batches.

No backend, API key, dependencies, automated searching, or tracking. Search links send the selected query to the chosen search engine. Clipboard access may require HTTPS; text downloads also work locally.

## GitHub Pages

Place `index.html` and `app.js` at the repository root. In the repository's **Settings → Pages**, choose **Deploy from a branch**, select the branch containing these files, and choose **/(root)**.

Use only for lawful research and authorized auditing. Search results and supported operators depend on the search engine.
