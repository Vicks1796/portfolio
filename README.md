# Case file VP-26-001 · Vignesh Prasad

A single-page portfolio written as a classified case file. The visitor reads the subject as an
investigation: a cover sheet, numbered exhibits (projects), a chain of custody (experience),
an attack-surface diagram (skills), credentials, known locations, and a section where the page
audits itself. Hand-written HTML, CSS and JavaScript. No framework, no third-party resources.

## Files

```
index.html              the case file
styles.css              all styling, dark and light ("paper") themes
main.js                 progressive enhancement only; the site works with JS off
netlify.toml            build command + the security headers (single source of truth)
scripts/build.sh        verifies the CSP hash, injects SRI, writes integrity.json
scripts/serve.py        local server that applies the netlify.toml headers
scripts/og.html         template the OG image is rendered from
.well-known/security.txt  RFC 9116 contact + policy
security/index.html     vulnerability disclosure policy (HTML twin of SECURITY.md)
exhibit-0/index.html    hidden page for the easter egg (noindex)
sent/index.html         thank-you page after the contact form
404.html                served by Netlify for unknown paths
robots.txt, sitemap.xml, site.webmanifest, pgp.asc
assets/img              portrait, school logos, the three places
assets/Vignesh_Prasad_Resume.pdf   résumé, linked from the cover and Disclosure
assets/icon             favicon.svg + PNG sizes (generated from the SVG)
assets/og.png           1200×630 social card (generated from scripts/og.html)
fonts/                  Geist and Geist Mono, self-hosted (SIL Open Font License 1.1)
```

## Run locally

```bash
python3 scripts/serve.py 4174
```

Then open http://127.0.0.1:4174/. The server reads `netlify.toml` and sends the same headers
Netlify will, so the "Response header audit" panel grades the real policy, and it computes
`/integrity.json` live so the "Page integrity" panel has a digest to compare. Plain
`python3 -m http.server` also works but sends no security headers, so the audit will show them missing.

The desktop launch config on this machine has a `vignesh-portfolio` entry that runs the same command.

## Build and deploy (Netlify)

`netlify.toml` sets `publish = "."` and `command = "sh scripts/build.sh"`. The build:

1. Extracts the one inline script (theme boot, in `<head>`), hashes it, and fails the build if that
   hash is not the one allowed by the CSP in every HTML file and in `netlify.toml`.
2. Adds `integrity="sha384-…"` to the `styles.css` and `main.js` tags in every page.
3. Writes `integrity.json` with SHA-256 digests of `index.html`, `styles.css` and `main.js`.

`skip_processing = true` stops Netlify's asset optimisation from rewriting files, which would
break both the SRI attributes and the published digests.

After changing the inline boot script, run `sh scripts/build.sh --fix` to rewrite the hash
everywhere, and `sh scripts/build.sh --check` to verify without touching anything.

Deploy with the Netlify CLI from this folder (`npx -y netlify-cli@latest deploy --prod`) or connect
the repo in the Netlify UI. The contact form needs Netlify Forms, which is detected automatically
from the `data-netlify` attribute at deploy time.

## Production-only behaviour

These only appear when served through Netlify (or `scripts/serve.py`), never from a plain file server:

| Feature | Why |
|---|---|
| All security headers (CSP, HSTS, XFO, COOP, COEP, CORP, Permissions-Policy, Referrer-Policy…) | sent by Netlify from `netlify.toml` |
| HSTS and the "Transport: https" check | needs TLS; local preview is http |
| `integrity.json` and the MATCH verdict | written by the build (served live by `serve.py`) |
| SRI attributes on `styles.css` / `main.js` | injected by the build, not committed |
| Contact form delivery | Netlify Forms |
| `/404.html` for unknown paths, `X-Robots-Tag` on hidden pages | Netlify routing and headers |

The `<meta http-equiv="Content-Security-Policy">` in each page is a fallback for any host that
drops headers; `frame-ancestors` cannot be set in a meta tag, so clickjacking protection is
header-only.

## Still to be supplied

Search for `placeholder` in `index.html`. Each spot is outlined on the page with a "to be supplied" tag:

- **Domain**: every `https://vignesh-prasad.netlify.app` must become the real origin.
  `grep -rl "vignesh-prasad.netlify.app" . | xargs sed -i '' 's#vignesh-prasad.netlify.app#REAL.DOMAIN#g'`
- **PGP**: replace `pgp.asc`, set `data-fingerprint="<40 hex chars>"` on `#hexgrid` in `index.html`,
  remove the `placeholder` class from that panel and the `<details>` block, then sign `security.txt`.
- **Certifications**: the last entry under Credentials.
- **CTF write-ups / security projects**: Exhibit 05.

## Security features, in short

Real: strict CSP (hash-allowed single inline script, Trusted Types required, no inline handlers),
HSTS with preload, X-Frame-Options and `frame-ancestors 'none'`, Referrer-Policy `no-referrer`,
Permissions-Policy denying every sensor, COOP/COEP/CORP, nosniff, SRI on first-party files,
self-hosted fonts and zero external requests, honeypot on the form, clipboard copies a fixed
string only, `rel="noopener noreferrer"` on every outbound link, `security.txt`, no analytics or cookies.

Visible: the header audit panel, the page-integrity digest with a terminal one-liner to verify it
independently, the PGP fingerprint grid, the attack-surface diagram, redaction bars with a
"Declassify all" switch, a persisted dark/light toggle, and Exhibit 0.

## Editing

- Text lives in `index.html`; sections are commented `===== 01 SUMMARY =====` and so on.
- Redact a phrase: wrap it in `<span class="redact" tabindex="0">…</span>`.
- Colours and type: the `:root` tokens at the top of `styles.css`. One accent colour, `--accent`.
- OG image: edit `scripts/og.html`, then render it headless at 1200×630 (see git history for the command).
- Icons: edit `assets/icon/favicon.svg` and regenerate the PNGs with ImageMagick.

## Credits

Portrait and location photographs belong to Vignesh Prasad. School marks belong to their institutions.
Geist typefaces by Vercel, SIL Open Font License 1.1.
