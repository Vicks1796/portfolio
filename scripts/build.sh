#!/bin/sh
# CASE FILE VP-26-001 · build script
#
#   sh scripts/build.sh          # Netlify build: verify CSP hash, inject SRI, write integrity.json
#   sh scripts/build.sh --fix    # local: rewrite the CSP hash in every HTML file and netlify.toml
#   sh scripts/build.sh --check  # local: verify only, change nothing (good for a pre-commit hook)
#
# POSIX sh + openssl only, so it runs the same on macOS and on Netlify's build image.
set -eu
cd "$(dirname "$0")/.."

MODE="${1:-build}"
HTML_FILES="index.html 404.html security/index.html exhibit-0/index.html sent/index.html"

# 1. The single inline script (theme boot) must be identical in every page.
BOOT=$(grep -o "<script>(function(){try{var t=localStorage[^<]*</script>" index.html | head -n1 | sed 's/^<script>//; s/<\/script>$//')
[ -n "$BOOT" ] || { echo "build: inline boot script not found in index.html" >&2; exit 1; }
for f in $HTML_FILES; do
  n=$(grep -c "<script>${BOOT}</script>" "$f" || true)
  [ "$n" = "1" ] || { echo "build: $f does not carry the exact boot script" >&2; exit 1; }
done
HASH=$(printf '%s' "$BOOT" | openssl dgst -sha256 -binary | openssl base64 -A)
echo "build: boot script sha256-$HASH"

# 2. Make sure the CSP (meta tags and netlify.toml) allows exactly that hash.
if [ "$MODE" = "--fix" ]; then
  for f in $HTML_FILES netlify.toml; do
    sed -i.bak "s#sha256-[A-Za-z0-9+/=_]*#sha256-${HASH}#g" "$f" && rm -f "$f.bak"
  done
  echo "build: CSP hash written to html files and netlify.toml"
fi
for f in $HTML_FILES netlify.toml; do
  grep -q "sha256-${HASH}" "$f" || { echo "build: $f CSP does not contain sha256-$HASH (run: sh scripts/build.sh --fix)" >&2; exit 1; }
done
echo "build: CSP hashes verified"

[ "$MODE" = "--check" ] && { echo "build: check passed"; exit 0; }
[ "$MODE" = "--fix" ] && exit 0

# 3. Subresource Integrity for the two first-party files every page loads.
sri() { openssl dgst -sha384 -binary "$1" | openssl base64 -A; }
CSS_SRI=$(sri styles.css)
JS_SRI=$(sri main.js)
for f in $HTML_FILES; do
  # -E so the optional group works in both GNU sed (Netlify) and BSD sed (macOS)
  sed -E -i.bak \
    -e "s#<link rel=\"stylesheet\" href=\"/styles.css\"( integrity=\"[^\"]*\")?>#<link rel=\"stylesheet\" href=\"/styles.css\" integrity=\"sha384-${CSS_SRI}\">#" \
    -e "s#<script src=\"/main.js\" defer( integrity=\"[^\"]*\")?></script>#<script src=\"/main.js\" defer integrity=\"sha384-${JS_SRI}\"></script>#" \
    "$f" && rm -f "$f.bak"
done
echo "build: SRI injected (styles sha384-$CSS_SRI)"

# 4. Published digests, read by the "Page integrity" panel.
hex() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
  printf '{\n  "generated": "%s",\n  "algorithm": "sha256",\n  "files": {\n' "$NOW"
  printf '    "index.html": "%s",\n' "$(hex index.html)"
  printf '    "styles.css": "%s",\n' "$(hex styles.css)"
  printf '    "main.js": "%s"\n' "$(hex main.js)"
  printf '  }\n}\n'
} > integrity.json
echo "build: integrity.json written"
