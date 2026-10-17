#!/usr/bin/env bash
# Turn the money-shot into a GIF. One dependency: `agg` (asciinema's GIF generator, a single static
# binary). This script finds it, or fetches the prebuilt linux x86_64 build, then renders the GIF
# from demo/money-shot.cast (regenerated here if missing). No asciinema, no cargo needed.
#
#   ./demo/record-gif.sh           -> demo/money-shot.gif
#
# Prefer a REAL live recording instead? With asciinema installed:
#   asciinema rec demo/money-shot.cast -c "node demo/demo.mjs --pace"   # then run this script
set -euo pipefail
cd "$(dirname "$0")/.."

CAST="demo/money-shot.cast"
GIF="demo/money-shot.gif"
[ -f "$CAST" ] || node demo/make-cast.mjs

AGG="$(command -v agg || true)"
[ -z "$AGG" ] && [ -x demo/.tools/agg ] && AGG="demo/.tools/agg"

if [ -z "$AGG" ]; then
  echo "agg not found, fetching the prebuilt binary (asciinema/agg, linux x86_64)..."
  mkdir -p demo/.tools
  URL="$(curl -fsSL https://api.github.com/repos/asciinema/agg/releases/latest 2>/dev/null \
    | grep -o 'https://[^"]*agg-x86_64-unknown-linux-gnu' | head -1 || true)"
  if [ -z "$URL" ]; then
    echo "Could not resolve the latest agg release automatically (offline or rate-limited)."
    echo "Download it manually: https://github.com/asciinema/agg/releases"
    echo "  asset: agg-x86_64-unknown-linux-gnu  ->  chmod +x it to demo/.tools/agg  ->  re-run."
    exit 1
  fi
  curl -fsSL "$URL" -o demo/.tools/agg
  chmod +x demo/.tools/agg
  AGG="demo/.tools/agg"
fi

echo "rendering GIF with: $AGG"
"$AGG" --font-size 15 --theme asciinema "$CAST" "$GIF"
echo "done -> $GIF"
