#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

rm -rf dist
mkdir -p dist/pkg
cp -R web/. dist/
wasm-pack build . --target web --release --out-dir dist/pkg
# wasm-pack writes package metadata that a static site does not need.
rm -f dist/pkg/package.json dist/pkg/README.md dist/pkg/.gitignore
touch dist/.nojekyll

printf 'Built static site in %s/dist\n' "$ROOT"
