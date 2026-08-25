#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

rm -rf dist
mkdir -p dist/pkg
cp -R web/. dist/
wasm-pack build . --target web --dev --out-dir dist/pkg
rm -f dist/pkg/package.json dist/pkg/README.md dist/pkg/.gitignore
touch dist/.nojekyll

printf 'Serving http://127.0.0.1:8080\n'
python3 -m http.server 8080 --directory dist
