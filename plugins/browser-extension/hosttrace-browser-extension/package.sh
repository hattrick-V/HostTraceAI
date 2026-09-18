#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT_NAME="hosttrace-browser-extension.zip"
OUT="$ROOT/dist/$OUT_NAME"
mkdir -p "$ROOT/dist"
rm -f "$OUT"
if command -v zip >/dev/null 2>&1; then
  (cd "$ROOT" && zip -r "$OUT" . \
    -x './dist/*' -x './package.sh' -x '*/.DS_Store')
elif command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
  PY_BIN="$(command -v python3 || command -v python)"
  (cd "$ROOT" && "$PY_BIN" - "dist/$OUT_NAME" <<'PY'
import os
import sys
import zipfile

out = sys.argv[1]
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
    for dirpath, dirnames, filenames in os.walk('.'):
        dirnames[:] = [d for d in dirnames if d not in {'dist', '.DS_Store'}]
        for filename in filenames:
            if filename in {'package.sh', '.DS_Store'}:
                continue
            path = os.path.join(dirpath, filename)
            arcname = path[2:] if path.startswith('./') else path
            zf.write(path, arcname.replace(os.sep, '/'))
PY
  )
else
  echo "Missing: zip or python (needed to package extension)."
  exit 1
fi
echo "[+] $OUT"
