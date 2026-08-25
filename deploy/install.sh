#!/bin/sh
# curl -fsSL https://raw.githubusercontent.com/PierreOssun/SOVRA/main/deploy/install.sh | sh
# Installs the `sovra` launcher (a single shell script — read it first if you
# like) into /usr/local/bin or ~/.local/bin. Docker is the only runtime
# dependency; everything else runs in containers.
set -eu

SRC="https://raw.githubusercontent.com/PierreOssun/SOVRA/main/deploy/sovra"
for dir in /usr/local/bin "$HOME/.local/bin"; do
  if [ -d "$dir" ] && [ -w "$dir" ]; then DEST="$dir/sovra"; break; fi
done
[ -n "${DEST:-}" ] || { mkdir -p "$HOME/.local/bin"; DEST="$HOME/.local/bin/sovra"; }

curl -fsSL "$SRC" -o "$DEST"
chmod +x "$DEST"
echo "installed $DEST"
command -v sovra >/dev/null 2>&1 || echo "note: add $(dirname "$DEST") to your PATH"
echo "try it: mkdir sovra-demo && cd sovra-demo && sovra init demo && sovra up"
