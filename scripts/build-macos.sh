#!/bin/sh
set -eu
if [ "$(uname -s)" != Darwin ]; then
    echo 'Build the macOS application on a Mac.' >&2
    exit 1
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
python=${1:-"$root/.venv/bin/python"}
if [ "$(uname -m)" = x86_64 ] && [ -z "${OPENSSL_DIR:-}" ] && command -v brew >/dev/null 2>&1; then
    OPENSSL_DIR=$(brew --prefix openssl@3)
    export OPENSSL_DIR
fi
"$python" -c 'import sys; minimum={(3,11):17,(3,12):15,(3,13):16,(3,14):8}; v=sys.version_info; assert (v[:2] in minimum and v.micro >= minimum[v[:2]]) or v[:2] >= (3,15), "Use a patched Python runtime"; assert sys.maxsize > 2**32'
"$python" -m pip install --upgrade 'pip>=26.2'
"$python" -m pip install -e '.[build]'
"$python" -m PyInstaller --noconfirm packaging/pingo-macos.spec
name="Pingo-macOS-$(uname -m)"
mkdir -p "dist/$name"
/usr/bin/ditto dist/Pingo.app "dist/$name/Pingo.app"
cp LICENSE NOTICE README.md 'Start Pingo.command' "dist/$name/"
chmod +x "dist/$name/Start Pingo.command"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "dist/$name" "dist/$name.zip"
echo "Built dist/$name.zip (native architecture; ad-hoc signed, not notarized)."
