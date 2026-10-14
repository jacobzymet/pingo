#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ "$(uname -s)" != Darwin ]; then
    echo 'This launcher requires macOS.' >&2
    exit 1
fi
if [ -x Pingo.app/Contents/MacOS/Pingo ]; then
    exec /usr/bin/sudo ./Pingo.app/Contents/MacOS/Pingo --data-dir "$HOME/Library/Application Support/Pingo"
fi
if [ -x dist/Pingo.app/Contents/MacOS/Pingo ]; then
    exec /usr/bin/sudo ./dist/Pingo.app/Contents/MacOS/Pingo --data-dir "$HOME/Library/Application Support/Pingo"
fi
if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
fi
if [ "$(uname -m)" = x86_64 ]; then
    if [ -z "${OPENSSL_DIR:-}" ] && command -v brew >/dev/null 2>&1; then
        OPENSSL_DIR=$(brew --prefix openssl@3)
        export OPENSSL_DIR
    fi
    if ! command -v cargo >/dev/null 2>&1 || ! command -v pkg-config >/dev/null 2>&1; then
        echo 'Intel source setup needs Xcode Command Line Tools, Rust, OpenSSL and pkgconf.' >&2
        echo 'Install those first; with Homebrew: brew install rust openssl@3 pkgconf' >&2
        exit 1
    fi
fi
if ! .venv/bin/python -c 'import webview,pingo.desktop,pingo.handshake; from importlib.metadata import version; assert tuple(map(int,version("cryptography").split("."))) >= (50,0,2); assert version("noiseprotocol") == "0.3.1"' >/dev/null 2>&1; then
    .venv/bin/python -m pip install --force-reinstall -e '.[gui]'
fi
.venv/bin/python -c 'import webview,pingo.desktop,pingo.handshake'
exec /usr/bin/sudo .venv/bin/python -m pingo gui --data-dir "$HOME/Library/Application Support/Pingo"
