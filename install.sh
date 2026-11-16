#!/bin/sh
# Run only the bundled, hash-pinned bootstrap; it verifies the signed manifest.
set -eu

usage() {
    printf '%s\n' 'Usage: sudo sh install.sh --prepare|--install-platform|--initialize-n8n|--activate-modules' \
        'Use the complete release bundle; piping this script alone to sh is unsupported.'
}

if [ "${1:-}" = '--help' ]; then
    usage
    exit 0
fi
if [ "$#" -ne 1 ]; then
    usage >&2
    exit 2
fi
case "$1" in
    --prepare|--install-platform|--initialize-n8n|--activate-modules) ;;
    *) usage >&2; exit 2 ;;
esac
if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'Bunker AI installation requires root.' >&2
    exit 1
fi
for tool in sha256sum python3 openssl curl tar; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing bootstrap command: %s\n' "$tool" >&2
        exit 1
    fi
done

bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
bootstrap="$bundle_dir/product-bootstrap.py"
if [ ! -f "$bootstrap" ] || [ -L "$bootstrap" ]; then
    printf '%s\n' 'Missing regular bundled product-bootstrap.py; do not run install.sh alone.' >&2
    exit 1
fi
bootstrap_sha256='939a33520f9b92e2a3f58fb4d3e687eb3cc5504e2ad049fa1222a2fbb6bfbcad'
if ! printf '%s  %s\n' "$bootstrap_sha256" "$bootstrap" | sha256sum --check --status; then
    printf '%s\n' 'Bundled bootstrap SHA-256 mismatch; refusing to execute.' >&2
    exit 1
fi

umask 077
release='https://github.com/karpizin/bunker-installer/releases/download/v1.0.0'
exec python3 "$bootstrap" \
    --manifest-url "$release/release-1.0.0.json" \
    --signature-url "$release/release-1.0.0.sig" \
    --public-key-url "$release/bunker-product-release-2026.pem" \
    --cache /var/cache/bunker-ai/1.0.0 \
    --ops-root /opt/bunker/releases \
    --source-root /opt/bunker/module-sources \
    --install-root /opt/bunker \
    --state-root /var/lib/bunker-platform \
    "$1"
