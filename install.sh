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
umask 077
temporary=$(mktemp -d /tmp/bunker-bootstrap.XXXXXXXX)
trap 'rm -rf -- "$temporary"' 0
trap 'exit 1' 1 2 3 15
trusted_bootstrap="$temporary/product-bootstrap.py"
cp -- "$bootstrap" "$trusted_bootstrap"
chmod 0400 "$trusted_bootstrap"
if ! printf '%s  %s\n' "$bootstrap_sha256" "$trusted_bootstrap" | sha256sum --check --status; then
    printf '%s\n' 'Bundled bootstrap SHA-256 mismatch; refusing to execute.' >&2
    exit 1
fi

release_tag=${BUNKER_RELEASE_TAG:-v1.0.0}
if [ "$release_tag" != 'v1.0.0' ] &&
   ! printf '%s\n' "$release_tag" | grep -Eq '^v1\.0\.0-rc[1-9][0-9]*$'; then
    printf '%s\n' 'Invalid BUNKER_RELEASE_TAG; use v1.0.0 or a 1.0.0 prerelease tag.' >&2
    exit 2
fi
release="https://github.com/karpizin/bunker-installer/releases/download/$release_tag"
# The verified Ops source must remain byte-for-byte unchanged during staging.
export PYTHONDONTWRITEBYTECODE=1
acceptance_id=${BUNKER_ACCEPTANCE_ID:-}
root=''
if [ -n "$acceptance_id" ]; then
    if ! printf '%s\n' "$acceptance_id" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'; then
        printf '%s\n' 'Invalid BUNKER_ACCEPTANCE_ID; use one safe path component.' >&2
        exit 2
    fi
    root="/var/lib/bunker-acceptance/$acceptance_id"
fi
python3 "$trusted_bootstrap" \
    --manifest-url "$release/release-1.0.0.json" \
    --signature-url "$release/release-1.0.0.sig" \
    --public-key-url "$release/bunker-product-release-2026.pem" \
    --cache "$root/var/cache/bunker-ai/1.0.0" \
    --ops-root "$root/opt/bunker/releases" \
    --source-root "$root/opt/bunker/module-sources" \
    --install-root "$root/opt/bunker" \
    --state-root "$root/var/lib/bunker-platform" \
    "$1"
