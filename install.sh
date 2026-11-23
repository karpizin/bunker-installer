#!/bin/sh
# Run only the bundled, hash-pinned bootstrap; it verifies the signed manifest.
set -eu

usage() {
    printf '%s\n' 'Usage: sudo sh install.sh --prepare|--install-platform|--initialize-n8n|--activate-modules' \
        '       sudo sh install.sh --configure [--non-interactive [--choices-json FILE]] [--space-root DIR] [--min-free-after-bytes BYTES] [--probe-download]' \
        'Use the complete release bundle; piping this script alone to sh is unsupported.'
}

if [ "${1:-}" = '--help' ]; then
    usage
    exit 0
fi
if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi
action=$1
shift
version=1.0.0
non_interactive='' choices='' probe_download='' space_root='' min_free_after_bytes=''
case "$action" in
    --configure)
        version=1.1.0
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --non-interactive) non_interactive=--non-interactive ;;
                --probe-download) probe_download=--probe-download ;;
                --choices-json)
                    if [ "$#" -lt 2 ] || [ -z "$2" ]; then usage >&2; exit 2; fi
                    choices=$2
                    shift
                    ;;
                --space-root)
                    if [ "$#" -lt 2 ] || [ -z "$2" ]; then usage >&2; exit 2; fi
                    space_root=$2
                    shift
                    ;;
                --min-free-after-bytes)
                    if [ "$#" -lt 2 ]; then usage >&2; exit 2; fi
                    case "$2" in ''|*[!0-9]*) usage >&2; exit 2 ;; esac
                    min_free_after_bytes=$2
                    shift
                    ;;
                *) usage >&2; exit 2 ;;
            esac
            shift
        done
        if [ -n "$choices" ] && [ -z "$non_interactive" ]; then usage >&2; exit 2; fi
        ;;
    --prepare|--install-platform|--initialize-n8n|--activate-modules)
        if [ "$#" -ne 0 ]; then usage >&2; exit 2; fi
        ;;
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
bootstrap_sha256='82273e3c4fc65d88bacb62f80400b12f15be0f970141c81dec29cdd7c141f7ec'
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

release_tag=${BUNKER_RELEASE_TAG:-v$version}
case "$version" in
    1.0.0) prerelease='^v1\.0\.0-rc[1-9][0-9]*$' ;;
    1.1.0) prerelease='^v1\.1\.0-rc[1-9][0-9]*$' ;;
esac
if [ "$release_tag" != "v$version" ] &&
   ! printf '%s\n' "$release_tag" | grep -Eq "$prerelease"; then
    printf '%s\n' "Invalid BUNKER_RELEASE_TAG; expected v$version or its prerelease tag." >&2
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
if [ "$action" = '--configure' ]; then
    set -- "$action" --profile "$root/var/lib/bunker-installer/$version/selection.json"
    if [ -n "$non_interactive" ]; then set -- "$@" "$non_interactive"; fi
    if [ -n "$choices" ]; then set -- "$@" "--choices-json=$choices"; fi
    if [ -n "$probe_download" ]; then set -- "$@" "$probe_download"; fi
    if [ -n "$space_root" ]; then set -- "$@" "--space-root=$space_root"; fi
    if [ -n "$min_free_after_bytes" ]; then set -- "$@" "--min-free-after-bytes=$min_free_after_bytes"; fi
    ops_root="$root/opt/bunker/selection-releases"
else
    set -- --source-root "$root/opt/bunker/module-sources" \
        --install-root "$root/opt/bunker" --state-root "$root/var/lib/bunker-platform" "$action"
    ops_root="$root/opt/bunker/releases"
fi
python3 "$trusted_bootstrap" \
    --manifest-url "$release/release-$version.json" \
    --signature-url "$release/release-$version.sig" \
    --public-key-url "$release/bunker-product-release-2026.pem" \
    --cache "$root/var/cache/bunker-ai/$version" --ops-root "$ops_root" "$@"
