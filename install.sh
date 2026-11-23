#!/bin/sh
# Run only the bundled, hash-pinned bootstrap; it verifies the signed manifest.
set -eu

usage() {
    printf '%s\n' 'Usage: sudo sh install.sh --prepare|--install-platform|--initialize-n8n|--activate-modules' \
        '       sudo sh install.sh --configure [--locale en|ru|zh-Hans] [--non-interactive [--choices-json FILE]] [--space-root DIR | --disk-layout-json FILE] [--min-free-after-bytes BYTES] [--probe-download]' \
        '       sudo env BUNKER_ACCEPTANCE_ID=release-110-rc1 sh install.sh --prepare-profile' \
        '       sudo env BUNKER_ACCEPTANCE_ID=release-110-rc1 sh install.sh --wikipedia setup-index|start-voice|start-operator|verify-chat|attach-chat PROFILE_SHA256' \
        '       sudo env BUNKER_ACCEPTANCE_ID=release-110-rc1 sh install.sh --wikipedia activate|recover PROFILE_SHA256 [ROLLBACK_SHA256]' \
        '       sudo sh install.sh --geo activate|recover|restart TRUST_DIR -- [managed Geo options]' \
        '       sudo env BUNKER_ACCEPTANCE_ID=release-110-rc1 sh install.sh --geo activate|recover|restart prepared:PROFILE_SHA256 -- [managed Geo options]' \
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
non_interactive='' choices='' probe_download='' space_root='' min_free_after_bytes='' disk_layout='' locale=''
case "$action" in
    --wikipedia)
        if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then usage >&2; exit 2; fi
        case "$1" in
            activate|recover) ;;
            setup-index|start-voice|start-operator|verify-chat|attach-chat) if [ "$#" -ne 2 ]; then usage >&2; exit 2; fi ;;
            *) usage >&2; exit 2 ;;
        esac
        for profile_id in "${2}" "${3:-$2}"; do
            if ! printf '%s\n' "$profile_id" | grep -Eq '^[0-9a-f]{64}$'; then usage >&2; exit 2; fi
        done
        version=1.1.0
        ;;
    --geo)
        if [ "$#" -lt 3 ] || [ -z "$2" ] || [ "$3" != '--' ]; then usage >&2; exit 2; fi
        case "$1" in activate|recover|restart) geo_action=$1 ;; *) usage >&2; exit 2 ;; esac
        geo_trust=$2
        shift 3
        version=1.1.0
        ;;
    --configure)
        version=1.1.0
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --non-interactive) non_interactive=--non-interactive ;;
                --probe-download) probe_download=--probe-download ;;
                --locale)
                    case "${2:-}" in en|ru|zh-Hans) locale=$2 ;; *) usage >&2; exit 2 ;; esac
                    shift
                    ;;
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
                --disk-layout-json)
                    if [ "$#" -lt 2 ] || [ -z "$2" ]; then usage >&2; exit 2; fi
                    disk_layout=$2
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
        if [ -n "$space_root" ] && [ -n "$disk_layout" ]; then usage >&2; exit 2; fi
        ;;
    --prepare-profile)
        if [ "$#" -ne 0 ]; then usage >&2; exit 2; fi
        version=1.1.0
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
bootstrap_sha256='600a50a62a21fbc8c9e6a9b415f44b1d9769bcbb62398c790532133240742afe'
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
    if [ "$version" = 1.1.0 ]; then
        if ! printf '%s\n' "$acceptance_id" | grep -Eq '^release-110-[a-z0-9][a-z0-9-]{0,51}$'; then
            printf '%s\n' '1.1 acceptance requires a lowercase release-110-* ID.' >&2
            exit 2
        fi
        root="/var/lib/bunker-acceptance-11/$acceptance_id"
    else
        root="/var/lib/bunker-acceptance/$acceptance_id"
    fi
fi
if [ "$action" = '--wikipedia' ]; then
    if ! printf '%s\n' "$acceptance_id" | grep -Eq '^release-110-[a-z0-9][a-z0-9-]{0,51}$'; then
        printf '%s\n' 'Managed Wikipedia requires a lowercase release-110-* acceptance ID.' >&2
        exit 2
    fi
    wiki_action=$1
    if [ "$#" -eq 3 ]; then
        set -- --prepared-profile "$2" --rollback-prepared "$3"
    else
        set -- --prepared-profile "$2"
    fi
    python3 "$trusted_bootstrap" --wikipedia "$wiki_action" --acceptance-id "$acceptance_id" \
        --ops-cache "$root/var/cache/bunker-ai/$version" --ops-root "$root/opt/bunker/selection-releases" "$@"
    exit
fi
if [ "$action" = '--geo' ]; then
    case "$acceptance_id" in
        release-100-*) printf '%s\n' 'Managed Geo requires a separate 1.1 project, not a 1.0 acceptance root.' >&2; exit 2 ;;
    esac
    case "$geo_trust" in
        prepared:*)
            if ! printf '%s\n' "$acceptance_id" | grep -Eq '^release-110-[A-Za-z0-9][A-Za-z0-9._-]{0,51}$'; then
                printf '%s\n' 'Prepared Geo requires a separate release-110-* acceptance ID.' >&2
                exit 2
            fi
            set -- --prepared-profile "${geo_trust#prepared:}" --acceptance-id "$acceptance_id" -- "$@"
            ;;
        *) set -- --trust-dir "$geo_trust" -- "$@" ;;
    esac
    python3 "$trusted_bootstrap" --geo "$geo_action" --ops-cache "$root/var/cache/bunker-ai/$version" \
        --ops-root "$root/opt/bunker/selection-releases" "$@"
    exit
fi
if [ "$action" = '--configure' ]; then
    set -- "$action" --profile "$root/var/lib/bunker-installer/$version/selection.json"
    if [ -n "$locale" ]; then set -- "$@" "--locale=$locale"; fi
    if [ -n "$non_interactive" ]; then set -- "$@" "$non_interactive"; fi
    if [ -n "$choices" ]; then set -- "$@" "--choices-json=$choices"; fi
    if [ -n "$probe_download" ]; then set -- "$@" "$probe_download"; fi
    if [ -n "$space_root" ]; then set -- "$@" "--space-root=$space_root"; fi
    if [ -n "$disk_layout" ]; then set -- "$@" "--disk-layout-json=$disk_layout"; fi
    if [ -n "$min_free_after_bytes" ]; then set -- "$@" "--min-free-after-bytes=$min_free_after_bytes"; fi
    ops_root="$root/opt/bunker/selection-releases"
elif [ "$action" = '--prepare-profile' ]; then
    if ! printf '%s\n' "$acceptance_id" | grep -Eq '^release-110-[A-Za-z0-9][A-Za-z0-9._-]{0,51}$'; then
        printf '%s\n' 'Profile preparation requires a separate release-110-* acceptance ID.' >&2
        exit 2
    fi
    set -- "$action" "$acceptance_id"
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
