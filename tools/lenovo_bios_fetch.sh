#!/usr/bin/env bash
# Download a vendor firmware/BIOS package and record exactly what was fetched.
#
#   tools/lenovo_bios_fetch.sh URL [--out DIR] [--sha256 HEX] [--name FILE]
#
# The URL is supplied by the caller: this script never guesses a download
# path.  It writes <name> and <name>.meta (URL, timestamp, size, SHA-256) so
# later extraction steps can cite the exact artifact.
set -euo pipefail

usage() {
    cat <<'EOF'
usage: lenovo_bios_fetch.sh URL [--out DIR] [--sha256 HEX] [--name FILE]

  --out DIR       destination directory (default: .)
  --sha256 HEX    expected SHA-256; the download is rejected on mismatch
  --name FILE     local file name (default: last path segment of URL)

Vendor support pages often block plain fetches (HTTP 403).  A direct
download.lenovo.com URL is required; verify it in a browser first.
EOF
}

if [[ $# -lt 1 ]]; then
    usage
    exit 2
fi

url=$1
shift
outdir=.
expected_sha=
name=

while [[ $# -gt 0 ]]; do
    case $1 in
        --out) outdir=$2; shift 2 ;;
        --sha256) expected_sha=${2,,}; shift 2 ;;
        --name) name=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

if [[ -z $name ]]; then
    name=${url%%\?*}
    name=${name##*/}
    [[ -z $name ]] && name=download.bin
fi

mkdir -p "$outdir"
dest="$outdir/$name"
part="$dest.part"

echo "url:  $url"
echo "dest: $dest"

# Retries help with the flaky redirect chains on support.lenovo.com.
curl --fail --location --retry 3 --retry-delay 2 --connect-timeout 20 \
     --user-agent 'Mozilla/5.0 (X11; Linux x86_64) tpm_re-fetch/1.0' \
     --output "$part" "$url"

size=$(stat -c %s "$part")
sha=$(sha256sum "$part" | cut -d' ' -f1)

if [[ -n $expected_sha && $sha != "$expected_sha" ]]; then
    echo "SHA-256 mismatch" >&2
    echo "  expected $expected_sha" >&2
    echo "  actual   $sha" >&2
    rm -f "$part"
    exit 1
fi

mv "$part" "$dest"
{
    printf 'url=%s\n' "$url"
    printf 'fetched=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'size=%s\n' "$size"
    printf 'sha256=%s\n' "$sha"
} > "$dest.meta"

echo "size:   $size bytes"
echo "sha256: $sha"
echo "meta:   $dest.meta"
echo
echo "next:   python3 -m tpm_re carve \"$dest\" --extract /tmp/opencode/tpmre/carve"
