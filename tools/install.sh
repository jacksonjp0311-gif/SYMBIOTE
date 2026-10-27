#!/bin/sh
set -eu
version=latest
install_dir=${HOME}/.local/bin
from_source=0
bundle_dir=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] || { echo '--version needs a tag' >&2; exit 2; }; version=$2; shift 2 ;;
        --install-dir) [ "$#" -ge 2 ] || { echo '--install-dir needs a directory' >&2; exit 2; }; install_dir=$2; shift 2 ;;
        --bundle-dir) [ "$#" -ge 2 ] || { echo '--bundle-dir needs a directory' >&2; exit 2; }; bundle_dir=$2; shift 2 ;;
        --from-source) from_source=1; shift ;;
        --help|-h) printf '%s\n' 'Usage: sh tools/install.sh [--version v0.3.0] [--install-dir DIR] [--from-source] [--bundle-dir DIR]'; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$bundle_dir" ] || [ "$from_source" -eq 0 ] || { echo '--bundle-dir and --from-source cannot be combined.' >&2; exit 2; }
[ -z "$bundle_dir" ] || [ "$version" != latest ] || { echo '--bundle-dir requires an explicit --version tag.' >&2; exit 2; }
install_validated_binary() (
    source_binary=$1
    mkdir -p -- "$install_dir"
    lease="$install_dir/.install.lock"
    mkdir -- "$lease" 2>/dev/null || { echo 'Installation lock unavailable; another installer may be active or interrupted. Existing binary unchanged.' >&2; exit 1; }
    incoming=
    trap '[ -z "$incoming" ] || rm -f -- "$incoming"; rmdir -- "$lease"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    incoming=$(mktemp "$install_dir/.symbiote-XXXXXXXXXX")
    install -m 755 "$source_binary" "$incoming"
    mv -f -- "$incoming" "$install_dir/symbiote"
)
if [ "$from_source" -eq 1 ]; then
    command -v cargo >/dev/null 2>&1 || { echo 'Rust/Cargo is required for --from-source.' >&2; exit 1; }
    source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
    [ -f "$source_root/crates/symbiote-runtime/Cargo.toml" ] || { echo 'Source checkout required.' >&2; exit 1; }
    temporary=$(mktemp -d)
    trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
    cargo install --path "$source_root/crates/symbiote-runtime" --locked --root "$temporary" --force
    source_version=$("$temporary/bin/symbiote" --version)
    if [ "$version" != latest ]; then [ "$source_version" = "SYMBIOTE ${version#v}" ] || { echo 'Local source version does not match --version; existing binary unchanged.' >&2; exit 1; }; fi
    install_validated_binary "$temporary/bin/symbiote"
fi
if [ "$from_source" -eq 0 ]; then
    command -v unzip >/dev/null 2>&1 || { echo 'Required tool missing: unzip' >&2; exit 1; }
    if [ -z "$bundle_dir" ]; then command -v curl >/dev/null 2>&1 || { echo 'Required tool missing: curl' >&2; exit 1; }; fi
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64) target=x86_64-unknown-linux-gnu ;;
        Darwin/arm64) target=aarch64-apple-darwin ;;
        Darwin/x86_64) target=x86_64-apple-darwin ;;
        *) echo 'No prebuilt bundle for this platform; use --from-source.' >&2; exit 1 ;;
    esac
    temporary=$(mktemp -d)
    trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
    if [ "$version" = latest ]; then
        curl --fail --silent --show-error --location 'https://api.github.com/repos/jacksonjp0311-gif/SYMBIOTE/releases/latest' -o "$temporary/release.json"
        # Extract only the constrained tag field; never execute downloaded text.
        version=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$temporary/release.json")
    fi
    printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || { echo 'Invalid release version.' >&2; exit 1; }
    asset="symbiote-$version-$target.zip"
    base_uri="https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/download/$version"
    if [ -z "$bundle_dir" ]; then
        curl --fail --silent --show-error --location "$base_uri/$asset" -o "$temporary/$asset" || { echo 'Release bundle unavailable; use --from-source from a checkout.' >&2; exit 1; }
        curl --fail --silent --show-error --location "$base_uri/SHA256SUMS" -o "$temporary/SHA256SUMS"
    fi
    if [ -n "$bundle_dir" ]; then
        cp -- "$bundle_dir/$asset" "$temporary/$asset"
        cp -- "$bundle_dir/SHA256SUMS" "$temporary/SHA256SUMS"
    fi
    expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$temporary/SHA256SUMS")
    [ "${#expected}" -eq 64 ] || { echo 'Checksum manifest must have exactly one matching bundle.' >&2; exit 1; }
    if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$temporary/$asset" | awk '{print $1}'); fi
    if ! command -v sha256sum >/dev/null 2>&1; then actual=$(shasum -a 256 "$temporary/$asset" | awk '{print $1}'); fi
    [ "$actual" = "$expected" ] || { echo 'SHA256 mismatch; nothing installed.' >&2; exit 1; }
    unzip -Z1 "$temporary/$asset" > "$temporary/entries"
    [ "$(grep -c '^symbiote$' "$temporary/entries")" -eq 1 ] || { echo 'Bundle needs exactly one binary.' >&2; exit 1; }
    if grep -Ev '^(symbiote|LICENSE|README\.md)$' "$temporary/entries" >/dev/null; then echo 'Unsafe or unsupported archive entry.' >&2; exit 1; fi
    binary_size=$(unzip -l "$temporary/$asset" | awk '$NF == "symbiote" {print $1}')
    case "$binary_size" in ''|*[!0-9]*) echo 'Invalid binary size in archive.' >&2; exit 1 ;; esac
    [ "$binary_size" -le 104857600 ] || { echo 'Binary exceeds installation limit.' >&2; exit 1; }
    # Extract exactly one flat binary; directory traversal and symlink entries
    # cannot become filesystem paths. The final file is created by install.
    unzip -p "$temporary/$asset" symbiote > "$temporary/symbiote"
    [ "$(wc -c < "$temporary/symbiote" | tr -d ' ')" -le 104857600 ] || { echo 'Binary exceeds installation limit.' >&2; exit 1; }
    chmod 755 "$temporary/symbiote"
    staged_version=$("$temporary/symbiote" --version)
    [ "$staged_version" = "SYMBIOTE ${version#v}" ] || { echo 'Staged executable version differs from release tag; nothing installed.' >&2; exit 1; }
    install_validated_binary "$temporary/symbiote"
fi
"$install_dir/symbiote" --version
printf 'Installed: %s/symbiote\nRun: %s/symbiote demo\n' "$install_dir" "$install_dir"
