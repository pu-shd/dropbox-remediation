#!/usr/bin/env zsh
# ---------------------------------------------------------------------------------
# Builds the Intune-ready scripts in build/ from src/.
#
#   build/Detect-DropboxWatchdog.ps1      -> Intune detection script
#   build/Remediate-DropboxWatchdog.ps1   -> Intune remediation script (payload embedded)
#   build/DetectRemoval-DropboxWatchdog.ps1 -> detection for the removal remediation
#   build/Uninstall-DropboxWatchdog.ps1   -> removal script
#   build/manifest.json                   -> version + hashes for the deploy scripts
#
# Runs on macOS (zsh) and inside the Linux test container.
# ---------------------------------------------------------------------------------
set -eu
set -o pipefail

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
SRC_DIR="$ROOT_DIR/src"
BUILD_DIR="$ROOT_DIR/build"
PAYLOAD="$SRC_DIR/payload/DropboxWatchdog.ps1"
CONTRACT="$SRC_DIR/common/SharedContract.ps1"

die() { print -u2 -- "build: ERROR: $*"; exit 1 }
info() { print -- "build: $*" }

sha256_of() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    die "neither sha256sum nor shasum is available"
  fi
}

[[ -f "$PAYLOAD" ]]  || die "payload not found: $PAYLOAD"
[[ -f "$CONTRACT" ]] || die "shared contract not found: $CONTRACT"

# ---- version + hash -------------------------------------------------------------
PAYLOAD_VERSION="$(grep -E '^\$Script:PayloadVersion\s*=' "$PAYLOAD" \
  | head -n 1 | sed -E "s/.*=[[:space:]]*'([^']+)'.*/\1/")"
[[ -n "$PAYLOAD_VERSION" ]] || die "could not read \$Script:PayloadVersion from $PAYLOAD"

PAYLOAD_SHA256="$(sha256_of "$PAYLOAD" | tr '[:lower:]' '[:upper:]')"
[[ ${#PAYLOAD_SHA256} -eq 64 ]] || die "unexpected SHA-256 length for payload: $PAYLOAD_SHA256"

info "payload version $PAYLOAD_VERSION, sha256 ${PAYLOAD_SHA256:0:16}..."

# ---- staging --------------------------------------------------------------------
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/dbw-build.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

# Shared contract with build-time values substituted.
sed -e "s/@@PAYLOAD_VERSION@@/${PAYLOAD_VERSION}/g" \
    -e "s/@@PAYLOAD_SHA256@@/${PAYLOAD_SHA256}/g" \
    "$CONTRACT" > "$STAGE/contract.ps1"

if grep -q '@@' "$STAGE/contract.ps1"; then
  die "unsubstituted placeholder left in shared contract"
fi

# gzip + base64 of the payload, wrapped for readability.
# -n keeps gzip output deterministic (no timestamp/filename in the header).
gzip -9 -n -c "$PAYLOAD" | base64 | tr -d '\n' | fold -w 120 > "$STAGE/payload.b64"
[[ -s "$STAGE/payload.b64" ]] || die "payload base64 encoding produced an empty file"

# ---- expand templates -----------------------------------------------------------
mkdir -p "$BUILD_DIR"

expand_template() {
  local template="$1" output="$2"
  [[ -f "$template" ]] || die "template not found: $template"
  awk -v contract_file="$STAGE/contract.ps1" -v b64_file="$STAGE/payload.b64" '
    /^@@SHARED_CONTRACT@@$/ {
      while ((getline line < contract_file) > 0) print line
      close(contract_file); next
    }
    /^@@PAYLOAD_B64@@$/ {
      while ((getline line < b64_file) > 0) print line
      close(b64_file); next
    }
    { print }
  ' "$template" > "$output"

  if grep -q '@@[A-Z_]*@@' "$output"; then
    die "unsubstituted placeholder remains in $output: $(grep -o '@@[A-Z_]*@@' "$output" | sort -u | tr '\n' ' ')"
  fi
  info "wrote $(basename "$output") ($(wc -c < "$output" | tr -d ' ') bytes)"
}

expand_template "$SRC_DIR/templates/Detect-DropboxWatchdog.ps1.tmpl"    "$BUILD_DIR/Detect-DropboxWatchdog.ps1"
expand_template "$SRC_DIR/templates/Remediate-DropboxWatchdog.ps1.tmpl" "$BUILD_DIR/Remediate-DropboxWatchdog.ps1"
expand_template "$SRC_DIR/templates/DetectRemoval-DropboxWatchdog.ps1.tmpl" "$BUILD_DIR/DetectRemoval-DropboxWatchdog.ps1"
expand_template "$SRC_DIR/templates/Uninstall-DropboxWatchdog.ps1.tmpl"     "$BUILD_DIR/Uninstall-DropboxWatchdog.ps1"

# Intune caps each script at 200 KB.
for f in "$BUILD_DIR"/*.ps1; do
  size=$(wc -c < "$f" | tr -d ' ')
  (( size < 200000 )) || die "$(basename "$f") is ${size} bytes, over the 200 KB Intune script limit"
done

# Windows PowerShell 5.1 reads a BOM-less file as ANSI, so a stray non-ASCII byte
# (a curly quote, an em dash) would be corrupted on the device. The payload is checked
# too, and matters most: it is base64-encoded into the remediation, so bad bytes there
# are invisible in the generated scripts but are written back out and executed on the
# device verbatim.
for f in "$PAYLOAD" "$BUILD_DIR"/*.ps1; do
  if LC_ALL=C grep -q '[^ -~'$'\t'']' "$f"; then
    die "$(basename "$f") contains non-ASCII characters, which Windows PowerShell 5.1 would misread. Offending lines: $(LC_ALL=C grep -n '[^ -~'$'\t'']' "$f" | head -3 | cut -c1-80 | tr '\n' ' ')"
  fi
done

# ---- manifest -------------------------------------------------------------------
cat > "$BUILD_DIR/manifest.json" <<JSON
{
  "payloadVersion": "$PAYLOAD_VERSION",
  "payloadSha256": "$PAYLOAD_SHA256",
  "detectionScript": "Detect-DropboxWatchdog.ps1",
  "remediationScript": "Remediate-DropboxWatchdog.ps1",
  "removalDetectionScript": "DetectRemoval-DropboxWatchdog.ps1",
  "uninstallScript": "Uninstall-DropboxWatchdog.ps1",
  "builtUtc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

info "build complete -> $BUILD_DIR"
