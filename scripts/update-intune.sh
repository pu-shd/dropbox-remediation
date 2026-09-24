#!/usr/bin/env zsh
# ---------------------------------------------------------------------------------
# Pushes a new payload version to an already-deployed Intune remediation.
#
#   scripts/update-intune.sh
#   scripts/update-intune.sh --display-name "Dropbox client watchdog" --group "Dropbox Watchdog Devices"
#
# Devices re-run detection on their normal schedule; the version bump in the payload
# makes detection report non-compliant, which reinstalls the new payload. Any watchdog
# loop already running in a user session notices the version change and exits, so the
# scheduled task starts the new one - no reboot or logoff required.
# ---------------------------------------------------------------------------------
set -eu
set -o pipefail

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
source "$SCRIPT_DIR/lib/graph.sh"

DISPLAY_NAME="Dropbox client watchdog"
GROUP=""
INTERVAL_HOURS=1
SKIP_BUILD=0

usage() {
  cat <<'USAGE'
Usage: update-intune.sh [options]

  --display-name <n>     Remediation to update. Default: "Dropbox client watchdog".
  --group <g>            Also refresh the assignment to this group. Optional.
  --interval-hours <n>   Used only with --group. Default: 1.
  --skip-build           Use the existing build/ output instead of rebuilding.
  -h, --help             This help.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --display-name)   DISPLAY_NAME="${2:-}"; shift ;;
    --group)          GROUP="${2:-}"; shift ;;
    --interval-hours) INTERVAL_HOURS="${2:-}"; shift ;;
    --skip-build)     SKIP_BUILD=1 ;;
    -h|--help)        usage; exit 0 ;;
    *) print -u2 -- "update: unknown argument '$1'"; usage; exit 2 ;;
  esac
  shift
done

graph_require_tools

if (( ! SKIP_BUILD )); then
  zsh "$SCRIPT_DIR/build.sh"
fi

DETECT="$ROOT_DIR/build/Detect-DropboxWatchdog.ps1"
REMEDIATE="$ROOT_DIR/build/Remediate-DropboxWatchdog.ps1"
MANIFEST="$ROOT_DIR/build/manifest.json"
for f in "$DETECT" "$REMEDIATE" "$MANIFEST"; do
  [[ -f "$f" ]] || graph_die "missing build artefact: $f"
done

PAYLOAD_VERSION="$(jq -r '.payloadVersion' "$MANIFEST")"

GRAPH_TOKEN="$(graph_token)"
export GRAPH_TOKEN
graph_assert_identity "$GRAPH_TOKEN"

SCRIPT_ID="$(graph_find_health_script "$DISPLAY_NAME")"
[[ -n "$SCRIPT_ID" ]] || graph_die "no remediation named '${DISPLAY_NAME}' exists. Use deploy-intune.sh to create it."

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dbw-update.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

jq -n \
  --arg detection   "$(graph_b64 "$DETECT")" \
  --arg remediation "$(graph_b64 "$REMEDIATE")" \
  --arg description "Installs and maintains a per-session Dropbox watchdog (payload ${PAYLOAD_VERSION}). Managed from source - do not edit in the portal." \
  '{
     "@odata.type": "#microsoft.graph.deviceHealthScript",
     description: $description,
     detectionScriptContent: $detection,
     remediationScriptContent: $remediation,
     runAs32Bit: false,
     runAsAccount: "system"
   }' > "$WORK/script.json"

graph_request PATCH "/deviceManagement/deviceHealthScripts/${SCRIPT_ID}" "$WORK/script.json" >/dev/null \
  || graph_die "failed to update the remediation"
graph_info "updated '${DISPLAY_NAME}' (${SCRIPT_ID}) to payload ${PAYLOAD_VERSION}"

if [[ -n "$GROUP" ]]; then
  GROUP_ID="$(graph_group_id "$GROUP")"
  jq -n --arg groupId "$GROUP_ID" --argjson interval "$INTERVAL_HOURS" \
    '{ deviceHealthScriptAssignments: [ {
         target: { "@odata.type": "#microsoft.graph.groupAssignmentTarget", groupId: $groupId },
         runRemediationScript: true,
         runSchedule: { "@odata.type": "#microsoft.graph.deviceHealthScriptHourlySchedule", interval: $interval }
       } ] }' > "$WORK/assign.json"
  graph_request POST "/deviceManagement/deviceHealthScripts/${SCRIPT_ID}/assign" "$WORK/assign.json" >/dev/null \
    || graph_die "failed to refresh the assignment"
  graph_info "assignment refreshed for group ${GROUP} (${GROUP_ID})"
fi

print -- "update: done. Devices install payload ${PAYLOAD_VERSION} on their next detection run."
