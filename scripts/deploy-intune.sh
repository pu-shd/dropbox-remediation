#!/usr/bin/env zsh
# ---------------------------------------------------------------------------------
# Creates (or updates) the Intune remediation and assigns it to a device group.
#
#   scripts/deploy-intune.sh --group "Dropbox Watchdog Devices"
#   scripts/deploy-intune.sh --group 0f2c...-...-... --interval-hours 1
#
# Auth: see scripts/lib/graph.sh (app registration env vars, or 'az login').
# ---------------------------------------------------------------------------------
set -eu
set -o pipefail

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
source "$SCRIPT_DIR/lib/graph.sh"

GROUP=""
DISPLAY_NAME="Dropbox client watchdog"
PUBLISHER="${DBW_PUBLISHER:-Endpoint Engineering}"
INTERVAL_HOURS=1
SKIP_BUILD=0
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: deploy-intune.sh --group <name-or-object-id> [options]

  --group <g>            Entra ID group to scope the remediation to (required).
  --display-name <n>     Remediation name in Intune. Default: "Dropbox client watchdog".
  --publisher <p>        Publisher shown in Intune. Default: $DBW_PUBLISHER or Endpoint Engineering.
  --interval-hours <n>   How often Intune re-runs detection. Default: 1 (the fastest Intune allows).
  --skip-build           Use the existing build/ output instead of rebuilding.
  --dry-run              Show what would be sent to Graph, then stop.
  -h, --help             This help.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --group)          GROUP="${2:-}"; shift ;;
    --display-name)   DISPLAY_NAME="${2:-}"; shift ;;
    --publisher)      PUBLISHER="${2:-}"; shift ;;
    --interval-hours) INTERVAL_HOURS="${2:-}"; shift ;;
    --skip-build)     SKIP_BUILD=1 ;;
    --dry-run)        DRY_RUN=1 ;;
    -h|--help)        usage; exit 0 ;;
    *) print -u2 -- "deploy: unknown argument '$1'"; usage; exit 2 ;;
  esac
  shift
done

[[ -n "$GROUP" ]] || { print -u2 -- "deploy: --group is required"; usage; exit 2 }
[[ "$INTERVAL_HOURS" =~ '^[0-9]+$' ]] || graph_die "--interval-hours must be a whole number"

graph_require_tools

if (( ! SKIP_BUILD )); then
  zsh "$SCRIPT_DIR/build.sh"
fi

DETECT="$ROOT_DIR/build/Detect-DropboxWatchdog.ps1"
REMEDIATE="$ROOT_DIR/build/Remediate-DropboxWatchdog.ps1"
MANIFEST="$ROOT_DIR/build/manifest.json"
for f in "$DETECT" "$REMEDIATE" "$MANIFEST"; do
  [[ -f "$f" ]] || graph_die "missing build artefact: $f (run scripts/build.sh)"
done

PAYLOAD_VERSION="$(jq -r '.payloadVersion' "$MANIFEST")"
DESCRIPTION="Installs and maintains a per-session Dropbox watchdog (payload ${PAYLOAD_VERSION}). \
Runs as SYSTEM; the watchdog itself runs in each interactive user session and relaunches \
Dropbox.exe if it exits, with crash-loop protection. Managed from source - do not edit in the portal."

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dbw-deploy.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

jq -n \
  --arg displayName "$DISPLAY_NAME" \
  --arg description "$DESCRIPTION" \
  --arg publisher   "$PUBLISHER" \
  --arg detection   "$(graph_b64 "$DETECT")" \
  --arg remediation "$(graph_b64 "$REMEDIATE")" \
  '{
     "@odata.type": "#microsoft.graph.deviceHealthScript",
     displayName: $displayName,
     description: $description,
     publisher: $publisher,
     detectionScriptContent: $detection,
     remediationScriptContent: $remediation,
     runAs32Bit: false,
     runAsAccount: "system",
     enforceSignatureCheck: false,
     roleScopeTagIds: ["0"]
   }' > "$WORK/script.json"

if (( DRY_RUN )); then
  print -- "deploy: DRY RUN - would deploy '${DISPLAY_NAME}' (payload ${PAYLOAD_VERSION}) to group '${GROUP}'"
  jq 'del(.detectionScriptContent, .remediationScriptContent) + {detectionScriptContent: "<base64>", remediationScriptContent: "<base64>"}' "$WORK/script.json"
  exit 0
fi

GRAPH_TOKEN="$(graph_token)"
export GRAPH_TOKEN
graph_assert_identity "$GRAPH_TOKEN"

GROUP_ID="$(graph_group_id "$GROUP")"
graph_info "target group: $GROUP -> $GROUP_ID"

EXISTING_ID="$(graph_find_health_script "$DISPLAY_NAME")"

if [[ -n "$EXISTING_ID" ]]; then
  graph_info "updating existing remediation $EXISTING_ID"
  graph_request PATCH "/deviceManagement/deviceHealthScripts/${EXISTING_ID}" "$WORK/script.json" >/dev/null \
    || graph_die "failed to update the remediation"
  SCRIPT_ID="$EXISTING_ID"
else
  graph_info "creating remediation '${DISPLAY_NAME}'"
  RESPONSE="$(graph_request POST "/deviceManagement/deviceHealthScripts" "$WORK/script.json")" \
    || graph_die "failed to create the remediation"
  SCRIPT_ID="$(print -- "$RESPONSE" | jq -r '.id')"
  [[ -n "$SCRIPT_ID" && "$SCRIPT_ID" != "null" ]] || graph_die "Graph did not return a script id"
fi

# Assignment. runRemediationScript:true means detection failures actually trigger the
# remediation rather than only reporting.
jq -n \
  --arg groupId "$GROUP_ID" \
  --argjson interval "$INTERVAL_HOURS" \
  '{
     deviceHealthScriptAssignments: [
       {
         target: {
           "@odata.type": "#microsoft.graph.groupAssignmentTarget",
           groupId: $groupId
         },
         runRemediationScript: true,
         runSchedule: {
           "@odata.type": "#microsoft.graph.deviceHealthScriptHourlySchedule",
           interval: $interval
         }
       }
     ]
   }' > "$WORK/assign.json"

graph_request POST "/deviceManagement/deviceHealthScripts/${SCRIPT_ID}/assign" "$WORK/assign.json" >/dev/null \
  || graph_die "failed to assign the remediation to group ${GROUP_ID}"

cat <<SUMMARY

deploy: done.
  remediation : ${DISPLAY_NAME}
  script id   : ${SCRIPT_ID}
  payload     : ${PAYLOAD_VERSION}
  group       : ${GROUP} (${GROUP_ID})
  schedule    : every ${INTERVAL_HOURS}h, remediation enabled
  portal      : https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/UXAnalyticsRemediationSummaryMenu/~/overview/id/${SCRIPT_ID}

Devices pick this up on their next Intune check-in (typically within 1 hour, or force
one with "Sync" in the portal / Company Portal). First run installs the watchdog; the
watchdog starts in each signed-in session within 30 minutes and at every logon after that.
SUMMARY
