#!/usr/bin/env zsh
# ---------------------------------------------------------------------------------
# Retires the Dropbox watchdog.
#
# IMPORTANT: deleting a remediation in Intune stops it running but does NOT undo what
# it already did. Devices keep the scheduled task and the ProgramData install forever.
# So the safe order is:
#
#   1. scripts/teardown-intune.sh --group "<group>" --deploy-cleanup
#        Deploys a removal remediation to the same group and DELETES the main one.
#        Leave this in place until the group reports compliant (usually a few days,
#        long enough for every device to check in).
#
#   2. scripts/teardown-intune.sh --purge
#        Deletes the removal remediation too, once the fleet is clean.
#
#   scripts/teardown-intune.sh --group "<group>" --delete-only
#        Deletes the main remediation without deploying cleanup. Only do this if you
#        are removing the watchdog from devices by some other means.
# ---------------------------------------------------------------------------------
set -eu
set -o pipefail

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
source "$SCRIPT_DIR/lib/graph.sh"

DISPLAY_NAME="Dropbox client watchdog"
CLEANUP_NAME="Dropbox client watchdog (removal)"
GROUP=""
DEPLOY_CLEANUP=0
DELETE_ONLY=0
PURGE=0
ASSUME_YES=0
SKIP_BUILD=0
INTERVAL_HOURS=1

usage() {
  cat <<'USAGE'
Usage: teardown-intune.sh [options]

  --group <g>            Entra ID group. Required with --deploy-cleanup.
  --deploy-cleanup       Deploy the removal remediation, then delete the main one. (recommended)
  --delete-only          Delete the main remediation without deploying cleanup.
  --purge                Delete the removal remediation (run after the fleet is clean).
  --display-name <n>     Main remediation name. Default: "Dropbox client watchdog".
  --cleanup-name <n>     Removal remediation name. Default: "<main> (removal)".
  --interval-hours <n>   Schedule for the removal remediation. Default: 1.
  --skip-build           Use the existing build/ output.
  -y, --yes              Do not prompt for confirmation.
  -h, --help             This help.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --group)          GROUP="${2:-}"; shift ;;
    --deploy-cleanup) DEPLOY_CLEANUP=1 ;;
    --delete-only)    DELETE_ONLY=1 ;;
    --purge)          PURGE=1 ;;
    --display-name)   DISPLAY_NAME="${2:-}"; CLEANUP_NAME="${2:-} (removal)"; shift ;;
    --cleanup-name)   CLEANUP_NAME="${2:-}"; shift ;;
    --interval-hours) INTERVAL_HOURS="${2:-}"; shift ;;
    --skip-build)     SKIP_BUILD=1 ;;
    -y|--yes)         ASSUME_YES=1 ;;
    -h|--help)        usage; exit 0 ;;
    *) print -u2 -- "teardown: unknown argument '$1'"; usage; exit 2 ;;
  esac
  shift
done

if (( DEPLOY_CLEANUP + DELETE_ONLY + PURGE == 0 )); then
  print -u2 -- "teardown: choose --deploy-cleanup, --delete-only or --purge"
  usage
  exit 2
fi
if (( DEPLOY_CLEANUP && DELETE_ONLY )); then
  graph_die "--deploy-cleanup and --delete-only are mutually exclusive"
fi
if (( DEPLOY_CLEANUP )) && [[ -z "$GROUP" ]]; then
  graph_die "--deploy-cleanup needs --group"
fi

graph_require_tools

confirm() {
  local prompt="$1"
  (( ASSUME_YES )) && return 0
  print -n -- "teardown: ${prompt} [y/N] "
  local reply
  read -r reply
  [[ "$reply" == [yY]* ]] || { print -- "teardown: aborted."; exit 1 }
}

GRAPH_TOKEN="$(graph_token)"
export GRAPH_TOKEN
graph_assert_identity "$GRAPH_TOKEN"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dbw-teardown.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if (( DEPLOY_CLEANUP )); then
  if (( ! SKIP_BUILD )); then
    zsh "$SCRIPT_DIR/build.sh"
  fi

  CLEANUP_DETECT="$ROOT_DIR/build/DetectRemoval-DropboxWatchdog.ps1"
  CLEANUP_REMEDIATE="$ROOT_DIR/build/Uninstall-DropboxWatchdog.ps1"
  for f in "$CLEANUP_DETECT" "$CLEANUP_REMEDIATE"; do
    [[ -f "$f" ]] || graph_die "missing build artefact: $f"
  done

  GROUP_ID="$(graph_group_id "$GROUP")"
  confirm "deploy '${CLEANUP_NAME}' to group '${GROUP}' (${GROUP_ID}) and delete '${DISPLAY_NAME}'?"

  jq -n \
    --arg displayName "$CLEANUP_NAME" \
    --arg detection   "$(graph_b64 "$CLEANUP_DETECT")" \
    --arg remediation "$(graph_b64 "$CLEANUP_REMEDIATE")" \
    --arg publisher   "${DBW_PUBLISHER:-Endpoint Engineering}" \
    '{
       "@odata.type": "#microsoft.graph.deviceHealthScript",
       displayName: $displayName,
       description: "Removes the Dropbox session watchdog (scheduled task, ProgramData install, per-user state). Temporary - delete once the target group reports compliant.",
       publisher: $publisher,
       detectionScriptContent: $detection,
       remediationScriptContent: $remediation,
       runAs32Bit: false,
       runAsAccount: "system",
       enforceSignatureCheck: false,
       roleScopeTagIds: ["0"]
     }' > "$WORK/cleanup.json"

  EXISTING_CLEANUP="$(graph_find_health_script "$CLEANUP_NAME")"
  if [[ -n "$EXISTING_CLEANUP" ]]; then
    graph_request PATCH "/deviceManagement/deviceHealthScripts/${EXISTING_CLEANUP}" "$WORK/cleanup.json" >/dev/null \
      || graph_die "failed to update the removal remediation"
    CLEANUP_ID="$EXISTING_CLEANUP"
    graph_info "updated removal remediation ${CLEANUP_ID}"
  else
    RESPONSE="$(graph_request POST "/deviceManagement/deviceHealthScripts" "$WORK/cleanup.json")" \
      || graph_die "failed to create the removal remediation"
    CLEANUP_ID="$(print -- "$RESPONSE" | jq -r '.id')"
    [[ -n "$CLEANUP_ID" && "$CLEANUP_ID" != "null" ]] || graph_die "Graph did not return a script id"
    graph_info "created removal remediation ${CLEANUP_ID}"
  fi

  jq -n --arg groupId "$GROUP_ID" --argjson interval "$INTERVAL_HOURS" \
    '{ deviceHealthScriptAssignments: [ {
         target: { "@odata.type": "#microsoft.graph.groupAssignmentTarget", groupId: $groupId },
         runRemediationScript: true,
         runSchedule: { "@odata.type": "#microsoft.graph.deviceHealthScriptHourlySchedule", interval: $interval }
       } ] }' > "$WORK/assign.json"
  graph_request POST "/deviceManagement/deviceHealthScripts/${CLEANUP_ID}/assign" "$WORK/assign.json" >/dev/null \
    || graph_die "failed to assign the removal remediation"
  graph_info "removal remediation assigned to ${GROUP} (${GROUP_ID})"
fi

if (( DEPLOY_CLEANUP || DELETE_ONLY )); then
  MAIN_ID="$(graph_find_health_script "$DISPLAY_NAME")"
  if [[ -z "$MAIN_ID" ]]; then
    graph_info "no remediation named '${DISPLAY_NAME}' to delete"
  else
    (( DEPLOY_CLEANUP )) || confirm "delete '${DISPLAY_NAME}' (${MAIN_ID})? Devices will KEEP the watchdog."
    graph_request DELETE "/deviceManagement/deviceHealthScripts/${MAIN_ID}" >/dev/null \
      || graph_die "failed to delete '${DISPLAY_NAME}'"
    graph_info "deleted '${DISPLAY_NAME}' (${MAIN_ID})"
  fi
fi

if (( PURGE )); then
  CLEANUP_ID="$(graph_find_health_script "$CLEANUP_NAME")"
  if [[ -z "$CLEANUP_ID" ]]; then
    graph_info "no removal remediation named '${CLEANUP_NAME}' to delete"
  else
    confirm "delete '${CLEANUP_NAME}' (${CLEANUP_ID})? Devices that have not checked in yet will keep the watchdog."
    graph_request DELETE "/deviceManagement/deviceHealthScripts/${CLEANUP_ID}" >/dev/null \
      || graph_die "failed to delete '${CLEANUP_NAME}'"
    graph_info "deleted '${CLEANUP_NAME}' (${CLEANUP_ID})"
  fi
fi

print -- "teardown: done."
if (( DEPLOY_CLEANUP )); then
  cat <<'NEXT'

Next: watch the removal remediation in Intune until the group reports compliant, then
run:  scripts/teardown-intune.sh --purge
NEXT
fi
