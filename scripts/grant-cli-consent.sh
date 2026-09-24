#!/usr/bin/env zsh
# ---------------------------------------------------------------------------------
# Grants the first-party Azure CLI application a DELEGATED Microsoft Graph permission,
# tenant-wide, so `az account get-access-token` returns a token that can manage Intune
# remediations.
#
#   zsh scripts/grant-cli-consent.sh              # dry run - shows the change, does nothing
#   zsh scripts/grant-cli-consent.sh --apply
#   zsh scripts/grant-cli-consent.sh --revoke --apply
#
# READ THIS FIRST
#   This is a TENANT-WIDE change to an application every Azure CLI user signs in to.
#   After it, any user who can already reach Intune through their own RBAC role can also
#   reach it through `az`. It does not grant anyone new Intune rights on its own -
#   Intune RBAC still applies - but it does widen what the CLI can be used for.
#
#   The narrower alternative is a dedicated app registration; see the README. Prefer that
#   unless your directory team is comfortable with this.
#
# Requires: DelegatedPermissionGrant.ReadWrite.All and Application.Read.All, plus a
# directory role permitted to consent (Privileged Role Administrator, Application
# Administrator, or Global Administrator).
# ---------------------------------------------------------------------------------
set -eu
set -o pipefail

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
source "$SCRIPT_DIR/lib/graph.sh"

AZURE_CLI_APP_ID='04b07795-8ddb-461a-bbee-02f9e1bf7b46'
GRAPH_APP_ID='00000003-0000-0000-c000-000000000000'
SCOPE='DeviceManagementScripts.ReadWrite.All'
APPLY=0
REVOKE=0

usage() {
  cat <<'USAGE'
Usage: grant-cli-consent.sh [options]

  --scope <name>     Delegated Graph permission. Default: DeviceManagementScripts.ReadWrite.All
  --client-id <id>   Client application. Default: the Azure CLI first-party app.
  --revoke           Remove the scope instead of adding it.
  --apply            Actually make the change. Without this, nothing is written.
  -h, --help         This help.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --scope)     SCOPE="${2:-}"; shift ;;
    --client-id) AZURE_CLI_APP_ID="${2:-}"; shift ;;
    --revoke)    REVOKE=1 ;;
    --apply)     APPLY=1 ;;
    -h|--help)   usage; exit 0 ;;
    *) print -u2 -- "grant: unknown argument '$1'"; usage; exit 2 ;;
  esac
  shift
done

graph_require_tools

GRAPH_TOKEN="$(graph_token)"
export GRAPH_TOKEN
graph_assert_identity "$GRAPH_TOKEN"

# --- resolve both service principals -------------------------------------------------
sp_object_id() {
  local app_id="$1" response
  local filter
  filter="$(graph_urlencode "appId eq '${app_id}'")"
  response="$(graph_request GET "/servicePrincipals?\$filter=${filter}&\$select=id,displayName")" \
    || graph_die "could not look up service principal ${app_id} (needs Application.Read.All)"
  local count
  count="$(print -- "$response" | jq '.value | length')"
  (( count == 1 )) || graph_die "expected one service principal for appId ${app_id}, found ${count}"
  print -- "$response" | jq -r '.value[0].id'
}

CLIENT_SP="$(sp_object_id "$AZURE_CLI_APP_ID")"
GRAPH_SP="$(sp_object_id "$GRAPH_APP_ID")"
graph_info "client service principal : ${CLIENT_SP} (appId ${AZURE_CLI_APP_ID})"
graph_info "resource service principal: ${GRAPH_SP} (Microsoft Graph)"

# --- find the existing tenant-wide grant, if any -------------------------------------
GRANTS="$(graph_request GET "/oauth2PermissionGrants?\$filter=$(graph_urlencode "clientId eq '${CLIENT_SP}'")")" \
  || graph_die "could not read existing permission grants (needs DelegatedPermissionGrant.ReadWrite.All)"

EXISTING="$(print -- "$GRANTS" | jq -r --arg r "$GRAPH_SP" \
  '[.value[] | select(.resourceId == $r and .consentType == "AllPrincipals")][0] // empty')"

if [[ -n "$EXISTING" ]]; then
  GRANT_ID="$(print -- "$EXISTING" | jq -r '.id')"
  CURRENT_SCOPES="$(print -- "$EXISTING" | jq -r '.scope // ""')"
else
  GRANT_ID=''
  CURRENT_SCOPES=''
fi

# --- compute the new scope string ----------------------------------------------------
# Graph stores scopes as a single space-delimited string; keep it sorted and unique so
# repeated runs are stable and the diff is readable.
NEW_SCOPES="$(print -- "$CURRENT_SCOPES" | tr ' ' '\n' | grep -v '^$' | sort -u | \
  if (( REVOKE )); then grep -vx "$SCOPE" || true; else cat; fi | tr '\n' ' ' | sed 's/ *$//')"

if (( ! REVOKE )); then
  if print -- " $NEW_SCOPES " | grep -q " ${SCOPE} "; then
    :
  else
    NEW_SCOPES="$(print -- "$NEW_SCOPES $SCOPE" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ *$//')"
  fi
fi

print --
print -- "grant: tenant-wide delegated consent for the client above"
print -- "  action  : $( (( REVOKE )) && print -- 'REVOKE' || print -- 'GRANT' ) ${SCOPE}"
print -- "  grant id: ${GRANT_ID:-<none - would be created>}"
print --
print -- "  current scopes:"
if [[ -z "$CURRENT_SCOPES" ]]; then print -- "    (none)"; else print -- "$CURRENT_SCOPES" | tr ' ' '\n' | sed 's/^/    /'; fi
print -- "  resulting scopes:"
if [[ -z "$NEW_SCOPES" ]]; then print -- "    (none)"; else print -- "$NEW_SCOPES" | tr ' ' '\n' | sed 's/^/    /'; fi
print --

if [[ "$CURRENT_SCOPES" == "$NEW_SCOPES" ]]; then
  graph_info "no change needed; already in the desired state"
  exit 0
fi

if (( ! APPLY )); then
  print -- "grant: DRY RUN - nothing was changed. Re-run with --apply to make it so."
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dbw-grant.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [[ -n "$GRANT_ID" ]]; then
  jq -n --arg scope "$NEW_SCOPES" '{scope: $scope}' > "$WORK/grant.json"
  graph_request PATCH "/oauth2PermissionGrants/${GRANT_ID}" "$WORK/grant.json" >/dev/null \
    || graph_die "failed to update the permission grant"
  graph_info "updated grant ${GRANT_ID}"
else
  jq -n --arg c "$CLIENT_SP" --arg r "$GRAPH_SP" --arg scope "$NEW_SCOPES" \
    '{clientId: $c, consentType: "AllPrincipals", principalId: null, resourceId: $r, scope: $scope}' \
    > "$WORK/grant.json"
  graph_request POST "/oauth2PermissionGrants" "$WORK/grant.json" >/dev/null \
    || graph_die "failed to create the permission grant"
  graph_info "created a new tenant-wide grant"
fi

cat <<SUMMARY

grant: done.

Consent changes apply to NEWLY issued tokens only, and the Azure CLI caches yours.
Refresh it, then confirm the scope is present:

  zsh scripts/intune-login.sh --account <your-intune-account>
  zsh scripts/intune-login.sh --status

To undo exactly this change:

  zsh scripts/grant-cli-consent.sh --revoke --apply
SUMMARY
