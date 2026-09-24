#!/usr/bin/env zsh
# ---------------------------------------------------------------------------------
# Shared Microsoft Graph helpers for the Intune deploy/update/teardown scripts.
# Sourced, not executed.
#
# Authentication, in order of preference:
#   1. App registration (non-interactive, best for CI):
#        DBW_TENANT_ID, DBW_CLIENT_ID, DBW_CLIENT_SECRET
#      The app needs the APPLICATION permission
#      DeviceManagementScripts.ReadWrite.All (admin consented). That is the permission
#      the deviceHealthScripts endpoint actually enforces - not
#      DeviceManagementConfiguration.*, which governs other Intune resources.
#   2. Azure CLI delegated token:
#        zsh scripts/intune-login.sh
#      The signed-in account needs both the Graph scope above and an Intune role that
#      can manage remediations (Intune Administrator, or a custom role with the
#      device-scripts permissions).
#
# Multiple identities: if your Intune access lives on a different account from the one
# you normally use with az, set DBW_AZURE_CONFIG_DIR to a dedicated Azure CLI profile
# directory. Every az call here then runs against that profile, so your day-to-day
# 'az login' is never switched, clobbered or accidentally used to change Intune.
# Set DBW_EXPECT_UPN to have the scripts refuse to run as anyone else.
#
# Both are read from a gitignored .dbw.env in the repo root if present, so you do not
# have to remember to export them. See .dbw.env.example.
# ---------------------------------------------------------------------------------

GRAPH_BASE="https://graph.microsoft.com/beta"

# Per-checkout defaults. Callers set ROOT_DIR before sourcing this file.
if [[ -n "${ROOT_DIR:-}" && -f "${ROOT_DIR}/.dbw.env" ]]; then
  source "${ROOT_DIR}/.dbw.env"
fi

graph_die() { print -u2 -- "graph: ERROR: $*"; exit 1 }
graph_info() { print -- "graph: $*" }

graph_require_tools() {
  command -v curl >/dev/null 2>&1 || graph_die "curl is required"
  command -v jq   >/dev/null 2>&1 || graph_die "jq is required (brew install jq)"
}

# Runs the Azure CLI against the dedicated profile directory when one is configured,
# leaving the caller's normal 'az login' session completely untouched.
graph_az() {
  if [[ -n "${DBW_AZURE_CONFIG_DIR:-}" ]]; then
    AZURE_CONFIG_DIR="${DBW_AZURE_CONFIG_DIR}" az "$@"
  else
    az "$@"
  fi
}

# Decodes base64url (JWT) payloads on both macOS and GNU coreutils.
graph_b64url_decode() {
  local data="${1//-/+}"
  data="${data//_//}"
  case $(( ${#data} % 4 )) in
    2) data="${data}==" ;;
    3) data="${data}=" ;;
  esac
  printf '%s' "$data" | base64 -d 2>/dev/null || printf '%s' "$data" | base64 -D 2>/dev/null
}

# graph_jwt_claim TOKEN CLAIM -> the claim value, or empty.
# Reads the unverified payload purely to report which identity is about to make
# changes; it is never used to make a trust decision.
graph_jwt_claim() {
  local token="$1" claim="$2"
  [[ "$token" == *.*.* ]] || return 0
  local payload="${token#*.}"
  payload="${payload%%.*}"
  [[ -n "$payload" ]] || return 0
  graph_b64url_decode "$payload" | jq -r --arg c "$claim" '.[$c] // empty' 2>/dev/null
}

# Prints who the token belongs to and refuses to continue if DBW_EXPECT_UPN is set
# and does not match. This is the guard against deploying as the wrong account.
graph_assert_identity() {
  local token="$1"
  local upn appid tid who scp roles

  upn="$(graph_jwt_claim "$token" upn)"
  [[ -n "$upn" ]] || upn="$(graph_jwt_claim "$token" unique_name)"
  appid="$(graph_jwt_claim "$token" appid)"
  tid="$(graph_jwt_claim "$token" tid)"

  if [[ -n "$upn" ]]; then
    who="$upn"
  elif [[ -n "$appid" ]]; then
    who="app registration ${appid}"
  else
    who="unknown identity"
  fi
  graph_info "acting as: ${who}${tid:+ (tenant ${tid})}"

  if [[ -n "${DBW_EXPECT_UPN:-}" ]]; then
    if [[ -z "$upn" ]]; then
      graph_die "DBW_EXPECT_UPN is set to ${DBW_EXPECT_UPN} but this is not a user token (${who}). Unset DBW_EXPECT_UPN to use an app registration."
    fi
    if [[ "${upn:l}" != "${DBW_EXPECT_UPN:l}" ]]; then
      graph_die "refusing to continue: signed in as ${upn}, expected ${DBW_EXPECT_UPN}. Run 'zsh scripts/intune-login.sh' to sign in with the Intune account."
    fi
  fi

  scp="$(graph_jwt_claim "$token" scp)"
  roles="$(graph_jwt_claim "$token" roles)"
  # deviceHealthScripts enforces DeviceManagementScripts.*; accept the Configuration
  # family too, since other Intune endpoints use it and tenants sometimes grant both.
  if [[ -n "$scp" && "$scp" != *DeviceManagementScripts* && "$scp" != *DeviceManagementConfiguration* ]]; then
    print -u2 -- "graph: WARNING: this token carries no Intune device-management scope, so calls will fail with 403."
    print -u2 -- "graph:          scopes: ${scp}"
    print -u2 -- "graph:          Remediations need DeviceManagementScripts.ReadWrite.All. Grant the Azure CLI app"
    print -u2 -- "graph:          consent for it, or use an app registration (see README)."
  elif [[ -z "$scp" && -n "$roles" && "$roles" != *DeviceManagementScripts* && "$roles" != *DeviceManagementConfiguration* ]]; then
    print -u2 -- "graph: WARNING: this app registration has no Intune device-management role; calls will fail with 403."
    print -u2 -- "graph:          roles: ${roles}"
    print -u2 -- "graph:          Grant it the DeviceManagementScripts.ReadWrite.All APPLICATION permission with admin consent."
  fi
}

graph_token() {
  if [[ -n "${DBW_GRAPH_TOKEN:-}" ]]; then
    print -- "$DBW_GRAPH_TOKEN"
    return 0
  fi

  if [[ -n "${DBW_TENANT_ID:-}" && -n "${DBW_CLIENT_ID:-}" && -n "${DBW_CLIENT_SECRET:-}" ]]; then
    local response
    response="$(curl -sS -X POST \
      "https://login.microsoftonline.com/${DBW_TENANT_ID}/oauth2/v2.0/token" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "client_id=${DBW_CLIENT_ID}" \
      --data-urlencode "client_secret=${DBW_CLIENT_SECRET}" \
      --data-urlencode 'scope=https://graph.microsoft.com/.default' \
      --data-urlencode 'grant_type=client_credentials')" || graph_die "token request failed"

    local token
    token="$(print -- "$response" | jq -r '.access_token // empty')"
    [[ -n "$token" ]] || graph_die "client credentials flow failed: $(print -- "$response" | jq -r '.error_description // .')"
    print -- "$token"
    return 0
  fi

  command -v az >/dev/null 2>&1 || graph_die \
    "no credentials. Either export DBW_TENANT_ID/DBW_CLIENT_ID/DBW_CLIENT_SECRET, or install the Azure CLI and run 'zsh scripts/intune-login.sh'."

  local -a args
  args=(account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
  if [[ -n "${DBW_TENANT_ID:-}" ]]; then
    args+=(--tenant "${DBW_TENANT_ID}")
  fi

  local token
  token="$(graph_az "${args[@]}" 2>/dev/null)" \
    || graph_die "az account get-access-token failed${DBW_AZURE_CONFIG_DIR:+ for profile ${DBW_AZURE_CONFIG_DIR}}. Run 'zsh scripts/intune-login.sh' first."
  [[ -n "$token" ]] || graph_die "Azure CLI returned an empty token"
  print -- "$token"
}

# graph_request METHOD PATH [BODY_FILE]
# Prints the response body. Exits non-zero (with the error shown) on HTTP >= 400.
graph_request() {
  # NOTE: neither 'path' nor 'status' may be used as variable names here. In zsh 'path'
  # is tied to $PATH as an array, so a local 'path' wipes command lookup for the whole
  # function, and 'status' is a read-only alias for $?. Both fail only at runtime.
  local method="$1" request_path="$2" body_file="${3:-}"
  local url="$request_path"
  [[ "$url" == http* ]] || url="${GRAPH_BASE}${request_path}"

  local tmp http_status
  tmp="$(mktemp "${TMPDIR:-/tmp}/dbw-graph.XXXXXX")" || {
    print -u2 -- "graph: could not create a temporary file"
    return 1
  }

  if [[ -n "$body_file" ]]; then
    http_status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H "Authorization: Bearer ${GRAPH_TOKEN}" \
      -H 'Content-Type: application/json' \
      --data-binary "@${body_file}")"
  else
    http_status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H "Authorization: Bearer ${GRAPH_TOKEN}")"
  fi

  if [[ -z "$http_status" ]]; then
    print -u2 -- "graph: ${method} ${request_path} -> no response from curl"
    rm -f "$tmp"
    return 1
  fi

  if (( http_status >= 400 )); then
    print -u2 -- "graph: ${method} ${request_path} -> HTTP ${http_status}"
    # Redirection order matters: send stdout to stderr FIRST, then silence jq's own
    # stderr. Reversing them points stdout at an already-nulled stderr and the message
    # disappears.
    jq -r '.error.message // .' "$tmp" >&2 2>/dev/null || cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi

  cat "$tmp"
  rm -f "$tmp"
  return 0
}

# graph_b64 FILE  -> base64 of the file with no line breaks (macOS + Linux).
graph_b64() {
  base64 < "$1" | tr -d '\n'
}

# graph_group_id NAME_OR_ID -> object id of an Entra ID group
graph_group_id() {
  local value="$1"
  if [[ "$value" =~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' ]]; then
    print -- "$value"
    return 0
  fi

  local escaped response id
  escaped="${value//\'/\'\'}"
  response="$(graph_request GET "/groups?\$filter=displayName eq '${escaped}'&\$select=id,displayName")" \
    || graph_die "group lookup failed for '$value'"

  local count
  count="$(print -- "$response" | jq '.value | length')"
  (( count == 1 )) || graph_die "expected exactly one group named '$value', found ${count}. Pass the group object id instead."
  id="$(print -- "$response" | jq -r '.value[0].id')"
  print -- "$id"
}

# graph_find_health_script DISPLAY_NAME -> id, or empty
graph_find_health_script() {
  local name="$1" response
  response="$(graph_request GET "/deviceManagement/deviceHealthScripts?\$select=id,displayName")" \
    || graph_die "could not list remediation scripts"
  print -- "$response" | jq -r --arg n "$name" '.value[] | select(.displayName == $n) | .id' | head -n 1
}
