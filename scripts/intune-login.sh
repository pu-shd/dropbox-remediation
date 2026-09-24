#!/usr/bin/env zsh
# ---------------------------------------------------------------------------------
# Signs the Intune-privileged account into a DEDICATED Azure CLI profile.
#
# Use this when your Intune access lives on a different account from the one you
# normally use with az. The login is written to its own AZURE_CONFIG_DIR, so your
# everyday 'az login' session is never switched, clobbered or accidentally used to
# change Intune - and 'az account show' in your normal shell keeps reporting your
# usual identity.
#
#   zsh scripts/intune-login.sh --account intune-admin@contoso.com
#   zsh scripts/intune-login.sh --status
#   zsh scripts/intune-login.sh --logout
#
# On success it writes .dbw.env in the repo root (gitignored) so the deploy, update
# and teardown scripts pick up the right profile and enforce the right identity
# without you having to export anything.
# ---------------------------------------------------------------------------------
set -eu
set -o pipefail

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
source "$SCRIPT_DIR/lib/graph.sh"

ACCOUNT="${DBW_EXPECT_UPN:-}"
PROFILE_DIR="${DBW_AZURE_CONFIG_DIR:-$HOME/.azure-intune}"
TENANT="${DBW_TENANT_ID:-}"
DEVICE_CODE=0
ACTION="login"
WRITE_ENV=1

usage() {
  cat <<'USAGE'
Usage: intune-login.sh [options]

  --account <upn>     Account to sign in with, e.g. intune-admin@contoso.com.
  --tenant <id>       Tenant id or domain. Optional; defaults to the account's home tenant.
  --profile <dir>     Azure CLI profile directory. Default: ~/.azure-intune
  --device-code       Use device-code flow instead of opening a browser.
  --status            Show who this profile is signed in as, then exit.
  --logout            Sign out of this profile and exit.
  --no-env            Do not write .dbw.env.
  -h, --help          This help.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --account)     ACCOUNT="${2:-}"; shift ;;
    --tenant)      TENANT="${2:-}"; shift ;;
    --profile)     PROFILE_DIR="${2:-}"; shift ;;
    --device-code) DEVICE_CODE=1 ;;
    --status)      ACTION="status" ;;
    --logout)      ACTION="logout" ;;
    --no-env)      WRITE_ENV=0 ;;
    -h|--help)     usage; exit 0 ;;
    *) print -u2 -- "intune-login: unknown argument '$1'"; usage; exit 2 ;;
  esac
  shift
done

command -v az >/dev/null 2>&1 || graph_die "the Azure CLI is required (brew install azure-cli)"
command -v jq >/dev/null 2>&1 || graph_die "jq is required (brew install jq)"

export DBW_AZURE_CONFIG_DIR="$PROFILE_DIR"

case "$ACTION" in
  logout)
    if [[ ! -d "$PROFILE_DIR" ]]; then
      graph_info "no profile at ${PROFILE_DIR}; nothing to do"
      exit 0
    fi
    graph_az logout 2>/dev/null || true
    rm -rf "$PROFILE_DIR"
    graph_info "signed out and removed ${PROFILE_DIR}"
    exit 0
    ;;

  status)
    [[ -d "$PROFILE_DIR" ]] || graph_die "no Intune profile at ${PROFILE_DIR}. Run: zsh scripts/intune-login.sh --account <upn>"
    SIGNED_IN="$(graph_az account show --query user.name -o tsv 2>/dev/null || true)"
    [[ -n "$SIGNED_IN" ]] || graph_die "profile ${PROFILE_DIR} is not signed in"
    graph_info "profile   : ${PROFILE_DIR}"
    graph_info "signed in : ${SIGNED_IN}"
    TOKEN="$(graph_token)"
    graph_assert_identity "$TOKEN"
    exit 0
    ;;
esac

[[ -n "$ACCOUNT" ]] || graph_die "--account is required (e.g. --account intune-admin@contoso.com)"

mkdir -p "$PROFILE_DIR"
chmod 700 "$PROFILE_DIR"

# --allow-no-subscriptions matters: an Intune-only admin account frequently has no
# Azure subscription, and without this az treats the login as a failure.
LOGIN_ARGS=(login --allow-no-subscriptions --username "$ACCOUNT" --only-show-errors)
if [[ -n "$TENANT" ]]; then
  LOGIN_ARGS+=(--tenant "$TENANT")
fi
if (( DEVICE_CODE )); then
  LOGIN_ARGS+=(--use-device-code)
fi

graph_info "signing in as ${ACCOUNT} into profile ${PROFILE_DIR}"
graph_az "${LOGIN_ARGS[@]}" >/dev/null || graph_die "az login failed"

SIGNED_IN="$(graph_az account show --query user.name -o tsv 2>/dev/null || true)"
[[ -n "$SIGNED_IN" ]] || graph_die "login appeared to succeed but the profile has no active account"

if [[ "${SIGNED_IN:l}" != "${ACCOUNT:l}" ]]; then
  graph_die "signed in as ${SIGNED_IN}, not ${ACCOUNT}. Sign out of the browser session and retry, or use --device-code."
fi

# Prove the account can actually get a Graph token with usable scopes before
# declaring success - a login that cannot call Intune is not a working login.
TOKEN="$(graph_token)"
DBW_EXPECT_UPN="$ACCOUNT" graph_assert_identity "$TOKEN"

if (( WRITE_ENV )); then
  ENV_FILE="$ROOT_DIR/.dbw.env"
  cat > "$ENV_FILE" <<ENV
# Written by scripts/intune-login.sh. Gitignored.
# Sourced by scripts/lib/graph.sh so the deploy/update/teardown scripts use the
# Intune identity's own Azure CLI profile and refuse to run as anyone else.
export DBW_AZURE_CONFIG_DIR="${PROFILE_DIR}"
export DBW_EXPECT_UPN="${ACCOUNT}"
ENV
  chmod 600 "$ENV_FILE"
  graph_info "wrote ${ENV_FILE}"
fi

cat <<SUMMARY

intune-login: ready.
  profile : ${PROFILE_DIR}
  account : ${SIGNED_IN}

Your normal 'az login' session is untouched - 'az account show' in this shell still
reports whatever it did before. The deploy, update and teardown scripts will now use
the profile above and refuse to run as any other account.
SUMMARY
