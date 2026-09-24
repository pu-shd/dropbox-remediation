#!/usr/bin/env zsh
# ---------------------------------------------------------------------------------
# Runs the full test suite in a Docker container (the same image CI uses).
#
#   scripts/test.sh                 # build image if needed, run everything
#   scripts/test.sh --rebuild       # force a fresh image
#   scripts/test.sh --local         # run against locally installed pwsh + Pester
#   scripts/test.sh tests/Payload.Tests.ps1
# ---------------------------------------------------------------------------------
set -eu
set -o pipefail

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="${SCRIPT_DIR:h}"
cd "$ROOT_DIR"

REBUILD=0
LOCAL=0
TEST_PATH=""

while (( $# > 0 )); do
  case "$1" in
    --rebuild) REBUILD=1 ;;
    --local)   LOCAL=1 ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) TEST_PATH="$1" ;;
  esac
  shift
done

mkdir -p "$ROOT_DIR/build"

if (( LOCAL )); then
  command -v pwsh >/dev/null 2>&1 || { print -u2 -- "test: pwsh not found; install PowerShell 7 or drop --local"; exit 1 }
  print -- "test: running locally with $(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')"
  if [[ -n "$TEST_PATH" ]]; then
    exec pwsh -NoLogo -NoProfile -File "$ROOT_DIR/tests/Invoke-Tests.ps1" -Path "$TEST_PATH" -MinimumTests 1
  fi
  exec pwsh -NoLogo -NoProfile -File "$ROOT_DIR/tests/Invoke-Tests.ps1"
fi

command -v docker-compose >/dev/null 2>&1 || { print -u2 -- "test: docker-compose not found"; exit 1 }

if (( REBUILD )); then
  print -- "test: rebuilding the test image"
  docker-compose build --no-cache tests
else
  docker-compose build tests
fi

if [[ -n "$TEST_PATH" ]]; then
  exec docker-compose run --rm tests -Path "/work/$TEST_PATH" -MinimumTests 1
fi

exec docker-compose run --rm tests
