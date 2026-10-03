#!/usr/bin/env bash
# Checks that every reference to the Postgres and Keycloak images names the one the quickstart
# runs. Dependabot keeps quickstart/compose.yaml current, but the references below are in files
# its docker and docker-compose ecosystems do not cover, so they are bumped by hand, and this
# fails the run while one of them is left behind.
#
#   check-image-pins.sh    prints every reference it checked; exits 1 naming each one that differs
#
# A reference pinned by digest must match the quickstart's exactly. One that names only a tag,
# such as the default Testcontainers starts, must name the quickstart's tag, so that a move to a
# new major version reaches it too. The oldest supported Postgres, which the postgres-16 job runs
# on purpose, is not a copy of the quickstart's and is not checked.
set -euo pipefail

cd "$(dirname "$0")/../.."

quickstart=quickstart/compose.yaml

# Prints the image of a service in the quickstart's compose file.
service_image() {
  awk -v service="$1:" '
    { sub(/\r$/, "") }  # a checkout on Windows may have CRLF endings
    /^ *#/ { next }
    /^[^ ]/ { top = $1 }
    top == "services:" && /^  [^ ]/ { current = $1 }
    top == "services:" && current == service && $1 == "image:" { print $2; exit }
  ' "$quickstart"
}

postgres=$(service_image postgres)
keycloak=$(service_image keycloak)
for reference in "$postgres" "$keycloak"; do
  case "$reference" in
    *@sha256:*) ;;
    *)
      echo "::error file=$quickstart,title=Image not pinned::the quickstart's '$reference' is not pinned by digest, so there is nothing to check the other references against."
      exit 1 ;;
  esac
done

failed=0

# check <file> <line pattern> <expected>: every line of the file matching the pattern must name
# the expected reference, which runs from the repository name to the next space or quote.
check() {
  local file="$1" pattern="$2" expected="$3" repository="${3%%:*}" found entry line reference
  found=$(awk -v pattern="$pattern" -v repository="$repository" '
    { sub(/\r$/, "") }
    $0 ~ pattern && match($0, repository ":[^ \"]+") { print NR ":" substr($0, RSTART, RLENGTH) }
  ' "$file")
  if [ -z "$found" ]; then
    echo "::error file=$file,title=Image reference not found::no line of $file matches '$pattern'. If the reference moved, update .github/scripts/check-image-pins.sh."
    failed=1
    return
  fi
  while IFS= read -r entry; do
    line=${entry%%:*}
    reference=${entry#*:}
    if [ "$reference" = "$expected" ]; then
      echo "$file:$line names $reference"
    else
      echo "::error file=$file,line=$line,title=Image pin differs from the quickstart's::$file names $reference, the quickstart $expected. Dependabot does not bump this file; bump it by hand (CONTRIBUTING.md)."
      failed=1
    fi
  done <<< "$found"
}

tag=${postgres%%@*}

# The service containers, and the Keycloak the keycloak job starts for the Terraform module.
check .github/workflows/ci.yml '^ *image: postgres:' "$postgres"
check .github/workflows/ci.yml 'quay.io/keycloak/keycloak:' "$keycloak"
# The sizing rig. Dependabot bumps it, in the same pull request as the quickstart.
check bench/compose.yaml '^ *image: postgres:' "$postgres"
# The kind cluster the chart is tried in.
check deploy/kind/dependencies.yaml '^ *image: postgres:' "$tag"
check deploy/kind/dependencies.yaml '^ *image: quay.io/keycloak/keycloak:' "$keycloak"
# What Testcontainers starts for the integration tests when no image is named.
check tests/SubactId.IntegrationTests/PostgresDatabaseFixture.cs 'DefaultImage = "postgres:' "$tag"

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "every reference names the quickstart's $postgres and $keycloak"
