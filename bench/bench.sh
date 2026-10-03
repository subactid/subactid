#!/usr/bin/env bash
# Runs one load generator command, locally or on another machine.
#
#   ./bench.sh setup --users 8
#   ./bench.sh load --shape exchange --rate 100 --warmup 15 --duration 45 --out /results/x.json
#
# By default the generator is a container on this host, on the rig's network. That is how
# docs/sizing.md was measured. At the ceiling it uses about 0.76 of a core on a four-core machine.
#
# Set BENCH_DOCKER_HOST to a Docker endpoint (`ssh://user@host` or `tcp://host:2375`) to run the
# generator there instead. This also needs:
#
#   - RIG_ADDRESS, an address of this host the generator can reach, with RIG_BIND publishing the
#     rig's ports on it. The issuer follows RIG_ADDRESS, since assertion `aud` must match it.
#   - the load generator image on that machine. `BENCH_DOCKER_HOST=... ./rig.sh build` builds it there.
#
# Agent signing keys live in a volume on the generator's machine, so `load` uses the agents an
# earlier `setup` registered. The result file is copied back into results/.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

[ $# -gt 0 ] || { echo "usage: bench.sh <bench arguments>" >&2; exit 2; }

# --no-deps: a run must never start or recreate the instance it measures.
if [ -z "${BENCH_DOCKER_HOST:-}" ]; then
  exec docker compose run --rm --no-deps bench "$@"
fi

if [ -z "${RIG_ADDRESS:-}" ]; then
  cat >&2 <<'EOF'
BENCH_DOCKER_HOST is set but RIG_ADDRESS is not, so the generator has no address to reach the
rig on. Set both, and bring the rig up with the same RIG_ADDRESS and a RIG_BIND that publishes
its ports where the generator can see them:

  export RIG_ADDRESS=10.0.0.5 RIG_BIND=10.0.0.5 BENCH_DOCKER_HOST=ssh://you@generator
EOF
  exit 2
fi

image="${BENCH_IMAGE:-subactid-bench/load-generator:local}"
keys_volume="${BENCH_KEYS_VOLUME:-subactid-bench-keys}"
envfile="$here/.secrets/generator.env"

[ -f "$here/.env" ] || { echo "no $here/.env; run ./rig.sh secrets first" >&2; exit 1; }

# Passes only the credentials the generator needs from .env, never the database passwords.
# --env-file keeps them off the command line on both machines.
set -a
# shellcheck disable=SC1091
. "$here/.env"
set +a

mkdir -p "$here/.secrets"
chmod 700 "$here/.secrets"
(
  umask 077
  cat > "$envfile" <<EOF
SUBACTID_ISSUER=http://$RIG_ADDRESS:5100
SUBACTID_ADMIN_API_KEY=${SUBACTID_ADMIN_API_KEY:?not in .env}
KEYCLOAK_URL=http://$RIG_ADDRESS:8080
KEYCLOAK_REALM=${KEYCLOAK_REALM:-subactid-bench}
KEYCLOAK_CLIENT_ID=${KEYCLOAK_CLIENT_ID:-bench-cli}
KEYCLOAK_ADMIN_USERNAME=${KEYCLOAK_ADMIN_USERNAME:-admin}
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:?not in .env}
BENCH_KEY_DIR=/keys
EOF
)

# The --out path, if any.
out=""
previous=""
for argument in "$@"; do
  [ "$previous" = "--out" ] && out="$argument"
  previous="$argument"
done

remote() { docker -H "$BENCH_DOCKER_HOST" "$@"; }

name="subactid-bench-$(date -u +%Y%m%d%H%M%S)-$$"
cleanup() { remote rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Not --rm, so the result can be copied out after exit. /results is not a mount, because
# `docker cp` does not read a stopped container's volumes. Only the keys are in a volume.
status=0
remote run --name "$name" \
  --env-file "$envfile" \
  --memory "${BENCH_MEM_LIMIT:-1g}" \
  -v "$keys_volume:/keys" \
  "$image" "$@" || status=$?

# A failed run wrote no result.
if [ -n "$out" ] && [ "$status" -eq 0 ]; then
  mkdir -p "$here/results"
  if ! remote cp "$name:$out" "$here/results/$(basename "$out")"; then
    echo "the generator's result could not be copied back from $BENCH_DOCKER_HOST" >&2
    status=1
  fi
fi

exit "$status"
