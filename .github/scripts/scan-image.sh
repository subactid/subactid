#!/usr/bin/env bash
# Scans a container image for known vulnerabilities with Trivy.
#
#   scan-image.sh report <image> <sarif-out>   writes every finding as SARIF, and never fails on one
#   scan-image.sh gate <image>                 fails on a high or critical finding that has a fix
#   scan-image.sh warn <image>                 the same check, as a warning that does not fail
#
# The image may be local (read through the Docker socket) or in a registry, including one on the
# runner itself. For a multi-platform image in a registry, set TRIVY_PLATFORM (for example
# linux/arm64) to choose which one is scanned. Trivy runs from its own image, pinned in
# .github/tools/Dockerfile, so no scanner is installed on the runner. Every mode shares one
# vulnerability database download per job.
set -euo pipefail

TRIVY=$("$(dirname "$0")/tool-image.sh" trivy)

mode="${1:?usage: scan-image.sh report <image> <sarif-out> | gate <image> | warn <image>}"
image="${2:?an image to scan}"

cache="${RUNNER_TEMP:-/tmp}/trivy-cache"
mkdir -p "$cache"

trivy() {
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$cache:/root/.cache/trivy" \
    -v "$PWD:/work" -w /work \
    --network host \
    -e TRIVY_PLATFORM \
    "$TRIVY" "$@"
}

case "$mode" in
  report)
    out="${3:?a path for the SARIF report}"
    # Relative to the working directory, which the container sees as /work.
    trivy image --quiet --scanners vuln --format sarif --output "/work/$out" "$image"
    echo "wrote $out"
    ;;
  gate)
    # Only findings with a fixed version fail the run: a finding with no fix cannot be acted on
    # by rebuilding, and is still in the report.
    trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$image"
    ;;
  warn)
    # For pull requests: a finding in the base image is not something a change can fix, so it is
    # reported here and blocks only the release and the weekly scan of what was published.
    if ! trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$image"; then
      echo "::warning title=Fixable vulnerability in the image::$image has a high or critical vulnerability with a fix available. A release of it would be refused until the base image is rebuilt."
    fi
    ;;
  *)
    echo "unknown mode '$mode'" >&2
    exit 2
    ;;
esac
