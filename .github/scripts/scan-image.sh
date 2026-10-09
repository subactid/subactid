#!/usr/bin/env bash
# Scans a container image for known vulnerabilities with Trivy.
#
#   scan-image.sh report <image> <sarif-out>           writes every finding that has a fix as SARIF, and never fails on one
#   scan-image.sh report-unfixed <image> <sarif-out>   writes every finding that has no fix as SARIF, and never fails on one
#   scan-image.sh gate <image>                         fails on a high or critical finding that has a fix
#   scan-image.sh warn <image>                         the same check, as a warning that does not fail
#
# The image may be local (read through the Docker socket) or in a registry, including one on the
# runner itself. For a multi-platform image in a registry, set TRIVY_PLATFORM (for example
# linux/arm64) to choose which one is scanned. Trivy runs from its own image, pinned in
# .github/tools/Dockerfile, so no scanner is installed on the runner. Every mode shares one
# vulnerability database download per job.
#
# A finding with no fixed version is left out of every mode but report-unfixed. Rebuilding cannot
# act on one, and the other modes report it the moment its fix is published, which is when there
# is something to do. Until then it is on record through report-unfixed, which the weekly scan of
# the published image uploads under its own code-scanning category and which gates nothing.
set -euo pipefail

TRIVY=$("$(dirname "$0")/tool-image.sh" trivy)

mode="${1:?usage: scan-image.sh report <image> <sarif-out> | report-unfixed <image> <sarif-out> | gate <image> | warn <image>}"
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
    trivy image --quiet --scanners vuln --ignore-unfixed --format sarif --output "/work/$out" "$image"
    echo "wrote $out"
    ;;
  report-unfixed)
    out="${3:?a path for the SARIF report}"
    # The complement of report: --ignore-unfixed is Trivy's shorthand for ignoring every status
    # but fixed, so ignoring fixed alone leaves exactly the findings report leaves out.
    trivy image --quiet --scanners vuln --ignore-status fixed --format sarif --output "/work/$out" "$image"
    echo "wrote $out"
    ;;
  gate)
    # Only a high or critical finding fails the run; the report mode covers every severity.
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
