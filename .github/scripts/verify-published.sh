#!/usr/bin/env bash
# Checks that what GHCR serves for a stable release is what the release workflow signed, and
# names the image digest to scan.
#
#   verify-published.sh <version>   checks the image tags and the chart of MAJOR.MINOR.PATCH
#
# The release pushes a stable version's image under three tags, <version>, <major.minor> and
# latest, and signs the one digest they share. Tags can be moved, so this resolves all three
# again and fails if they have come apart, naming the tag that differs. It then verifies the
# digest with cosign against the identity the release run for this version had, which is
# release.yml on the tag v<version>, so a signature from any other run of the workflow does not
# count. The chart at <version> is verified the same way, and the image's GitHub build
# provenance with gh attestation verify. The digest that passed is printed last and, in a
# workflow, written to GITHUB_OUTPUT as "digest", so that what gets scanned is that digest and
# not a tag that may move in the meantime.
#
# Needs docker, cosign and gh, with GH_TOKEN set for gh.
set -euo pipefail

version="${1:?usage: verify-published.sh <version>}"
if ! printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "::error title=Not a stable version::'$version' is not MAJOR.MINOR.PATCH. Only a stable release has the latest and major.minor tags."
  exit 1
fi

image=ghcr.io/subactid/subactid
chart=ghcr.io/subactid/charts/subactid
issuer=https://token.actions.githubusercontent.com
# The release run for this version, exactly: the workflow on its tag.
identity="https://github.com/subactid/subactid/.github/workflows/release.yml@refs/tags/v${version}"

# Prints the digest a reference resolves to, which is the hash of the manifest the registry serves.
resolve() {
  local digest
  if ! digest=$(docker buildx imagetools inspect --raw "$1" | sha256sum | cut -d ' ' -f 1); then
    echo "::error title=Cannot resolve $1::the registry did not serve a manifest for $1." >&2
    return 1
  fi
  echo "sha256:${digest}"
}

# Verifies a cosign signature on a reference, made by the release run for this version.
verify() {
  local what="$1" ref="$2"
  if ! cosign verify "$ref" --certificate-oidc-issuer "$issuer" --certificate-identity "$identity"; then
    echo "::error title=The $what does not verify::$ref carries no cosign signature from $identity, so it is not what the release published."
    return 1
  fi
  echo "$ref is signed by $identity"
}

digest=$(resolve "${image}:${version}")
echo "${image}:${version} is ${digest}"

moved=0
for tag in "${version%.*}" latest; do
  other=$(resolve "${image}:${tag}")
  if [ "$other" = "$digest" ]; then
    echo "${image}:${tag} is ${digest}"
  else
    echo "::error title=Tag moved::${image}:${tag} is ${other}, the release ${version} is ${digest}."
    moved=1
  fi
done
if [ "$moved" -ne 0 ]; then
  exit 1
fi

verify image "${image}@${digest}"
verify chart "${chart}:${version}"

if ! gh attestation verify "oci://${image}@${digest}" --owner subactid --cert-identity "$identity"; then
  echo "::error title=The image has no build provenance::GitHub holds no build provenance attestation for ${image}@${digest} from $identity."
  exit 1
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "digest=${digest}" >> "$GITHUB_OUTPUT"
fi
echo "${image}:${version}, :${version%.*} and :latest, and ${chart}:${version}, are what the release signed; scan ${image}@${digest}"
