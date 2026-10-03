# The images CI and the release run as tools, pinned here and nowhere else, so Dependabot's docker
# updater keeps them current. Nothing builds this file: .github/scripts/tool-image.sh reads the
# reference for a stage name.

# Scans images for known vulnerabilities (.github/scripts/scan-image.sh).
FROM aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 AS trivy

# Registers QEMU, so the release can run its arm64 image.
FROM tonistiigi/binfmt:qemu-v10.2.3@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0 AS binfmt

# The registry the release builds into, runs and scans from, then copies to GHCR.
FROM registry:3.1.1@sha256:325b4b29b041e82803abeb703e201655e4e23ab83264ec1a7c9ddb0a5b14a6e0 AS registry

# Checks that every file carries licensing information and every licence named has its text
# (REUSE.toml, LICENSES/). Run by the reuse job in ci.yml.
FROM fsfe/reuse:6.2.0@sha256:85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e AS reuse

# Scans the tree and a pull request's commits for secrets. Run by the gitleaks job in ci.yml.
FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks
