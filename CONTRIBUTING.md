# Contributing

## Who contributes

Changes come from members of the subactid GitHub organization, on branches of this repository.
A pull request from outside the organization is closed by a workflow without review, and issues
and comments are limited to collaborators. This is a control plane for delegated authority, and
the people who change it are known to the maintainers.

From outside the organization:

- To report a bug, email support@subactid.com with the version or commit, what you did and what
  happened instead.
- To report a vulnerability, follow [`SECURITY.md`](SECURITY.md). Never open an issue for one.
- To ask about joining, email the same address and say what you would like to work on.

## Before you start

Open an issue before writing code for anything non-trivial. This is security infrastructure,
and agreeing on the design first saves a rejected pull request.

## Sign-off and licensing

Sign off every commit (DCO). The `dco` workflow checks every commit in a pull request:

    git commit -s -m "fix: reject widened scopes on refresh"

There is no contributor licence agreement. Your sign-off certifies, under the Developer
Certificate of Origin, that you may contribute the change under the licence that covers the files
it touches: AGPL-3.0-or-later for the server, CC-BY-4.0 for `docs/`, and Apache-2.0 for the
samples, the charts, the deployment files, the quickstart and the bench. `REUSE.toml` records
which applies where. Contributions stay under those licences and are not relicensed.

## Ground rules

- One issue per pull request, and never split an issue across several. Keep diffs small where
  you can; if one is large, say so in the description.
- Use conventional commit messages: `feat:`, `fix:`, `docs:`, `chore:`, `test:`.
- `tests/SubactId.Conformance/` is maintained by the maintainers. If a pull request changes it, it
  changes no server behaviour. See [Conformance](docs/conformance.md).
- A pull request must pass the `ci` workflow: build, format check, unit and integration tests,
  the conformance suite, and the image, quickstart, chart and Keycloak jobs.
- Link documentation pages to each other with relative links. The website rewrites them when it
  copies the pages. Name a file instead of linking it only when the website has no page for it,
  such as a source file or a test.

## Architecture rules

- `SubactId.Core` is the pure domain. It has no I/O and no EF Core or ASP.NET references, and no
  package or project references at all.
- The policy engine is a pure function of the user's scopes, the agent, the requested scopes,
  the audience and the delegation depth, returning allow or deny. It does no I/O.
- Storage is reached only through repository interfaces defined in `SubactId.Core`.
- Migrations are applied by an explicit command, never automatically at startup.

## Local development

To run the whole system on your machine (identity provider, control plane, tool server and an
agent acting for a human):

    cd quickstart
    docker compose up

[`quickstart/README.md`](quickstart/README.md) explains what to watch.

To work on the control plane, run the same checks as CI:

    dotnet build
    dotnet format --verify-no-changes
    dotnet test tests/SubactId.UnitTests
    dotnet test tests/SubactId.IntegrationTests

Name the test projects rather than running `dotnet test` at the root. The solution also holds the
conformance suite, which fails every case unless `SUBACTID_CONFORMANCE_URL` points at a running
server; [Conformance](docs/conformance.md) explains how to run it.

The integration tests start Postgres 18 with Testcontainers, so they need Docker.
[`docs/README.md`](docs/README.md) lists the rest of the documentation.

## Cutting a release

A release is a signed tag:

    git tag -s v0.1.0 -m "v0.1.0" && git push origin v0.1.0

`.github/workflows/release.yml` then:

- runs the whole `ci` workflow on the tagged commit, and publishes nothing unless every job
  passes;
- after `ci` passes on the tag, waits in **Actions** until a reviewer clicks
  **Review deployments → Approve and deploy**;
- takes the version from the tag, which must be `vMAJOR.MINOR.PATCH` or
  `vMAJOR.MINOR.PATCH-prerelease`;
- builds the image for amd64 and arm64 once, with its SBOM and provenance, into a registry on
  the runner. It runs each platform (arm64 under emulation) and scans each with Trivy. A high or
  critical vulnerability with a fix available stops the release before anything is published;
- copies that same image to `ghcr.io/subactid/subactid`, unchanged, so the digest published and
  signed is the one that was run and scanned;
- sets `version` and `appVersion` in the chart from the tag, and publishes the chart to
  `oci://ghcr.io/subactid/charts`. Do not edit them in a pull request;
- signs the image and the chart keylessly with cosign.

A prerelease tag such as `v0.2.0-rc.1` is published only under its own version. It does not
move `latest` or the major.minor tag.

The `image-scan` workflow scans the published `latest` image every week. When it fails, the
release ships a fixable vulnerability: rebuild on the patched base image and cut a patch release.

A version is published once. Re-running the release for a tag that is already published stops
before pushing anything.

The images CI and the release run as tools (Trivy, QEMU's binfmt and the registry) are pinned by
digest in `.github/tools/Dockerfile`, where Dependabot keeps them current. Pin a new one there
and read it with `.github/scripts/tool-image.sh`, never inline.

Postgres and Keycloak are pinned by digest in `quickstart/compose.yaml`, and Postgres in
`bench/compose.yaml`, where Dependabot keeps them current. CI's service containers, the Keycloak
its `keycloak` job starts and the kind manifest name the same images in files Dependabot does not
cover. When it bumps the compose files, bump those by hand in the same pull request, to the digest
`docker buildx imagetools inspect <image:tag>` prints. `.github/scripts/check-image-pins.sh`,
which CI runs, lists every such reference and fails while one differs from the quickstart's; the
integration tests' default image must name the quickstart's tag the same way.

CI lints and renders the chart but never installs it. Before tagging, install it into a kind
cluster with [`deploy/kind/README.md`](deploy/kind/README.md).
