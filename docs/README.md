# Documentation

The spec is the contract. If a page here disagrees with it, the spec is right.

## Start here

- [`../README.md`](../README.md): what Subact ID is, what it guarantees, and a first deployment.
- [`../quickstart/README.md`](../quickstart/README.md): the whole system on one machine in one command.
- [Concepts](concepts.md): delegation, tasks, scope, audiences, depth and the ledger.
- [The v0.1 API surface](spec/v0.1.md): endpoints, claims, the audit record and error codes.
- [Revocation](revocation.md): local validation or per-call introspection, and how to choose per audience.

## Running it

In the order an install usually happens:

1. [Storage](storage.md): Postgres or the embedded database, migrations and retention.
2. [Signing keys](keys.md): making, configuring and rotating the signing key.
3. [Keycloak](keycloak.md): configuring the identity provider, and the realm as code.
4. [Kubernetes](kubernetes.md): the Helm chart, its required values and upgrades.
5. [SCIM provisioning](scim.md): receiving deactivations from a SCIM client. Optional.
6. [Shared Signals](shared-signals.md): receiving CAEP and RISC security events. Optional.
7. [Agents as files](gitops.md): `agent init`, `agent apply` and the CI job around them.

## Reference

- [Configuration](configuration.md): every setting, its environment variable, default and accepted values.
- [Sizing](sizing.md): cost per request, what one instance serves, and its limits.
- [Admin API](admin-api.md): the agent registry, kill switches and audit query.
- [Conformance](conformance.md): the twenty adversarial tests and how to run them against a live instance.

## Licence of these pages

Everything under `docs/`, the spec included, is licensed CC-BY-4.0: copy, quote or translate it
with attribution, and build other implementations on the spec. The server itself is
AGPL-3.0-or-later, and `REUSE.toml` at the root of the repository records which licence covers
each path.

## Running a modified version

Subact ID is licensed AGPL-3.0-or-later. If you modify it and let people use your modified version
over a network, section 13 of the licence requires you to offer those users the Corresponding
Source of your version, for example through a link on a page they can reach. Running an
unmodified release adds no such duty. The full terms are in `LICENSE` at the root of the
repository.

## Elsewhere in the repository

- [`../samples`](../samples): a tool server, an agent and a portal written without a library.
- [`../tests/SubactId.Conformance`](../tests/SubactId.Conformance): the conformance tests.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md): how to propose a change.
- [`../SECURITY.md`](../SECURITY.md): how to report a vulnerability.
