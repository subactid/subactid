# Security policy

## Reporting a vulnerability

Do not open a public issue.

The preferred channel is GitHub's private vulnerability reporting:
[report a vulnerability](https://github.com/subactid/subactid/security/advisories/new). The report
stays private between you and the maintainers until an advisory is published.

If you cannot use GitHub, email support@subactid.com.

Include the affected version or commit, a description of the issue, and reproduction steps if
you have them.

## What to expect

- Acknowledgement within 3 working days.
- An assessment and a planned fix timeline within 10 working days.
- Coordinated disclosure. We ask for 90 days before public disclosure, and usually publish
  sooner once a fix is released.

## Scope

In scope: this repository, which is the control plane: token issuance and validation, the audit
ledger, the Helm chart and the reference deployment files. The SDKs live in a separate
repository, `subactid-sdk` (not public), and are covered by that repository's security policy.

Out of scope:

- Findings that require an already compromised host.
- Issues in the quickstart's Docker Compose configuration, which is a demonstration and is not
  hardened for production.
- Denial of service through unbounded request volume.

## Supported versions

Until the first release, security fixes land on `main` only. After that, during 0.x, only the
latest release receives security fixes.
