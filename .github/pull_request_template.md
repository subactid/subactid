Closes #

## What changed

<!-- What this pull request does and why. If the diff is large, say so here. -->

## Checklist

- [ ] It is linked to an issue, and it is the only pull request for that issue.
- [ ] Every commit is signed off (`git commit -s`), with the author's own email.
- [ ] If it changes `tests/SubactId.Conformance/`, it changes no server behaviour.

### Invariants

- [ ] `sub` is always the human. The agent appears only in the `act` claim.
- [ ] Scope only narrows: at issue, at refresh and at every delegation hop.
- [ ] A token's lifetime never exceeds the task's remaining lifetime.
- [ ] Every authorization decision writes an audit event, including every denial.
- [ ] No secret is logged, returned in an error response, or committed.
