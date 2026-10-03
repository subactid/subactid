# Signing keys

Subact ID signs every token and every audit checkpoint with ES256 (ECDSA on P-256). This page covers
making a key, configuring it, rotating it and losing it.

Two rules:

- **Subact ID never generates a key for you**, except an ephemeral one in the `Development`
  environment. Anywhere else, the server does not start without a key.
- **Keep a retired key published until every token it signed has expired.** A token whose key is
  no longer published fails verification.

## Making the first key

```sh
SubactId.Server keys generate --out /run/secrets/subactid/active.pem
```

This reads no configuration, so it works before any deployment exists. It writes an unencrypted
PKCS#8 PEM readable only by its owner, refuses to overwrite an existing file, and prints the key
id and the setting to use:

```
Wrote a new P-256 signing key to /run/secrets/subactid/active.pem, readable by its owner only.
Key id: ORGq_6TVhUM63Slvc6zMo9W6D2CaI4W-WitEHnPnO2Q (RFC 7638 thumbprint)

Configure the server with:
    SubactId__Signing__Keys__0__Path=/run/secrets/subactid/active.pem
```

The key id (`kid`) is the RFC 7638 thumbprint of the public key. Verifiers use it to pick the key
from JWKS. To choose the id yourself, pass `--kid <name>`; the command then also prints
`SubactId__Signing__Keys__0__Kid=<name>`. The thumbprint is the better default because two different
keys never share one.

The private key is never printed.

To see the JWKS the configured keys publish, and which key is active:

```sh
SubactId.Server keys
```

## Configuring keys

| Setting | What it is |
|---|---|
| `SubactId__Signing__Keys__N__Path` | Path to a PEM file, typically a mounted secret. |
| `SubactId__Signing__Keys__N__Pem` | The PEM inline. Set exactly one of `Path` or `Pem` per key. |
| `SubactId__Signing__Keys__N__Kid` | An explicit key id. Omit it to use the RFC 7638 thumbprint. |
| `SubactId__Signing__ActiveKid` | The key to sign with. Required when more than one key is configured. |

Every configured key is published in JWKS. Only the active key signs. `N` is a number from `0`;
gaps are allowed, and keys are read in numeric order. With one key, `ActiveKid` is optional. With
two or more, the server does not start until it is set.

In Kubernetes, mount the PEM from a Secret. See [Kubernetes](kubernetes.md).

## Rotating a key

```sh
SubactId.Server keys rotate --out /run/secrets/subactid/next.pem
```

This loads the configured keys as the server would, writes a new key file, and prints the
settings for each step below. It changes nothing else.

Roll it out in three deploys, in this order.

**Step 1: publish the new key without signing with it.** Add the new key and set `ActiveKid` to
the current key:

```
SubactId__Signing__Keys__1__Path=/run/secrets/subactid/next.pem
SubactId__Signing__ActiveKid=<the current key id>
```

Both keys are now in JWKS and tokens are still signed by the old one. `ActiveKid` is required
here even if it was unset before, because there are now two keys. Deploy, then wait for
verifiers to refresh their cached JWKS. A verifier that has not seen the new key rejects tokens
signed with it.

**Step 2: sign with the new key.**

```
SubactId__Signing__ActiveKid=<the new key id>
```

New tokens are signed by the new key. Tokens signed by the old key still verify, because it is
still published.

**Step 3 (optional): stop publishing the old key.** Remove its `SubactId__Signing__Keys__N__*`
settings (`rotate` prints the number) and delete the file. Do this only after the wait `rotate`
prints has passed since step 2. The wait is:

- the largest `max_token_ttl` of any registered agent, disabled agents included; or
- `SubactId:Tokens:DefaultTokenTtl` if no agent is registered; or
- `SubactId:Agents:MaxTokenTtl` if the registry cannot be read.

Waiting longer is always safe.

### Retired keys and the audit ledger

Audit checkpoints (§7 of [the spec](spec/v0.1.md)) are signed with the active key. A checkpoint
verifies only while its key is published. If you remove a key that was ever active:

- `audit-verify` reports the first checkpoint that key signed as a bad signature and checks
  nothing after it.
- Inclusion proofs for records under those checkpoints cannot be checked.
- Archived months sealed by that key cannot be verified either, because an export is checked
  against the published key set.

So for a routine rotation, skip step 3: keep the old key configured. It signs nothing and stays
in JWKS so old checkpoints still verify. If you archive the ledger, keep every key that was ever
active for as long as you keep the exports. If you do remove a key, record the last checkpoint
`audit-verify` reports first.

## Losing a key

A lost key cannot be recovered. Every token it signed becomes unverifiable. Run `keys generate`,
configure the new key and restart; agents holding old tokens must exchange again.

If a key is disclosed, treat every token it signed as compromised:

1. Generate a new key and make it active at once.
2. Remove the disclosed key without waiting.
3. Revoke the affected tasks.
4. Keep the last checkpoint `audit-verify` reported before the disclosure. Checkpoints signed by
   the disclosed key can no longer be trusted or verified, so the seal starts again from the
   first checkpoint the new key signs.

Store keys in a secret store that is backed up and audited, mount them read-only, and never
commit them.

## Not in v0.1

Keys held in a KMS (Vault Transit, AWS KMS, Azure Key Vault) are not supported. The signing key
is a file.
