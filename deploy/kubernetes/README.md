# Reference deployment

Files to copy and adapt for a production install of the chart in [`../helm/subactid`](../helm/subactid):

| File | What it is |
|---|---|
| `values.yaml` | Annotated chart values for a production install |
| `external-secret.yaml` | The Secrets the chart reads, projected from a secret manager with the External Secrets Operator |
| `agent.yaml` | An annotated agent registration, for `SubactId.Server agent apply` |

[Running on Kubernetes](../../docs/kubernetes.md) covers the install, the required values,
migrations and key rotation.
