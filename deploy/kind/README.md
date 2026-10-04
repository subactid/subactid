# Trying the chart in kind

CI lints the chart, checks that it refuses bad values, and validates the rendered manifests
against the Kubernetes schemas. It never installs the chart. This harness does. Run it before a
release, or after changing the chart, the Dockerfile or the server's configuration keys.

```sh
kind create cluster --name subactid
docker build -t subactid:kind .
kind load docker-image subactid:kind --name subactid

kubectl apply -f deploy/kind/dependencies.yaml
kubectl -n subactid rollout status deployment/postgres deployment/keycloak --timeout=5m

kubectl -n subactid create secret generic subactid-db \
  --from-literal=connection-string='Host=postgres;Database=subactid;Username=subactid;Password=kind-only'
kubectl -n subactid create secret generic subactid-db-migrate \
  --from-literal=connection-string='Host=postgres;Database=subactid;Username=subactid;Password=kind-only'
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out active.pem
kubectl -n subactid create secret generic subactid-signing --from-file=active.pem && rm active.pem
kubectl -n subactid create secret generic subactid-admin --from-literal=api-key="$(openssl rand -hex 32)"

helm install subactid deploy/helm/subactid -n subactid -f deploy/kind/values.yaml --wait --timeout 5m
helm test subactid -n subactid
```

The install has the NetworkPolicy enabled. Pods that become ready have reached the database,
loaded the signing key and fetched Keycloak's keys through it.

Postgres starts with a role of its own for Subact ID, `subactid`, that owns the database and is
not a superuser. Both database Secrets name it. Postgres answers every privilege check with yes
for a superuser, so with the image's bootstrap account `doctor` would report the ledger's revoked
privileges as still held, and `helm test` would fail on a guard that is in place.

Everything here is throwaway. The credentials protect nothing, Postgres and Keycloak keep no
data past the pod, and `kind delete cluster --name subactid` removes it all.

If the install hangs, the events say why:

```sh
kubectl -n subactid get pods,jobs -o wide
kubectl -n subactid describe jobs -l app.kubernetes.io/component=migrate
kubectl -n subactid get events --sort-by=.lastTimestamp | tail -40
```

See [Running on Kubernetes](../../docs/kubernetes.md) for the chart itself.
