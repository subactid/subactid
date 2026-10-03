# The sizing rig

The numbers in [docs/sizing.md](../docs/sizing.md) were measured with what is in this directory,
when it ran Postgres 16. It now runs Postgres 18, and they have not been measured again on it yet.
Re-run it to check them, or to size for your own hardware.

## What it is

Four containers on one host, described by [compose.yaml](compose.yaml):

| | |
|---|---|
| `subactid` | The control plane, built from the repository's [Dockerfile](../Dockerfile), the same image a release publishes. .NET 10, `Release`, Server GC. |
| `postgres` | Postgres 18 with [postgres/postgresql.conf](postgres/postgresql.conf) rather than the packaged defaults. |
| `keycloak` | Keycloak 26.7.4, built from the release tarball by [keycloak/Dockerfile](keycloak/Dockerfile) with its checksum pinned. |
| `bench` | The load generator, [SubactId.Bench](SubactId.Bench). No dependencies beyond the platform. It runs on the same host unless you [move it](#running-the-generator-on-another-machine). |

The rig runs the control plane the way a deployment does:

- Migrations are applied by the explicit `migrate` command before the server starts.
- `ASPNETCORE_ENVIRONMENT` is `Production`, so a missing signing key stops startup.
- `rig.sh` generates the signing key and admin API key into `.secrets/` and `.env`. Both are
  ignored by git.
- The control plane connects to Postgres as an ordinary login role, not a superuser. A superuser
  bypasses the ledger's `REVOKE` guard, and `doctor` does not call that configuration guarded.
- The sponsor check is in its default `poll` mode, so every exchange calls Keycloak's admin API.
- The Npgsql pool is 100 (`SUBACTID_DB_POOL` changes it).
- Audit aggregation and the one-minute checkpoint interval are at their defaults.
- Logging is at the server's defaults.
- The rate limiter is on in `compose.yaml`, with its limit raised above the offered load.
  `campaign.sh` turns it off for the capacity runs so the ceiling is the service's own, and
  measures the limiter in separate phases.

It differs from a deployment in two ways:

- **No TLS.** Everything speaks http on a private bridge network. A deployment terminates TLS at
  an ingress, and the rig does not measure that hop.
- **Keycloak runs in development mode** with an in-memory database, and its subject tokens last
  an hour. It is a dependency, not the thing under test, and a second Postgres would take cores
  from the measurement. The sponsor check's call to Keycloak is still measured on every exchange.

## Running it

```sh
./preflight.sh          # check this machine is worth measuring on
./rig.sh build          # build the control plane image, Keycloak and the load generator
./rig.sh up             # bring it up and wait for /readyz
./campaign.sh all       # capacity, then growth
```

`./campaign.sh plan` prints the rates it would use without running anything.

| command | what it measures | time |
|---|---|---|
| `./campaign.sh capacity` | what each request costs and where the service stops | about 55 min |
| `./campaign.sh growth` | the soak the ledger's row counts come from | about 27 min |
| `./campaign.sh all` | both, in that order | about 80 min |

Allow another 15 minutes for `./rig.sh build` on a cold machine. Each half empties the database
first: the ladder needs an empty one, and the soak needs one nothing else has written to.

Rates scale with the machine. Each rate is a fraction of an estimated peak: the core count times
about 100 exchanges a second (125 with a remote generator). On four cores that gives a ladder of
1 to 300/s and a ceiling sweep of 350 to 850/s. Override the estimate with `PEAK`, or its two
halves with `CORES` and `PER_CORE`.

If a rung's completed rate falls behind its offered rate while the machine still has idle cores,
the generator ran out, not the service. Move the generator to its own machine or lower `PEAK`.

To run one measurement:

```sh
./bench.sh setup --users 64
./measure.sh my-run -- load --shape exchange --rate 100 --warmup 15 --duration 45
./measure.sh my-idle -- idle 60
./storage-report.sh
```

`bench.sh` is the only script that starts a load generator. `rig.sh reset` empties the database;
`rig.sh down` leaves it.

Behind a network that intercepts TLS, set `BUILD_CA_FILE` to its certificate authority before
`./rig.sh build`.

## Stress runs

[stress.sh](stress.sh) runs the rig past its ceiling and with its dependencies taken away:

```sh
./rig.sh build && ./rig.sh up
CEILING=340 MIX_CEILING=850 ./stress.sh all    # about an hour
```

- `CEILING` is the highest clean exchange rate from a capacity run.
- `MIX_CEILING` is the same for the production mix (70% introspection, 10% each of exchange,
  refresh and JWKS).
- Every stress rate is a fraction of one of them. Without them, `stress.sh` estimates both from
  the core count. `./stress.sh plan` prints the rates.
- `./stress.sh <scenario>` runs one scenario. The script's header lists them: spike, overload,
  limiter, Postgres paused and restarted, Keycloak stopped and frozen, the control plane
  restarted and killed, slow senders, smoke and soak.

[compose.stress.yaml](compose.stress.yaml) adds two things to the rig:

- a restart policy on the control plane, as an orchestrator would provide;
- the per-address introspection limit raised above the offered load, because all load comes from
  the generator's one address. The `limiter` scenario runs the shipped defaults.

After each scenario the script reconciles the audit ledger against the responses the generator
received, and exits non-zero on a mismatch:

- every exchange answered with a token has a `token.issued` record;
- every refresh answered with a token is counted on its grant;
- every refusal the service answered has a denial record.

A `503` for an unreachable database is the one answer with no record, because the ledger is what
could not be reached. The reconciliation counts it separately.

The overload and failure figures in [docs/sizing.md](../docs/sizing.md#what-overload-does-and-why-the-limiter-is-on)
come from a stress run on a 4-vCPU machine with one thread per core, 15.7 GB of memory and a
local disk (fsync p50 0.18 ms), cgroup v1, 0.5% steal. The audit reconciliation passed in every
scenario of that run.

## Running the generator on another machine

By default the generator shares the host with what it measures. At the ceiling it uses about
three quarters of a core of a four-core machine. To give it a machine of its own:

```sh
export RIG_ADDRESS=10.0.0.5           # an address of this host the generator can reach
export RIG_BIND=10.0.0.5              # where to publish the rig's ports
export BENCH_DOCKER_HOST=ssh://you@generator
./rig.sh build                        # also builds the generator image there
./rig.sh up
./campaign.sh all
```

`bench.sh` runs the generator on that Docker endpoint with the same arguments and copies its
result file back into `results/`. The `machine` row then covers the service alone.

What makes this work:

- **The issuer follows `RIG_ADDRESS`.** An agent's `private_key_jwt` has the issuer as its
  `aud`, so the generator must reach the server by the name the server uses for itself.
- **Keycloak's hostname is pinned** to its name on the rig's network, so subject tokens carry
  the issuer the control plane trusts however the generator connects.
- **The agents' keys live in a volume on the generator's machine**, so `load` runs authenticate
  as the agents `setup` registered.

`RIG_BIND` defaults to loopback. The rig is not hardened: Keycloak's bootstrap administrator and
the control plane's admin API are behind those ports. Publish only on a network you trust.

## What the machine has to be

Linux, running the same kernel as the containers. `measure.sh` reads each container's own cgroup
counter. It finds the container's process with `docker inspect`, reads its cgroup path from
`/proc/<pid>/cgroup`, and refuses to sample a path that does not name the container. Both cgroup
versions and both Docker cgroup drivers work.

Docker Desktop on Windows or macOS does not work: its containers run in a separate VM kernel.
On Windows, run Docker Engine inside a WSL2 distribution instead:

```sh
sudo apt-get install -y docker.io docker-compose-v2 git
sudo service docker start
git clone <this repository> ~/subactid && cd ~/subactid/bench
./rig.sh build && ./rig.sh up && ./campaign.sh all
```

- Keep the clone on the distribution's own filesystem, not under `/mnt/c`.
- The rig's containers ask for about 6 GB between them. WSL2 takes half the machine's memory by
  default, so on a 16 GB laptop raise it in `.wslconfig`.
- A laptop on battery, thermally throttled or running a browser reports a busy laptop's ceiling.

## On a rented machine

Run [preflight.sh](preflight.sh) first. It offers no load and starts nothing. It reports what
the campaign would do and flags four things that make results unusable:

- **A burstable instance type** (`t3`, `t4g`, `e2-medium`, `Standard_B*`). It serves low rates
  from banked CPU credit and high ones from a throttle.
- **A vCPU that is half a core.** Most cloud vCPUs are one hyperthread, so eight vCPUs are four
  physical cores.
- **A network disk.** Postgres runs with `synchronous_commit` on, so every commit waits on an
  fsync. A network volume can add several milliseconds to each exchange.
- **A neighbour.** Steal time at the ceiling reads as the service being slow.

Ask for a non-burstable instance with a local SSD, at least 8 GB of memory and a 40 GB root disk,
and put Docker's data root on the SSD. x86_64 keeps results comparable with the sizing page.
Every image the rig uses is also published for arm64, but those numbers are a different
architecture's.

- Keep `RIG_BIND` at its loopback default. A rented machine usually has a public address.
- Do not put a repository token in the instance's user-data or metadata. Clone over SSH with a
  forwarded agent, or copy the checkout up.

## How the numbers are taken

- **Open-model load.** A fixed arrival rate, whether or not earlier requests have returned. A
  closed loop would lower the offered rate as the server slowed and hide the ceiling.
- **Latency from when a request was due**, not from when it was sent. That is what a caller
  sees.
- **Throughput counted where the answer was produced**, not where the request arrived.
- **CPU from the kernel's own accounting.** `measure.sh` differences each container's cgroup CPU
  counter across the measured window. The `machine` row is read from the root cgroup, not
  `/proc/stat`, whose tick-based counts under-report on some machines. Memory is the peak and
  mean resident set over the same window.
- **Warm instances only.** Every run discards a warmup window. After a restart, the campaign
  runs a discarded 60-second load before it measures load. Tiered JIT makes a cold instance look
  several times more expensive, and Keycloak's JVM needs the same warming.
- **Phases that measure memory restart the instance first**, because .NET does not return
  memory after an overload run.
- **Rows per exchange come from one soak.** One population of tasks is never renewed, another is
  renewed until its task ends. Both are then left for more than two task lifetimes, so the
  sweeper writes every terminal record, before the ledger is counted by agent and event.

## The machine behind docs/sizing.md

One 4-vCPU machine with 16 GB of RAM ran everything at once. Postgres used the rig's
`postgresql.conf`: 512 MB `shared_buffers`, `synchronous_commit` on, `max_connections` 200,
checkpoints every 15 minutes with `max_wal_size` 4 GB.

Keep these in mind when reading its numbers:

- **The load generator shares the machine.** At the ceiling it used about 0.76 of a core,
  roughly a fifth of the four. Per-request CPU is measured per container and is unaffected; the ceiling is not.
- **The ceiling varies about 15% between runs.** Two campaigns on the same build put it
  between 326 and 391 exchanges a second.
- **Every latency includes about 2 to 2.5 ms of container networking.**
- **The database is local.** A network hop to Postgres adds to exchange latency.
- **Some figures are carried over from earlier runs** rather than re-measured: the limiter's A/B
  cost, which needs four runs of its own, and the archive state sizes in
  [docs/storage.md](../docs/storage.md).

These are measurements on one machine, not a certification or a claim about your hardware.
