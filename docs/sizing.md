# Sizing

What one instance costs, what it can serve, and where it stops.

Every number here comes from the rig in [`bench/`](../bench/README.md): one 4-vCPU machine with
16 GB of RAM running the control plane, Postgres 16, Keycloak and the load generator at once.
The rig has since moved to Postgres 18, and these numbers have not yet been measured again on it.
Read the numbers as a floor, and re-run the rig on your own hardware before you commit to a
capacity plan. The rig's README describes the machine, its caveats and how to reproduce every
figure.

## The short version

| | |
|---|---|
| Idle, settled | 16 millicores |
| Idle, just started | 38 millicores, 27 MB |
| Ready to serve | 3.2 s from container start |
| A token exchange | 5.9 CPU-ms, 21 database statements, 1 ledger row, ~0.5 KB of storage |
| An introspection | 2.7 CPU-ms, 7 database statements, no ledger row |
| Exchange ceiling | ~350–370/s on this rig, clean to 300/s |
| Introspection ceiling | ~1,200–1,275/s, clean to 900/s |
| Cost of one exchange/s | 4.4 millicores of Subact ID, 2.9 of Postgres, 1.1 of the identity provider |
| Ten exchanges/s | 200m and 512 MiB, database included |
| Three hundred exchanges/s | 2.5 vCPU and 512 MiB |

Issuing a token is expensive. What a tool server does afterwards, introspecting and fetching
keys, is cheap: JWKS serves 1,500 a second for a third of a core. Size for the issue rate, not
for total traffic.

## How much to provision

Measured on one warm instance with the rate limiter off, so the rate offered is the rate served.
The last two columns are the measurements with headroom, rounded to values you would put in a
manifest.

| exchanges/s | Subact ID CPU | Subact ID RSS | Postgres CPU | Keycloak CPU | DB connections | **provision Subact ID** | **provision Postgres** |
|---|---|---|---|---|---|---|---|
| 1 | 9 millicores | 91 MB | 44 millicores | 11 millicores | 2 | 100m / 512 MiB | 0.25 vCPU |
| 5 | 42 millicores | 113 MB | 38 millicores | 21 millicores | 2 | 100m / 512 MiB | 0.25 vCPU |
| 10 | 86 millicores | 108 MB | 60 millicores | 32 millicores | 2 | 200m / 512 MiB | 0.25 vCPU |
| 25 | 195 millicores | 114 MB | 135 millicores | 71 millicores | 3 | 400m / 512 MiB | 0.25 vCPU |
| 50 | 351 millicores | 73 MB | 193 millicores | 104 millicores | 3 | 750m / 512 MiB | 0.5 vCPU |
| 100 | 612 millicores | 70 MB | 357 millicores | 155 millicores | 7 | 1.25 vCPU / 512 MiB | 0.75 vCPU |
| 150 | 821 millicores | 105 MB | 476 millicores | 187 millicores | 13 | 1.5 vCPU / 512 MiB | 1 vCPU |
| 200 | 982 millicores | 128 MB | 619 millicores | 239 millicores | 24 | 2 vCPU / 512 MiB | 1.25 vCPU |
| 250 | 1.06 vCPU | 90 MB | 772 millicores | 292 millicores | 101 | 2 vCPU / 512 MiB | 1.5 vCPU |
| 300 | 1.11 vCPU | 151 MB | 941 millicores | 348 millicores | 100 | 2.5 vCPU / 512 MiB | 1.75 vCPU |

CPU is linear in the rate. To size for a rate not in the table, use the marginal cost of one more
exchange a second, fitted from 1/s to 250/s:

    Subact ID CPU      ≈ 4.4 millicores per exchange/s
    Postgres CPU  ≈ 2.9 millicores per exchange/s
    Keycloak CPU  ≈ 1.1 millicores per exchange/s
    Subact ID memory   ≈ flat; 70–151 MB at every rate measured

Dividing a row gives a higher figure (6.1 CPU-ms at 100/s) because it includes the fixed cost of
running at all. Use the slope to extrapolate.

The connection column is what each rate holds open. Past 250/s the pool is full, and concurrency
is bounded by `Maximum Pool Size` (100 by default) rather than by the rate.

- **The identity provider is in the hot path.** In the default `poll` mode the sponsor check
  calls the provider's admin API on every exchange. That is about a millicore per exchange a
  second on the provider, which does not show in Subact ID's metrics. In `signals` mode the provider
  is not asked; see [Configuration](configuration.md#upstream-identity-provider) for the
  trade-off. A refresh reuses a status the control plane fetched no earlier than its task was
  created. With the default five-minute tokens that costs no extra admin calls, because the
  cached status has expired by the first refresh anyway. With tokens shorter than
  about 50 seconds, or an agent that narrows its scope right after the exchange, a task's first
  refresh can cost one more admin call. The runs below do not exercise that case.
- **Memory does not scale with rate.** The `512 MiB` in every row is headroom for overload, not
  for the steady state. With overload shedding, RSS stayed under 290 MB at every rate up to
  850/s offered.
- **Size every replica for the whole rate.** When one replica fails, the survivor carries all the
  traffic. Three replicas at 100 exchanges a second each need the 100/s row.
- **Size Postgres memory by retention and working set**, not by request rate. These runs used
  512 MB of `shared_buffers` and were never short of it.

## Idle and startup

| | Subact ID CPU | Subact ID RSS | Postgres CPU |
|---|---|---|---|
| Just started, has served nothing | 38 millicores | 27 MB | 18 millicores |
| Settled, after serving 9,000 exchanges | **16 millicores** | 191 MB | 59 millicores |

Size for the settled figure and expect the first minute to cost more. Idle CPU is the background
work: the checkpoint pass every `SubactId:Audit:Checkpoint:Interval`, the hourly partition top-up, the
expiry sweeper and the outbox drain. Resident memory follows the heaviest work the process has
done, not what it is doing now.

An instance is ready 3.2 s after `docker start`. Almost all of that is readiness work: checking
the database, the upstream provider's keys and the current month's partition.

The Helm chart's `100m` CPU request serves about twelve exchanges a second.

## What each request costs

Warm instance, below saturation:

| path | at | p50 | p90 | CPU-ms | DB statements | ledger rows |
|---|---|---|---|---|---|---|
| `POST /oauth2/token` (exchange) | 100/s | 12.4 ms | 14.9 ms | 5.9 | 21.0 | 1 |
| `POST /oauth2/token` (refresh) | 100/s | 9.0 ms | 11.6 ms | 5.2 | 16.6 | 1, or 0 (below) |
| `POST /oauth2/introspect` | 300/s | 5.3 ms | 7.3 ms | 2.7 | 6.7 | 0 |
| `GET /.well-known/jwks.json` | 300/s | 2.6 ms | 4.3 ms | 0.52 | 0 | 0 |
| `GET /.well-known/openid-configuration` | 300/s | 2.6 ms | 4.2 ms | 0.51 | 0 | 0 |
| A denied anonymous request | 300/s | 2.7 ms | 4.5 ms | 0.60 | 0 | ~0 (collapsed) |

- **A refresh usually writes no ledger row.** A task's first renewal is written as it happens.
  Later renewals are counted on the task's grant and written as one summary record when the task
  ends. Renewed tokens after the first therefore have no `jti` in the ledger.
- **About 2 ms of every latency is the rig's container network.** Discovery does no database
  work and still takes 2.6 ms. Subtract that to estimate a deployment whose caller is closer.
- **The exchange latency is round trips, not CPU.** It is 21 statements ending in a durable
  commit, so it barely moves with load until the ceiling. A network hop to Postgres raises it.
- **p99 is not reported.** It varies about threefold between runs of the same rate, depending on
  whether a checkpoint or a garbage collection lands in the window.

### `GET /audit`

Measured against a ledger of 47,002 records, 6,000 of them denials:

| query shape | mean |
|---|---|
| since `ts`, limit 1000 | 361 µs |
| `sponsor` + `ts`, limit 50 | 258–296 µs |
| `task_id`, limit 100 | 146 µs |
| `decision=deny` + `ts`, limit 1000 | 442 µs |

Every partition the ledger holds is one the planner weighs on each query. A query with no `ts`
bound, such as `task_id` or `jti`, cannot prune any of them. Size `/audit` for the retention
window plus `SubactId:Audit:Partitions:MonthsAhead` months.

## The ceiling, and what sets it

| offered | completed | Subact ID RSS |
|---|---|---|
| 300/s | 300/s | 151 MB |
| 350/s | 354/s | 230 MB |
| 400/s | 326/s | 687 MB |
| 500/s | 361/s | 687 MB |
| 850/s | 347/s | 720 MB |

Throughput stops at about 350 to 370 exchanges a second, and 300/s is the highest rate that
stays clean. The plateau varies by about 15% between runs on the same build (326 to 391 across
two campaigns), so treat it as a band. The memory above 290 MB in this table was measured without
overload shedding; see [what overload does](#what-overload-does-and-why-the-limiter-is-on) for the
shipped behaviour.

**The machine sets the ceiling.** At the ceiling Subact ID used 1.40 cores, Postgres 1.20 and Keycloak
0.40, while the whole machine was at 3.76 of 4. The rest was the load generator. Ledger appends
do not wait on each other. This rig cannot show whether replicas scale, because on four shared
cores two instances only divide them.

**The connection pool is not the limit.** It is admission control for the database:

| offered | pool 25 | pool 50 | pool 100 | pool 400 |
|---|---|---|---|---|
| 300/s | 300/s | 300/s | 300/s | 301/s |
| 400/s | 383/s | 389/s | 377/s | **89/s** |
| 500/s | 372/s | 379/s | 350/s | **97/s** |

From 25 to 100 connections the ceiling barely moves. At 400, throughput falls by three quarters:
Postgres doubles to 2.2 cores spent on contention while Subact ID's CPU falls. If you raise the pool,
raise `max_connections` and the database's cores with it.

**The read paths go much higher:**

| shape | offered | completed | p50 | Subact ID CPU |
|---|---|---|---|---|
| introspect | 600/s | 600/s | 6.8 ms | 1.26 vCPU |
| introspect | 900/s | 903/s | 11.1 ms | 1.50 vCPU |
| introspect | 1,200/s | 1,196/s | 96 ms | 1.60 vCPU |
| introspect | 1,500/s | 1,275/s | — | 1.83 vCPU |
| JWKS | 500/s | 500/s | 2.56 ms | 211 millicores |
| JWKS | 1,500/s | 1,500/s | 2.79 ms | 338 millicores |

JWKS did not reach a ceiling at 1,500/s.

## Storage

Measured over a soak of 14,500 exchanges and 29,776 renewals, counted after every task had
expired and the sweeper had written its terminal record.

| table | bytes/row | rows per exchange | pruned? |
|---|---|---|---|
| `audit_events` | 499 | 1 to 5 (below) | **never** |
| `tasks` | 492 | 1 | `SubactId:Tasks:Retention` after the task expires (default a week) |
| `task_grants` | 423 | 1 | `SubactId:Tasks:Retention` after the task expires |
| `assertion_replays` | 933 | 1 per exchange and per refresh | purged after expiry |
| `audit_checkpoints` | 2,731 | one per checkpoint interval that had records | **never** |

The soak revoked nothing, so `revocations` is not in the table. It gains one row per revocation,
including one per accepted back-channel logout and per Shared Signals `session-revoked` whether or
not anything was running. Those sign-out rows are removed `SubactId:Revocations:SignOutRetention`
after they were recorded (a day by default), so they hold steady at about a day of sign-outs.
The other rows (an operator's kill switch or block, an agent's token or task revocation) are
**never** pruned; they grow with how often those happen, which is rarely. `ssf_signal_watermarks`
holds one small row per person a Shared Signals transmitter has sent an account event about, and
is never pruned either.

The replay table is a short window: 2,019 rows remained after more than 44,000 assertions.
Checkpoints do not grow with traffic: eighteen of them, 48 kB in total, sealed all 47,002 records.
Of a ledger row's 499 bytes, 230 are heap and 268 are indexes.

### Ledger rows per exchange

| traffic shape | rows per exchange |
|---|---|
| Issue and walk away | 1 |
| Issue, let the task expire | 2 |
| Renew until the task ends, then stop | 4 |
| Renew until refused | 5 |

The count is bounded however many times a task renews:

- 1 for the exchange
- 1 for the first renewal
- 1 summary for all later renewals
- 1 for the task's end (`task.expired` or `task.revoked`)
- 1 more if the agent asks again after the end

The last row is avoidable. A client that stops when the task ends never writes it, and `@subactid/client`
in the SDKs stops that way.

`audit_events` refuses `DELETE` and `TRUNCATE`, so plan retention against its growth. At a
sustained ten exchanges a second:

| rows/exchange | GB/day | GB/month |
|---|---|---|
| 1 | 0.43 | 13 |
| 2 | 0.86 | 26 |
| 5 | 2.16 | 65 |

To take old months out of the ledger, see
[Storage](storage.md#retention-taking-a-month-out-of-the-ledger).

## What overload does, and why the limiter is on

Overload shedding (`SubactId:Overload`, on by default) bounds the work an instance takes on. For each
kind of work (the token endpoint, introspection, the paths that take access away, everything
else), at most 16 requests per core run at once and a bounded queue waits at most a second. The
rest are refused at once with `503`, `Retry-After` and `temporarily_unavailable`, and recorded
under the reason `overloaded`. See [Configuration](configuration.md#overload) for the settings.

Past the ceiling, measured on a second 4-core machine (see
[the rig's stress runs](../bench/README.md#stress-runs)):

| offered exchanges | served | worst latency | Subact ID RSS |
|---|---|---|---|
| 400/s | 397/s | 1.0 s | 233 MB |
| 550/s | 408/s | 1.2 s | 261 MB |
| 850/s | 390/s | 1.2 s | 239 MB |

Without shedding, the same load queued without bound: latency reached tens of seconds, memory
went past the chart's 512 MiB limit, and the instance kept working for callers who had given up.

When a dependency fails:

| failure | what callers see |
|---|---|
| Spike of 3× the ceiling for 30 s | ~330/s served, the rest refused with `503` within a second; `/readyz` stays up; normal within 1 s of the spike ending |
| Postgres paused 15 s | Requests already running wait for it; the rest are refused with `503` after a second in the queue. Raise `SubactId:Overload:QueueTimeout` (up to `PT30S`) if you prefer slow to refused |
| Postgres restarted | `503 temporarily_unavailable` with `Retry-After: 5` until it is back |
| Keycloak stopped | Every exchange refused in ~8 ms |
| Keycloak frozen | For the first ~10 s (the provider client's timeout), exchanges hold their turns and the rest are refused. Then the sponsor-check circuit opens after five provider failures in a row, and exchanges are refused in ~8 ms. It lets one exchange through every 5 s to probe |
| 300 connections trickling request bodies | No effect: a form is read before its request takes a turn |

`/readyz` uses its own pool of four connections, so it stays accurate under load.

**The rate limiter bounds each source; overload shedding bounds the sum.** With the shipped
defaults, 100 exchanges a second from one source for 45 seconds gave:

- 450 served, exactly ten a second, which is what 600 permits a minute means
- 4,050 refused with `429` and `slow_down`
- the refusals collapsed into four ledger rows

A fleet of agents behind one egress address is one source, so `SubactId:RateLimit:PermitsPerMinute`
is the first setting to revisit. Tool servers introspecting high-risk tokens spend their own
bucket, `SubactId:RateLimit:Introspection:*` (6,000 a minute, burst 1,200, by default); raise it with
the agents' limit. [Configuration](configuration.md#rate-limiting) lists which path spends which
bucket.

The limiter is close to free: at 300 exchanges a second it costs 1–3% of Subact ID's CPU, and at
100/s the cost is below the rig's noise.

**Denial aggregation** (`SubactId:Audit:Aggregation:Enabled`) collapses anonymous denials. On the same
anonymous denial traffic:

| | Subact ID CPU-ms | Postgres CPU | p50 |
|---|---|---|---|
| On (default) | 0.60 | 17 millicores | 2.7 ms |
| Off | 1.61 | **326 millicores** | 4.7 ms |

With it on, 2,000 anonymous denials wrote one ledger row. The same setting controls renewal
summaries. A denial that can be attributed to an agent, task or human is never collapsed.

## Recommendations

- **Size from your issue rate** using [How much to provision](#how-much-to-provision): 200m at
  ten exchanges a second, 2.5 vCPU at three hundred, 512 MiB of memory at every rate. Budget
  about a millicore per exchange a second on the identity provider too.
- **Keep the connection pool at or below the default of 100.** At 400 connections this rig lost
  three quarters of its throughput. If you raise it, add database cores to match.
- **Keep the database close.** Each exchange makes 21 round trips to it. A faster disk does not
  raise the ceiling; a network hop to Postgres raises latency.
- **Keep the partition runway short.** `SubactId:Audit:Partitions:MonthsAhead` defaults to 2. Every
  extra month is a partition each `/audit` query plans over.
- **Tune Postgres checkpoints before you set a latency SLO.** Spread them and raise
  `max_wal_size`, as the rig's [`postgresql.conf`](../bench/postgres/postgresql.conf) does. The
  packaged defaults do not.
- **Do not let the expiry sweeper fall behind.** Each batch writes a record per task. The default
  `PT1M` sweep keeps up with normal traffic; a burst of task creation or an instance that was
  down while tasks expired builds a backlog.
- **Raise `SubactId:RateLimit:PermitsPerMinute`** to match your fleet, and set
  `SubactId:RateLimit:TrustedProxies` if anything fronts the service, or every caller shares one
  bucket. Keep the limiter and `SubactId:Overload` on.
- **Leave `SubactId:Audit:Checkpoint:Interval` at its default** unless you have a reason. A minute is
  how long a record can sit unsealed. Shorter seals sooner and writes more checkpoint rows
  (about 2.7 kB each). It does not affect the append path.
- **Leave `SubactId:Audit:Aggregation:Enabled` on.**
- **Budget ledger growth from your agents' traffic shape:** between 0.5 and 2.5 KB per exchange,
  permanently, depending on whether tasks renew.
