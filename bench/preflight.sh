#!/usr/bin/env bash
# Checks whether this machine can produce publishable benchmark numbers.
#
#   ./preflight.sh
#
# Run it before the campaign on a new machine, especially a rented one. It detects problems that
# silently skew results: burstable instances, slow network disks, CPU steal, and a Docker daemon
# in a separate VM.
#
# Offers no load and starts nothing.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

fails=0
warns=0
ok()   { printf '  ok    %s\n' "$*"; }
warn() { printf '  WARN  %s\n' "$*"; warns=$((warns + 1)); }
bad()  { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }

echo "== the machine"

if [ "$(uname -s)" != "Linux" ]; then
  bad "$(uname -s), and the rig reads Linux cgroups. It has to run where the containers' kernel is."
else
  ok "Linux $(uname -r) on $(uname -m)"
  [ "$(uname -m)" = "x86_64" ] || warn "$(uname -m): every image the rig uses publishes it, but the page's numbers are x86_64 and the two are not comparable line for line."
fi

# The accounting measure.sh uses.
if [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then
  ok "cgroup v1 accounting is readable"
elif grep -q '^usage_usec ' /sys/fs/cgroup/cpu.stat 2>/dev/null; then
  ok "cgroup v2 accounting is readable"
else
  bad "no readable cgroup CPU accounting, so measure.sh has nothing to difference"
fi

cores="$(nproc)"
threads_per_core="$(lscpu 2>/dev/null | awk -F: '/^Thread\(s\) per core/ { gsub(/ /, "", $2); print $2 }')"
if [ "${threads_per_core:-1}" -gt 1 ] 2>/dev/null; then
  warn "$cores vCPUs, but $threads_per_core threads per core — that is $((cores / threads_per_core)) physical cores. A cloud vCPU is usually a hyperthread; the page's four were four whole cores."
else
  ok "$cores vCPUs, one thread per core"
fi

mem_gb="$(awk '/MemTotal/ { printf "%.1f", $2 / 1048576 }' /proc/meminfo)"
# Container limits: 2g Postgres, 2g Keycloak, 1g control plane, 1g generator.
if awk -v m="$mem_gb" 'BEGIN { exit !(m < 8) }'; then
  warn "$mem_gb GB of memory; the rig's containers ask for about 6 GB between them"
else
  ok "$mem_gb GB of memory"
fi

# CPU steal time. Assigned, not piped, so warn() runs in this shell and its count is kept.
steal="$(awk '/^cpu /{ total = $2 + $3 + $4 + $5 + $6 + $7 + $8 + $9; printf "%.2f", $9 / total * 100; exit }' /proc/stat)"
if awk -v s="$steal" 'BEGIN { exit !(s > 1) }'; then
  warn "$steal% steal time since boot: this machine shares its cores with somebody else"
else
  ok "$steal% steal time"
fi

# Burstable instances throttle once their CPU credit runs out. The instance type comes from DMI.
instance="$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)"
case "$instance" in
  t1.*|t2.*|t3.*|t3a.*|t4g.*|e2-micro|e2-small|e2-medium|f1-*|g1-*|Standard_B*)
    warn "$instance is a burstable type: it serves from CPU credit and then throttles, and the ceiling it reports is that throttle" ;;
  ?*) ok "instance type $instance" ;;
esac

echo
echo "== docker"

if ! docker info >/dev/null 2>&1; then
  bad "no reachable Docker daemon"
else
  ok "daemon $(docker info --format '{{.ServerVersion}}' 2>/dev/null)"

  # measure.sh needs the daemon on this kernel. Docker Desktop runs it in a VM.
  daemon_kernel="$(docker info --format '{{.KernelVersion}}' 2>/dev/null)"
  if [ -n "$daemon_kernel" ] && [ "$daemon_kernel" != "$(uname -r)" ]; then
    bad "the daemon runs on kernel $daemon_kernel and this shell on $(uname -r): its containers' accounting is in another kernel and cannot be read from here"
  else
    ok "the daemon shares this kernel, so its containers' accounting is readable"
  fi

  docker compose version >/dev/null 2>&1 && ok "compose $(docker compose version --short 2>/dev/null)" \
    || bad "no 'docker compose' (the v2 plugin); the rig is described by a compose file"

  root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"
  free_gb="$(df -BG --output=avail "$root" 2>/dev/null | tail -1 | tr -dc '0-9')"
  if [ -n "$free_gb" ] && [ "$free_gb" -lt 20 ]; then
    warn "${free_gb} GB free on $root; the images and the soak's ledger want about 20"
  elif [ -n "$free_gb" ]; then
    ok "${free_gb} GB free on $root"
  fi
fi

echo
echo "== the disk under the database"

# With synchronous_commit on, each commit costs an fsync, which sets a latency floor. Local NVMe
# takes a fraction of a millisecond. A network disk can take several.
fsync_target="${TMPDIR:-/tmp}"
if [ -n "${root:-}" ] && [ -d "$root" ]; then
  # Warn if Docker's volumes are on a different filesystem from the one measured.
  same="$(df --output=source "$root" 2>/dev/null | tail -1)"
  mine="$(df --output=source "$here" 2>/dev/null | tail -1)"
  [ "$same" = "$mine" ] || warn "Docker's volumes are on $same and this checkout on $mine; the figure below is for the checkout's disk, not the database's"
fi

# The Python snippet prints only the median. The verdict is made here.
if ! command -v python3 >/dev/null 2>&1; then
  warn "no python3, so fsync latency was not measured; it is what synchronous_commit costs per commit"
else
  p50="$(python3 - "$fsync_target" <<'EOF'
import os, sys, tempfile, time, statistics
try:
    fd, path = tempfile.mkstemp(dir=sys.argv[1])
except OSError:
    raise SystemExit(1)
block = b"x" * 8192
try:
    os.write(fd, block); os.fsync(fd)
    lat = []
    for _ in range(200):
        t = time.perf_counter()
        os.write(fd, block)
        os.fsync(fd)
        lat.append((time.perf_counter() - t) * 1000)
finally:
    os.close(fd); os.unlink(path)
print(f"{statistics.median(lat):.3f}")
EOF
)"
  if [ -z "$p50" ]; then
    warn "could not write to $fsync_target, so fsync latency was not measured"
  else
    commits="$(awk -v p="$p50" 'BEGIN { printf "%.0f", 1000 / p }')"
    if awk -v p="$p50" 'BEGIN { exit !(p >= 1) }'; then
      warn "fsync p50 $p50 ms ($commits serial commits/s): a network disk. Commit latency, not the service, may set what you measure."
    else
      ok "fsync p50 $p50 ms ($commits serial commits/s)"
    fi
    echo "        for comparison, the page's machine is about 0.25 ms, which is local NVMe"
  fi
fi

echo
echo "== what the campaign would do here"
./campaign.sh plan

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails blocking problem(s) and $warns warning(s). The campaign will not produce numbers worth publishing here."
  exit 1
fi
if [ "$warns" -gt 0 ]; then
  echo "$warns warning(s). Nothing blocks the campaign; state each one alongside whatever it reports."
  exit 0
fi
echo "Nothing to report. This machine will measure cleanly."
