#!/usr/bin/env bash
# Runs one load generator command and reports each container's CPU and memory during it.
#
#   ./measure.sh <label> -- load --shape exchange --rate 100 --warmup 20 --duration 60
#
# CPU comes from the kernel's per-container cgroup accounting, differenced over the interval.
# Memory is the peak and mean resident set over the same interval.
#
# The interval is the measured window the load generator reports, so warmup is excluded.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

label="${1:?usage: measure.sh <label> -- <bench arguments>}"
shift
[ "${1:-}" = "--" ] && shift

services=(subactid postgres keycloak)
sampled=("${services[@]}" machine)
results="$here/results"
mkdir -p "$results/samples"
samples="$results/samples/$label.csv"
run="$results/$label.json"

# Detect the cgroup version. v1: CPU in nanoseconds in cpuacct.usage, memory as total_rss.
# v2: CPU in microseconds in cpu.stat, memory as anon.
if [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then
  cgroups=1
  root_cpu=/sys/fs/cgroup/cpuacct/cpuacct.usage
elif grep -q '^usage_usec ' /sys/fs/cgroup/cpu.stat 2>/dev/null; then
  cgroups=2
  root_cpu=/sys/fs/cgroup/cpu.stat
else
  cat >&2 <<'EOF'
no readable cpu accounting for the machine: neither /sys/fs/cgroup/cpuacct/cpuacct.usage (cgroup
v1) nor a usage_usec in /sys/fs/cgroup/cpu.stat (v2). This has to run on the machine whose kernel
holds the containers' accounting, which is not the case for a Docker Desktop that keeps its
daemon in a VM of its own.
EOF
  exit 1
fi

# CPU in nanoseconds for either version. printf avoids awk's scientific notation for large numbers.
read_cpu() {
  if [ "$cgroups" = 1 ]; then
    cat "$1" 2>/dev/null || echo 0
  else
    awk '/^usage_usec /{ printf "%.0f", $2 * 1000; found = 1; exit } END { if (!found) print 0 }' "$1" 2>/dev/null || echo 0
  fi
}

read_rss() {
  if [ "$cgroups" = 1 ]; then
    awk '/^total_rss /{ print $2; exit }' "$1" 2>/dev/null || echo 0
  else
    awk '/^anon /{ print $2; exit }' "$1" 2>/dev/null || echo 0
  fi
}

# Finds each container's cgroup from /proc/<pid>/cgroup, which works for every cgroup version
# and Docker driver.
declare -A cpu_file
declare -A mem_file
for service in "${services[@]}"; do
  id="$(docker compose ps -q "$service" || true)"
  if [ -z "$id" ]; then
    echo "$service is not running; bring the rig up first" >&2
    exit 1
  fi

  pid="$(docker inspect --format '{{.State.Pid}}' "$id" 2>/dev/null || true)"
  if [ -z "$pid" ] || [ "$pid" = "0" ] || [ ! -r "/proc/$pid/cgroup" ]; then
    echo "cannot find the host process of $service, so its accounting cannot be read" >&2
    exit 1
  fi

  if [ "$cgroups" = 1 ]; then
    path="$(awk -F: '$2 ~ /(^|,)cpuacct(,|$)/ { print $3; exit }' "/proc/$pid/cgroup")"
    memory_path="$(awk -F: '$2 ~ /(^|,)memory(,|$)/ { print $3; exit }' "/proc/$pid/cgroup")"
    cpu_file[$service]="/sys/fs/cgroup/cpuacct$path/cpuacct.usage"
    mem_file[$service]="/sys/fs/cgroup/memory$memory_path/memory.stat"
  else
    path="$(awk -F: '$1 == "0" { print $3; exit }' "/proc/$pid/cgroup")"
    cpu_file[$service]="/sys/fs/cgroup$path/cpu.stat"
    mem_file[$service]="/sys/fs/cgroup$path/memory.stat"
  fi

  # Docker's cgroup paths contain the container id. If not, the daemon runs in a VM (as with
  # Docker Desktop) and the pid is some unrelated local process, so refuse.
  case "$path" in
    *"$id"*) ;;
    *)
      echo "$service's accounting is not on this machine: pid $pid is in '$path', which does not" >&2
      echo "name the container. Run the rig where its daemon's kernel is — inside the WSL2" >&2
      echo "distribution or the VM, not beside it." >&2
      exit 1
      ;;
  esac

  if [ ! -r "${cpu_file[$service]}" ]; then
    echo "no readable cpu accounting for $service at ${cpu_file[$service]}" >&2
    exit 1
  fi
done

# One line per service per second: time, service, CPU nanoseconds so far, resident bytes now.
#
# "machine" is the whole host, including a local load generator. Its RSS column is the host's
# used memory. Its CPU is read from the root cgroup, not /proc/stat, whose tick-based counts are
# inaccurate here and not comparable with the per-container numbers.
: > "$samples"
(
  while true; do
    now="$(date -u +%s.%N)"
    for service in "${services[@]}"; do
      echo "$now,$service,$(read_cpu "${cpu_file[$service]}"),$(read_rss "${mem_file[$service]}")"
    done
    # Used memory is total minus available.
    used="$(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{printf "%.0f", (t - a) * 1024}' /proc/meminfo)"
    echo "$now,machine,$(read_cpu "$root_cpu"),$used"
    sleep 1
  done
) >> "$samples" &
sampler=$!
trap 'kill "$sampler" 2>/dev/null || true' EXIT

if [ "${1:-}" = "idle" ]; then
  # No load: measures the rig's idle cost, the baseline for per-exchange numbers.
  #
  # Wait for the sampler's first reading before opening the window, so there is a start value.
  sleep 3
  from="$(date -u +%s.%N)"
  sleep "${2:-60}"
  to="$(date -u +%s.%N)"
  from_iso="$(date -u -d "@$from" +%Y-%m-%dT%H:%M:%SZ)"
  to_iso="$(date -u -d "@$to" +%Y-%m-%dT%H:%M:%SZ)"
else
  # bench.sh leaves the result in results/ under this label, wherever the generator ran.
  ./bench.sh "$@" --out "/results/$label.json"
fi

# Keep sampling briefly after the run, so there is a reading after the window closes.
sleep 3
kill "$sampler" 2>/dev/null || true
wait "$sampler" 2>/dev/null || true
trap - EXIT

if [ "${1:-}" != "idle" ]; then
  if [ ! -f "$run" ]; then
    echo "the load generator wrote no result for $label" >&2
    exit 1
  fi

  # The measured window the generator reports.
  from_iso="$(sed -n 's/.*"measured_from": *"\([^"]*\)".*/\1/p' "$run" | head -1)"
  to_iso="$(sed -n 's/.*"measured_to": *"\([^"]*\)".*/\1/p' "$run" | head -1)"
fi

if [ -z "$from_iso" ] || [ -z "$to_iso" ]; then
  echo "no measured window for $label" >&2
  exit 1
fi
if [ "${1:-}" != "idle" ]; then
  from="$(date -u -d "$from_iso" +%s.%N)"
  to="$(date -u -d "$to_iso" +%s.%N)"
fi

# Fail if the window could not be resolved.
if [ -z "${from:-}" ] || [ -z "${to:-}" ]; then
  echo "could not resolve the measured window for $label" >&2
  exit 1
fi

echo
echo "$label: $from_iso to $to_iso"
printf '%-10s %12s %12s %12s\n' service millicores "peak RSS MB" "mean RSS MB"

metrics="$results/$label.resources.csv"
echo "service,millicores,cpu_seconds,peak_rss_bytes,mean_rss_bytes,window_seconds" > "$metrics"

for service in "${sampled[@]}"; do
  awk -F, -v service="$service" -v from="$from" -v to="$to" -v out="$metrics" '
    $2 != service { next }
    {
      t = $1 + 0; cpu = $3 + 0; rss = $4 + 0;
      # The last reading at or before the window opens, and the first at or after it closes.
      if (t <= from && (startT == 0 || t > startT)) { startT = t; startCpu = cpu }
      if (t >= to && (endT == 0 || t < endT)) { endT = t; endCpu = cpu }
      if (t > lastT) { lastT = t; lastCpu = cpu }
      if (t >= from && t <= to) {
        if (rss > peak) peak = rss;
        sum += rss; n++;
      }
    }
    END {
      # With no reading after the close, use the last reading. The rate uses the actual interval.
      if (endT == 0) { endT = lastT; endCpu = lastCpu }
      if (startT == 0 || endT == 0 || endT <= startT) {
        printf "%-10s %12s %12s %12s\n", service, "n/a", "n/a", "n/a";
        exit;
      }
      seconds = endT - startT;
      cpuSeconds = (endCpu - startCpu) / 1e9;
      millicores = cpuSeconds / seconds * 1000;
      mean = n > 0 ? sum / n : 0;
      printf "%-10s %12.0f %12.1f %12.1f\n", service, millicores, peak / 1048576, mean / 1048576;
      printf "%s,%.1f,%.3f,%d,%d,%.1f\n", service, millicores, cpuSeconds, peak, mean, seconds >> out;
    }
  ' "$samples"
done

# The containers' CPU cannot exceed the machine's. If it does, the sampling was wrong.
awk -F, 'NR > 1 { if ($1 == "machine") machine = $2; else containers += $2 }
  END {
    if (machine > 0 && containers > machine * 1.05) {
      printf "  WARNING: the containers account for %.0f millicores and the machine for only %.0f.\n", containers, machine;
      printf "           This run sampled wrong; do not report it.\n";
    }
  }' "$metrics"

echo
if [ "${1:-}" = "idle" ]; then
  echo "wrote $metrics"
else
  echo "wrote $run and $metrics"
fi
