#!/bin/sh
# ios-sampled.sh DIR COMMAND...: run COMMAND (an xcodebuild test run) while the KeepCrypt app's threads are
# sampled every 20 s into DIR; if COMMAND fails, print the runner's memory, the booted simulators, the sampler's
# log and the main thread's heaviest frames of the last four samples. Exits with COMMAND's status.
#
# U3n and M7-3 began it inline in the narrow iPhone's step. M7-14 (the owner's word at the gate, 2026-11-23)
# moves it here for every journeys job: run 45071035420's journeys-2 (macos-26) lost a tap whose touch-down the
# app logged, with the app's facts frozen from that moment, and the log alone cannot tell an app whose main
# thread stalled (ours to fix) from a simulator that dropped the touch-up (the runner's). A sample taken while
# the test waits says which.
#
# The loop runs with errexit off: pgrep exits 1 until the app starts, and under `sh -e` the first tick would
# end the sampler (M7-3, run 44925400647). Every tick is logged, so a sampler that takes nothing says why.
# Function names of the TestHooks app on test values; nothing is uploaded.
set -u

[ "$#" -ge 2 ] || { echo "FAIL: usage: ios-sampled.sh DIR COMMAND..." >&2; exit 2; }
dir=$1
shift
mkdir -p "$dir/samples" || { echo "FAIL: cannot make $dir/samples" >&2; exit 2; }
log=$dir/sampler.log
: > "$log"

(
  set +e
  while :; do
    t=$(date +%s)
    pid=$(pgrep -x KeepCrypt | head -n 1)
    if [ -n "$pid" ]; then
      sample "$pid" 2 -mayDie -file "$dir/samples/$t.txt" >> "$log" 2>&1
      echo "$t: pid $pid, sample exit $?" >> "$log"
    else
      echo "$t: no KeepCrypt process" >> "$log"
    fi
    sleep 20
  done
) &
sampler=$!

status=0
"$@" || status=$?
kill "$sampler" 2> /dev/null || true
wait "$sampler" 2> /dev/null || true

if [ "$status" -ne 0 ]; then
  echo "== the runner's memory and booted simulators at the failure"
  memory_pressure -Q || echo "memory_pressure failed"
  xcrun simctl list devices booted || echo "simctl list failed"
  echo "== the sampler's log (last 40 lines)"
  tail -n 40 "$log" || echo "no sampler log"
  for f in $(ls "$dir/samples" | tail -n 4); do
    echo "== sample $f (the main thread's heaviest frames)"
    sed -n '/^Call graph:/,/^Total number in stack/p' "$dir/samples/$f" | head -n 120
  done
fi
exit "$status"
