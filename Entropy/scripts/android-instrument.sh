#!/bin/sh
# Runs the app's instrumented tests on an emulator, one `am instrument` per test class (tasks/todo.md,
# M5 group 6; Q55). The instrumentation shares the app's process, and the ceremony's slot is that
# process's, so a class (or, named as CLASS#METHOD, a test that halts or kills the process) gets a
# process of its own: a latched Halted slot or a dead process never fails the next one. No Test
# Orchestrator: am instrument kills the target's process when a run ends.
#
# Usage: scripts/android-instrument.sh ADB SERIAL API TEST_PACKAGE TARGET_PACKAGE TEST...
#   ADB the job's own adb; SERIAL the emulator (emulator-5554); API its API level, for the printed
#   lines; TEST_PACKAGE the instrumented-test APK's package (TARGET_PACKAGE.test); TARGET_PACKAGE the
#   app it instruments; each TEST a class, or CLASS#METHOD.
#
# Each run is `am instrument -w -r -e class TEST TEST_PACKAGE/androidx.test.runner.AndroidJUnitRunner`.
# It passes only when its raw output holds a test start for every test and as many passes, no
# failure, error, ignored test or assumption failure, the runner's final INSTRUMENTATION_CODE: -1 and
# no INSTRUMENTATION_FAILED, INSTRUMENTATION_ABORTED or shortMsg (a crashed process). Then it is judged
# from the shell, as the crash test is: TARGET_PACKAGE's process is gone, no crash or not-responding
# window exists, `logcat -b crash` holds no line naming com.keepcrypt.entropy (any of our packages:
# only the count is printed, never the lines) and `dumpsys dropbox` shows no new data_app_crash entry.
# The tests' own status values (status code 2) are printed as they come: kc_probe as "probe: api=API
# VALUE" (the platform probe's facts), kc_pass as "pass: api=API VALUE" and every other kc_ key as
# "kc: KEY=VALUE" (the window region the frame checker needs). The whole raw output is printed when a
# run fails (the tests use gate seeds only). Prints "instrument: api=API PASS TEST (N tests)" per run.
# Exit: 0 every run passed; 1 a run failed; 2 bad usage or an adb that cannot reach the emulator.
set -u
unset CDPATH

if [ $# -lt 6 ]; then
  echo "usage: scripts/android-instrument.sh ADB SERIAL API TEST_PACKAGE TARGET_PACKAGE TEST..." >&2
  exit 2
fi
adb=$1
serial=$2
api=$3
testpkg=$4
target=$5
shift 5

fail() {
  echo "FAIL: instrument: api=$api: $1" >&2
  exit 1
}
dev() { "$adb" -s "$serial" "$@"; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/kc-instrument.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT

# app_crashes: the number of data_app_crash entries dumpsys dropbox lists; non-zero when unreadable.
app_crashes() {
  dev shell dumpsys dropbox > "$tmp/dropbox" 2>&1 || return 2
  grep -c -e ' data_app_crash ' "$tmp/dropbox"
  [ $? -le 1 ]
}

for t in "$@"; do
  before=$(app_crashes) || { echo "instrument: api=$api: dumpsys dropbox cannot be read" >&2; exit 2; }
  dev shell am instrument -w -r -e class "$t" "$testpkg/androidx.test.runner.AndroidJUnitRunner" > "$tmp/raw" 2>&1
  rc=$?
  tr -d '\r' < "$tmp/raw" > "$tmp/out"
  sed -n 's/^INSTRUMENTATION_STATUS: kc_probe=/probe: api='"$api"' /p' "$tmp/out"
  sed -n 's/^INSTRUMENTATION_STATUS: kc_pass=/pass: api='"$api"' /p' "$tmp/out"
  sed -n -e '/^INSTRUMENTATION_STATUS: kc_probe=/d' -e '/^INSTRUMENTATION_STATUS: kc_pass=/d' \
    -e 's/^INSTRUMENTATION_STATUS: kc_/kc: /p' "$tmp/out"
  counts=$(awk '
    /^INSTRUMENTATION_STATUS_CODE: / {
      if ($2 == "1") started++
      else if ($2 == "0") passed++
      else if ($2 == "-1" || $2 == "-2" || $2 == "-3" || $2 == "-4") bad++
    }
    /^INSTRUMENTATION_CODE: -1$/ { done = 1 }
    /^INSTRUMENTATION_(FAILED|ABORTED)/ || /^INSTRUMENTATION_RESULT: shortMsg=/ { bad++ }
    END { printf "%d %d %d %d\n", started, passed, bad, done }
  ' "$tmp/out")
  started=${counts%% *}
  rest=${counts#* }
  passed=${rest%% *}
  rest=${rest#* }
  bad=${rest%% *}
  finished=${rest#* }
  if [ "$started" -lt 1 ] || [ "$passed" -ne "$started" ] || [ "$bad" -ne 0 ] || [ "$finished" -ne 1 ]; then
    cat "$tmp/out"
    fail "$t: $started started, $passed passed, $bad failed, errored, ignored or aborted (adb exit $rc)"
  fi
  # The judge from the shell. am instrument stops the target when the run ends; allow it 20 s.
  i=0
  while dev shell pidof "$target" > /dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -le 20 ] || fail "$t: $target is still running 20 s after the run"
    sleep 1
  done
  dev shell dumpsys window windows > "$tmp/windows" 2>&1 || fail "$t: dumpsys window windows failed"
  if grep -q -e 'Application Error' -e 'Application Not Responding' "$tmp/windows"; then
    fail "$t: a crash or not-responding window is open"
  fi
  dev shell logcat -b crash -d > "$tmp/crash" 2>&1 || fail "$t: logcat -b crash failed"
  n=$(grep -c -e 'com[.]keepcrypt[.]entropy' "$tmp/crash")
  [ "$n" -eq 0 ] || fail "$t: logcat -b crash holds $n line(s) naming com.keepcrypt.entropy"
  after=$(app_crashes) || fail "$t: dumpsys dropbox cannot be read"
  [ "$after" -eq "$before" ] || fail "$t: dumpsys dropbox gained $((after - before)) data_app_crash entries"
  echo "instrument: api=$api PASS $t ($passed tests; process gone, no crash window, crash buffer and dropbox clean)"
done
