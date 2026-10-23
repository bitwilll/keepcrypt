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
#   app it instruments; each TEST a class, or CLASS#METHOD, or either with the prefix killed: for a
#   test that ends its own process (the crash test, M5 group 14); or CLASS-METHOD[-METHOD...], the
#   class without those tests (am instrument's notClass), for a check the device cannot make, which
#   the caller names (scripts/android-local.sh on a user build; CI's legs never leave one out). Its
#   PASS line names each test left out, and a run that starts one of them fails.
#
# Each run is `am instrument -w -r -e class TEST TEST_PACKAGE/androidx.test.runner.AndroidJUnitRunner`
# (with `-e notClass CLASS#METHOD,...` after the class for a CLASS-METHOD... TEST). It passes only when its raw output holds a test start for every test and as many passes, no
# failure, error, ignored test or assumption failure, the runner's final INSTRUMENTATION_CODE: -1 and
# no INSTRUMENTATION_FAILED, INSTRUMENTATION_ABORTED or shortMsg (a crashed process). A killed: run
# passes only when the process ended during it instead: a test started, none passed, and the activity
# manager's shortMsg says the process went. Then every run is judged from the shell, the crash test's
# too: TARGET_PACKAGE's process is gone, no crash or not-responding window exists, `logcat -b crash`
# holds no line naming com.keepcrypt.entropy (any of our packages: only counts are printed, never the
# lines) and `dumpsys dropbox` shows no new data_app_crash entry. After a killed: run the crash buffer
# must instead hold exactly one crash of our packages, the trigger's: Android's own uncaught-exception
# pre-handler, which apps cannot replace, logs it before the app's handler wipes and ends the process
# (Q75, an accepted residual). Its AndroidRuntime block ("FATAL EXCEPTION:", then "Process:" naming one
# of our packages) must have the trigger's exception line, no "Caused by:" or "Suppressed:", and no
# line outside it may name our packages.
# The tests' own status values (status code 2) are printed as they come: kc_probe as "probe: api=API
# VALUE" (the platform probe's facts), kc_pass as "pass: api=API VALUE" and every other kc_ key as
# "kc: KEY=VALUE" (the window region the frame checker needs). The whole raw output is printed when a
# run fails (the tests use gate seeds only). Prints "instrument: api=API PASS TEST (N tests)" per run
# ("PASS TEST (killed during the test ...)" for a killed: one).
# Exit: 0 every run passed; 1 a run failed; 2 bad usage or an adb that cannot reach the emulator.
#
# scripts/android-instrument.sh --selftest runs this script on a stand-in adb (written to a temporary
# directory) answering from recorded outputs: a passing class, the same with CRLF line ends and with
# the process gone only after 2 s each pass; each status -1 to -4, a missing end status, shortMsg,
# INSTRUMENTATION_FAILED and _ABORTED, no final INSTRUMENTATION_CODE: -1, no test, a process still
# running after 20 s, a crash and a not-responding window, a crash-buffer line naming one of our
# packages and a new data_app_crash entry each fail (exit 1); an unreadable dropbox and too few
# arguments exit 2. A class without one of its tests, and without two, passes with its notClass
# filter on the command line and the tests named in its PASS line; one whose run starts a test it was
# to leave out fails. For a killed: test: a run whose process ends during its one test (shortMsg), with
# the trigger's crash in the crash buffer, passes, and so does one where the runner also reports that
# test failed; a run that passes, one whose test passes before the shortMsg, one with no test started
# and one that ends without a shortMsg fail, and so do, after it, a crash window, no crash of ours, two,
# one with another exception, one with no exception line, one with a Caused by, a line naming our
# packages outside the crash, and a new data_app_crash entry.
# Exit 0 when every case behaves, 1 otherwise. It takes about 25 s (the 20 s wait).
set -u
unset CDPATH

# raw END TAIL: am instrument -r output for a two-test run of CaptureTest with the tests' kc_ status
# values; END is the second test's end status ("none": no end status), TAIL the run's end: ok (the
# runner's OK and INSTRUMENTATION_CODE: -1), code0 (OK, then INSTRUMENTATION_CODE: 0), crashed
# (shortMsg), failed, aborted (INSTRUMENTATION_FAILED or _ABORTED after the OK), or empty (no test).
raw() {
  c=com.keepcrypt.entropy.CaptureTest
  if [ "$2" != empty ]; then
    for t in 1 2; do
      printf 'INSTRUMENTATION_STATUS: class=%s\nINSTRUMENTATION_STATUS: current=%s\n' "$c" "$t"
      printf 'INSTRUMENTATION_STATUS: id=AndroidJUnitRunner\nINSTRUMENTATION_STATUS: numtests=2\n'
      printf 'INSTRUMENTATION_STATUS: stream=\nINSTRUMENTATION_STATUS: test=test%s\n' "$t"
      printf 'INSTRUMENTATION_STATUS_CODE: 1\n'
      if [ "$t" = 1 ]; then
        printf 'INSTRUMENTATION_STATUS: kc_region=0,48,720,1184\nINSTRUMENTATION_STATUS_CODE: 2\n'
        printf 'INSTRUMENTATION_STATUS: kc_probe=first-launch: 0 lit pixels\nINSTRUMENTATION_STATUS_CODE: 2\n'
        printf 'INSTRUMENTATION_STATUS: kc_pass=first-launch: drawn, then black\nINSTRUMENTATION_STATUS_CODE: 2\n'
      fi
      end=0
      [ "$t" = 1 ] || end=$1
      if [ "$end" != none ]; then
        printf 'INSTRUMENTATION_STATUS: class=%s\nINSTRUMENTATION_STATUS: current=%s\n' "$c" "$t"
        printf 'INSTRUMENTATION_STATUS: stream=.\nINSTRUMENTATION_STATUS: test=test%s\n' "$t"
        printf 'INSTRUMENTATION_STATUS_CODE: %s\n' "$end"
      fi
    done
  fi
  case $2 in
    crashed) printf 'INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: 0\n' ;;
    *)
      n=2
      [ "$2" = empty ] && n=0
      printf 'INSTRUMENTATION_RESULT: stream=\n\nTime: 3.2\n\nOK (%s tests)\n\n\n' "$n"
      case $2 in
        failed) printf 'INSTRUMENTATION_FAILED: com.keepcrypt.entropy.test/androidx.test.runner.AndroidJUnitRunner\n' ;;
        aborted) printf 'INSTRUMENTATION_ABORTED: System has crashed.\n' ;;
      esac
      if [ "$2" = code0 ]; then echo 'INSTRUMENTATION_CODE: 0'; else echo 'INSTRUMENTATION_CODE: -1'; fi
      ;;
  esac
}

# killed_raw TAIL: am instrument -r output for a run of CrashTest whose process ends during its one
# test: crashed (its start, then the activity manager's shortMsg), reported (the same with the runner's
# failure report of the test before it), passed (the test passes and the run ends as usual),
# passedshort (the test passes, then the shortMsg), nostart (the shortMsg alone) or noshort (the
# start, then INSTRUMENTATION_CODE: 0 and no shortMsg).
killed_raw() {
  c=com.keepcrypt.entropy.CrashTest
  if [ "$1" != nostart ]; then
    printf 'INSTRUMENTATION_STATUS: class=%s\nINSTRUMENTATION_STATUS: current=1\n' "$c"
    printf 'INSTRUMENTATION_STATUS: id=AndroidJUnitRunner\nINSTRUMENTATION_STATUS: numtests=1\n'
    printf 'INSTRUMENTATION_STATUS: stream=\nINSTRUMENTATION_STATUS: test=anUncaughtException\n'
    printf 'INSTRUMENTATION_STATUS_CODE: 1\n'
    printf 'INSTRUMENTATION_STATUS: kc_probe=crash test: a session started\nINSTRUMENTATION_STATUS_CODE: 2\n'
  fi
  case $1 in
    reported)
      printf 'INSTRUMENTATION_STATUS: class=%s\nINSTRUMENTATION_STATUS: current=1\n' "$c"
      printf 'INSTRUMENTATION_STATUS: stack=java.lang.IllegalStateException: KeepCrypt crash test\n'
      printf 'INSTRUMENTATION_STATUS: test=anUncaughtException\nINSTRUMENTATION_STATUS_CODE: -2\n'
      ;;
    passed | passedshort)
      printf 'INSTRUMENTATION_STATUS: class=%s\nINSTRUMENTATION_STATUS: current=1\n' "$c"
      printf 'INSTRUMENTATION_STATUS: test=anUncaughtException\nINSTRUMENTATION_STATUS_CODE: 0\n'
      if [ "$1" = passed ]; then
        printf 'INSTRUMENTATION_RESULT: stream=\n\nOK (1 test)\n\n\nINSTRUMENTATION_CODE: -1\n'
        return
      fi
      ;;
    noshort)
      printf 'INSTRUMENTATION_CODE: 0\n'
      return
      ;;
  esac
  printf 'INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: 0\n'
}

# selftest: the cases listed in the header, each on a fresh case directory the stand-in adb reads.
selftest() {
  self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0") || exit 2
  st=$(mktemp -d "${TMPDIR:-/tmp}/kc-instrument-selftest.XXXXXX") || exit 2
  trap 'rm -rf "$st"' EXIT
  cat > "$st/adb" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in adb: -s emulator-5554 shell COMMAND, answered from the files in $KC_STUB.
[ "$1" = -s ] && [ "$2" = emulator-5554 ] && [ "$3" = shell ] || { echo "stub adb: unexpected: $*" >&2; exit 1; }
shift 3
case "$*" in
  'dumpsys dropbox')
    [ -f "$KC_STUB/dropbox-fails" ] && exit 1
    if [ -f "$KC_STUB/dropbox-read" ] && [ -f "$KC_STUB/dropbox-after" ]; then
      cat "$KC_STUB/dropbox-after"
    else
      : > "$KC_STUB/dropbox-read"
      cat "$KC_STUB/dropbox"
    fi
    ;;
  'am instrument -w -r -e class com.keepcrypt.entropy.CaptureTest com.keepcrypt.entropy.test/androidx.test.runner.AndroidJUnitRunner' | \
    'am instrument -w -r -e class com.keepcrypt.entropy.CrashTest com.keepcrypt.entropy.test/androidx.test.runner.AndroidJUnitRunner')
    cat "$KC_STUB/raw" ;;
  'am instrument -w -r -e class com.keepcrypt.entropy.CaptureTest -e notClass '*' com.keepcrypt.entropy.test/androidx.test.runner.AndroidJUnitRunner')
    echo "$*" > "$KC_STUB/command"
    cat "$KC_STUB/raw" ;;
  'pidof com.keepcrypt.entropy')
    # alive holds how many more times the process is still running, or "always".
    [ -f "$KC_STUB/alive" ] || exit 1
    n=$(cat "$KC_STUB/alive")
    [ "$n" = always ] && { echo 4242; exit 0; }
    [ "$n" -gt 0 ] || exit 1
    echo $((n - 1)) > "$KC_STUB/alive"
    echo 4242
    ;;
  'dumpsys window windows') cat "$KC_STUB/windows" ;;
  'logcat -b crash -d') cat "$KC_STUB/crash" ;;
  *) echo "stub adb: unexpected command: $*" >&2; exit 1 ;;
esac
EOF
  chmod +x "$st/adb" || exit 2
  passed=0
  failed=0
  # fresh: a case directory for a passing run; the case then changes what it needs.
  fresh() {
    rm -rf "$st/c" && mkdir "$st/c" || exit 2
    raw 0 ok > "$st/c/raw"
    printf 'Drop box contents: 2 entries\n\n2026-10-19 10:00:00 SYSTEM_BOOT (text, 20 bytes)\n2026-10-19 10:00:05 data_app_crash (text, 900 bytes)\n' > "$st/c/dropbox"
    printf 'WINDOW MANAGER WINDOWS (dumpsys window windows)\n  Window #0 Window{a1 u0 com.android.launcher3/com.android.launcher3.uioverlay.QuickstepLauncher}:\n' > "$st/c/windows"
    printf -- '--------- beginning of crash\nE AndroidRuntime: Process: com.example.other, PID: 1001\n' > "$st/c/crash"
  }
  # expect NAME EXIT TEXT...: the script on the stand-in adb, on the test in $test, exits EXIT and
  # prints every TEXT.
  test=com.keepcrypt.entropy.CaptureTest
  expect() {
    name=$1
    want=$2
    shift 2
    KC_STUB=$st/c sh "$self" "$st/adb" emulator-5554 31 com.keepcrypt.entropy.test com.keepcrypt.entropy \
      "$test" > "$st/out" 2>&1
    got=$?
    ok=yes
    [ "$got" -eq "$want" ] || ok=no
    for text in "$@"; do
      grep -q -F -e "$text" "$st/out" || ok=no
    done
    if [ "$ok" = yes ]; then
      passed=$((passed + 1))
      echo "PASS $name"
    else
      failed=$((failed + 1))
      echo "FAIL $name (exit $got, wanted $want)"
      sed 's/^/  | /' "$st/out"
    fi
  }
  bad='failed, errored, ignored or aborted'
  # trigger_crash [EXCEPTION]: the pre-handler's AndroidRuntime block for the crash test's process,
  # with the trigger's exception line or EXCEPTION, appended to the crash buffer.
  trigger_crash() {
    pre='10-21 10:24:33.144  4242  4242 E AndroidRuntime: '
    {
      printf '%sFATAL EXCEPTION: main\n' "$pre"
      printf '%sProcess: com.keepcrypt.entropy, PID: 4242\n' "$pre"
      printf '%s%s\n' "$pre" "${1:-java.lang.IllegalStateException: KeepCrypt crash test}"
      printf '%s\tat com.keepcrypt.entropy.CrashTest.anUncaughtException$lambda$0(CrashTest.kt:43)\n' "$pre"
      printf '%s\tat android.os.Handler.handleCallback(Handler.java:959)\n' "$pre"
      printf '%s\tat android.os.Looper.loop(Looper.java:317)\n' "$pre"
    } >> "$st/c/crash"
  }

  fresh
  expect "a passing class" 0 "probe: api=31 first-launch: 0 lit pixels" "pass: api=31 first-launch: drawn, then black" \
    "kc: region=0,48,720,1184" "instrument: api=31 PASS com.keepcrypt.entropy.CaptureTest (2 tests;"
  fresh
  raw 0 ok | awk '{ printf "%s\r\n", $0 }' > "$st/c/raw"
  expect "a passing class with CRLF line ends" 0 "kc: region=0,48,720,1184" "instrument: api=31 PASS"
  fresh
  echo 2 > "$st/c/alive"
  expect "a passing class whose process is gone after 2 s" 0 "instrument: api=31 PASS"
  for code in -1 -2 -3 -4; do
    fresh
    raw "$code" ok > "$st/c/raw"
    expect "end status $code" 1 "2 started, 1 passed, 1 $bad"
  done
  fresh
  raw none ok > "$st/c/raw"
  expect "a test with no end status" 1 "2 started, 1 passed, 0 $bad"
  fresh
  raw none crashed > "$st/c/raw"
  expect "a crashed process (shortMsg)" 1 "2 started, 1 passed, 1 $bad"
  fresh
  raw 0 failed > "$st/c/raw"
  expect "INSTRUMENTATION_FAILED" 1 "2 started, 2 passed, 1 $bad"
  fresh
  raw 0 aborted > "$st/c/raw"
  expect "INSTRUMENTATION_ABORTED" 1 "2 started, 2 passed, 1 $bad"
  fresh
  raw 0 code0 > "$st/c/raw"
  expect "no final INSTRUMENTATION_CODE: -1" 1 "2 started, 2 passed, 0 $bad"
  fresh
  raw 0 empty > "$st/c/raw"
  expect "no test" 1 "0 started, 0 passed, 0 $bad"
  fresh
  echo always > "$st/c/alive"
  expect "a process still running" 1 "com.keepcrypt.entropy is still running 20 s after the run"
  fresh
  echo '  Window #1 Window{b2 u0 Application Error: com.keepcrypt.entropy}:' >> "$st/c/windows"
  expect "a crash window" 1 "a crash or not-responding window is open"
  fresh
  echo '  Window #1 Window{b2 u0 Application Not Responding: com.keepcrypt.entropy}:' >> "$st/c/windows"
  expect "a not-responding window" 1 "a crash or not-responding window is open"
  fresh
  echo 'E AndroidRuntime: Process: com.keepcrypt.entropy.testregistry, PID: 4242' >> "$st/c/crash"
  expect "a crash-buffer line naming one of our packages" 1 "logcat -b crash holds 1 line(s) naming com.keepcrypt.entropy"
  fresh
  { cat "$st/c/dropbox"; echo '2026-10-19 10:01:00 data_app_crash (text, 950 bytes)'; } > "$st/c/dropbox-after"
  expect "a new data_app_crash entry" 1 "dumpsys dropbox gained 1 data_app_crash entries"
  fresh
  : > "$st/c/dropbox-fails"
  expect "an unreadable dropbox" 2 "dumpsys dropbox cannot be read"
  # A class without some of its tests (CLASS-METHOD...), and the notClass filter the stand-in adb was given.
  cls=com.keepcrypt.entropy.CaptureTest
  # filtered NAME FILTER: the stand-in adb's am instrument command line held the notClass filter FILTER.
  filtered() {
    want="am instrument -w -r -e class $cls -e notClass $2 com.keepcrypt.entropy.test/androidx.test.runner.AndroidJUnitRunner"
    if [ "$(cat "$st/c/command" 2>/dev/null)" = "$want" ]; then
      passed=$((passed + 1))
      echo "PASS $1: the command line"
    else
      failed=$((failed + 1))
      echo "FAIL $1: the command line is '$(cat "$st/c/command" 2>/dev/null)', not '$want'"
    fi
  }
  fresh
  test=$cls-test3
  expect "a class without one of its tests" 0 "instrument: api=31 PASS $cls (2 tests, without test3; process gone"
  filtered "a class without one of its tests" "$cls#test3"
  fresh
  test=$cls-test3-test4
  expect "a class without two of its tests" 0 "instrument: api=31 PASS $cls (2 tests, without test3 test4; process gone"
  filtered "a class without two of its tests" "$cls#test3,$cls#test4"
  fresh
  test=$cls-test2
  expect "a run that starts a test it was to leave out" 1 "the run started test2, which it was to leave out"
  # A test that ends its own process (killed:).
  test=killed:com.keepcrypt.entropy.CrashTest
  killed='the process did not end during the test'
  fresh
  killed_raw crashed > "$st/c/raw"
  trigger_crash
  expect "a killed test whose process ends during it" 0 "probe: api=31 crash test: a session started" \
    "instrument: api=31 PASS com.keepcrypt.entropy.CrashTest (killed during the test, as it must be;" \
    "the crash buffer holds only the trigger's crash (Q75)"
  fresh
  killed_raw reported > "$st/c/raw"
  trigger_crash
  expect "a killed test the runner reports failed as its process ends" 0 "instrument: api=31 PASS com.keepcrypt.entropy.CrashTest (killed"
  fresh
  killed_raw passed > "$st/c/raw"
  expect "a killed test that passes" 1 "1 started, 1 passed: $killed"
  fresh
  killed_raw passedshort > "$st/c/raw"
  expect "a killed test that passes before its process ends" 1 "1 started, 1 passed: $killed"
  fresh
  killed_raw nostart > "$st/c/raw"
  expect "a killed test that never starts" 1 "0 started, 0 passed: $killed"
  fresh
  killed_raw noshort > "$st/c/raw"
  expect "a killed test with no shortMsg" 1 "1 started, 0 passed: $killed"
  fresh
  killed_raw crashed > "$st/c/raw"
  trigger_crash
  echo '  Window #1 Window{b2 u0 Application Error: com.keepcrypt.entropy}:' >> "$st/c/windows"
  expect "a killed test with a crash window" 1 "a crash or not-responding window is open"
  fresh
  killed_raw crashed > "$st/c/raw"
  expect "a killed test with no crash of ours in the crash buffer" 1 \
    "logcat -b crash holds 0 crash(es) of our packages (exactly one, the trigger's, is allowed)"
  fresh
  killed_raw crashed > "$st/c/raw"
  trigger_crash
  trigger_crash
  expect "a killed test with two crashes of ours" 1 "logcat -b crash holds 2 crash(es) of our packages"
  fresh
  killed_raw crashed > "$st/c/raw"
  trigger_crash 'java.lang.IllegalArgumentException: not the trigger'
  expect "a killed test whose crash is another exception" 1 "logcat -b crash: our crash is not the trigger's exception"
  fresh
  killed_raw crashed > "$st/c/raw"
  printf 'E AndroidRuntime: FATAL EXCEPTION: main\nE AndroidRuntime: Process: com.keepcrypt.entropy, PID: 4242\n' >> "$st/c/crash"
  expect "a killed test whose crash has no exception line" 1 "logcat -b crash: our crash is not the trigger's exception"
  fresh
  killed_raw crashed > "$st/c/raw"
  trigger_crash
  echo '10-21 10:24:33.144  4242  4242 E AndroidRuntime: Caused by: java.lang.RuntimeException: inner' >> "$st/c/crash"
  expect "a killed test whose crash has a Caused by" 1 "logcat -b crash: our crash holds 1 other exception(s) (Caused by or Suppressed)"
  fresh
  killed_raw crashed > "$st/c/raw"
  trigger_crash
  echo '10-21 10:24:33.150   612   640 W SomeTag: com.keepcrypt.entropy after the crash' >> "$st/c/crash"
  expect "a killed test with a line naming our package outside its crash" 1 \
    "logcat -b crash holds 1 line(s) naming com.keepcrypt.entropy outside the trigger's crash"
  fresh
  killed_raw crashed > "$st/c/raw"
  trigger_crash
  { cat "$st/c/dropbox"; echo '2026-10-19 10:01:00 data_app_crash (text, 950 bytes)'; } > "$st/c/dropbox-after"
  expect "a killed test with a new data_app_crash entry" 1 "dumpsys dropbox gained 1 data_app_crash entries"
  test=com.keepcrypt.entropy.CaptureTest
  sh "$self" "$st/adb" emulator-5554 31 > "$st/out" 2>&1
  if [ "$?" -eq 2 ] && grep -q -e '^usage: ' "$st/out"; then
    passed=$((passed + 1))
    echo "PASS too few arguments"
  else
    failed=$((failed + 1))
    echo "FAIL too few arguments"
  fi
  echo "android-instrument selftest: $passed passed, $failed failed"
  [ "$failed" -eq 0 ]
}

if [ $# -eq 1 ] && [ "$1" = --selftest ]; then
  selftest
  exit
fi

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

# The crash test's exception line (CrashTest.kt's fixed text), the one crash of ours a killed: run's
# crash buffer holds (Q75).
trigger='java.lang.IllegalStateException: KeepCrypt crash test'

# crash_counts: five counts from logcat -b crash in $tmp/crash: the lines naming com.keepcrypt.entropy;
# the AndroidRuntime crash blocks of our processes ("FATAL EXCEPTION:", then "Process:" naming one of
# our packages, then the lines with the same tag); of those, the ones whose exception line is missing or
# not the trigger's; the "Caused by:" and "Suppressed:" lines in them; and the lines naming our packages
# outside them.
crash_counts() {
  awk -v trigger="$trigger" '
    function end_block() { if (ours && !exc) badexc++; inblock = 0; ours = 0; want = "" }
    {
      line = $0
      sub(/\r$/, "", line)
      at = index(line, " AndroidRuntime: ")
      msg = at ? substr(line, at + 17) : ""
      if (!at) end_block()
      else if (index(msg, "FATAL EXCEPTION: ") == 1) { end_block(); inblock = 1; want = "process" }
      else if (inblock && want == "process") {
        want = ""
        if (index(msg, "Process: ") == 1 && index(msg, "com.keepcrypt.entropy") > 0) { ours = 1; exc = 0; blocks++; want = "exception" }
      } else if (ours && want == "exception") {
        want = ""
        exc = 1
        if (msg != trigger) badexc++
      } else if (ours && (msg ~ /^Caused by: / || msg ~ /^[ \t]*Suppressed: /)) other++
      if (index(line, "com.keepcrypt.entropy") > 0) {
        named++
        if (!ours) stray++
      }
    }
    END { end_block(); printf "%d %d %d %d %d\n", named, blocks, badexc, other, stray }
  ' "$tmp/crash"
}

# app_crashes: the number of data_app_crash entries dumpsys dropbox lists; non-zero when unreadable.
app_crashes() {
  dev shell dumpsys dropbox > "$tmp/dropbox" 2>&1 || return 2
  grep -c -e ' data_app_crash ' "$tmp/dropbox"
  [ $? -le 1 ]
}

for t in "$@"; do
  # killed:TEST, a test that ends its own process (the crash test).
  killed=
  case $t in
    killed:*)
      killed=yes
      t=${t#killed:}
      ;;
  esac
  # CLASS-METHOD[-METHOD...]: the class without those tests.
  without=
  case $t in
    *-*)
      without=$(printf '%s\n' "${t#*-}" | tr '-' ' ')
      t=${t%%-*}
      ;;
  esac
  filter=
  for m in $without; do
    filter="$filter,$t#$m"
  done
  [ -z "$filter" ] || filter="-e notClass ${filter#,}"
  before=$(app_crashes) || { echo "instrument: api=$api: dumpsys dropbox cannot be read" >&2; exit 2; }
  # $filter unquoted: its words, the option and the class's own names, hold no space.
  dev shell am instrument -w -r -e class "$t" $filter "$testpkg/androidx.test.runner.AndroidJUnitRunner" > "$tmp/raw" 2>&1
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
  if [ -n "$killed" ]; then
    # The process went during the test: a start, no pass, and the activity manager's shortMsg.
    if [ "$started" -lt 1 ] || [ "$passed" -ne 0 ] || ! grep -q -e '^INSTRUMENTATION_RESULT: shortMsg=' "$tmp/out"; then
      cat "$tmp/out"
      fail "$t: $started started, $passed passed: the process did not end during the test (adb exit $rc)"
    fi
  elif [ "$started" -lt 1 ] || [ "$passed" -ne "$started" ] || [ "$bad" -ne 0 ] || [ "$finished" -ne 1 ]; then
    cat "$tmp/out"
    fail "$t: $started started, $passed passed, $bad failed, errored, ignored or aborted (adb exit $rc)"
  fi
  for m in $without; do
    if grep -q -x -F -e "INSTRUMENTATION_STATUS: test=$m" "$tmp/out"; then
      cat "$tmp/out"
      fail "$t: the run started $m, which it was to leave out"
    fi
  done
  left=
  [ -z "$without" ] || left=", without $without"
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
  read -r named blocks badexc other stray <<EOF
$(crash_counts)
EOF
  if [ -n "$killed" ]; then
    # Q75: Android's own pre-handler logged the trigger's exception before the app's handler ran.
    [ "$blocks" -eq 1 ] || fail "$t: logcat -b crash holds $blocks crash(es) of our packages (exactly one, the trigger's, is allowed)"
    [ "$badexc" -eq 0 ] || fail "$t: logcat -b crash: our crash is not the trigger's exception"
    [ "$other" -eq 0 ] || fail "$t: logcat -b crash: our crash holds $other other exception(s) (Caused by or Suppressed)"
    [ "$stray" -eq 0 ] || fail "$t: logcat -b crash holds $stray line(s) naming com.keepcrypt.entropy outside the trigger's crash"
  else
    [ "$named" -eq 0 ] || fail "$t: logcat -b crash holds $named line(s) naming com.keepcrypt.entropy"
  fi
  after=$(app_crashes) || fail "$t: dumpsys dropbox cannot be read"
  [ "$after" -eq "$before" ] || fail "$t: dumpsys dropbox gained $((after - before)) data_app_crash entries"
  if [ -n "$killed" ]; then
    echo "instrument: api=$api PASS $t (killed during the test, as it must be$left; process gone, no crash window, the crash buffer holds only the trigger's crash (Q75), dropbox clean)"
  else
    echo "instrument: api=$api PASS $t ($passed tests$left; process gone, no crash window, crash buffer and dropbox clean)"
  fi
done
