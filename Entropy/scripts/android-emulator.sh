#!/bin/sh
# One emulator leg of the Android workflow (tasks/todo.md, M5 group 6; Q55, Q56): boots a headless
# x86_64 emulator of one API level, installs the APKs the job already built, signed and checked, runs
# the capture harness on them (or, on the 16 KB-page image, the native-library leg below), prints
# the platform probe's facts and shuts the emulator down. The workflow runs it once per image, one
# after another, on the same signed bytes.
#
# Usage: scripts/android-emulator.sh API SDK_ROOT ADB APK_DIR WORK_DIR
#   API      31 or 36: system-images;android-API;default;x86_64; or 16k:
#            system-images;android-36;google_apis_ps16k;x86_64, the 16 KB-page image (group 6)
#   SDK_ROOT the emulator's SDK root (sdkmanager --sdk_root), holding emulator/ and that image (the
#            script adds the empty platforms/ and the platform-tools/ link the emulator looks for)
#   ADB      the job's own adb (the runner's platform-tools)
#   APK_DIR  the signed APKs: app-shipping-release, app-withTestRegistry-release, their -androidTest
#            APKs and capture-control-release (.apk)
#   WORK_DIR a new directory for the AVD, the emulator's log and, in captures/, the shell's screencap
#            of each of capture-control's two screens (step 2), which the workflow uploads: never the
#            APKs, and never a capture of the app
# Or: scripts/android-emulator.sh --booted API SERIAL ADB APK_DIR WORK_DIR [CLASS-TEST[-TEST...]...]
#   the same steps from the keyguard on, on an emulator already up at SERIAL, with no AVD written and
#   nothing booted or shut down: scripts/android-local.sh's kc37 (M5 Stage L, Q76; never a CI step).
#   API (digits alone) only names the printed lines, and the default images' steps run, never 16k's.
#   Each CLASS-TEST... runs that class without those tests (android-instrument.sh's form), for a check
#   the caller names as one the device cannot make; one that no run here holds fails the leg.
#
# The emulator: a hand-written AVD (720x1280 at 320 dpi, 4 cores, 4 GB, no camera, no audio, no
# snapshot, data wiped), no window, SwiftShader graphics, KVM. A boot that does not complete within
# 10 minutes, or an emulator that exits first, is re-run once, logged as "re-run: api=API ..."; a
# second failure fails the leg. A test failure is never re-run. Once booted: the keyguard dismissed,
# the animation scales 0 (a cold launch draws its windows without a transition) and the screen kept on.
#
# Then, in order (every "probe:" line is one of the platform probe's facts for the lead):
#   1. The shell's facts: the build, ro.debuggable, the ABI list, the page size, WIFI_ON and
#      AIRPLANE_MODE_ON, disable_secure_windows, whether logcat -b crash and dumpsys dropbox can be
#      read, what dumpsys content_capture shows, and screenrecord's raw-frame facts
#      (android-frames.py probe).
#   2. Once the APKs are installed, the shell's own screencap (adb exec-out) with each of
#      capture-control's two screens in front, its first screen and dice-99-words12's first words
#      page (a public gate seed, drawn by the app's words composable), then with the shipping app's:
#      its exit, byte count and stderr. The control's two PNGs are kept as
#      WORK_DIR/captures/control-apiAPI-first-launch.png and -words.png, the owner's screen review of
#      the control (M5 group 6; lead decision M5-68 (f)), which the workflow uploads; an empty one fails
#      the leg at its end. The app's goes straight into wc and is never written anywhere.
#   3. ControlTest (positive control (a) in screencap, takeScreenshot, dumpsys and recents, on the
#      control's first screen and its words page), once, first; then capture-control's data is
#      cleared (pm clear), which also takes its tasks out of recents, so that its thumbnail is not
#      beside the app's in CaptureTest's recents view.
#   4. For each app APK (shipping, then test registry): CaptureTest, through android-instrument.sh
#      (every screen drawn and then black in screencap and takeScreenshot, SECURE on every window,
#      the recents thumbnail, disable_secure_windows, the empty saved-state Bundle, the cover's TEST
#      REGISTRY strip in that APK alone, data-sensitive nodes). Its report gives the app window's
#      region, which the frame checker reads.
#      A test class that fails is reported at once and fails the leg at its end: every class runs,
#      so one run gives both the control's result and the app's.
#   4a. PhoneMotionTest, FlowTest and CheckTest on the shipping app, then SnapshotDrillTest on the
#      test-registry app (M5 groups 15 and 16): PhoneMotion on the emulator's own sensors (lead decision
#      M5-51: an accelerometer sample within 5 s, and a gyroscope one where the image lists a gyroscope,
#      in its layout, and none after stop); then the screens from the start to the dice driven through
#      UI Automator, a new seed and a dice-only seed to their minimums, the 256-roll cap, Back, Start
#      disabled online, the airplane-mode settings button, and Wi-Fi on during the dice; then the
#      collision check without a snapshot (the dice's Done, Skip, Match found and Cannot check confirmed
#      and Back there, a wrong go-ahead code refused with the check kept, and the code computed from the
#      drawn check QR typed on the Crockford pad); then, in the test-registry app, a snapshot loaded
#      through core and the check that runs on its own: the collision before any words, the report QR
#      behind the privacy gate, and "Add fresh entropy" at 99 rolls.
#   4b. LifecycleTest on the shipping app (M5 group 14): the app left during a backup's scrypt and
#      during its start-up self-test, and Wi-Fi turned on during a start, each discarding the session
#      with no ANR.
#   4c. CrashTest on the shipping app (group 14), as killed:com.keepcrypt.entropy.CrashTest: an
#      exception thrown on the main thread must end the process through the app's own handler, judged
#      from the shell. It is the last instrumented run of the leg, since the crash buffer and DropBox
#      it is judged on are the device's, read whole by every later judge.
#   5. Control (a) in raw frames: capture-control's black curtain, a recording, the control's first
#      screen: some frame must show its known pixels (android-frames.py --expect visible); then the
#      same with its words page, whose known pixels are its TEST REGISTRY strip's.
#   6. The first frame, for each app APK: the curtain, the app force-stopped, a recording from under
#      the curtain through its cold launch (am start -W, which must report COLD) to its first screen
#      and 3 s more: every frame black over the app's window (android-frames.py --expect black). Its
#      first frame is the curtain's and a stream may carry no frame after it (screenrecord writes one
#      only when the display changes), so a second recording starts with the app's first screen up,
#      whose first frame screenrecord composes at once: every frame black over the window too.
# On the 16 KB-page image (API 16k; M5 group 6, the ARM and 16 KB leg, from commit 14) steps 2-6 are
# not run. After step 1: getconf PAGE_SIZE must be 16384; the shipping APK is installed (the
# package manager's primaryCpuAbi must be x86_64) with its test APK, and NativeTest runs through
# android-instrument.sh: the app's own start to First launch, whose Continue loads the library
# (System.loadLibrary, JNI_OnLoad) and runs the self-test through the bridge, then Go offline (lead
# decision M5-50), the self-test called again and dice-50-words12's Seal ID through the bridge.
# Then, for arm64-v8a and armeabi-v7a, each only if ro.product.cpu.abilist lists it (the image's ARM
# translation, a probe fact): the APK installed again with adb install --abi ABI
# (primaryCpuAbi must then be ABI) and NativeTest again, so the ARM library loads, binds and runs
# translated. An ABI the list lacks is printed as a probe line, for the gate report and Q56: a
# translated run proves loading, symbol binding, JNI_OnLoad and the self-test, never native ARM
# execution.
# Every recording is one continuous raw-frame stream with no time limit (lead decision M5-17: in
# raw-frames mode screenrecord ignores --time-limit and records until SIGINT): the checker starts
# it, and when the scenario is done this script sends the checker SIGTERM, which stops screenrecord
# with SIGINT on the device and must see the stream end within 5 s. A recording that ends before
# that, or reaches the checker's cap (--duration, 120 s), fails.
# Prints "pass: api=API ..." for each control and check that passed; exit 0 all passed, 1 anything
# failed, 2 bad usage. The emulator is shut down on every exit.
#
# scripts/android-emulator.sh --selftest runs whole legs of this script, with the real frame checker,
# on stand-ins written to a temporary directory: an adb, an emulator, a screenrecord that writes a raw
# frame of the screen at its start and on each change of it until SIGINT, and an instrument runner. A
# leg where everything passes exits 0, having run PhoneMotionTest, and FlowTest and CheckTest on the
# shipping app, SnapshotDrillTest on the test-registry app, and LifecycleTest and then the killed
# CrashTest on the shipping app as its last five instrumented runs (a case of its own), and kept the
# control's two screencaps (a case of its own); a failing ControlTest, CaptureTest, PhoneMotionTest,
# FlowTest, CheckTest, SnapshotDrillTest, LifecycleTest and CrashTest each exit 1 at the leg's end,
# after the later checks ran, and so does an empty screencap of the control's screens; capture-control
# still in recents after pm clear, a recording that ends before it is stopped, raw frames that never
# show the control's words page, the app's window lit in the first-frame stream, and the same with that
# stream carrying no frame after the curtain (only the second stream sees it) each exit 1.
# On the 16 KB-page image: a leg with arm64-v8a listed passes, running NativeTest with the app
# installed for x86_64 and again for arm64-v8a (the stand-in runner names the ABI of each run) and
# naming armeabi-v7a as not listed; a page size of 4096, a failing NativeTest and an install whose
# primaryCpuAbi stays x86_64 under --abi each exit 1. With --booted (API 37, no SDK): a leg naming
# CaptureTest's control (c) passes with both CaptureTest runs given that test to leave out, the same
# last five runs, no AVD written and no emulator started; one naming a class no run holds exits 1.
# Too few arguments, --booted on 16k and a --booted class with no test exit 2.
# Exit 0 when every case behaves, 1 otherwise. The legs run at once; it takes about a minute.
set -u
unset CDPATH

# selftest: the cases listed in the header, each a whole leg on its own case directory.
selftest() {
  self=$(cd "$(dirname "$0")" && pwd) || exit 2
  st=$(mktemp -d "${TMPDIR:-/tmp}/kc-emulator-selftest.XXXXXX") || exit 2
  trap 'rm -rf "$st"' EXIT
  mkdir "$st/scripts" || exit 2
  cp "$self/$(basename "$0")" "$st/scripts/android-emulator.sh" || exit 2
  cp "$self/android-frames.py" "$st/scripts/android-frames.py" || exit 2
  cat > "$st/scripts/android-instrument.sh" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in instrument runner: it names the package, the class (with any tests it is to
# leave out) and the ABI the app was last installed for; CaptureTest reports the window's region; the
# class named in KC_FAILCLASS fails.
echo "instrument stub: $5 $6 abi=$(cat "$KC_STUB/abi" 2>/dev/null)"
case ${6%%-*} in *.CaptureTest) printf 'kc: region=0,48,720,1184
kc: display=720x1280
' ;; esac
case ${6%%-*} in *."${KC_FAILCLASS:-none}") exit 1 ;; esac
exit 0
EOF
  cat > "$st/emulator" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in emulator: it boots at once and runs until adb's emu kill.
case $1 in -help) echo '-no-metrics'; exit 0 ;; -version) echo 'stand-in emulator'; exit 0 ;; esac
echo $$ > "$KC_STUB/emulator.pid"
exec sleep 300
EOF
  cat > "$st/adb" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in adb: -s emulator-5554 COMMAND, answered from and into the case directory
# $KC_STUB (screen: what the display shows; front: the package whose MainActivity was started last).
# The control's words page shows the known colour, as its first screen does, unless KC_WORDS_SCREEN
# names another screen; KC_SCREENCAP_EMPTY makes the shell's screencap give nothing.
s=$KC_STUB
[ "$*" = start-server ] && exit 0
[ "$1" = -s ] && [ "$2" = emulator-5554 ] || { echo "stub adb: unexpected: $*" >&2; exit 1; }
shift 2
case "$*" in
  'emu kill') kill "$(cat "$s/emulator.pid")" ;;
  'shell getprop sys.boot_completed') echo 1 ;;
  'shell dumpsys power') echo '  mWakefulness=Awake' ;;
  'shell dumpsys display') echo '  mScreenState=ON' ;;
  'exec-out screencap -p') [ -n "${KC_SCREENCAP_EMPTY:-}" ] || printf 'stand-in png' ;;
  'shell screenrecord '*) exec python3 -I "$(dirname "$0")/screenrecord.py" "$s" none ;;
  'exec-out screenrecord '*) exec python3 -I "$(dirname "$0")/screenrecord.py" "$s" stream ;;
  'shell pkill -INT -x screenrecord') kill -INT "$(cat "$s/recorder.pid")" ;;
  'install --abi '*)
    [ -n "${KC_ABI_STUCK:-}" ] || echo "$3" > "$s/abi"
    echo Success
    ;;
  'install '*)
    case "$*" in *'/app-shipping-release.apk') echo x86_64 > "$s/abi" ;; esac
    echo Success
    ;;
  'uninstall com.keepcrypt.entropy') echo Success ;;
  'shell dumpsys package com.keepcrypt.entropy') printf '    primaryCpuAbi=%s\n' "$(cat "$s/abi")" ;;
  'shell getconf PAGE_SIZE') echo "${KC_PAGE_SIZE:-4096}" ;;
  'shell getprop ro.product.cpu.abilist') echo "${KC_ABILIST:-x86_64}" ;;
  'shell am start -W '*)
    for a; do c=$a; done
    case $c in
      *.CurtainActivity) echo black > "$s/screen" ;;
      *.ControlActivity) echo control > "$s/screen" ;;
      *.WordsActivity) echo "${KC_WORDS_SCREEN:-control}" > "$s/screen" ;;
      *.MainActivity) echo "${KC_APP_SCREEN:-black}" > "$s/screen"; echo "${c%%/*}" > "$s/front" ;;
    esac
    printf 'Status: ok
LaunchState: COLD
'
    ;;
  'shell pm clear com.keepcrypt.entropy.capturecontrol') printf 'Success
' ;;
  'shell dumpsys activity recents')
    echo 'ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)'
    [ -z "${KC_RECENTS:-}" ] || echo '  * Recent #0: Task{a1 #12 type=standard A=10123:com.keepcrypt.entropy.capturecontrol}'
    ;;
  'shell dumpsys window') printf '  mCurrentFocus=Window{b2 u0 %s/com.keepcrypt.entropy.MainActivity}
' "$(cat "$s/front")" ;;
  'shell input '* | 'shell wm '* | 'shell settings '* | 'shell svc '* | 'shell getprop '* | 'shell getconf '* | \
    'shell logcat -b crash -d' | 'shell dumpsys dropbox' | 'shell dumpsys content_capture' | \
    'shell pm list instrumentation' | 'shell am force-stop '*) ;;
  *) echo "stub adb: unexpected command: $*" >&2; exit 1 ;;
esac
EOF
  cat > "$st/screenrecord.py" <<'EOF' || exit 2
# The selftest's stand-in screenrecord --output-format=raw-frames --size 360x640 (rgb888): "stream"
# writes a frame of the case's screen at its start and whenever the screen changes (but to
# lit-unsent: the app's window drawn and no frame written for it), "none" writes nothing; both run
# until SIGINT, or end after their first frame under KC_REC_END.
import os, signal, sys, time
case, kind = sys.argv[1], sys.argv[2]
with open(os.path.join(case, "recorder.pid"), "w") as f:
    f.write(str(os.getpid()))
stopped = []
signal.signal(signal.SIGINT, lambda *a: stopped.append(1))
w, h = 360, 640
shown = None
while not stopped:
    with open(os.path.join(case, "screen")) as f:
        screen = f.read().strip()
    # The stand-in adb rewrites the file with a shell redirection, which truncates it first; a read
    # in between sees an empty file, not a screen (run 39336246707: a lit frame from that gap).
    if not screen:
        time.sleep(0.01)
        continue
    if kind == "stream" and screen != shown and (shown is None or screen != "lit-unsent"):
        frame = bytearray(w * h * 3)
        if screen == "control":
            frame[300 * w * 3:(300 * w + 100) * 3] = bytes((0xFF, 0xD5, 0x4F)) * 100
        elif screen != "black":
            frame[:] = b"\xff" * len(frame)
        sys.stdout.buffer.write(frame)
        sys.stdout.buffer.flush()
        if os.environ.get("KC_REC_END"):
            sys.exit(0)
    shown = screen
    time.sleep(0.05)
EOF
  chmod +x "$st/scripts/android-instrument.sh" "$st/emulator" "$st/adb" || exit 2
  # case_dir NAME: the case directory $st/NAME, c, with the five stand-in APKs and a black screen.
  case_dir() {
    c=$st/$1
    mkdir -p "$c/apks" || exit 2
    for f in app-shipping-release app-shipping-release-androidTest app-withTestRegistry-release \
      app-withTestRegistry-release-androidTest capture-control-release; do
      : > "$c/apks/$f.apk" || exit 2
    done
    echo black > "$c/screen" || exit 2
  }
  # leg NAME [VAR=VALUE...]: one whole leg on API 31 (16k for a NAME that starts with 16k) in the
  # background, its case directory $st/NAME, with VAR=VALUE set for the stand-ins; its output in out
  # and its exit status in rc.
  leg() {
    case_dir "$1"
    case $1 in 16k*) lapi=16k limage=android-36/google_apis_ps16k/x86_64 ;; *) lapi=31 limage=android-31/default/x86_64 ;; esac
    shift
    mkdir -p "$c/sdk/emulator" "$c/sdk/system-images/$limage" || exit 2
    cp "$st/emulator" "$c/sdk/emulator/emulator" || exit 2
    echo 'Pkg.Revision=1' > "$c/sdk/system-images/$limage/source.properties" || exit 2
    {
      env KC_STUB="$c" "$@" sh "$st/scripts/android-emulator.sh" "$lapi" "$c/sdk" "$st/adb" "$c/apks" "$c/work"
      echo $? > "$c/rc"
    } > "$c/out" 2>&1 &
  }
  # booted NAME CLASS-TEST...: a leg through --booted 37 emulator-5554 on the stand-in adb, with no SDK
  # and no emulator started, in the background as leg's.
  booted() {
    case_dir "$1"
    shift
    {
      env KC_STUB="$c" sh "$st/scripts/android-emulator.sh" --booted 37 emulator-5554 "$st/adb" "$c/apks" "$c/work" "$@"
      echo $? > "$c/rc"
    } > "$c/out" 2>&1 &
  }
  passed=0
  failed=0
  # expect NAME EXIT TEXT...: leg NAME exited EXIT and printed every TEXT.
  expect() {
    name=$1
    want=$2
    shift 2
    got=$(cat "$st/$name/rc")
    ok=yes
    [ "$got" = "$want" ] || ok=no
    for text in "$@"; do
      grep -q -F -e "$text" "$st/$name/out" || ok=no
    done
    if [ "$ok" = yes ]; then
      passed=$((passed + 1))
      echo "PASS $name"
    else
      failed=$((failed + 1))
      echo "FAIL $name (exit $got, wanted $want)"
      sed 's/^/  | /' "$st/$name/out"
    fi
  }

  leg pass
  leg control-test-fails KC_FAILCLASS=ControlTest
  leg capture-test-fails KC_FAILCLASS=CaptureTest
  leg motion-test-fails KC_FAILCLASS=PhoneMotionTest
  leg flow-test-fails KC_FAILCLASS=FlowTest
  leg check-test-fails KC_FAILCLASS=CheckTest
  leg snapshot-drill-fails KC_FAILCLASS=SnapshotDrillTest
  leg lifecycle-test-fails KC_FAILCLASS=LifecycleTest
  leg crash-test-fails KC_FAILCLASS=CrashTest
  leg control-in-recents KC_RECENTS=1
  leg recording-ends-early KC_REC_END=1
  leg words-page-not-shown KC_WORDS_SCREEN=black
  leg screencap-empty KC_SCREENCAP_EMPTY=1
  leg app-window-lit KC_APP_SCREEN=lit
  leg app-window-lit-no-frame KC_APP_SCREEN=lit-unsent
  leg 16k-pass KC_PAGE_SIZE=16384 KC_ABILIST=x86_64,arm64-v8a
  leg 16k-page-4096 KC_ABILIST=x86_64,arm64-v8a
  leg 16k-native-test-fails KC_PAGE_SIZE=16384 KC_FAILCLASS=NativeTest
  leg 16k-abi-not-forced KC_PAGE_SIZE=16384 KC_ABILIST=x86_64,arm64-v8a KC_ABI_STUCK=1
  booted booted-pass com.keepcrypt.entropy.CaptureTest-disableSecureWindowsShowsTheScreenOnlyWhileSet
  booted booted-class-unheld com.keepcrypt.entropy.NoSuchTest-aTest
  wait
  expect pass 0 "pass: api=31 control (a) raw frames:" "pass: api=31 control (a) raw frames, words page:" \
    "probe: api=31 adb exec-out screencap -p (capture-control's first screen), kept as control-api31-first-launch.png: exit 0, 12 bytes" \
    "probe: api=31 adb exec-out screencap -p (capture-control's words page), kept as control-api31-words.png: exit 0, 12 bytes" \
    "pass: api=31 first frame (shipping): every frame black" \
    "pass: api=31 first frame (shipping, its first screen up)" "pass: api=31 first frame (registry, its first screen up)" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.PhoneMotionTest" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.FlowTest" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.CheckTest" \
    "instrument stub: com.keepcrypt.entropy.testregistry com.keepcrypt.entropy.SnapshotDrillTest" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.LifecycleTest" \
    "instrument stub: com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest" \
    "emulator: api=31: every check passed"
  # Steps 4a-4c: the leg NAME's last five instrumented runs are FlowTest, CheckTest, SnapshotDrillTest
  # (on the test-registry app), LifecycleTest and then the killed CrashTest, so no run comes after the
  # crash test.
  last_five() {
    order=$(sed -n 's/^instrument stub: \([^ ]*\) \([^ ]*\) .*/\1 \2/p' "$st/$1/out" | tail -n 5 | tr '\n' ' ')
    if [ "$order" = "com.keepcrypt.entropy com.keepcrypt.entropy.FlowTest com.keepcrypt.entropy com.keepcrypt.entropy.CheckTest com.keepcrypt.entropy.testregistry com.keepcrypt.entropy.SnapshotDrillTest com.keepcrypt.entropy com.keepcrypt.entropy.LifecycleTest com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest " ]; then
      passed=$((passed + 1))
      echo "PASS $1: FlowTest, CheckTest, SnapshotDrillTest (test registry), LifecycleTest, then the killed CrashTest, last"
    else
      failed=$((failed + 1))
      echo "FAIL $1: the leg's last five instrumented runs are $order"
    fi
  }
  last_five pass
  # Step 2: the control's two screencaps kept for the upload, and nothing else in captures/.
  kept=$(cd "$st/pass/work/captures" 2> /dev/null && ls | tr '\n' ' ')
  if [ "$kept" = "control-api31-first-launch.png control-api31-words.png " ] &&
    [ "$(cat "$st/pass/work/captures/control-api31-words.png")" = 'stand-in png' ]; then
    passed=$((passed + 1))
    echo "PASS pass: the control's two screencaps kept in captures/"
  else
    failed=$((failed + 1))
    echo "FAIL pass: captures/ holds $kept"
  fi
  expect motion-test-fails 1 \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.FlowTest" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.LifecycleTest" \
    "instrument stub: com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest" \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: instrumented tests failed on com.keepcrypt.entropy (com.keepcrypt.entropy.PhoneMotionTest) (each reported above)"
  expect flow-test-fails 1 \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.CheckTest" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.LifecycleTest" \
    "instrument stub: com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest" \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: instrumented tests failed on com.keepcrypt.entropy (com.keepcrypt.entropy.FlowTest) (each reported above)"
  expect check-test-fails 1 \
    "instrument stub: com.keepcrypt.entropy.testregistry com.keepcrypt.entropy.SnapshotDrillTest" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.LifecycleTest" \
    "instrument stub: com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest" \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: instrumented tests failed on com.keepcrypt.entropy (com.keepcrypt.entropy.CheckTest) (each reported above)"
  expect snapshot-drill-fails 1 \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.LifecycleTest" \
    "instrument stub: com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest" \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: instrumented tests failed on com.keepcrypt.entropy.testregistry (com.keepcrypt.entropy.SnapshotDrillTest) (each reported above)"
  expect lifecycle-test-fails 1 \
    "instrument stub: com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest" \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: instrumented tests failed on com.keepcrypt.entropy (com.keepcrypt.entropy.LifecycleTest) (each reported above)"
  expect crash-test-fails 1 \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: instrumented tests failed on com.keepcrypt.entropy (killed:com.keepcrypt.entropy.CrashTest) (each reported above)"
  expect control-test-fails 1 \
    "instrumented tests failed on com.keepcrypt.entropy (com.keepcrypt.entropy.ControlTest) (the leg goes on" \
    "instrument stub: com.keepcrypt.entropy.testregistry com.keepcrypt.entropy.CaptureTest" \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: instrumented tests failed on com.keepcrypt.entropy (com.keepcrypt.entropy.ControlTest) (each reported above)"
  expect capture-test-fails 1 \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: instrumented tests failed on com.keepcrypt.entropy (com.keepcrypt.entropy.CaptureTest); instrumented tests failed on com.keepcrypt.entropy.testregistry (com.keepcrypt.entropy.CaptureTest) (each reported above)"
  expect control-in-recents 1 "probe: api=31 recents after pm clear com.keepcrypt.entropy.capturecontrol: 1 lines name it" \
    "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: capture-control is still in recents after pm clear (each reported above)"
  expect recording-ends-early 1 "before it was stopped" "FAIL: emulator: api=31: control"
  expect words-page-not-shown 1 "pass: api=31 control (a) raw frames:" \
    "FAIL: emulator: api=31: control (a): the raw frames do not show the capture control's words page"
  expect screencap-empty 1 "pass: api=31 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=31: the shell's screencap of capture-control's first screen failed or is empty; the shell's screencap of capture-control's words page failed or is empty (each reported above)"
  expect app-window-lit 1 "FAIL: emulator: api=31: shipping: a raw frame shows the app's window"
  expect app-window-lit-no-frame 1 "pass: api=31 first frame (shipping): every frame black" \
    "FAIL: emulator: api=31: shipping: a raw frame with the app's first screen up shows its window"
  expect 16k-pass 0 "probe: api=16k ro.product.cpu.abilist=x86_64,arm64-v8a; getconf PAGE_SIZE=16384" \
    "probe: api=16k app installed (x86_64): primaryCpuAbi=x86_64" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.NativeTest abi=x86_64" \
    "probe: api=16k app installed (arm64-v8a): primaryCpuAbi=arm64-v8a" \
    "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.NativeTest abi=arm64-v8a" \
    "pass: api=16k native library: x86_64, arm64-v8a" \
    "probe: api=16k armeabi-v7a: not in ro.product.cpu.abilist (x86_64,arm64-v8a): not run here" \
    "emulator: api=16k: every check passed"
  expect 16k-page-4096 1 "FAIL: emulator: api=16k: getconf PAGE_SIZE is 4096, not 16384"
  expect 16k-native-test-fails 1 \
    "FAIL: emulator: api=16k: instrumented tests failed on com.keepcrypt.entropy (com.keepcrypt.entropy.NativeTest) (each reported above)"
  expect 16k-abi-not-forced 1 "FAIL: emulator: api=16k: the app's primaryCpuAbi is x86_64, not arm64-v8a"
  # --booted: the steps alone, both CaptureTest runs without the test named, and no AVD or emulator.
  left=com.keepcrypt.entropy.CaptureTest-disableSecureWindowsShowsTheScreenOnlyWhileSet
  expect booted-pass 0 "instrument stub: com.keepcrypt.entropy com.keepcrypt.entropy.ControlTest" \
    "instrument stub: com.keepcrypt.entropy $left" "instrument stub: com.keepcrypt.entropy.testregistry $left" \
    "pass: api=37 control (a) raw frames:" "pass: api=37 control (a) raw frames, words page:" \
    "kept as control-api37-words.png: exit 0, 12 bytes" "pass: api=37 first frame (registry, its first screen up)" \
    "emulator: api=37: every check passed"
  last_five booted-pass
  if [ ! -e "$st/booted-pass/work/avd" ] && [ ! -e "$st/booted-pass/emulator.pid" ]; then
    passed=$((passed + 1))
    echo "PASS booted-pass: no AVD written, no emulator started"
  else
    failed=$((failed + 1))
    echo "FAIL booted-pass: an AVD was written or an emulator started"
  fi
  expect booted-class-unheld 1 "pass: api=37 first frame (registry, its first screen up)" \
    "FAIL: emulator: api=37: --booted named com.keepcrypt.entropy.NoSuchTest to run without aTest, and no instrumented run here is that class (each reported above)"
  # refused NAME TEXT ARG...: the script on ARG... exits 2 with a line that starts with TEXT, running no leg.
  refused() {
    name=$1
    text=$2
    shift 2
    sh "$st/scripts/android-emulator.sh" "$@" > "$st/out" 2>&1
    if [ "$?" -eq 2 ] && grep -q -e "^$text" "$st/out"; then
      passed=$((passed + 1))
      echo "PASS $name"
    else
      failed=$((failed + 1))
      echo "FAIL $name"
      sed 's/^/  | /' "$st/out"
    fi
  }
  refused "too few arguments" 'usage: ' 31
  refused "--booted on 16k" 'android-emulator: --booted needs an API level of digits alone' \
    --booted 16k emulator-5554 "$st/adb" "$st/pass/apks" "$st/out-booted"
  refused "--booted with a class and no test" 'android-emulator: not a CLASS-TEST' \
    --booted 37 emulator-5554 "$st/adb" "$st/pass/apks" "$st/out-booted" com.keepcrypt.entropy.CaptureTest
  echo "android-emulator selftest: $passed passed, $failed failed"
  [ "$failed" -eq 0 ]
}

if [ $# -eq 1 ] && [ "$1" = --selftest ]; then
  selftest
  exit
fi

booted=
if [ $# -ge 6 ] && [ "$1" = --booted ]; then
  booted=yes
  shift
elif [ $# -ne 5 ]; then
  echo "usage: scripts/android-emulator.sh API SDK_ROOT ADB APK_DIR WORK_DIR" >&2
  echo "       scripts/android-emulator.sh --booted API SERIAL ADB APK_DIR WORK_DIR [CLASS-TEST[-TEST...]...]" >&2
  exit 2
fi
api=$1
sdk=$2
adb=$3
apks=$4
work=$5
shift 5
serial=emulator-5554
without=
used=
if [ -n "$booted" ]; then
  # SERIAL in SDK_ROOT's place; API only names the printed lines; each CLASS-TEST... a class whose
  # run leaves those tests out.
  serial=$sdk
  sdk=
  case $api in
    '' | *[!0-9]*) echo "android-emulator: --booted needs an API level of digits alone" >&2; exit 2 ;;
  esac
  for w; do
    case $w in
      *[!A-Za-z0-9_.-]* | -* | *- | *--*) echo "android-emulator: not a CLASS-TEST[-TEST...]: $w" >&2; exit 2 ;;
      ?*-?*) without="$without $w" ;;
      *) echo "android-emulator: not a CLASS-TEST[-TEST...]: $w" >&2; exit 2 ;;
    esac
  done
else
  case $api in
    31 | 36) level=$api tag=default ;;
    16k) level=36 tag=google_apis_ps16k ;;
    *) echo "android-emulator: API must be 31, 36 or 16k" >&2; exit 2 ;;
  esac
  image="system-images;android-$level;$tag;x86_64"
  sysdir=system-images/android-$level/$tag/x86_64
  avd=kc$api
fi

here=$(cd "$(dirname "$0")" && pwd) || exit 2
size=360x640
cap=120
control=com.keepcrypt.entropy.capturecontrol
curtain=$control/$control.CurtainActivity

fail() {
  echo "FAIL: emulator: api=$api: $1" >&2
  exit 1
}
say() { echo "emulator: api=$api: $1"; }
probe() { echo "probe: api=$api $1"; }
dev() { "$adb" -s "$serial" "$@"; }
# value CMD...: a device command's output on one line, carriage returns dropped.
value() { dev shell "$@" 2>&1 | tr -d '\r' | tr '\n' ' ' | sed 's/ *$//'; }

[ -x "$adb" ] || fail "no adb at $adb"
for f in app-shipping-release app-shipping-release-androidTest app-withTestRegistry-release \
  app-withTestRegistry-release-androidTest capture-control-release; do
  [ -f "$apks/$f.apk" ] || fail "no $apks/$f.apk"
done
mkdir -p "$work" || exit 2

emu_pid=
stop_emulator() {
  [ -n "$emu_pid" ] || return 0
  dev emu kill > /dev/null 2>&1
  i=0
  while kill -0 "$emu_pid" 2> /dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
      kill -9 "$emu_pid" 2> /dev/null
      break
    fi
    sleep 1
  done
  wait "$emu_pid" 2> /dev/null
  emu_pid=
}
trap stop_emulator EXIT

# boot N: start the emulator (attempt N) and wait up to 600 s for sys.boot_completed; 1 on failure.
boot() {
  log=$work/emulator-$1.log
  say "boot attempt $1: emulator $options"
  # $options unquoted: its words hold no space.
  ANDROID_SDK_ROOT=$sdk ANDROID_HOME=$sdk ANDROID_AVD_HOME=$work/avd \
    "$sdk/emulator/emulator" $options > "$log" 2>&1 &
  emu_pid=$!
  start=$(date +%s)
  while :; do
    if ! kill -0 "$emu_pid" 2> /dev/null; then
      say "the emulator exited during boot attempt $1"
      return 1
    fi
    if [ "$(dev shell getprop sys.boot_completed 2> /dev/null | tr -d '\r')" = 1 ]; then
      say "booted in $(($(date +%s) - start)) s (attempt $1)"
      return 0
    fi
    [ $(($(date +%s) - start)) -lt 600 ] || { say "no boot within 600 s (attempt $1)"; return 1; }
    sleep 5
  done
}

"$adb" start-server > /dev/null 2>&1 || fail "adb start-server failed"
# The leg's own AVD and boot; with --booted the emulator is already up, and nothing here runs.
if [ -z "$booted" ]; then
  [ -x "$sdk/emulator/emulator" ] || fail "no emulator in $sdk"
  [ -d "$sdk/$sysdir" ] || fail "no $image in $sdk"
  mkdir -p "$work/avd/$avd.avd" || exit 2
  # The emulator takes SDK_ROOT for an SDK only when it has a platforms and a platform-tools directory:
  # an empty one, and the runner's platform-tools (ADB's own directory) linked in.
  mkdir -p "$sdk/platforms" || exit 2
  [ -e "$sdk/platform-tools" ] || ln -s "$(dirname "$adb")" "$sdk/platform-tools" || exit 2

  # The AVD, written by hand (no avdmanager): image.sysdir.1 is relative to SDK_ROOT.
  cat > "$work/avd/$avd.ini" <<EOF || exit 2
avd.ini.encoding=UTF-8
path=$work/avd/$avd.avd
target=android-$level
EOF
  cat > "$work/avd/$avd.avd/config.ini" <<EOF || exit 2
avd.ini.encoding=UTF-8
AvdId=$avd
avd.ini.displayname=$avd
abi.type=x86_64
hw.cpu.arch=x86_64
hw.cpu.ncore=4
hw.ramSize=4096
image.sysdir.1=$sysdir/
tag.id=$tag
hw.lcd.width=720
hw.lcd.height=1280
hw.lcd.density=320
hw.keyboard=yes
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader_indirect
hw.camera.back=none
hw.camera.front=none
hw.audioInput=no
hw.audioOutput=no
disk.dataPartition.size=6G
fastboot.forceColdBoot=yes
showDeviceFrame=no
EOF

  options="-avd $avd -no-window -no-audio -no-boot-anim -no-snapshot -wipe-data -gpu swiftshader_indirect"
  options="$options -camera-back none -camera-front none -port 5554"
  if "$sdk/emulator/emulator" -help 2>&1 | grep -q -e '-no-metrics'; then
    options="$options -no-metrics"
  fi

  echo "== $image: $(sed -n 's/^Pkg[.]Revision=//p' "$sdk/$sysdir/source.properties")"
  echo "== emulator: $("$sdk/emulator/emulator" -version 2>&1 | head -n 1)"
  if ! boot 1; then
    tail -n 40 "$work/emulator-1.log"
    stop_emulator
    echo "re-run: api=$api emulator boot attempt 2 (the plan allows one re-run of a boot failure, never of a test)"
    if ! boot 2; then
      tail -n 40 "$work/emulator-2.log"
      fail "the emulator did not boot in two attempts"
    fi
  fi
fi

dev shell input keyevent 82 > /dev/null 2>&1
dev shell wm dismiss-keyguard > /dev/null 2>&1
for s in window_animation_scale transition_animation_scale animator_duration_scale; do
  dev shell settings put global "$s" 0 || fail "settings put global $s failed"
done
dev shell svc power stayon true || fail "svc power stayon failed"
dev shell settings put system screen_off_timeout 1800000 || fail "settings put system screen_off_timeout failed"
# Wake the display: stayon keeps an awake screen on but does not wake one that is already off, and
# with the display off screencap returns nothing and screenrecord waits forever for a frame (run
# 39287689866: "screencap -p gave no image"; the screenrecord probe timed out).
dev shell input keyevent KEYCODE_WAKEUP || fail "input keyevent KEYCODE_WAKEUP failed"
dev shell wm dismiss-keyguard > /dev/null 2>&1
sleep 10
wake=$(value dumpsys power | grep -o 'mWakefulness=[A-Za-z]*' | head -n 1)
shown=$(value dumpsys display | grep -o 'mScreenState=[A-Z_]*' | head -n 1)
probe "display: $wake; $shown"
# shell_screencap WHAT: the shell's own screencap while WHAT is on screen, as a probe line of its
# exit, its byte count and its stderr. The PNG goes straight into wc and is never written anywhere.
shell_screencap() {
  bytes=$({
    dev exec-out screencap -p 2> "$work/screencap.err"
    echo $? > "$work/screencap.rc"
  } | wc -c | tr -d ' ')
  probe "adb exec-out screencap -p ($1): exit $(cat "$work/screencap.rc"), $bytes bytes, stderr: $(tr -d '\r' < "$work/screencap.err" | tr '\n' ' ')"
}
shell_screencap "the display just woken, no app started"
case $wake in
  mWakefulness=Awake) ;;
  *) fail "the display is not awake ($wake; $shown)" ;;
esac

# fail_later MESSAGE: a failure reported now that fails the leg at its end, so the checks after it
# still run.
failed=
fail_later() {
  echo "FAIL: emulator: api=$api: $1 (the leg goes on, and fails at its end)" >&2
  failed="$failed; $1"
}

# instrument TARGET CLASS...: android-instrument.sh on TARGET's test APK, its output kept in
# $work/instrument.log for the kc: lines; a class --booted named runs without the tests it named.
instrument() {
  target=$1
  shift
  tests=
  for t; do
    for w in $without; do
      case $w in "$t"-*) t=$w used="$used $w" ;; esac
    done
    tests="$tests $t"
  done
  # $tests unquoted: class and test names hold no space.
  sh "$here/android-instrument.sh" "$adb" "$serial" "$api" "$target.test" "$target" $tests > "$work/instrument.log" 2>&1
  rc=$?
  cat "$work/instrument.log"
  [ "$rc" -eq 0 ] || fail_later "instrumented tests failed on $target ($*)"
}

# 1. The shell's facts.
probe "build: $(value getprop ro.build.fingerprint); sdk $(value getprop ro.build.version.sdk); type $(value getprop ro.build.type); ro.debuggable=$(value getprop ro.debuggable)"
probe "ro.product.cpu.abilist=$(value getprop ro.product.cpu.abilist); getconf PAGE_SIZE=$(value getconf PAGE_SIZE)"
probe "settings global wifi_on=$(value settings get global wifi_on); airplane_mode_on=$(value settings get global airplane_mode_on)"
probe "settings secure disable_secure_windows=$(value settings get secure disable_secure_windows) (null: unset)"
dev shell logcat -b crash -d > "$work/crash.txt" 2>&1
rc=$?
probe "logcat -b crash -d: exit $rc, $(wc -l < "$work/crash.txt") lines"
dev shell dumpsys dropbox > "$work/dropbox.txt" 2>&1
rc=$?
probe "dumpsys dropbox: exit $rc, $(grep -c -e ' data_app_crash ' "$work/dropbox.txt") data_app_crash entries, $(wc -l < "$work/dropbox.txt") lines"
dev shell dumpsys content_capture 2>&1 | tr -d '\r' | sed '/^[[:space:]]*$/d' | head -n 20 | while IFS= read -r line; do
  probe "dumpsys content_capture: $line"
done
python3 -I "$here/android-frames.py" probe "$adb" "$serial" "$api" "$size" 720x1280 || say "the screenrecord probe stopped early"

# The 16 KB-page image (M5 group 6, the ARM and 16 KB leg): the page size, then NativeTest on the
# shipping APK for x86_64 and for each ARM ABI the image lists (translated), each install's ABI
# read back from the package manager; steps 2-6 are the default images' (see the header).
if [ "$api" = 16k ]; then
  page=$(value getconf PAGE_SIZE)
  [ "$page" = 16384 ] || fail "getconf PAGE_SIZE is $page, not 16384"
  abis=$(value getprop ro.product.cpu.abilist)
  app=com.keepcrypt.entropy
  out=$(dev install "$apks/app-shipping-release-androidTest.apk" 2>&1)
  case $out in *Success*) say "installed app-shipping-release-androidTest.apk" ;; *) echo "$out"; fail "adb install app-shipping-release-androidTest.apk failed" ;; esac
  ran=
  # native_on ABI [INSTALL-OPTION...]: the shipping APK installed afresh with the options given,
  # its primaryCpuAbi ABI, then NativeTest in its process.
  native_on() {
    want=$1
    shift
    dev uninstall "$app" > /dev/null 2>&1
    out=$(dev install "$@" "$apks/app-shipping-release.apk" 2>&1)
    case $out in *Success*) ;; *) echo "$out"; fail "adb install $* app-shipping-release.apk failed" ;; esac
    got=$(value dumpsys package "$app" | tr ' ' '\n' | sed -n 's/^primaryCpuAbi=//p' | head -n 1)
    probe "app installed ($want): primaryCpuAbi=$got"
    if [ "$got" != "$want" ]; then
      fail_later "the app's primaryCpuAbi is $got, not $want"
      return
    fi
    before=$failed
    instrument "$app" com.keepcrypt.entropy.NativeTest
    [ "$failed" != "$before" ] || ran="$ran, $want"
  }
  native_on x86_64
  for abi in arm64-v8a armeabi-v7a; do
    case ",$abis," in
      *",$abi,"*) native_on "$abi" --abi "$abi" ;;
      *) probe "$abi: not in ro.product.cpu.abilist ($abis): not run here (the gate report and Q56 name it)" ;;
    esac
  done
  [ -z "$failed" ] || fail "${failed#; } (each reported above)"
  echo "pass: api=$api native library: ${ran#, } (page size $page): JNI_OnLoad, the self-test and dice-50-words12's Seal ID through the bridge"
  say "every check passed"
  exit 0
fi

for f in app-shipping-release app-withTestRegistry-release capture-control-release \
  app-shipping-release-androidTest app-withTestRegistry-release-androidTest; do
  out=$(dev install "$apks/$f.apk" 2>&1)
  case $out in
    *Success*) say "installed $f.apk" ;;
    *) echo "$out"; fail "adb install $f.apk failed" ;;
  esac
done
dev shell pm list instrumentation

# start_activity COMPONENT [am start option...]: am start -W, which must report Status: ok; its
# output is kept in $work/start.txt.
start_activity() {
  c=$1
  shift
  dev shell am start -W "$@" -n "$c" > "$work/start.txt" 2>&1
  tr -d '\r' < "$work/start.txt"
  grep -q -e '^Status: ok' "$work/start.txt" || fail "am start $c did not report Status: ok"
}

# keep_capture WHAT NAME: shell_screencap's probe line for capture-control's WHAT on screen, but its
# PNG kept as captures/control-apiAPI-NAME.png in WORK_DIR, the owner's screen review of the control,
# which the workflow uploads (M5 group 6; lead decision M5-68 (f)): the control's screens alone, gate
# seeds, never Reveal D and never a capture of the app. A failed or empty one fails the leg at its end.
keep_capture() {
  kept=$work/captures/control-api$api-$2.png
  mkdir -p "$work/captures" || exit 2
  dev exec-out screencap -p > "$kept" 2> "$work/screencap.err"
  rc=$?
  bytes=$(($(wc -c < "$kept")))
  probe "adb exec-out screencap -p ($1), kept as $(basename "$kept"): exit $rc, $bytes bytes, stderr: $(tr -d '\r' < "$work/screencap.err" | tr '\n' ' ')"
  [ "$rc" -eq 0 ] && [ "$bytes" -gt 0 ] || fail_later "the shell's screencap of $1 failed or is empty"
}

# 2. The shell's own screencap with each app in front, capture-control's two screens kept. Run
# 39290401362: with the launcher in front it held 319,321 bytes while the instrumentation's screencap
# held none. The words page shares the control's task, which is cleared first, so it alone is shown.
start_activity "$control/$control.ControlActivity"
sleep 2
keep_capture "capture-control's first screen" first-launch
start_activity "$control/$control.WordsActivity" --activity-clear-task
sleep 2
keep_capture "capture-control's words page" words
start_activity com.keepcrypt.entropy/com.keepcrypt.entropy.MainActivity
sleep 2
shell_screencap "the shipping app's first screen"

# 3. Control (a) in screencap, takeScreenshot, dumpsys and recents, first; then capture-control's
# tasks leave recents with its (empty) data.
instrument com.keepcrypt.entropy com.keepcrypt.entropy.ControlTest
out=$(value pm clear "$control")
[ "$out" = Success ] || fail "pm clear $control: $out"
left=$(dev shell dumpsys activity recents 2>&1 | grep -c -e "$control")
probe "recents after pm clear $control: $left lines name it"
[ "$left" -eq 0 ] || fail_later "capture-control is still in recents after pm clear"

# 4. CaptureTest on each app; each reports its window's region in the display's pixels.
instrument com.keepcrypt.entropy com.keepcrypt.entropy.CaptureTest
region_shipping=$(sed -n 's/^kc: region=//p' "$work/instrument.log" | tail -n 1)
display_shipping=$(sed -n 's/^kc: display=//p' "$work/instrument.log" | tail -n 1)
instrument com.keepcrypt.entropy.testregistry com.keepcrypt.entropy.CaptureTest
region_registry=$(sed -n 's/^kc: region=//p' "$work/instrument.log" | tail -n 1)
display_registry=$(sed -n 's/^kc: display=//p' "$work/instrument.log" | tail -n 1)
[ -n "$region_shipping" ] && [ -n "$display_shipping" ] && [ -n "$region_registry" ] && [ -n "$display_registry" ] ||
  fail "CaptureTest reported no window region"

# 4a. PhoneMotion on the emulator's own sensors (M5-51), then the screens from the start to the dice,
# driven through UI Automator (group 15), then the collision check (group 16): without a snapshot on the
# shipping app, and with one, loaded through core, on the test-registry app (the only one that trusts
# the test registry key).
instrument com.keepcrypt.entropy com.keepcrypt.entropy.PhoneMotionTest
instrument com.keepcrypt.entropy com.keepcrypt.entropy.FlowTest
instrument com.keepcrypt.entropy com.keepcrypt.entropy.CheckTest
instrument com.keepcrypt.entropy.testregistry com.keepcrypt.entropy.SnapshotDrillTest
# 4b. Discards during "Working...": the app left during a backup's scrypt and its start-up self-test,
# Wi-Fi turned on during a start.
instrument com.keepcrypt.entropy com.keepcrypt.entropy.LifecycleTest
# 4c. The crash path, the last instrumented run: the crash test's process ends during the test, by
# the app's own handler, and the judge reads the device's whole crash buffer and DropBox.
instrument com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest
# A class --booted named that no run holds left nothing out, and never passes for one that did.
for w in $without; do
  case " $used " in
    *" $w "*) ;;
    *) fail_later "--booted named ${w%%-*} to run without ${w#*-}, and no instrumented run here is that class" ;;
  esac
done

# wait_for FILE TEXT SECONDS PID: until FILE holds TEXT; 1 when PID exits first or time runs out.
wait_for() {
  i=0
  until grep -q -e "$2" "$1"; do
    kill -0 "$4" 2> /dev/null || return 1
    i=$((i + 1))
    [ "$i" -le "$3" ] || return 1
    sleep 1
  done
}

# curtain: capture-control's black curtain alone in its task, under whatever is launched next.
curtain() {
  start_activity "$curtain" --activity-clear-task
  sleep 2
}

# start_recording NAME OPTION...: android-frames.py record in the background, one raw-frame stream
# with no time limit and a cap of $cap s, its output in $work/frames-NAME.log; returns once its
# first frame has come (the checker itself fails a first frame later than --max-gap, 5 s).
start_recording() {
  rname=$1
  frames=$work/frames-$1.log
  shift
  python3 -I "$here/android-frames.py" record "$adb" "$serial" --size "$size" --format rgb888 --duration "$cap" \
    "$@" > "$frames" 2>&1 &
  fpid=$!
  wait_for "$frames" 'first frame after' 60 "$fpid" || { cat "$frames"; fail "$rname: no first frame"; }
}

# stop_recording NAME: the scenario is done. SIGTERM to the checker, which stops screenrecord with
# SIGINT on the device, waits for the stream to end and judges it; 0 when it passed. A checker that
# has already ended (its stream ended by itself, or it reached its cap) fails the leg here.
stop_recording() {
  kill -TERM "$fpid" 2> /dev/null || { cat "$frames"; fail "$1: the recording ended before the scenario was done"; }
  wait "$fpid"
  rc=$?
  cat "$frames"
  return "$rc"
}

# 5. Control (a) in raw frames, the same pipeline as the first-frame recordings below: capture-control's
# first screen, then its words page (dice-99-words12's first, its known pixels the TEST REGISTRY
# strip's), each over the curtain.
curtain
start_recording control --expect visible
start_activity "$control/$control.ControlActivity"
sleep 3
stop_recording control || fail "control (a): the raw frames do not show the capture-control's screen"
echo "pass: api=$api control (a) raw frames: $(sed -n 's/^android-frames: PASS visible: //p' "$frames")"
curtain
start_recording control-words --expect visible
start_activity "$control/$control.WordsActivity"
sleep 3
stop_recording control-words || fail "control (a): the raw frames do not show the capture control's words page"
echo "pass: api=$api control (a) raw frames, words page: $(sed -n 's/^android-frames: PASS visible: //p' "$frames")"

# first_frame NAME PACKAGE REGION DISPLAY: step 6 for one app.
first_frame() {
  name=$1
  pkg=$2
  curtain
  dev shell am force-stop "$pkg" || fail "am force-stop $pkg failed"
  start_recording "$name" --expect black --display "$4" --region "$3"
  start_activity "$pkg/com.keepcrypt.entropy.MainActivity"
  grep -q -e '^LaunchState: COLD' "$work/start.txt" || fail "$name: am start did not report a cold launch"
  sleep 3
  dev shell dumpsys window > "$work/focus.txt" 2>&1
  grep -q -e "mCurrentFocus=.* $pkg/com[.]keepcrypt[.]entropy[.]MainActivity}" "$work/focus.txt" ||
    fail "$name: the app's activity is not in focus after its launch"
  stop_recording "$name" || fail "$name: a raw frame shows the app's window, or the stream failed its checks"
  echo "pass: api=$api first frame ($name): $(sed -n 's/^android-frames: PASS black: //p' "$frames")"
  # A fresh stream with the app's first screen up: at least one frame recorded with it on screen.
  start_recording "$name-up" --expect black --display "$4" --region "$3"
  sleep 1
  stop_recording "$name-up" || fail "$name: a raw frame with the app's first screen up shows its window, or the stream failed its checks"
  echo "pass: api=$api first frame ($name, its first screen up): $(sed -n 's/^android-frames: PASS black: //p' "$frames")"
  dev shell am force-stop "$pkg" || fail "am force-stop $pkg failed"
}

# 6. The first frame.
first_frame shipping com.keepcrypt.entropy "$region_shipping" "$display_shipping"
first_frame registry com.keepcrypt.entropy.testregistry "$region_registry" "$display_registry"
probe "starting window: black (the raw frames from before each cold launch to the first screen show nothing but black in the app's window)"

[ -z "$failed" ] || fail "${failed#; } (each reported above)"
say "every check passed"
