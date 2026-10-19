#!/bin/sh
# One emulator leg of the Android workflow (tasks/todo.md, M5 group 6; Q55, Q56): boots a headless
# x86_64 emulator of one API level, installs the APKs the job already built, signed and checked, runs
# the capture harness on them, prints the platform probe's facts and shuts the emulator down. The
# workflow runs it once per image, one after another, on the same signed bytes.
#
# Usage: scripts/android-emulator.sh API SDK_ROOT ADB APK_DIR WORK_DIR
#   API      31 or 36: system-images;android-API;default;x86_64
#   SDK_ROOT the emulator's SDK root (sdkmanager --sdk_root), holding emulator/ and that image (the
#            script adds the empty platforms/ and the platform-tools/ link the emulator looks for)
#   ADB      the job's own adb (the runner's platform-tools)
#   APK_DIR  the signed APKs: app-shipping-release, app-withTestRegistry-release, their -androidTest
#            APKs and capture-control-release (.apk)
#   WORK_DIR a new directory for the AVD and the emulator's log (never the APKs or any capture)
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
#   2. For each app APK (shipping, then test registry): CaptureTest, through android-instrument.sh
#      (every screen drawn and then black in screencap and takeScreenshot, SECURE on every window,
#      the recents thumbnail, disable_secure_windows, the empty saved-state Bundle, data-sensitive
#      nodes). Its report gives the app window's region, which the frame checker reads.
#   3. ControlTest (positive control (a) in screencap, takeScreenshot, dumpsys and recents), once.
#   4. Control (a) in raw frames: capture-control's black curtain, a recording, the control's first
#      screen: some frame must show its known pixels (android-frames.py --expect visible).
#   5. The first frame, for each app APK: the curtain, the app force-stopped, a recording in two
#      back-to-back segments of --time-limit 170 from before its cold launch (am start -W, which must
#      report COLD) to its first screen and on: every frame black over the app's window
#      (android-frames.py --expect black). Segment 1 must still be recording once the app's first
#      screen is up, and the last segment until it is stopped: adb exec-out carries no exit status
#      of screenrecord's, so one that ended early is caught by the frames log ("segment N ended").
#      The shipping app's first segment runs to its time limit and must have lasted at least the
#      limit less 2 s (--min-first-segment), so screenrecord's own end is proven on each image (API
#      31's 180 s cap, no --time-limit 0); the test registry's is stopped once the first screen is
#      up. Each second segment is stopped after its first frame.
# Prints "pass: api=API ..." for each control and check that passed; exit 0 all passed, 1 anything
# failed, 2 bad usage. The emulator is shut down on every exit.
set -u
unset CDPATH

if [ $# -ne 5 ]; then
  echo "usage: scripts/android-emulator.sh API SDK_ROOT ADB APK_DIR WORK_DIR" >&2
  exit 2
fi
api=$1
sdk=$2
adb=$3
apks=$4
work=$5
case $api in 31 | 36) ;; *) echo "android-emulator: API must be 31 or 36" >&2; exit 2 ;; esac

here=$(cd "$(dirname "$0")" && pwd) || exit 2
serial=emulator-5554
image="system-images;android-$api;default;x86_64"
avd=kc$api
size=360x640
limit=170
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

[ -x "$sdk/emulator/emulator" ] || fail "no emulator in $sdk"
[ -d "$sdk/system-images/android-$api/default/x86_64" ] || fail "no $image in $sdk"
[ -x "$adb" ] || fail "no adb at $adb"
for f in app-shipping-release app-shipping-release-androidTest app-withTestRegistry-release \
  app-withTestRegistry-release-androidTest capture-control-release; do
  [ -f "$apks/$f.apk" ] || fail "no $apks/$f.apk"
done
mkdir -p "$work/avd/$avd.avd" || exit 2
# The emulator takes SDK_ROOT for an SDK only when it has a platforms and a platform-tools directory:
# an empty one, and the runner's platform-tools (ADB's own directory) linked in.
mkdir -p "$sdk/platforms" || exit 2
[ -e "$sdk/platform-tools" ] || ln -s "$(dirname "$adb")" "$sdk/platform-tools" || exit 2

# The AVD, written by hand (no avdmanager): image.sysdir.1 is relative to SDK_ROOT.
cat > "$work/avd/$avd.ini" <<EOF || exit 2
avd.ini.encoding=UTF-8
path=$work/avd/$avd.avd
target=android-$api
EOF
cat > "$work/avd/$avd.avd/config.ini" <<EOF || exit 2
avd.ini.encoding=UTF-8
AvdId=$avd
avd.ini.displayname=$avd
abi.type=x86_64
hw.cpu.arch=x86_64
hw.cpu.ncore=4
hw.ramSize=4096
image.sysdir.1=system-images/android-$api/default/x86_64/
tag.id=default
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

options="-avd $avd -no-window -no-audio -no-boot-anim -no-snapshot -wipe-data -gpu swiftshader_indirect"
options="$options -camera-back none -camera-front none -port 5554"
if "$sdk/emulator/emulator" -help 2>&1 | grep -q -e '-no-metrics'; then
  options="$options -no-metrics"
fi

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
echo "== $image: $(sed -n 's/^Pkg[.]Revision=//p' "$sdk/system-images/android-$api/default/x86_64/source.properties")"
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
dev exec-out screencap -p > "$work/screencap-probe.png" 2> "$work/screencap-probe.err"
rc=$?
probe "adb exec-out screencap -p: exit $rc, $(wc -c < "$work/screencap-probe.png" | tr -d ' ') bytes, stderr: $(tr -d '\r' < "$work/screencap-probe.err" | tr '\n' ' ')"
rm -f "$work/screencap-probe.png"
case $wake in
  mWakefulness=Awake) ;;
  *) fail "the display is not awake ($wake; $shown)" ;;
esac

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

for f in app-shipping-release app-withTestRegistry-release capture-control-release \
  app-shipping-release-androidTest app-withTestRegistry-release-androidTest; do
  out=$(dev install "$apks/$f.apk" 2>&1)
  case $out in
    *Success*) say "installed $f.apk" ;;
    *) echo "$out"; fail "adb install $f.apk failed" ;;
  esac
done
dev shell pm list instrumentation

# instrument TARGET CLASS...: android-instrument.sh on TARGET's test APK, its output kept in
# $work/instrument.log for the kc: lines.
instrument() {
  target=$1
  shift
  sh "$here/android-instrument.sh" "$adb" "$serial" "$api" "$target.test" "$target" "$@" > "$work/instrument.log" 2>&1
  rc=$?
  cat "$work/instrument.log"
  [ "$rc" -eq 0 ] || fail "instrumented tests failed on $target"
}

# 2. CaptureTest on each app; each reports its window's region in the display's pixels.
instrument com.keepcrypt.entropy com.keepcrypt.entropy.CaptureTest
region_shipping=$(sed -n 's/^kc: region=//p' "$work/instrument.log" | tail -n 1)
display_shipping=$(sed -n 's/^kc: display=//p' "$work/instrument.log" | tail -n 1)
instrument com.keepcrypt.entropy.testregistry com.keepcrypt.entropy.CaptureTest
region_registry=$(sed -n 's/^kc: region=//p' "$work/instrument.log" | tail -n 1)
display_registry=$(sed -n 's/^kc: display=//p' "$work/instrument.log" | tail -n 1)
[ -n "$region_shipping" ] && [ -n "$display_shipping" ] && [ -n "$region_registry" ] && [ -n "$display_registry" ] ||
  fail "CaptureTest reported no window region"

# 3. Control (a) in screencap, takeScreenshot, dumpsys and recents.
instrument com.keepcrypt.entropy com.keepcrypt.entropy.ControlTest

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

# start_activity COMPONENT [am start option...]: am start -W, which must report Status: ok; its
# output is kept in $work/start.txt.
start_activity() {
  c=$1
  shift
  dev shell am start -W "$@" -n "$c" > "$work/start.txt" 2>&1
  tr -d '\r' < "$work/start.txt"
  grep -q -e '^Status: ok' "$work/start.txt" || fail "am start $c did not report Status: ok"
}

# curtain: capture-control's black curtain alone in its task, under whatever is launched next.
curtain() {
  start_activity "$curtain" --activity-clear-task
  sleep 2
}

# stop_recording: screenrecord stops at once (SIGINT); the checker then ends that segment.
stop_recording() { dev shell pkill -INT screenrecord > /dev/null 2>&1; }

# recording FILE N: segment N of the frames log FILE has not ended (the checker prints "segment N
# ended" when its stream does); 1 once it has.
recording() { ! grep -q -e "segment $2 ended" "$1"; }

# 4. Control (a) in raw frames, the same pipeline as the first-frame recordings below.
curtain
frames=$work/frames-control.log
python3 -I "$here/android-frames.py" record "$adb" "$serial" --size "$size" --format rgb888 --time-limit "$limit" \
  --segments 1 --expect visible > "$frames" 2>&1 &
fpid=$!
wait_for "$frames" 'segment 1 first frame' 60 "$fpid" || { cat "$frames"; fail "control: no first frame"; }
start_activity "$control/$control.ControlActivity"
sleep 3
stop_recording
wait "$fpid"
rc=$?
cat "$frames"
[ "$rc" -eq 0 ] || fail "control (a): the raw frames do not show the capture-control's screen"
echo "pass: api=$api control (a) raw frames: $(sed -n 's/^android-frames: PASS visible: //p' "$frames")"

# first_frame NAME PACKAGE REGION DISPLAY NATURAL: step 5 for one app; NATURAL=yes lets the first
# segment run to its time limit, which it must then have lasted (less 2 s).
first_frame() {
  name=$1
  pkg=$2
  curtain
  dev shell am force-stop "$pkg" || fail "am force-stop $pkg failed"
  frames=$work/frames-$name.log
  min_first=0
  [ "$5" = yes ] && min_first=$((limit - 2))
  python3 -I "$here/android-frames.py" record "$adb" "$serial" --size "$size" --format rgb888 \
    --time-limit "$limit" --segments 2 --expect black --display "$4" --region "$3" \
    --min-first-segment "$min_first" > "$frames" 2>&1 &
  fpid=$!
  wait_for "$frames" 'segment 1 first frame' 60 "$fpid" || { cat "$frames"; fail "$name: no first frame"; }
  start_activity "$pkg/com.keepcrypt.entropy.MainActivity"
  grep -q -e '^LaunchState: COLD' "$work/start.txt" || fail "$name: am start did not report a cold launch"
  sleep 3
  dev shell dumpsys window > "$work/focus.txt" 2>&1
  grep -q -e "mCurrentFocus=.* $pkg/com[.]keepcrypt[.]entropy[.]MainActivity}" "$work/focus.txt" ||
    fail "$name: the app's activity is not in focus after its launch"
  recording "$frames" 1 || { cat "$frames"; fail "$name: segment 1 ended before the app's first screen was up"; }
  if [ "$5" = yes ]; then
    say "$name: the first segment runs to its $limit s time limit"
    wait_for "$frames" 'segment 2 first frame' $((limit + 60)) "$fpid" || { cat "$frames"; fail "$name: no second segment"; }
  else
    stop_recording
    wait_for "$frames" 'segment 2 first frame' 60 "$fpid" || { cat "$frames"; fail "$name: no second segment"; }
  fi
  sleep 2
  recording "$frames" 2 || { cat "$frames"; fail "$name: segment 2 ended before it was stopped"; }
  stop_recording
  wait "$fpid"
  rc=$?
  cat "$frames"
  [ "$rc" -eq 0 ] || fail "$name: a raw frame shows the app's window, or a segment failed its checks"
  echo "pass: api=$api first frame and segments ($name): $(sed -n 's/^android-frames: PASS black: //p' "$frames")"
  dev shell am force-stop "$pkg" || fail "am force-stop $pkg failed"
}

# 5. The first frame and the segments.
first_frame shipping com.keepcrypt.entropy "$region_shipping" "$display_shipping" yes
first_frame registry com.keepcrypt.entropy.testregistry "$region_registry" "$display_registry" no
probe "starting window: black (the raw frames from before each cold launch to the first screen show nothing but black in the app's window)"

say "every check passed"
