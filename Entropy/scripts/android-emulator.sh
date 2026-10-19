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
#   2. Once the APKs are installed, the shell's own screencap (adb exec-out) with capture-control's
#      first screen in front, then with the shipping app's: its exit, byte count and stderr only.
#   3. ControlTest (positive control (a) in screencap, takeScreenshot, dumpsys and recents), once,
#      first; then capture-control's data is cleared (pm clear), which also takes its tasks out of
#      recents, so that its thumbnail is not beside the app's in CaptureTest's recents view.
#   4. For each app APK (shipping, then test registry): CaptureTest, through android-instrument.sh
#      (every screen drawn and then black in screencap and takeScreenshot, SECURE on every window,
#      the recents thumbnail, disable_secure_windows, the empty saved-state Bundle, data-sensitive
#      nodes). Its report gives the app window's region, which the frame checker reads.
#      A test class that fails is reported at once and fails the leg at its end: every class runs,
#      so one run gives both the control's result and the app's.
#   5. Control (a) in raw frames: capture-control's black curtain, a recording, the control's first
#      screen: some frame must show its known pixels (android-frames.py --expect visible).
#   6. The first frame, for each app APK: the curtain, the app force-stopped, a recording from under
#      the curtain through its cold launch (am start -W, which must report COLD) to its first screen
#      and 3 s more: every frame black over the app's window (android-frames.py --expect black). Its
#      first frame is the curtain's and a stream may carry no frame after it (screenrecord writes one
#      only when the display changes), so a second recording starts with the app's first screen up,
#      whose first frame screenrecord composes at once: every frame black over the window too.
# Every recording is one continuous raw-frame stream with no time limit (lead decision M5-17: in
# raw-frames mode screenrecord ignores --time-limit and records until SIGINT): the checker starts
# it, and when the scenario is done this script sends the checker SIGTERM, which stops screenrecord
# with SIGINT on the device and must see the stream end within 5 s. A recording that ends before
# that, or reaches the checker's cap (--duration, 120 s), fails.
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

# start_activity COMPONENT [am start option...]: am start -W, which must report Status: ok; its
# output is kept in $work/start.txt.
start_activity() {
  c=$1
  shift
  dev shell am start -W "$@" -n "$c" > "$work/start.txt" 2>&1
  tr -d '\r' < "$work/start.txt"
  grep -q -e '^Status: ok' "$work/start.txt" || fail "am start $c did not report Status: ok"
}

# 2. The shell's own screencap with each app in front. Run 39290401362: with the launcher in front
# it held 319,321 bytes while the instrumentation's screencap held none.
start_activity "$control/$control.ControlActivity"
sleep 2
shell_screencap "capture-control's first screen"
start_activity com.keepcrypt.entropy/com.keepcrypt.entropy.MainActivity
sleep 2
shell_screencap "the shipping app's first screen"

# fail_later MESSAGE: a failure reported now that fails the leg at its end, so the checks after it
# still run.
failed=
fail_later() {
  echo "FAIL: emulator: api=$api: $1 (the leg goes on, and fails at its end)" >&2
  failed="$failed; $1"
}

# instrument TARGET CLASS...: android-instrument.sh on TARGET's test APK, its output kept in
# $work/instrument.log for the kc: lines.
instrument() {
  target=$1
  shift
  sh "$here/android-instrument.sh" "$adb" "$serial" "$api" "$target.test" "$target" "$@" > "$work/instrument.log" 2>&1
  rc=$?
  cat "$work/instrument.log"
  [ "$rc" -eq 0 ] || fail_later "instrumented tests failed on $target ($*)"
}

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

# 5. Control (a) in raw frames, the same pipeline as the first-frame recordings below.
curtain
start_recording control --expect visible
start_activity "$control/$control.ControlActivity"
sleep 3
stop_recording control || fail "control (a): the raw frames do not show the capture-control's screen"
echo "pass: api=$api control (a) raw frames: $(sed -n 's/^android-frames: PASS visible: //p' "$frames")"

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
