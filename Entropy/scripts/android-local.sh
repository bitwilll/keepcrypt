#!/bin/sh
# The app's instrumented tests on the owner's Mac (tasks/todo.md, M5 Stage L, L2; Q76): the local
# loop's fast check before a commit. CI's emulator legs (scripts/android-emulator.sh) stay the gate:
# a run here is reported as local, and this script is never a CI step. It uses the project's own AVD
# kc37 alone: the SDK's installed system-images/android-37.0/google_apis_playstore/arm64-v8a image (a
# user build: ro.debuggable=0, so adbd never runs as root), CI's screen (720x1280 at 320 dpi), 4 cores,
# 4 GB and the virtual-scene back camera. Any other AVD, the owner's Medium_Phone among them, is never
# read or touched.
#
# Usage: scripts/android-local.sh [APK_DIR]
#   APK_DIR  the five signed APKs android-emulator.sh installs (app-shipping-release,
#            app-withTestRegistry-release, their -androidTest APKs and capture-control-release, .apk),
#            with goahead-collision-dice-50.png beside them for the Camera2 check's scan (CI's
#            android-apks upload holds that PNG). Without it they are built as CI's job builds them:
#            android-rust.sh for both flavours, then android-gradle.sh's strict build of the five APKs
#            and the JVM tests (which write the P4 PNGs to mobile/android/app/build/p4/), each APK then
#            signed with a throwaway key made in the run's temporary directory (keytool from JAVA_HOME,
#            apksigner from build-tools 36.0.0), as CI's signing step does.
# ANDROID_HOME: the SDK (default $HOME/Library/Android/sdk), with emulator/, platform-tools/ and that
#   image.
#
# kc37 is ~/.android/avd/kc37.ini and kc37.avd/config.ini, written by hand as avdmanager would write
# them (the SDK has no cmdline-tools) when both are missing; when they exist they must be exactly
# these files, or the run stops before booting and changes nothing. The emulator runs headless on
# its own console port, 5580 (serial emulator-5580; a device already there stops the run), with
# -no-snapshot (no snapshot saved) and -wipe-data (a fresh data partition each boot), SwiftShader
# graphics and no audio, as CI's legs run theirs. It writes only under ~/.android/avd/kc37.avd and the
# run's temporary directory, which is its HOME (its console token, its settings and its update check's
# time land there) and holds a copy of adb's key pair, so that the user build trusts the running adb
# server; the directory is removed at the end. The image's own services reach the network while the
# guest is online, as on any phone; nothing of ours does.
#
# In order:
#   1. kc37 booted with no camera (-camera-back none: the CI legs' no-camera facts, M5-59, which
#      SnapshotDrillTest's scan screen expects), then android-emulator.sh --booted on it: a CI leg's
#      steps 1-6 (the probes, the shell's screencaps, ControlTest with the capture control, CaptureTest
#      in both APKs, PhoneMotionTest, FlowTest, CheckTest, SnapshotDrillTest, LifecycleTest and CrashTest
#      last, each through android-instrument.sh's judge, then the raw-frame control and the first
#      frames). Before it, every check the user build cannot make is printed as "not made on kc37"
#      with the reason and left out of its class's run (android-instrument.sh's CLASS-TEST form), and
#      the image's answer to adb root is printed; no check is skipped silently. After it, each
#      instrumented run's result in android-emulator.sh's order, read from its own instrument lines;
#      a run with no result, or a result out of that order, fails.
#   2. kc37 booted again with its virtual-scene camera: the Camera2 check (M5-59; CI's AVDs have no
#      camera). The shipping app, CAMERA granted from the shell (pm grant) and the phone offline, is
#      driven through the UI from the shell (uiautomator dump for each screen's test tags, input tap)
#      to a dice-only 12-word seed of 50 rolls, Check now and Scan go-ahead QR. Its camera client must
#      be listed among dumpsys media.camera's active clients while the scan screen shows, be gone
#      within 10 s of Home, be listed again once the app is back and its cover tapped, and be gone
#      within 10 s of Back, which returns to the seal card. Then goahead-collision-dice-50.png on the
#      virtual scene's wall (the console's virtualscene-image) and the SDK's Walk_to_image_room macro,
#      which turns the camera to it: the test-registry app, driven the same way to dice-50-words12's
#      seed (123456 repeated, so the proof's seal), scans for up to 60 s. The collision result passes;
#      no result, or no PNG, is printed as a check not made, never a pass.
# The emulator is shut down after each phase and on every exit.
# Prints android-emulator.sh's lines and "local:" lines, with "pass: local ..." for each local check
# that passed. Exit 0 when every check made passed, 1 when one failed, 2 bad usage or a missing tool.
#
# scripts/android-local.sh --selftest runs whole runs of this script, with the real
# android-emulator.sh, on stand-ins written to a temporary directory: an SDK whose emulator records
# its arguments and environment and runs until adb's emu kill, an adb that answers the leg's commands
# and simulates the app's screens for the Camera2 check (the camera client listed while the scan
# screen scans), an instrument runner that names each run and passes it, and a frame checker that
# passes. A run where everything passes exits 0, having written kc37's two files exactly, booted twice
# on port 5580 with no snapshot (first with no camera, then the virtual scene) with its HOME and
# ANDROID_AVD_HOME set, named CaptureTest's control (c) as not made on the user build and left it out
# of both CaptureTest runs, run the nine instrumented runs in android-emulator.sh's order and listed
# their results, passed the camera client's four checks and decoded the PNG. Each of these is its own
# case: no decode (the check named as not made, exit 0); no PNG (the same); a debuggable build (no
# test left out); kc37 already this script's (kept, exit 0); a failing class (exit 1, the camera check
# still run and the emulator stopped); kc37 with other files (exit 1, nothing booted or changed); a
# device already on the port (exit 1); no camera client while the scan screen shows, and one still
# listed after Home (exit 1 each); and too many arguments (exit 2).
# Exit 0 when every case behaves, 1 otherwise. The cases run at once; it takes about two minutes.
set -u
unset CDPATH

# selftest: the cases listed in the header, each a whole run on its own case directory.
selftest() {
  self=$(cd "$(dirname "$0")" && pwd) || exit 2
  st=$(mktemp -d "${TMPDIR:-/tmp}/kc-local-selftest.XXXXXX") || exit 2
  trap 'rm -rf "$st"' EXIT
  mkdir "$st/scripts" || exit 2
  cp "$self/$(basename "$0")" "$st/scripts/android-local.sh" || exit 2
  cp "$self/android-emulator.sh" "$st/scripts/android-emulator.sh" || exit 2
  cat > "$st/scripts/android-instrument.sh" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in judge: it names the package and the run, passes it (CaptureTest with the
# window's region), and fails the class named in KC_FAILCLASS, as the real judge prints its results.
echo "instrument stub: $5 $6"
t=${6#killed:}
t=${t%%-*}
case $t in *.CaptureTest) printf 'kc: region=0,48,720,1184\nkc: display=720x1280\n' ;; esac
case $t in *."${KC_FAILCLASS:-none}") echo "FAIL: instrument: api=$3: $t: stand-in failure" >&2; exit 1 ;; esac
echo "instrument: api=$3 PASS $t (1 tests; stand-in)"
EOF
  cat > "$st/scripts/android-frames.py" <<'EOF' || exit 2
# The selftest's stand-in frame checker: a probe that ends at once, and a recording whose first frame
# comes at once and which passes when SIGTERM stops it.
import signal, sys, time
if sys.argv[1] == "probe":
    sys.exit(0)
expect = sys.argv[sys.argv.index("--expect") + 1]
print("android-frames: first frame after 0.1 s", flush=True)
stopped = []
signal.signal(signal.SIGTERM, lambda *a: stopped.append(1))
while not stopped:
    time.sleep(0.05)
print("android-frames: PASS %s: stand-in" % expect)
EOF
  cat > "$st/emulator" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in emulator: it records its arguments, the environment it was given and
# whether adb's key is in its HOME, then runs until adb's emu kill.
key=no
[ -f "$HOME/.android/adbkey" ] && [ -f "$HOME/.android/adbkey.pub" ] && key=yes
echo "$* | HOME=$HOME | ANDROID_AVD_HOME=$ANDROID_AVD_HOME | adbkey=$key" >> "$KC_STUB/boots"
echo $$ > "$KC_STUB/emulator.pid"
exec sleep 300
EOF
  cat > "$st/adb" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in adb: -s emulator-5580 COMMAND, answered from and into the case directory
# $KC_STUB. For the Camera2 check it keeps the app's screen (ui), the app in front (pkg), the dice's
# count (rolls) and the camera (on while the scan screen scans), and draws each screen's test tags,
# tag number i at y 100 + 30i, so a tap's y names its tag.
s=$KC_STUB
tags='first_launch_continue start dice_only_seed words_12 key_1 key_2 key_3 key_4 key_5 key_6 confirm dice_done check_now scan_qr cover'
case "$*" in
  start-server) exit 0 ;;
  devices)
    echo 'List of devices attached'
    [ -z "${KC_PORT_TAKEN:-}" ] || printf 'emulator-5580\tdevice\n'
    exit 0
    ;;
esac
[ "$1" = -s ] && [ "$2" = emulator-5580 ] || { echo "stub adb: unexpected: $*" >&2; exit 1; }
shift 2
screen() { cat "$s/ui" 2>/dev/null || echo launcher; }
# scanning: the scan screen shows uncovered: the camera opens, and the walked scene's poster decodes
# once the scan screen has been drawn.
scanning() {
  echo scan > "$s/ui"
  [ -n "${KC_NO_CLIENT:-}" ] || echo on > "$s/camera"
  if [ -n "${KC_DECODE:-}" ] && [ -f "$s/walked" ] && [ -f "$s/poster" ] && [ "$(cat "$s/pkg")" = com.keepcrypt.entropy.testregistry ]; then
    : > "$s/decode"
  fi
}
camera_off() { [ -n "${KC_CAMERA_STUCK:-}" ] || echo off > "$s/camera"; }
node() {
  i=0
  for t in $tags; do
    [ "$t" = "$1" ] && break
    i=$((i + 1))
  done
  y=$((100 + 30 * i))
  printf '<node text="%s" resource-id="%s" enabled="true" bounds="[0,%d][720,%d]" />' "$2" "$1" "$y" $((y + 20))
}
case "$*" in
  'root') echo 'adbd cannot run as root in production builds' ;;
  'emu kill') kill "$(cat "$s/emulator.pid")" ;;
  'emu automation play '*) : > "$s/walked"; echo OK ;;
  'emu virtualscene-image wall '*) : > "$s/poster"; echo OK ;;
  'shell getprop sys.boot_completed') echo 1 ;;
  'shell getprop ro.debuggable') echo "${KC_DEBUGGABLE:-0}" ;;
  'shell getprop ro.build.type') echo user ;;
  'shell dumpsys power') echo '  mWakefulness=Awake' ;;
  'shell dumpsys display') echo '  mScreenState=ON' ;;
  'exec-out screencap -p') printf 'stand-in png' ;;
  'install '*) echo Success ;;
  'shell pm clear com.keepcrypt.entropy.capturecontrol') echo Success ;;
  'shell dumpsys activity recents') echo 'ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)' ;;
  'shell dumpsys window') printf '  mCurrentFocus=Window{b2 u0 %s/com.keepcrypt.entropy.MainActivity}\n' "$(cat "$s/front" 2>/dev/null)" ;;
  'shell pm grant '*' android.permission.CAMERA') echo "$4" >> "$s/granted" ;;
  'shell dumpsys package '*)
    grep -q -x -F -e "$4" "$s/granted" 2>/dev/null && echo '      android.permission.CAMERA: granted=true, flags=[ USER_SET ]'
    ;;
  'shell am start -W '*)
    for a; do c=$a; done
    case $c in
      */com.keepcrypt.entropy.MainActivity)
        p=${c%%/*}
        echo "$p" > "$s/front"
        if [ "$(screen)" = launcher ] && [ "$(cat "$s/pkg" 2>/dev/null)" = "$p" ]; then echo cover > "$s/ui"; else echo first_launch > "$s/ui"; fi
        echo "$p" > "$s/pkg"
        ;;
    esac
    printf 'Status: ok\nLaunchState: COLD\n'
    ;;
  'exec-out uiautomator dump /dev/tty')
    u=$(screen)
    printf '<?xml version="1.0" encoding="UTF-8"?><hierarchy rotation="0">'
    # The screen's root node: none on the launcher, and the cover is its own one node.
    case $u in launcher | cover) ;; *) printf '<node text="" resource-id="%s" enabled="true" bounds="[0,48][720,1280]">' "$u" ;; esac
    case $u in
      first_launch) node first_launch_continue Continue ;;
      go_offline) node start Start ;;
      home) node dice_only_seed 'Dice-only seed' ;;
      length) node words_12 '12 words (default)' ;;
      dice)
        for k in 1 2 3 4 5 6; do node "key_$k" "$k"; done
        node confirm Confirm
        node dice_done Done
        printf '<node text="%s / 50 rolls, 129.2 bits" resource-id="dice_count" bounds="[0,800][720,820]" />' "$(cat "$s/rolls")"
        ;;
      check_prompt) node check_now 'Check now (recommended)' ;;
      seal_card) node scan_qr 'Scan go-ahead QR' ;;
      scan)
        printf '<node text="Looking for the go-ahead QR..." resource-id="scan_line" bounds="[0,800][720,820]" />'
        if [ -f "$s/decode" ]; then
          rm "$s/decode"
          echo collision > "$s/ui"
          echo off > "$s/camera"
        fi
        ;;
      cover) node cover 'Tap to show the screen again' ;;
      collision)
        printf '<node text="Collision found. This seed is not unique and has been destroyed." resource-id="collision_text" bounds="[0,800][720,820]" />'
        ;;
    esac
    case $u in launcher | cover) ;; *) printf '</node>' ;; esac
    printf '</hierarchy>UI hierchary dumped to: /dev/tty\n'
    ;;
  'shell input tap '*'; sleep '*)
    [ "$(screen)" = dice ] && echo $(($(cat "$s/rolls") + 1)) > "$s/rolls"
    ;;
  'shell input tap '*)
    t=$(echo $tags | cut -d ' ' -f $((($5 - 110) / 30 + 1)))
    case $t in
      first_launch_continue) echo go_offline > "$s/ui" ;;
      start) echo home > "$s/ui" ;;
      dice_only_seed) echo length > "$s/ui" ;;
      words_12) echo dice > "$s/ui"; echo 0 > "$s/rolls" ;;
      dice_done) [ "$(cat "$s/rolls")" -ge 50 ] && echo check_prompt > "$s/ui" ;;
      check_now) echo seal_card > "$s/ui" ;;
      scan_qr | cover) scanning ;;
    esac
    ;;
  'shell input keyevent KEYCODE_HOME') echo launcher > "$s/ui"; camera_off ;;
  'shell input keyevent KEYCODE_BACK') [ "$(screen)" = scan ] && echo seal_card > "$s/ui"; camera_off ;;
  'shell dumpsys media.camera')
    printf '== Service global info: ==\n\nNumber of camera devices: 1\nActive Camera Clients:\n'
    if [ "$(cat "$s/camera" 2>/dev/null)" = on ]; then
      printf '[\n(Camera ID: 10, Cost: 100, PID: 4242, Score: 0, State: 2User Id: 0, Client Package Name: %s, Conflicting Client Devices: {})\n]\n' "$(cat "$s/pkg")"
    else
      printf '[]\n'
    fi
    printf 'Allowed user IDs: 0\n'
    ;;
  'shell input '* | 'shell wm '* | 'shell settings '* | 'shell svc '* | 'shell getprop '* | 'shell getconf '* | \
    'shell cmd connectivity '* | 'shell cmd wifi '* | 'shell logcat -b crash -d' | 'shell dumpsys dropbox' | \
    'shell dumpsys content_capture' | 'shell pm list instrumentation' | 'shell am force-stop '*) ;;
  *) echo "stub adb: unexpected command: $*" >&2; exit 1 ;;
esac
EOF
  chmod +x "$st/scripts/android-instrument.sh" "$st/emulator" "$st/adb" || exit 2
  # prepare NAME: the case directory $st/NAME, c: a stand-in SDK, a HOME with adb's key pair, and an
  # APK_DIR with the five APKs and the go-ahead PNG.
  prepare() {
    c=$st/$1
    image=$c/sdk/system-images/android-37.0/google_apis_playstore/arm64-v8a
    mkdir -p "$c/sdk/emulator/resources/macros" "$c/sdk/platform-tools" "$image" "$c/home/.android" "$c/apks" "$c/tmp" || exit 2
    cp "$st/emulator" "$c/sdk/emulator/emulator" || exit 2
    cp "$st/adb" "$c/sdk/platform-tools/adb" || exit 2
    echo 'Pkg.Revision=7' > "$image/source.properties" || exit 2
    : > "$c/sdk/emulator/resources/macros/Walk_to_image_room" || exit 2
    echo 'stand-in key' > "$c/home/.android/adbkey" || exit 2
    echo 'stand-in key.pub' > "$c/home/.android/adbkey.pub" || exit 2
    for f in app-shipping-release app-shipping-release-androidTest app-withTestRegistry-release \
      app-withTestRegistry-release-androidTest capture-control-release; do
      : > "$c/apks/$f.apk" || exit 2
    done
    : > "$c/apks/goahead-collision-dice-50.png" || exit 2
  }
  # launch NAME [VAR=VALUE...]: one whole run on the prepared case NAME, in the background, with
  # VAR=VALUE set for the stand-ins; its output in out and its exit status in rc.
  launch() {
    c=$st/$1
    shift
    {
      env HOME="$c/home" ANDROID_HOME="$c/sdk" TMPDIR="$c/tmp" KC_STUB="$c" "$@" sh "$st/scripts/android-local.sh" "$c/apks"
      echo $? > "$c/rc"
    } > "$c/out" 2>&1 &
  }
  # run NAME [VAR=VALUE...]: prepare and launch.
  run() {
    prepare "$1"
    launch "$@"
  }
  # kc37's two files as the script must write them, for the case directory $1.
  kc37_ini() {
    printf 'avd.ini.encoding=UTF-8\npath=%s/home/.android/avd/kc37.avd\npath.rel=avd/kc37.avd\ntarget=android-37.0\n' "$1"
  }
  kc37_config() {
    cat <<'CONFIG'
AvdId=kc37
PlayStore.enabled=true
abi.type=arm64-v8a
avd.ini.displayname=kc37
avd.ini.encoding=UTF-8
disk.dataPartition.size=6G
fastboot.forceColdBoot=yes
hw.audioInput=no
hw.audioOutput=no
hw.camera.back=virtualscene
hw.camera.front=none
hw.cpu.arch=arm64
hw.cpu.ncore=4
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader_indirect
hw.keyboard=yes
hw.lcd.density=320
hw.lcd.height=1280
hw.lcd.width=720
hw.ramSize=4096
image.sysdir.1=system-images/android-37.0/google_apis_playstore/arm64-v8a/
showDeviceFrame=no
tag.display=Google Play
tag.id=google_apis_playstore
CONFIG
  }
  # A case whose kc37 is already there: this script's files, or one changed line.
  for name in avd-kept avd-other; do
    mkdir -p "$st/$name/home/.android/avd/kc37.avd" || exit 2
    kc37_ini "$st/$name" > "$st/$name/home/.android/avd/kc37.ini" || exit 2
    kc37_config > "$st/$name/home/.android/avd/kc37.avd/config.ini" || exit 2
  done
  sed 's/^hw.ramSize=4096$/hw.ramSize=2048/' "$st/avd-other/home/.android/avd/kc37.avd/config.ini" > "$st/config.ini" &&
    mv "$st/config.ini" "$st/avd-other/home/.android/avd/kc37.avd/config.ini" || exit 2
  run pass KC_DECODE=1
  run no-decode
  prepare no-png
  rm "$st/no-png/apks/goahead-collision-dice-50.png" || exit 2
  launch no-png KC_DECODE=1
  run debuggable KC_DEBUGGABLE=1 KC_DECODE=1
  run avd-kept KC_DECODE=1
  run flow-test-fails KC_FAILCLASS=FlowTest KC_DECODE=1
  run avd-other
  run port-taken KC_PORT_TAKEN=1
  run no-client KC_NO_CLIENT=1
  run camera-stuck KC_CAMERA_STUCK=1
  wait
  passed=0
  failed=0
  # check NAME OK WHAT: one result line for case NAME.
  check() {
    if [ "$2" = yes ]; then
      passed=$((passed + 1))
      echo "PASS $1${3:+: $3}"
    else
      failed=$((failed + 1))
      echo "FAIL $1${3:+: $3}"
      [ -n "${3:-}" ] || sed 's/^/  | /' "$st/$1/out"
    fi
  }
  # expect NAME EXIT TEXT...: case NAME exited EXIT and printed every TEXT.
  expect() {
    name=$1
    want=$2
    shift 2
    ok=yes
    [ "$(cat "$st/$name/rc")" = "$want" ] || ok=no
    for text in "$@"; do
      grep -q -F -e "$text" "$st/$name/out" || ok=no
    done
    [ "$ok" = yes ] || echo "  (exit $(cat "$st/$name/rc"), wanted $want)"
    check "$name" "$ok"
  }
  # avd NAME: case NAME's kc37 files are this script's, byte for byte.
  avd() {
    ok=yes
    kc37_ini "$st/$1" | cmp -s - "$st/$1/home/.android/avd/kc37.ini" || ok=no
    kc37_config | cmp -s - "$st/$1/home/.android/avd/kc37.avd/config.ini" || ok=no
    check "$1" "$ok" "kc37.ini and kc37.avd/config.ini as avdmanager writes them"
  }
  left=com.keepcrypt.entropy.CaptureTest-disableSecureWindowsShowsTheScreenOnlyWhileSet
  # runs NAME CAPTURE: case NAME's instrumented runs, in order, CaptureTest run as CAPTURE.
  runs() {
    got=$(sed -n 's/^instrument stub: //p' "$st/$1/out" | tr '\n' ' ')
    want="com.keepcrypt.entropy com.keepcrypt.entropy.ControlTest com.keepcrypt.entropy $2 com.keepcrypt.entropy.testregistry $2"
    want="$want com.keepcrypt.entropy com.keepcrypt.entropy.PhoneMotionTest com.keepcrypt.entropy com.keepcrypt.entropy.FlowTest"
    want="$want com.keepcrypt.entropy com.keepcrypt.entropy.CheckTest com.keepcrypt.entropy.testregistry com.keepcrypt.entropy.SnapshotDrillTest"
    want="$want com.keepcrypt.entropy com.keepcrypt.entropy.LifecycleTest com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest "
    ok=yes
    [ "$got" = "$want" ] || { ok=no; echo "  got: $got"; }
    check "$1" "$ok" "the nine instrumented runs in android-emulator.sh's order"
  }
  # boots NAME: case NAME booted twice on port 5580 with no snapshot, first with no camera and then
  # the virtual scene, with its own HOME holding adb's key and the AVD home under the case's HOME.
  boots() {
    ok=yes
    [ "$(wc -l < "$st/$1/boots" | tr -d ' ')" = 2 ] || ok=no
    for n in 1 2; do
      line=$(sed -n "${n}p" "$st/$1/boots")
      case $n in 1) camera=none ;; 2) camera=virtualscene ;; esac
      case $line in
        "-avd kc37 -no-window -no-audio -no-boot-anim -no-snapshot -wipe-data -gpu swiftshader_indirect -camera-back $camera -camera-front none -port 5580 -no-metrics | HOME="*) ;;
        *) ok=no ;;
      esac
      case $line in *" | HOME=$st/$1/tmp/kc-local."*"/home | "*) ;; *) ok=no ;; esac
      case $line in *" | ANDROID_AVD_HOME=$st/$1/home/.android/avd | adbkey=yes") ;; *) ok=no ;; esac
    done
    [ "$ok" = yes ] || sed 's/^/  boot: /' "$st/$1/boots"
    check "$1" "$ok" "two boots, no camera and then the virtual scene, port 5580, no snapshot, its own HOME"
  }
  # stopped NAME: case NAME left no stand-in emulator running.
  stopped() {
    ok=yes
    if [ -f "$st/$1/emulator.pid" ] && kill -0 "$(cat "$st/$1/emulator.pid")" 2> /dev/null; then
      ok=no
      kill "$(cat "$st/$1/emulator.pid")"
    fi
    check "$1" "$ok" "the emulator stopped"
  }
  camera_passes='pass: local camera: the camera client of com.keepcrypt.entropy is listed in dumpsys media.camera while the scan screen shows'
  expect pass 0 "local: made the AVD kc37" \
    "local: not made on kc37 (ro.debuggable=0): com.keepcrypt.entropy.CaptureTest#disableSecureWindowsShowsTheScreenOnlyWhileSet" \
    "local: no adb root on kc37: adb root says: adbd cannot run as root in production builds" \
    "instrument stub: com.keepcrypt.entropy $left" "emulator: api=37: every check passed" \
    "local: run 9 of 9, com.keepcrypt.entropy killed:com.keepcrypt.entropy.CrashTest: instrument: api=37 PASS com.keepcrypt.entropy.CrashTest" \
    "$camera_passes" "pass: local camera: gone from dumpsys media.camera within 10 s of Home" \
    "pass: local camera: listed again with the app back and its cover tapped" \
    "pass: local camera: gone within 10 s of Back, on the seal card" \
    "pass: local camera: the scanner decoded goahead-collision-dice-50.png from the virtual scene's wall: the collision result" \
    "local: every check made on kc37 passed"
  avd pass
  runs pass "$left"
  boots pass
  stopped pass
  expect no-decode 0 "$camera_passes" "local: not made on kc37: the scanner decoded nothing in 60 s" \
    "local: every check made on kc37 passed"
  expect no-png 0 "local: not made on kc37: the scan of goahead-collision-dice-50.png: no such file in" \
    "local: every check made on kc37 passed"
  expect debuggable 0 "local: every check made on kc37 passed"
  runs debuggable com.keepcrypt.entropy.CaptureTest
  if grep -q -e '^local: not made on kc37 (ro.debuggable' -e '^local: no adb root' "$st/debuggable/out"; then
    check debuggable no "no test left out and no adb root asked on a debuggable build"
  else
    check debuggable yes "no test left out and no adb root asked on a debuggable build"
  fi
  expect avd-kept 0 "local: the AVD kc37 is this script's" "local: every check made on kc37 passed"
  avd avd-kept
  expect flow-test-fails 1 "local: run 5 of 9, com.keepcrypt.entropy com.keepcrypt.entropy.FlowTest: FAIL: instrument: api=37: com.keepcrypt.entropy.FlowTest" \
    "$camera_passes" "FAIL: local: the leg on kc37 failed (each failure reported above)"
  stopped flow-test-fails
  expect avd-other 1 "-hw.ramSize=4096" "+hw.ramSize=2048" \
    "FAIL: local: kc37 is there, but its files are not this script's (the differences above); nothing was booted or changed"
  if [ ! -e "$st/avd-other/boots" ] && grep -q -x -F -e 'hw.ramSize=2048' "$st/avd-other/home/.android/avd/kc37.avd/config.ini"; then
    check avd-other yes "nothing booted, the file kept"
  else
    check avd-other no "nothing booted, the file kept"
  fi
  expect port-taken 1 "FAIL: local: a device is already at emulator-5580"
  if [ ! -e "$st/port-taken/boots" ]; then
    check port-taken yes "nothing booted"
  else
    check port-taken no "nothing booted"
  fi
  expect no-client 1 "FAIL: local: camera: com.keepcrypt.entropy's camera client is not listed in dumpsys media.camera within 10 s of the scan screen"
  stopped no-client
  expect camera-stuck 1 "$camera_passes" "FAIL: local: camera: com.keepcrypt.entropy's camera client is still listed 10 s after Home"
  sh "$st/scripts/android-local.sh" one two > "$st/out" 2>&1
  if [ "$?" -eq 2 ] && grep -q -e '^usage: ' "$st/out"; then
    check "too many arguments" yes
  else
    check "too many arguments" no
  fi
  echo "android-local selftest: $passed passed, $failed failed"
  [ "$failed" -eq 0 ]
}

if [ $# -eq 1 ] && [ "$1" = --selftest ]; then
  selftest
  exit
fi
case $# in
  0) apkdir= ;;
  1) apkdir=$1 ;;
  *) apkdir=-- ;;
esac
case $apkdir in
  -*)
    echo "usage: scripts/android-local.sh [APK_DIR]" >&2
    echo "       scripts/android-local.sh --selftest" >&2
    exit 2
    ;;
esac

here=$(cd "$(dirname "$0")" && pwd) || exit 2
root=$(cd "$here/.." && pwd) || exit 2
sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk}
adb=$sdk/platform-tools/adb
emulator=$sdk/emulator/emulator
sysdir=system-images/android-37.0/google_apis_playstore/arm64-v8a
macro=$sdk/emulator/resources/macros/Walk_to_image_room
avds=$HOME/.android/avd
avd=kc37
port=5580
serial=emulator-$port
api=37
shipping=com.keepcrypt.entropy
registry=com.keepcrypt.entropy.testregistry
png=goahead-collision-dice-50.png

say() { echo "local: $1"; }
refuse() {
  echo "local: $1" >&2
  exit 2
}
fail() {
  echo "FAIL: local: $1" >&2
  exit 1
}
# fail_later MESSAGE: a failure reported now that fails the run at its end, so the checks after it
# still run.
failed=
fail_later() {
  echo "FAIL: local: $1 (the run goes on, and fails at its end)" >&2
  failed="$failed; $1"
}
dev() { "$adb" -s "$serial" "$@"; }
# value CMD...: a device command's output on one line, carriage returns dropped.
value() { dev shell "$@" 2>&1 | tr -d '\r' | tr '\n' ' ' | sed 's/ *$//'; }

# The checks a user build cannot make (ro.debuggable=0), each "CLASS-TEST why" on a line: named on
# every run and left out of its class's run, never skipped silently.
user_build_refusals() {
  echo "com.keepcrypt.entropy.CaptureTest-disableSecureWindowsShowsTheScreenOnlyWhileSet positive control (c): Android reads disable_secure_windows on a debuggable build only, so with it set the app's captures stay black here; CI's API 36 leg makes it"
}

[ -x "$adb" ] || refuse "no adb at $adb (ANDROID_HOME: the SDK)"
[ -x "$emulator" ] || refuse "no emulator at $emulator"
[ -f "$sdk/$sysdir/source.properties" ] || refuse "no $sysdir in $sdk"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/kc-local.XXXXXX") || exit 2
emu_pid=
# console COMMAND...: the emulator's console through adb, with the emulator's HOME and so its token.
console() { HOME=$tmp/home "$adb" -s "$serial" emu "$@"; }
stop_emulator() {
  [ -n "$emu_pid" ] || return 0
  console kill > /dev/null 2>&1
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
trap 'stop_emulator; rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM
mkdir "$tmp/apks" "$tmp/run" || exit 2

# The APKs: APK_DIR's, or built and signed as CI's job does.
if [ -n "$apkdir" ]; then
  apks=$(cd "$apkdir" 2> /dev/null && pwd) || refuse "no directory $apkdir"
else
  [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/keytool" ] || refuse "no keytool in JAVA_HOME (a JDK 17 or later)"
  bt=$sdk/build-tools/36.0.0
  [ -x "$bt/apksigner" ] || refuse "no apksigner in $bt"
  sh "$here/android-rust.sh" shipping || fail "android-rust.sh shipping failed"
  sh "$here/android-rust.sh" withTestRegistry || fail "android-rust.sh withTestRegistry failed"
  sh "$here/android-gradle.sh" --dependency-verification strict \
    :app:assembleShippingRelease :app:assembleWithTestRegistryRelease \
    :app:assembleShippingReleaseAndroidTest :app:assembleWithTestRegistryReleaseAndroidTest \
    :capture-control:assembleRelease \
    :core-ffi:testAndroidHostTest :screens:testAndroidHostTest test || fail "the Gradle build failed"
  "$JAVA_HOME/bin/keytool" -genkeypair -keystore "$tmp/kc-throwaway.p12" -storetype PKCS12 -storepass kc-throwaway \
    -alias kc -keyalg RSA -keysize 3072 -validity 30 \
    -dname 'CN=KeepCrypt local throwaway key, OU=development build, O=KeepCrypt' || fail "keytool failed"
  out=$root/mobile/android/app/build/outputs/apk
  for apk in "$out/shipping/release/app-shipping-release-unsigned.apk" \
    "$out/withTestRegistry/release/app-withTestRegistry-release-unsigned.apk" \
    "$out/androidTest/shipping/release/app-shipping-release-androidTest.apk" \
    "$out/androidTest/withTestRegistry/release/app-withTestRegistry-release-androidTest.apk" \
    "$root/mobile/android/capture-control/build/outputs/apk/release/capture-control-release-unsigned.apk"; do
    name=$(basename "$apk" .apk)
    "$bt/apksigner" sign --ks "$tmp/kc-throwaway.p12" --ks-type PKCS12 --ks-pass pass:kc-throwaway \
      --ks-key-alias kc --out "$tmp/apks/${name%-unsigned}.apk" "$apk" || fail "apksigner failed on $apk"
  done
  cp "$root/mobile/android/app/build/p4/$png" "$tmp/apks/$png" || fail "the JVM tests wrote no $png"
  apks=$tmp/apks
fi
for f in app-shipping-release app-shipping-release-androidTest app-withTestRegistry-release \
  app-withTestRegistry-release-androidTest capture-control-release; do
  [ -f "$apks/$f.apk" ] || refuse "no $apks/$f.apk"
done

# kc37, as avdmanager would write it: made when both files are missing, else exactly these.
printf 'avd.ini.encoding=UTF-8\npath=%s\npath.rel=avd/%s.avd\ntarget=android-37.0\n' "$avds/$avd.avd" "$avd" > "$tmp/avd.ini" || exit 2
cat > "$tmp/config.ini" <<EOF || exit 2
AvdId=$avd
PlayStore.enabled=true
abi.type=arm64-v8a
avd.ini.displayname=$avd
avd.ini.encoding=UTF-8
disk.dataPartition.size=6G
fastboot.forceColdBoot=yes
hw.audioInput=no
hw.audioOutput=no
hw.camera.back=virtualscene
hw.camera.front=none
hw.cpu.arch=arm64
hw.cpu.ncore=4
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader_indirect
hw.keyboard=yes
hw.lcd.density=320
hw.lcd.height=1280
hw.lcd.width=720
hw.ramSize=4096
image.sysdir.1=$sysdir/
showDeviceFrame=no
tag.display=Google Play
tag.id=google_apis_playstore
EOF
if [ ! -e "$avds/$avd.ini" ] && [ ! -e "$avds/$avd.avd" ]; then
  mkdir -p "$avds/$avd.avd" || exit 2
  cp "$tmp/avd.ini" "$avds/$avd.ini" && cp "$tmp/config.ini" "$avds/$avd.avd/config.ini" || exit 2
  say "made the AVD $avd ($avds/$avd.ini and $avds/$avd.avd/config.ini, $sysdir)"
elif cmp -s "$tmp/avd.ini" "$avds/$avd.ini" && cmp -s "$tmp/config.ini" "$avds/$avd.avd/config.ini"; then
  say "the AVD $avd is this script's ($avds/$avd.ini and $avds/$avd.avd/config.ini)"
else
  diff -u "$tmp/avd.ini" "$avds/$avd.ini"
  diff -u "$tmp/config.ini" "$avds/$avd.avd/config.ini"
  fail "$avd is there, but its files are not this script's (the differences above); nothing was booted or changed"
fi

# The emulator's HOME: adb's key pair, so the image trusts the adb server already running.
"$adb" start-server > /dev/null 2>&1 || fail "adb start-server failed"
[ -f "$HOME/.android/adbkey" ] && [ -f "$HOME/.android/adbkey.pub" ] || fail "adb has no key pair in $HOME/.android"
if "$adb" devices 2>&1 | tr -d '\r' | grep -q -e "^$serial[[:space:]]"; then
  fail "a device is already at $serial (console port $port): stop it first"
fi
(umask 077 && mkdir -p "$tmp/home/.android" && cp "$HOME/.android/adbkey" "$HOME/.android/adbkey.pub" "$tmp/home/.android/") ||
  exit 2

# boot WHAT CAMERA: kc37 headless with that back camera, until sys.boot_completed (600 s at most).
boot() {
  log=$tmp/emulator-$1.log
  say "booting $avd ($1): emulator -avd $avd -no-window -no-snapshot -wipe-data -camera-back $2 -port $port"
  # The emulator's own files go to HOME/.android, here the run's temporary directory.
  (cd "$tmp/run" && exec env HOME="$tmp/home" TMPDIR="$tmp/run" ANDROID_EMULATOR_HOME="$tmp/home/.android" \
    ANDROID_USER_HOME="$tmp/home/.android" ANDROID_SDK_ROOT="$sdk" ANDROID_HOME="$sdk" ANDROID_AVD_HOME="$avds" \
    "$emulator" -avd "$avd" -no-window -no-audio -no-boot-anim -no-snapshot -wipe-data -gpu swiftshader_indirect \
    -camera-back "$2" -camera-front none -port "$port" -no-metrics) > "$log" 2>&1 &
  emu_pid=$!
  start=$(date +%s)
  until [ "$(dev shell getprop sys.boot_completed 2> /dev/null | tr -d '\r')" = 1 ]; do
    if ! kill -0 "$emu_pid" 2> /dev/null; then
      tail -n 40 "$log"
      emu_pid=
      fail "the emulator exited while booting ($1)"
    fi
    if [ $(($(date +%s) - start)) -ge 600 ]; then
      tail -n 40 "$log"
      fail "$avd did not boot within 600 s ($1)"
    fi
    sleep 2
  done
  say "booted in $(($(date +%s) - start)) s ($1)"
}

# 1. The leg: android-emulator.sh --booted on kc37 with no camera.
boot "the leg, no camera" none
debuggable=$(value getprop ro.debuggable)
say "$avd: ro.build.type=$(value getprop ro.build.type), ro.debuggable=$debuggable"
without=
if [ "$debuggable" != 1 ]; then
  say "no adb root on $avd: adb root says: $(dev root 2>&1 | tr -d '\r' | head -n 1) (no check here needs root)"
  while read -r left why; do
    [ -n "$left" ] || continue
    say "not made on $avd (ro.debuggable=$debuggable): ${left%%-*}#${left#*-}: $why"
    without="$without $left"
  done <<EOF
$(user_build_refusals)
EOF
fi
# $without unquoted: CLASS-TEST words with no space.
{
  sh "$here/android-emulator.sh" --booted "$api" "$serial" "$adb" "$apks" "$tmp/leg" $without
  echo $? > "$tmp/leg.rc"
} 2>&1 | tee "$tmp/leg.log"
[ "$(cat "$tmp/leg.rc")" = 0 ] || fail_later "the leg on $avd failed (each failure reported above)"
# Each instrumented run's result, in android-emulator.sh's order (its own instrument lines).
sed -n 's/^instrument \([^ ]*\) \([^ ]*\)$/\1 \2/p' "$here/android-emulator.sh" > "$tmp/runs"
grep -e "^instrument: api=$api PASS " -e "^FAIL: instrument: api=$api: " -e "^instrument: api=$api: " "$tmp/leg.log" > "$tmp/results"
if ! awk '
  NR == FNR { run[++n] = $0; next }
  { result[++m] = $0 }
  END {
    bad = 0
    for (i = 1; i <= n; i++) {
      split(run[i], f, " ")
      class = f[2]
      sub(/^killed:/, "", class)
      if (i > m || index(result[i], " " class " ") == 0 && index(result[i], " " class ":") == 0) { bad = 1; result[i] = "no result" }
      printf "local: run %d of %d, %s: %s\n", i, n, run[i], result[i]
    }
    exit (bad || m != n || n == 0)
  }' "$tmp/runs" "$tmp/results"; then
  fail_later "the leg's results do not give each of android-emulator.sh's $(wc -l < "$tmp/runs" | tr -d ' ') instrumented runs one result, in its order"
fi
stop_emulator

# 2. The Camera2 check on kc37's virtual-scene camera (M5-59).
boot "the Camera2 check, the virtual scene" virtualscene
dev shell input keyevent 82 > /dev/null 2>&1
dev shell wm dismiss-keyguard > /dev/null 2>&1
for s in window_animation_scale transition_animation_scale animator_duration_scale; do
  dev shell settings put global "$s" 0 > /dev/null 2>&1
done
dev shell svc power stayon true > /dev/null 2>&1
dev shell input keyevent KEYCODE_WAKEUP > /dev/null 2>&1
dev shell cmd connectivity airplane-mode enable > /dev/null 2>&1
dev shell cmd wifi set-wifi-enabled disabled > /dev/null 2>&1

ui=$tmp/ui.xml
# The UI from the shell: uiautomator dump's nodes, found by their resource ids (the Compose test tags).
dump() { dev exec-out uiautomator dump /dev/tty > "$ui" 2> /dev/null; }
node() { tr '>' '\n' < "$ui" | grep -F -e "resource-id=\"$1\"" | head -n 1; }
centre() {
  node "$1" | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p' |
    awk '{ printf "%d %d\n", ($1 + $3) / 2, ($2 + $4) / 2 }'
}
text() { node "$1" | sed -n 's/.* text="\([^"]*\)".*/\1/p'; }
# await TAG SECONDS [enabled]: TAG on screen (and enabled) within SECONDS; 1 and a line otherwise.
await() {
  start=$(date +%s)
  until dump && [ -n "$(node "$1")" ] && { [ -z "${3:-}" ] || node "$1" | grep -q -F -e 'enabled="true"'; }; do
    if [ $(($(date +%s) - start)) -ge "$2" ]; then
      say "camera: no $1${3:+ enabled} on screen within $2 s"
      return 1
    fi
    sleep 1
  done
}
tap() {
  await "$1" 10 || return 1
  # The centre unquoted: its two numbers are input tap's two arguments.
  dev shell input tap $(centre "$1")
}
# to_scan PACKAGE: the app from its start to the scan screen: CAMERA granted, Continue, Start offline,
# a dice-only 12-word seed of 123456 repeated to 50 rolls, Done, Check now and Scan go-ahead QR.
to_scan() {
  dev shell pm grant "$1" android.permission.CAMERA > /dev/null 2>&1
  dev shell dumpsys package "$1" 2>&1 | grep -q -F -e 'android.permission.CAMERA: granted=true' ||
    { say "camera: CAMERA is not granted to $1 after pm grant"; return 1; }
  dev shell am start -W -n "$1/com.keepcrypt.entropy.MainActivity" 2>&1 | tr -d '\r' | grep -q -e '^Status: ok' ||
    { say "camera: am start $1 did not report Status: ok"; return 1; }
  await first_launch 30 && tap first_launch_continue && await start 150 enabled && tap start &&
    await home 10 && tap dice_only_seed && await length 10 && tap words_12 && await dice 30 || return 1
  keys=$(for k in 1 2 3 4 5 6; do echo "$k $(centre "key_$k")"; done)
  confirm=$(centre confirm)
  n=0
  while [ "$n" -lt 50 ]; do
    face=$(printf '%s' 123456 | cut -c $((n % 6 + 1)))
    # A pause after each tap, so that the pick lands before Confirm reads it, and Confirm before the next.
    dev shell "input tap $(echo "$keys" | awk -v k="$face" '$1 == k { print $2, $3 }'); sleep 0.3; input tap $confirm; sleep 0.3"
    n=$((n + 1))
  done
  dump
  case $(text dice_count) in
    '50 / 50 rolls, '*) ;;
    *) say "camera: the dice show '$(text dice_count)' after 50 rolls"; return 1 ;;
  esac
  tap dice_done && await check_prompt 60 && tap check_now && await seal_card 30 && tap scan_qr && await scan 10 || return 1
}
# listed PACKAGE: PACKAGE's camera client is among dumpsys media.camera's active clients.
listed() {
  dev shell dumpsys media.camera 2>&1 | tr -d '\r' | sed -n '/^Active Camera Clients:/,/^Allowed user IDs:/p' |
    grep -q -F -e "Client Package Name: $1,"
}
# client PACKAGE yes|no SECONDS: the client is listed (yes) or gone (no) within SECONDS.
client() {
  start=$(date +%s)
  while :; do
    if listed "$1"; then [ "$2" = yes ] && return 0; else [ "$2" = no ] && return 0; fi
    [ $(($(date +%s) - start)) -lt "$3" ] || return 1
    sleep 1
  done
}
for f in app-shipping-release app-withTestRegistry-release; do
  case $(dev install "$apks/$f.apk" 2>&1) in
    *Success*) say "camera: installed $f.apk" ;;
    *) fail_later "camera: adb install $f.apk failed" ;;
  esac
done
p=$shipping
if ! to_scan "$p"; then
  fail_later "camera: $p did not reach the scan screen"
elif ! client "$p" yes 10; then
  fail_later "camera: $p's camera client is not listed in dumpsys media.camera within 10 s of the scan screen"
else
  echo "pass: local camera: the camera client of $p is listed in dumpsys media.camera while the scan screen shows"
  dev shell input keyevent KEYCODE_HOME
  if ! client "$p" no 10; then
    fail_later "camera: $p's camera client is still listed 10 s after Home"
  else
    echo "pass: local camera: gone from dumpsys media.camera within 10 s of Home"
    dev shell am start -W -n "$p/com.keepcrypt.entropy.MainActivity" > /dev/null 2>&1
    if ! { tap cover && await scan 10; }; then
      fail_later "camera: $p did not show the scan screen again under its cover"
    elif ! client "$p" yes 10; then
      fail_later "camera: $p's camera client is not listed again within 10 s of the cover's tap"
    else
      echo "pass: local camera: listed again with the app back and its cover tapped"
      dev shell input keyevent KEYCODE_BACK
      if ! { await seal_card 10 && client "$p" no 10; }; then
        fail_later "camera: $p's camera client is still listed 10 s after Back, or no seal card"
      else
        echo "pass: local camera: gone within 10 s of Back, on the seal card"
      fi
    fi
  fi
fi
dev shell dumpsys media.camera 2>&1 | tr -d '\r' | sed -n '/events log/,/^$/p' | grep -F -e "package $p (" |
  head -n 6 | while IFS= read -r line; do say "camera: dumpsys media.camera:$line"; done
dev shell am force-stop "$p" > /dev/null 2>&1
# The scan of the go-ahead PNG on the virtual scene's wall.
p=$registry
if [ ! -f "$apks/$png" ]; then
  say "not made on $avd: the scan of $png: no such file in $apks"
elif ! console virtualscene-image wall "$apks/$png" 2>&1 | tr -d '\r' | grep -q -x -e OK; then
  fail_later "camera: the console's virtualscene-image wall $png failed"
elif ! console automation play "$macro" 2>&1 | tr -d '\r' | grep -q -x -e OK; then
  fail_later "camera: the console's automation play $macro failed"
else
  # The macro walks the scene's camera to the wall for about 15 s.
  sleep 20
  if ! to_scan "$p"; then
    fail_later "camera: $p did not reach the scan screen"
  else
    # Until the collision result, the scan screen with another line than its scanning one, or 60 s.
    start=$(date +%s)
    while :; do
      dump
      [ -z "$(node collision_text)" ] || break
      [ -z "$(node scan)" ] || [ "$(text scan_line)" = 'Looking for the go-ahead QR...' ] || break
      [ $(($(date +%s) - start)) -lt 60 ] || break
      sleep 2
    done
    if [ -n "$(node collision_text)" ]; then
      case $(text collision_text) in
        'Collision found. This seed is not unique and has been destroyed.')
          echo "pass: local camera: the scanner decoded $png from the virtual scene's wall: the collision result"
          ;;
        *) fail_later "camera: $p's collision result reads '$(text collision_text)'" ;;
      esac
    elif [ -n "$(node scan)" ] && [ "$(text scan_line)" != 'Looking for the go-ahead QR...' ]; then
      fail_later "camera: the scan of $png ended on '$(text scan_line)', not the collision result"
    else
      say "not made on $avd: the scanner decoded nothing in 60 s from $png on the virtual scene's wall; the owner's phone scans it (P4)"
    fi
  fi
fi
stop_emulator

[ -z "$failed" ] || fail "${failed#; }"
say "every check made on $avd passed (each check not made is named above)"
