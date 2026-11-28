#!/bin/sh
# ios-warmup.sh UDID APP: launch the app once on a booted simulator before XCTest drives it.
#
# Owner's choice (b) at the M7 gate (2026-11-23, M7-13): the macos-26 journeys jobs failed four times in eight
# runs with XCTest's own IPC timing out in the simulator's services (an app launch, an accessibility query, a
# screenshot request), on a simulator booted moments before, never with a crash or hang of the app. So each
# journeys job, after the build and before its tests, installs the app, launches it, waits for its process and
# lets it settle, then terminates and uninstalls it: the tests start on a simulator that has launched this app
# once, and with no data container left from the warm-up (xcodebuild installs the app again).
#
# Not a retry and not a fallback: any step that fails fails the job, so a simulator that cannot launch the app
# says so here, before the tests. The app is the TestHooks app on test values; nothing is captured or kept.
set -eu

fail() { echo "FAIL: warm-up: $1" >&2; exit 1; }

[ "$#" -eq 2 ] || fail "usage: ios-warmup.sh UDID APP"
udid=$1
app=$2
[ -d "$app" ] || fail "no app at $app"
id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Info.plist") || fail "no CFBundleIdentifier in $app/Info.plist"
[ -n "$id" ] || fail "an empty CFBundleIdentifier in $app/Info.plist"

start=$(date +%s)
xcrun simctl install "$udid" "$app" || fail "simctl install $id on $udid failed"
xcrun simctl launch "$udid" "$id" || fail "simctl launch $id on $udid failed"

# The app's process on the simulator, within 120 s of its launch.
tries=0
until xcrun simctl spawn "$udid" launchctl list | grep "UIKitApplication:$id" > /dev/null; do
  tries=$((tries + 1))
  [ "$tries" -le 60 ] || fail "$id not running on $udid 120 s after its launch"
  sleep 2
done
up=$(($(date +%s) - start))

# Settle: the first launch's work in the simulator's services (the app's and SpringBoard's) ends before the
# tests begin.
sleep 20

xcrun simctl terminate "$udid" "$id" || fail "simctl terminate $id on $udid failed"
xcrun simctl uninstall "$udid" "$id" || fail "simctl uninstall $id on $udid failed"
echo "warm-up: $id launched on $udid, running after ${up} s, settled 20 s, terminated and uninstalled ($(($(date +%s) - start)) s in all)"
