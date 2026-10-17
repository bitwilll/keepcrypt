#!/bin/sh
# Runs Gradle on the Android project, mobile/android (tasks/todo.md, M5 group 4; Q54). There is no
# wrapper jar in git (the gate's KtBinary rule refuses any jar under mobile/): this script fetches
# Gradle's own distribution from services.gradle.org, checks its SHA-256 against the pin below and
# refuses it before any of its code runs when the bytes differ. The pin was copied from the
# published gradle-9.7.1-bin.zip.sha256 on 2026-10-17; a new Gradle is a reviewed change to both
# lines. Gradle 9.7.1 came out on 2026-08-19 (the 14-day cool-off; 9.8.x was inside it).
#
# Every run unpacks the checked zip afresh into a temporary directory and removes it afterwards,
# so what runs is always the checked bytes. Gradle runs with --no-daemon (nothing stays behind)
# and --no-scan (no build scan is ever published), and with its own user home under KC_GRADLE_HOME
# instead of ~/.gradle, so no init script, gradle.properties or cache of another build on the
# machine applies. The downloaded zip is kept there too and checked again on every run.
#
# Usage: scripts/android-gradle.sh GRADLE-ARGUMENT...   (from any directory; the project
#        directory is passed to Gradle, so the arguments are tasks and options as usual)
# KC_GRADLE_HOME: where the zip and Gradle's user home live (default: $HOME/.keepcrypt-gradle; an
#        absolute path outside the repo).
# Needs curl, unzip and sha256sum or shasum, and a JDK 17 in JAVA_HOME (Gradle 9 and AGP 9 run on
# it; CI prints which one). Exit: Gradle's own status; 2 when the distribution cannot be fetched,
# checked or unpacked (nothing of Gradle has run then).
set -u

version=9.7.1
sha256=acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a
url=https://services.gradle.org/distributions/gradle-$version-bin.zip

fail() {
    echo "android-gradle: $1" >&2
    exit 2
}

here=$(cd "$(dirname "$0")" && pwd) || fail "cannot find the script's directory"
project=$here/../mobile/android
[ -f "$project/settings.gradle.kts" ] || fail "no $project/settings.gradle.kts"
home=${KC_GRADLE_HOME:-$HOME/.keepcrypt-gradle}
case $home in
    /*) ;;
    *) fail "KC_GRADLE_HOME must be an absolute path: $home" ;;
esac
mkdir -p "$home" || fail "cannot create $home"
zip=$home/gradle-$version-bin.zip

# sha256_of FILE: the file's SHA-256 in lower-case hex, from sha256sum (Linux) or shasum (macOS).
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        out=$(sha256sum "$1") || return 1
    elif command -v shasum >/dev/null 2>&1; then
        out=$(shasum -a 256 "$1") || return 1
    else
        return 1
    fi
    printf '%s\n' "${out%% *}"
}

if [ ! -f "$zip" ]; then
    rm -f "$zip.part" || fail "cannot remove $zip.part"
    # https only, redirects included (services.gradle.org redirects to its download host).
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --output "$zip.part" "$url" || fail "cannot download $url"
    mv "$zip.part" "$zip" || fail "cannot move the download to $zip"
fi
got=$(sha256_of "$zip") || fail "no sha256sum or shasum to check $zip"
if [ "$got" != "$sha256" ]; then
    rm -f "$zip"
    fail "$zip has SHA-256 $got, not the pinned $sha256; removed, nothing of it ran"
fi
echo "android-gradle: gradle-$version-bin.zip SHA-256 $got (pinned)"

dist=$(mktemp -d "${TMPDIR:-/tmp}/kc-gradle.XXXXXX") || fail "cannot make a temporary directory"
if ! unzip -q "$zip" -d "$dist"; then
    rm -rf "$dist"
    fail "cannot unpack $zip"
fi
GRADLE_USER_HOME=$home/user-home
export GRADLE_USER_HOME
"$dist/gradle-$version/bin/gradle" --no-daemon --no-scan --project-dir "$project" "$@"
status=$?
rm -rf "$dist"
exit "$status"
