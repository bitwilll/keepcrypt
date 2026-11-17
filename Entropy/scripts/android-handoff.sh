#!/bin/sh
# The Android workflow's hand-off of the signed APKs from its build job to its leg jobs, six since
# commit U1a (tasks/todo.md, M5 group 6; lead decision M5-70 (b), commit L9): the checks each side
# makes, here with their own cases (commit L9c) rather than in the workflow's run steps, where
# nothing tested them.
# The build job hands $RUNNER_TEMP/apks over through actions/cache and its SHA256SUMS as the job's
# output, which reaches the legs apart from the cache; so each leg installs only the bytes the build
# job hashed, and the build job hashed the shipped two only as the bytes it uploaded.
#
# Usage:
#   scripts/android-handoff.sh --sums APKS UPLOADED OUT   (the build job, its last step but the save)
#     APKS must hold the five signed APKs android-emulator.sh installs (app-shipping-release,
#     app-shipping-release-androidTest, app-withTestRegistry-release,
#     app-withTestRegistry-release-androidTest and capture-control-release, .apk) and may hold more
#     (apksigner's .idsig files), plain files alone. OUT gets every file's SHA-256 as sha256sum writes
#     it (a SHA-256, two spaces and the name), and is printed. UPLOADED is the uploaded SHA256SUMS:
#     app-shipping-release.apk must have the SHA-256 it gives app-shipping-release.apk, and
#     app-withTestRegistry-release.apk the one it gives app-withTestRegistry-release-NOT-FOR-RELEASE.apk.
#     Prints the files' count and bytes.
#   scripts/android-handoff.sh --check APKS               (each leg job, before it installs anything)
#     KC_SHA256SUMS holds the build job's OUT as the job output gave it (one newline at its end is
#     dropped): it must hold a line, and each line a SHA-256 in lower-case hex, two spaces and a plain
#     file name (a letter or digit, then letters, digits, dots, underscores and hyphens); APKS must
#     hold exactly the files it lists (none missing and none more, a hidden file or a directory
#     counted too); and each file must have its SHA-256 (sha256sum --check --strict).
# Prints what it read and "FAIL: hand-off: ..." on stderr for a check that fails.
# Exit: 0 every check passed; 1 one failed; 2 bad usage.
#
# scripts/android-handoff.sh --selftest runs both forms on directories it makes in a temporary
# directory, as the two jobs run them: the build side on five stand-in APKs with their .idsig files
# passes and writes ten lines, and fails with an APK missing, an entry that is no plain file and a
# shipped APK the upload's SHA256SUMS gives another SHA-256 or does not list; the leg side, on a copy
# of what the build side hashed and its OUT, passes, with one newline more at the output's end too,
# and fails with a file more, a hidden file more, a directory more, a file missing, a changed byte, a
# line twice, a name with a path, upper-case hex, an empty line, no output and no directory.
# Exit 0 when every case behaves, 1 otherwise.
set -u
unset CDPATH

fail() {
  echo "FAIL: hand-off: $1" >&2
  exit 1
}

usage() {
  echo 'usage: scripts/android-handoff.sh --sums APKS UPLOADED OUT | --check APKS | --selftest' >&2
  exit 2
}

nl='
'

# sums APKS UPLOADED OUT: the build job's side.
sums() {
  apks=$1
  uploaded=$2
  out=$3
  for f in app-shipping-release app-shipping-release-androidTest app-withTestRegistry-release \
    app-withTestRegistry-release-androidTest capture-control-release; do
    [ -f "$apks/$f.apk" ] || fail "no $apks/$f.apk"
  done
  for f in "$apks"/*; do
    [ -f "$f" ] && [ ! -L "$f" ] || fail "$f is not a plain file"
  done
  (cd "$apks" && sha256sum -- *) > "$out" || fail "sha256sum could not hash $apks"
  cat "$out"
  for pair in app-shipping-release.apk:app-shipping-release.apk \
    app-withTestRegistry-release.apk:app-withTestRegistry-release-NOT-FOR-RELEASE.apk; do
    have=$(awk -v n="${pair%%:*}" '$2 == n { print $1 }' "$out") || fail "cannot read $out"
    up=$(awk -v n="${pair#*:}" '$2 == n { print $1 }' "$uploaded") || fail "cannot read $uploaded"
    [ -n "$have" ] && [ "$have" = "$up" ] || fail "$apks/${pair%%:*} is not the uploaded ${pair#*:} (SHA256SUMS)"
  done
  bytes=$(cat -- "$apks"/* | wc -c) || fail "cannot read $apks"
  echo "hand-off: $(($(wc -l < "$out"))) files, $((bytes)) bytes"
}

# check APKS: a leg job's side, on KC_SHA256SUMS.
check() {
  apks=$1
  given=${KC_SHA256SUMS-}
  given=${given%"$nl"}
  [ -n "$given" ] || fail "the build job's output holds no SHA256SUMS"
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/kc-handoff.XXXXXX") || exit 2
  trap 'rm -rf "$tmp"' EXIT
  list=$tmp/SHA256SUMS
  printf '%s\n' "$given" > "$list" || exit 2
  echo "== the build job's SHA256SUMS"
  cat "$list"
  [ -d "$apks" ] || fail "no $apks: this run's cache entry was not restored"
  rc=0
  grep -q -v -E -e '^[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._-]*$' "$list" || rc=$?
  [ "$rc" -eq 1 ] || fail "a line of the build job's SHA256SUMS is not a SHA-256, two spaces and a file name (grep exit $rc)"
  cut -c 67- "$list" | LC_ALL=C sort > "$tmp/listed" || exit 2
  (cd "$apks" && find . -mindepth 1) | sed 's|^\./||' | LC_ALL=C sort > "$tmp/found" || exit 2
  if ! cmp -s "$tmp/listed" "$tmp/found"; then
    diff "$tmp/listed" "$tmp/found" || :
    fail "the files handed over (>) are not the files the build job's SHA256SUMS lists (<)"
  fi
  (cd "$apks" && sha256sum --check --strict "$list") || fail "a file handed over does not have the build job's SHA-256"
  echo "hand-off: the $(($(wc -l < "$list"))) files handed over have the build job's SHA-256"
}

# selftest: the cases listed in the header.
selftest() {
  self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0") || exit 2
  st=$(mktemp -d "${TMPDIR:-/tmp}/kc-handoff-selftest.XXXXXX") || exit 2
  trap 'rm -rf "$st"' EXIT
  passed=0
  failed=0
  # built NAME: a build runner's temp directory: the five stand-in APKs, their .idsig files, and the
  # uploads' SHA256SUMS over the two shipped APKs under their uploaded names.
  built() {
    b=$st/$1
    mkdir -p "$b/apks" "$b/upload" || exit 2
    for f in app-shipping-release app-shipping-release-androidTest app-withTestRegistry-release \
      app-withTestRegistry-release-androidTest capture-control-release; do
      printf '%s bytes\n' "$f" > "$b/apks/$f.apk" || exit 2
      printf '%s v4 signature\n' "$f" > "$b/apks/$f.apk.idsig" || exit 2
    done
    cp "$b/apks/app-shipping-release.apk" "$b/upload/app-shipping-release.apk" || exit 2
    cp "$b/apks/app-withTestRegistry-release.apk" "$b/upload/app-withTestRegistry-release-NOT-FOR-RELEASE.apk" || exit 2
    printf 'p4\n' > "$b/upload/p4-seal-ids.txt" || exit 2
    (cd "$b/upload" && sha256sum -- *.apk p4-seal-ids.txt > SHA256SUMS) || exit 2
  }
  # expect NAME EXIT TEXT COMMAND...: COMMAND exits EXIT and prints TEXT.
  expect() {
    name=$1
    want=$2
    text=$3
    shift 3
    out=$("$@" 2>&1)
    rc=$?
    case $out in
      *"$text"*) [ "$rc" -eq "$want" ] && { passed=$((passed + 1)); echo "PASS $name (exit $rc)"; return; } ;;
    esac
    failed=$((failed + 1))
    echo "FAIL $name: wanted exit $want with '$text', got exit $rc:"
    printf '%s\n' "$out" | sed 's/^/    /'
  }
  # The build side.
  built build
  expect build-passes 0 'hand-off: 10 files, ' sh "$self" --sums "$st/build/apks" "$st/build/upload/SHA256SUMS" "$st/build/out"
  if [ "$(grep -c -E -e '^[0-9a-f]{64}  [a-z].*' "$st/build/out")" = 10 ] && [ "$(wc -l < "$st/build/out")" -eq 10 ]; then
    passed=$((passed + 1))
    echo "PASS build-writes-ten-lines"
  else
    failed=$((failed + 1))
    echo "FAIL build-writes-ten-lines:"
    sed 's/^/    /' "$st/build/out"
  fi
  built build-missing-apk
  rm "$st/build-missing-apk/apks/capture-control-release.apk" || exit 2
  expect build-missing-apk 1 'no '"$st/build-missing-apk/apks/capture-control-release.apk" \
    sh "$self" --sums "$st/build-missing-apk/apks" "$st/build-missing-apk/upload/SHA256SUMS" "$st/build-missing-apk/out"
  built build-directory
  mkdir "$st/build-directory/apks/sub" || exit 2
  expect build-directory 1 'sub is not a plain file' \
    sh "$self" --sums "$st/build-directory/apks" "$st/build-directory/upload/SHA256SUMS" "$st/build-directory/out"
  built build-upload-differs
  printf 'other bytes\n' > "$st/build-upload-differs/upload/app-withTestRegistry-release-NOT-FOR-RELEASE.apk" || exit 2
  (cd "$st/build-upload-differs/upload" && sha256sum -- *.apk p4-seal-ids.txt > SHA256SUMS) || exit 2
  expect build-upload-differs 1 'app-withTestRegistry-release.apk is not the uploaded app-withTestRegistry-release-NOT-FOR-RELEASE.apk' \
    sh "$self" --sums "$st/build-upload-differs/apks" "$st/build-upload-differs/upload/SHA256SUMS" "$st/build-upload-differs/out"
  built build-upload-unlisted
  grep -v -e ' app-shipping-release[.]apk$' "$st/build-upload-unlisted/upload/SHA256SUMS" > "$st/build-upload-unlisted/sums" || exit 2
  expect build-upload-unlisted 1 'app-shipping-release.apk is not the uploaded app-shipping-release.apk' \
    sh "$self" --sums "$st/build-upload-unlisted/apks" "$st/build-upload-unlisted/sums" "$st/build-upload-unlisted/out"
  # The leg side, on a copy of the build side's directory, as the cache restores it, and its OUT as
  # GitHub gives a NAME<<DELIMITER output (its lines joined by newlines, none at the end).
  sums=$(cat "$st/build/out") || exit 2
  leg() {
    l=$st/leg-$1
    mkdir -p "$l" || exit 2
    cp -R "$st/build/apks" "$l/apks" || exit 2
  }
  leg passes
  expect leg-passes 0 'hand-off: the 10 files handed over have the build job' env KC_SHA256SUMS="$sums" sh "$self" --check "$st/leg-passes/apks"
  leg trailing-newline
  expect leg-trailing-newline 0 'have the build job' env KC_SHA256SUMS="$sums$nl" sh "$self" --check "$st/leg-trailing-newline/apks"
  leg extra-file
  printf 'x\n' > "$st/leg-extra-file/apks/extra.apk" || exit 2
  expect leg-extra-file 1 'are not the files the build job' env KC_SHA256SUMS="$sums" sh "$self" --check "$st/leg-extra-file/apks"
  leg hidden-file
  printf 'x\n' > "$st/leg-hidden-file/apks/.hidden" || exit 2
  expect leg-hidden-file 1 'are not the files the build job' env KC_SHA256SUMS="$sums" sh "$self" --check "$st/leg-hidden-file/apks"
  leg directory
  mkdir "$st/leg-directory/apks/sub" || exit 2
  expect leg-directory 1 'are not the files the build job' env KC_SHA256SUMS="$sums" sh "$self" --check "$st/leg-directory/apks"
  leg missing-file
  rm "$st/leg-missing-file/apks/app-shipping-release.apk.idsig" || exit 2
  expect leg-missing-file 1 'are not the files the build job' env KC_SHA256SUMS="$sums" sh "$self" --check "$st/leg-missing-file/apks"
  leg changed-byte
  printf 'app-shipping-release bytez\n' > "$st/leg-changed-byte/apks/app-shipping-release.apk" || exit 2
  expect leg-changed-byte 1 'does not have the build job' env KC_SHA256SUMS="$sums" sh "$self" --check "$st/leg-changed-byte/apks"
  leg line-twice
  expect leg-line-twice 1 'are not the files the build job' env KC_SHA256SUMS="$sums$nl${sums%%"$nl"*}" sh "$self" --check "$st/leg-line-twice/apks"
  leg path-in-name
  first=${sums%%"$nl"*}
  expect leg-path-in-name 1 'is not a SHA-256, two spaces and a file name' \
    env KC_SHA256SUMS="$sums$nl$(printf '%s' "$first" | cut -c 1-66)../apks/x.apk" sh "$self" --check "$st/leg-path-in-name/apks"
  leg upper-case-hex
  expect leg-upper-case-hex 1 'is not a SHA-256, two spaces and a file name' \
    env KC_SHA256SUMS="$(printf '%s\n' "$sums" | tr 'a-f' 'A-F')" sh "$self" --check "$st/leg-upper-case-hex/apks"
  leg empty-line
  expect leg-empty-line 1 'is not a SHA-256, two spaces and a file name' env KC_SHA256SUMS="$sums$nl$nl" sh "$self" --check "$st/leg-empty-line/apks"
  leg no-output
  expect leg-no-output 1 'output holds no SHA256SUMS' env KC_SHA256SUMS= sh "$self" --check "$st/leg-no-output/apks"
  expect leg-no-directory 1 'cache entry was not restored' env KC_SHA256SUMS="$sums" sh "$self" --check "$st/leg-absent/apks"
  expect usage 2 'usage:' sh "$self" --check
  echo "android-handoff selftest: $passed passed, $failed failed"
  [ "$failed" -eq 0 ]
}

case ${1-} in
  --sums) [ $# -eq 4 ] || usage; sums "$2" "$3" "$4" ;;
  --check) [ $# -eq 2 ] || usage; check "$2" ;;
  --selftest) [ $# -eq 1 ] || usage; selftest; exit ;;
  *) usage ;;
esac
