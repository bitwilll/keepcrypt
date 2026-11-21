#!/bin/sh
# The iPhone app's Rust library (tasks/todo.md, M6 item C1; Q87, lead decision M6-1): keepcrypt-capi's
# libkeepcrypt_capi.a for one of the app's two configurations, built with plain cargo exactly as
# entropy-ci.yml's two iOS cross legs build it (release, --locked, IPHONEOS_DEPLOYMENT_TARGET 17.0, the
# deployment target of docs/build-plan.md's iOS row), for aarch64-apple-ios (the iPhone) and
# aarch64-apple-ios-sim (the simulator on an Apple-silicon Mac), and copied into
# mobile/ios/build/rust/FLAVOUR/TARGET/, from which mobile/ios/KeepCrypt.xcodeproj links it by path
# (the Shipping configuration the shipping copy, WithTestRegistry the withTestRegistry one). Xcode never
# builds Rust: the project has no Run Script phase, and its link fails when a flavour's archive is
# missing. mobile/ios/build/ is ignored by git, and the gate refuses a tracked file under it (Build) and
# any tracked archive under mobile/ (KtBinary).
#
# Usage: scripts/ios-rust.sh shipping | withTestRegistry | --selftest
#   shipping          default features, in target/: the shipping app's library.
#   withTestRegistry  keepcrypt-core's test-registry feature, switched on from the command line with -p
#                     (never in a manifest; keepcrypt-capi has no keepcrypt-core edge, as keepcrypt-jni,
#                     lead decision M5-35), in its own target dir, target/capi-test-registry, the cross
#                     legs' own: the test-registry app's library. It never ships.
#
# The archive is not scanned here: a staticlib carries every upstream object, libstd's random-key path
# among them, so the release-artifact scan reads what links it (the cross legs' C probe, M6-4, and the
# built app, C4's --ios-app). For each target: the archive cargo wrote, its size and SHA-256, and the
# copy's SHA-256, which must be the same. The flavour's directory under mobile/ios/build/rust/ is
# emptied first, so no archive of an earlier build stays behind.
#
# Needs a macOS arm64 host (CI's macos-26 and macos-15 runners, or the owner's Mac for local
# development, Q90), cargo and rustc of the pinned toolchain (rust-toolchain.toml, with its two iOS
# targets; the script runs them from the repo root, so rustup picks that toolchain), and macOS's
# shasum -a 256; any other host is refused. No Xcode tool runs here, but cargo's C build of
# secp256k1-sys (cc) asks xcrun for the iOS SDKs, so Xcode must be the active developer directory
# (xcode-select, or DEVELOPER_DIR for this run alone).
# Exit 0 built and copied; 1 a build or copy failed; 2 bad usage, a missing tool or another host.
#
# scripts/ios-rust.sh --selftest runs this script, a fresh copy for each case, on stand-ins written
# to a temporary directory (no cargo build is real): a cargo that writes a stand-in archive where
# cargo would and prints its arguments and IPHONEOS_DEPLOYMENT_TARGET; a uname that says Darwin arm64,
# or what the case sets; and a shasum that gives -a 256 FILE's SHA-256 from the machine's own tool.
# Both flavours pass, each with its features and target dir, both targets built in order, a copy of
# each archive under mobile/ios/build/rust/FLAVOUR/TARGET/ equal to cargo's, and a stale file there
# removed. Each of these exits 1: a failing cargo build, an archive cargo did not write, a copy with
# other bytes. Each of these exits 2: a shasum that fails or prints no SHA-256, no cargo on PATH, a
# host that is not macOS arm64 (Linux x86_64, macOS x86_64), another flavour and no argument. Exit 0
# when every case behaves, 1 otherwise.
set -u
unset CDPATH

fail() {
  echo "FAIL: ios-rust: $1" >&2
  exit 1
}
refuse() {
  echo "ios-rust: $1" >&2
  exit 2
}

# selftest: the cases listed in the header, each on its own copy of this script.
selftest() {
  self=$(cd "$(dirname "$0")" && pwd) || exit 2
  realcp=$(command -v cp) || exit 2
  # The machine's own SHA-256 tool, for built() and the stand-in shasum.
  if realsha=$(command -v sha256sum); then
    :
  elif realsha=$(command -v shasum); then
    realsha="$realsha -a 256"
  else
    exit 2
  fi
  st=$(mktemp -d "${TMPDIR:-/tmp}/kc-ios-rust-selftest.XXXXXX") || exit 2
  trap 'rm -rf "$st"' EXIT
  mkdir "$st/bin" "$st/sha-fails" "$st/sha-junk" "$st/cp-other" "$st/no-cargo" || exit 2
  cp "$self/$(basename "$0")" "$st/ios-rust.sh" || exit 2
  cat > "$st/bin/cargo" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in cargo: a build writes a stand-in libkeepcrypt_capi.a where cargo would and
# prints its arguments and IPHONEOS_DEPLOYMENT_TARGET. KC_CARGO=fails fails the build; KC_CARGO=nolib
# writes nothing.
echo "cargo stand-in: $* | IPHONEOS_DEPLOYMENT_TARGET=${IPHONEOS_DEPLOYMENT_TARGET:-unset}"
[ "${KC_CARGO:-}" != fails ] || exit 101
t=
d=
while [ $# -gt 0 ]; do
  case $1 in --target) t=$2; shift ;; --target-dir) d=$2; shift ;; esac
  shift
done
[ "${KC_CARGO:-}" != nolib ] || exit 0
mkdir -p "$d/$t/release" || exit 1
echo "stand-in libkeepcrypt_capi.a for $t in $d" > "$d/$t/release/libkeepcrypt_capi.a"
EOF
  cat > "$st/bin/uname" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in uname: Darwin (or KC_UNAME_S) on arm64 (or KC_UNAME_M).
case $1 in -s) echo "${KC_UNAME_S:-Darwin}" ;; -m) echo "${KC_UNAME_M:-arm64}" ;; *) exit 1 ;; esac
EOF
  # shasum -a 256 FILE gives FILE's SHA-256 from the machine's own tool; any other use of it fails.
  cat > "$st/bin/shasum" <<EOF || exit 2
#!/bin/sh
[ \$# -eq 3 ] && [ "\$1" = -a ] && [ "\$2" = 256 ] || exit 1
exec $realsha "\$3"
EOF
  printf '#!/bin/sh\nexit 1\n' > "$st/sha-fails/shasum" || exit 2
  printf '#!/bin/sh\necho "no-hash  $3"\n' > "$st/sha-junk/shasum" || exit 2
  cat > "$st/cp-other/cp" <<EOF || exit 2
#!/bin/sh
# A cp that writes other bytes under mobile/ios/build/; any other copy is the real cp's.
case \$2 in */mobile/ios/build/*) echo other > "\$2"; exit 0 ;; esac
exec "$realcp" "\$@"
EOF
  # PATH without cargo: the stand-in uname and shasum and the system's own tools.
  cp "$st/bin/uname" "$st/bin/shasum" "$st/no-cargo/" || exit 2
  chmod +x "$st/bin"/* "$st/sha-fails"/* "$st/sha-junk"/* "$st/cp-other/cp" "$st/no-cargo"/* || exit 2
  # run NAME ARG [VAR=VALUE...]: ios-rust.sh ARG (none for "") on a fresh copy of the script in
  # $st/NAME/repo/scripts, with the stand-ins first on PATH unless a VAR=VALUE sets it; its output in
  # out and its exit status in rc. Then each target whose copy equals cargo's archive adds
  # "selftest: TARGET copy equals", and the stale file planted in the flavour's directory, if still
  # there, "selftest: a stale file stayed".
  run() {
    c=$st/$1
    arg=$2
    shift 2
    b=$c/repo/mobile/ios/build/rust/$arg
    mkdir -p "$c/repo/scripts" "$b/old" || exit 2
    cp "$st/ios-rust.sh" "$c/repo/scripts/" || exit 2
    echo stale > "$b/old/libkeepcrypt_capi.a" || exit 2
    # $arg unquoted: an empty one is no argument.
    env PATH="$st/bin:$PATH" "$@" sh "$c/repo/scripts/ios-rust.sh" $arg > "$c/out" 2>&1
    echo $? > "$c/rc"
    [ ! -e "$b/old/libkeepcrypt_capi.a" ] || echo "selftest: a stale file stayed" >> "$c/out"
    case $arg in withTestRegistry) td=target/capi-test-registry ;; *) td=target ;; esac
    for t in aarch64-apple-ios aarch64-apple-ios-sim; do
      if [ -f "$b/$t/libkeepcrypt_capi.a" ] && cmp -s "$b/$t/libkeepcrypt_capi.a" "$c/repo/$td/$t/release/libkeepcrypt_capi.a"; then
        echo "selftest: $t copy equals" >> "$c/out"
      fi
    done
  }
  passed=0
  failed=0
  # expect NAME EXIT TEXT...: run NAME exited EXIT and printed every TEXT, and no TEXT that starts
  # with "!".
  expect() {
    name=$1
    want=$2
    shift 2
    got=$(cat "$st/$name/rc")
    ok=yes
    [ "$got" = "$want" ] || ok=no
    for text in "$@"; do
      case $text in
        !*) ! grep -q -F -e "${text#!}" "$st/$name/out" || ok=no ;;
        *) grep -q -F -e "$text" "$st/$name/out" || ok=no ;;
      esac
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
  # built TDIR TARGET: the line ios-rust.sh prints for the stand-in archive cargo wrote for TARGET in
  # TDIR, its size and SHA-256 computed here.
  built() {
    printf 'stand-in libkeepcrypt_capi.a for %s in %s\n' "$2" "$1" > "$st/lib" || exit 2
    h=$($realsha "$st/lib") || exit 2
    echo "$1/$2/release/libkeepcrypt_capi.a: $(wc -c < "$st/lib" | tr -d ' ') bytes, SHA-256 ${h%% *}"
  }
  run shipping-passes shipping
  run test-registry-passes withTestRegistry
  run cargo-fails shipping KC_CARGO=fails
  run no-archive-after-the-build shipping KC_CARGO=nolib
  run copy-with-other-bytes shipping "PATH=$st/cp-other:$st/bin:$PATH"
  run shasum-fails shipping "PATH=$st/sha-fails:$st/bin:$PATH"
  run shasum-prints-no-hash shipping "PATH=$st/sha-junk:$st/bin:$PATH"
  run no-cargo shipping "PATH=$st/no-cargo:/usr/bin:/bin"
  run another-host-linux-x86_64 shipping KC_UNAME_S=Linux KC_UNAME_M=x86_64
  run another-host-macos-x86_64 shipping KC_UNAME_M=x86_64
  run another-flavour release
  run no-argument ""
  dt=IPHONEOS_DEPLOYMENT_TARGET=17.0
  reg="-p keepcrypt-core --features keepcrypt-core/test-registry"
  expect shipping-passes 0 \
    "cargo stand-in: build --release --locked -p keepcrypt-capi --lib --target aarch64-apple-ios --target-dir target | $dt" \
    "cargo stand-in: build --release --locked -p keepcrypt-capi --lib --target aarch64-apple-ios-sim --target-dir target | $dt" \
    "$(built target aarch64-apple-ios)" "$(built target aarch64-apple-ios-sim)" \
    "selftest: aarch64-apple-ios copy equals" "selftest: aarch64-apple-ios-sim copy equals" \
    "ios-rust: shipping: built and copied into" "!selftest: a stale file stayed" "!test-registry"
  expect test-registry-passes 0 \
    "cargo stand-in: build --release --locked -p keepcrypt-capi $reg --lib --target aarch64-apple-ios --target-dir target/capi-test-registry | $dt" \
    "cargo stand-in: build --release --locked -p keepcrypt-capi $reg --lib --target aarch64-apple-ios-sim --target-dir target/capi-test-registry | $dt" \
    "$(built target/capi-test-registry aarch64-apple-ios)" "$(built target/capi-test-registry aarch64-apple-ios-sim)" \
    "selftest: aarch64-apple-ios copy equals" "selftest: aarch64-apple-ios-sim copy equals" \
    "ios-rust: withTestRegistry: built and copied into" "!selftest: a stale file stayed"
  expect cargo-fails 1 "FAIL: ios-rust: cargo build for aarch64-apple-ios failed" "!copied to"
  expect no-archive-after-the-build 1 "FAIL: ios-rust: no target/aarch64-apple-ios/release/libkeepcrypt_capi.a after the build"
  expect copy-with-other-bytes 1 \
    "FAIL: ios-rust: the copy in " \
    "/copy-with-other-bytes/repo/mobile/ios/build/rust/shipping/aarch64-apple-ios differs from target/aarch64-apple-ios/release/libkeepcrypt_capi.a"
  expect shasum-fails 2 "ios-rust: shasum -a 256 cannot hash target/aarch64-apple-ios/release/libkeepcrypt_capi.a" "!copied to"
  expect shasum-prints-no-hash 2 "ios-rust: shasum -a 256 gave no SHA-256 for target/aarch64-apple-ios/release/libkeepcrypt_capi.a" \
    "!copied to"
  expect no-cargo 2 "ios-rust: no cargo on PATH"
  expect another-host-linux-x86_64 2 "ios-rust: a macOS arm64 host only"
  expect another-host-macos-x86_64 2 "ios-rust: a macOS arm64 host only"
  expect another-flavour 2 "ios-rust: the flavour is shipping or withTestRegistry, not release"
  expect no-argument 2 "ios-rust: usage: scripts/ios-rust.sh shipping | withTestRegistry"
  echo "ios-rust selftest: $passed passed, $failed failed"
  [ "$failed" -eq 0 ]
}

if [ $# -eq 1 ] && [ "$1" = --selftest ]; then
  selftest
  exit
fi

[ $# -eq 1 ] || refuse "usage: scripts/ios-rust.sh shipping | withTestRegistry"
flavour=$1
case $flavour in
  shipping)
    features=
    tdir=target
    ;;
  withTestRegistry)
    features="-p keepcrypt-core --features keepcrypt-core/test-registry"
    tdir=target/capi-test-registry
    ;;
  *) refuse "the flavour is shipping or withTestRegistry, not $flavour" ;;
esac

here=$(cd "$(dirname "$0")" && pwd) || exit 2
root=$(cd "$here/.." && pwd) || exit 2
cd "$root" || exit 2
case $(uname -s)-$(uname -m) in
  Darwin-arm64) ;;
  *) refuse "a macOS arm64 host only (CI's macOS runners or the owner's Mac): the iOS targets need Apple's SDKs" ;;
esac
command -v cargo > /dev/null 2>&1 || refuse "no cargo on PATH"
out=$root/mobile/ios/build/rust/$flavour

# sha256_of FILE: FILE's SHA-256 into $sha, 64 lowercase hex digits, from macOS's shasum. Called
# outside any command substitution, so a tool that fails or prints anything else refuses (exit 2): no
# check below compares an empty hash.
sha256_of() {
  sha=$(shasum -a 256 "$1") || refuse "shasum -a 256 cannot hash $1"
  sha=${sha%% *}
  printf '%s\n' "$sha" | grep -q -x -E '[0-9a-f]{64}' || refuse "shasum -a 256 gave no SHA-256 for $1"
}

# The deployment target, read by rustc and cc on the iOS targets only, as the cross legs set it.
export IPHONEOS_DEPLOYMENT_TARGET=17.0
rm -rf "$out" || exit 2
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  echo "== $target ($flavour)"
  # $features unquoted: its words hold no space.
  cargo build --release --locked -p keepcrypt-capi $features --lib --target "$target" --target-dir "$tdir" ||
    fail "cargo build for $target failed"
  lib=$tdir/$target/release/libkeepcrypt_capi.a
  [ -f "$lib" ] || fail "no $lib after the build"
  sha256_of "$lib"
  built=$sha
  echo "$lib: $(wc -c < "$lib" | tr -d ' ') bytes, SHA-256 $built"
  mkdir -p "$out/$target" || exit 2
  cp "$lib" "$out/$target/libkeepcrypt_capi.a" || exit 2
  sha256_of "$out/$target/libkeepcrypt_capi.a"
  [ "$sha" = "$built" ] || fail "the copy in $out/$target differs from $lib"
  echo "copied to $out/$target/libkeepcrypt_capi.a"
done
echo "ios-rust: $flavour: built and copied into $out"
