#!/bin/sh
# The Android app's Rust library (tasks/todo.md, M5 group 4 and lead decision M5-9; "Rust is built by
# script, not by Gradle"): keepcrypt-jni's libkeepcrypt.so for one of :app's flavours, built with
# plain cargo exactly as entropy-ci.yml's three Android cross legs build it (release, --locked, NDK
# r30's clang at API 31 as the C compiler and linker, llvm-ar, and getrandom's linux_getrandom backend
# through CARGO_TARGET_<T>_RUSTFLAGS, never a global RUSTFLAGS), for MA:23's three ABIs, scanned with
# the release-artifact scan, and copied into mobile/android/app/src/<flavour>/jniLibs/<abi>/, Gradle's
# default native-library source set, from which :app packages it unchanged (keepDebugSymbols): the
# APK check (banned-api-check.sh --apk) requires each APK's library to be these bytes. Gradle never
# builds Rust, and fails when a flavour's library is missing (app/build.gradle.kts).
#
# Usage: scripts/android-rust.sh shipping | withTestRegistry
#   shipping          default features, in target/: the shipping APK's library. The scan must be
#                     clean.
#   withTestRegistry  keepcrypt-core's test-registry feature, switched on from the command line with
#                     -p (never in a manifest; keepcrypt-jni has no keepcrypt-core edge, lead decision
#                     M5-35), in its own target dir, target/ffi-test-registry: the test-registry APK's
#                     library. The scan must give exactly its registry marker and the test key. Then
#                     the same build for the host, x86_64-unknown-linux-gnu, with the same cfg, in the
#                     same target dir: the library :core-ffi's JVM tests load (java.library.path,
#                     core-ffi/build.gradle.kts), scanned the same way. It never ships.
#
# For each Android library, after its scan: every undefined dynamic symbol must be defined in NDK
# r30's API 31 stub libraries for its ABI (the sysroot's libc.so, libm.so and libdl.so), so the
# library binds on the oldest Android it supports; its size, SHA-256, LOAD segments and DT_NEEDED
# libraries are printed, and the copy in jniLibs must have the same SHA-256 (the APK check judges
# the exports, DT_NEEDED and 16 KB pages of the packaged copy). The flavour's jniLibs directory is
# emptied first, so no library of an earlier build stays behind.
#
# Needs a Linux x86_64 host (the NDK's linux-x86_64 prebuilt; CI only: nothing is installed on the
# owner's Mac, Q56), ANDROID_HOME holding ndk/30.0.16248370 (its source.properties is checked, and
# no other NDK is used), and cargo and rustc of the pinned toolchain (rust-toolchain.toml, with its
# Android targets; the script runs them from the repo root, so rustup picks that toolchain).
# Exit 0 built, scanned and copied; 1 a scan or check failed; 2 bad usage or a missing tool or NDK.
set -u
unset CDPATH

fail() {
  echo "FAIL: android-rust: $1" >&2
  exit 1
}
refuse() {
  echo "android-rust: $1" >&2
  exit 2
}

[ $# -eq 1 ] || refuse "usage: scripts/android-rust.sh shipping | withTestRegistry"
flavour=$1
case $flavour in
  shipping)
    features=
    tdir=target
    ;;
  withTestRegistry)
    features="-p keepcrypt-core --features keepcrypt-core/test-registry"
    tdir=target/ffi-test-registry
    ;;
  *) refuse "the flavour is shipping or withTestRegistry, not $flavour" ;;
esac

ndk_version=30.0.16248370
here=$(cd "$(dirname "$0")" && pwd) || exit 2
root=$(cd "$here/.." && pwd) || exit 2
cd "$root" || exit 2
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || refuse "a Linux x86_64 host only (the NDK's linux-x86_64 prebuilt; CI)"
sdk=${ANDROID_HOME:-}
[ -n "$sdk" ] && [ -d "$sdk" ] || refuse "no Android SDK (ANDROID_HOME)"
ndk=$sdk/ndk/$ndk_version
props=$ndk/source.properties
[ -f "$props" ] || refuse "no NDK $ndk_version ($props)"
grep -q "^Pkg[.]Revision = $ndk_version\$" "$props" || refuse "$props is not NDK $ndk_version"
bin=$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
stubs=$ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib
for tool in llvm-ar llvm-nm llvm-readelf aarch64-linux-android31-clang armv7a-linux-androideabi31-clang \
  x86_64-linux-android31-clang; do
  [ -x "$bin/$tool" ] || refuse "no $tool in $bin"
done
command -v cargo > /dev/null 2>&1 || refuse "no cargo on PATH"
cfg='--cfg getrandom_backend="linux_getrandom"'
jni=$root/mobile/android/app/src/$flavour/jniLibs
work=$(mktemp -d "${TMPDIR:-/tmp}/kc-android-rust.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT

sha256_of() {
  out=$(sha256sum "$1") || exit 2
  printf '%s\n' "${out%% *}"
}

# names FILE: the dynamic symbol names llvm-nm prints for FILE with the further options given before
# it, one per line, version suffixes (@LIBC, @@LIBC_P) dropped.
names() {
  f=$1
  shift
  "$bin/llvm-nm" -D -j "$@" "$f" > "$work/nm" 2> "$work/nm-err" || { cat "$work/nm-err" >&2; refuse "llvm-nm cannot read $f"; }
  sed -e '/^$/d' -e 's/@.*$//' "$work/nm" | LC_ALL=C sort -u
}

# scan TARGET SO: the release-artifact scan, as the cross legs run it: clean for shipping; for the
# test registry exactly two hits, its registry marker and the test key (so no stub marker, no RNG
# symbol, no stripped file and the OS import there).
scan() {
  rc=0
  out=$(sh "$here/banned-api-check.sh" --artifact "$1" "$2" 2>&1) || rc=$?
  printf '%s\n' "$out"
  case $flavour in
    shipping) [ "$rc" -eq 0 ] || fail "$2: the release-artifact scan exited $rc, not 0" ;;
    withTestRegistry)
      [ "$rc" -eq 1 ] || fail "$2: the release-artifact scan exited $rc, not 1 (its two hits)"
      for want in "Marker: $2: KC_TEST_REGISTRY_DO_NOT_SHIP" "TestKey: $2: the test registry public key " \
        "banned-api-check --artifact $1: 2 hit(s) in 1 file(s)"; do
        case $out in *"$want"*) ;; *) fail "$2: no line of the scan holds \"$want\"" ;; esac
      done
      ;;
  esac
}

# build TARGET: the flavour's cargo build for TARGET, with the getrandom cfg for TARGET alone; the
# C compiler, archiver and linker for an Android TARGET come from the caller's environment.
build() {
  tu=$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')
  # $features unquoted: its words hold no space.
  env "CARGO_TARGET_${tu}_RUSTFLAGS=$cfg" \
    cargo build --release --locked -p keepcrypt-jni $features --lib --target "$1" --target-dir "$tdir" ||
    fail "cargo build for $1 failed"
}

rm -rf "$jni" || exit 2
for abi in arm64-v8a armeabi-v7a x86_64; do
  case $abi in
    arm64-v8a) target=aarch64-linux-android clang=aarch64-linux-android31-clang sysroot=aarch64-linux-android ;;
    armeabi-v7a) target=armv7-linux-androideabi clang=armv7a-linux-androideabi31-clang sysroot=arm-linux-androideabi ;;
    x86_64) target=x86_64-linux-android clang=x86_64-linux-android31-clang sysroot=x86_64-linux-android ;;
  esac
  echo "== $abi ($target, $flavour)"
  t=$(printf '%s' "$target" | tr '-' '_')
  tu=$(printf '%s' "$target" | tr 'a-z-' 'A-Z_')
  # The C compiler, archiver and linker for this target alone, as the cross legs set them.
  (
    export "CC_$t=$bin/$clang" "AR_$t=$bin/llvm-ar" "CARGO_TARGET_${tu}_LINKER=$bin/$clang"
    build "$target"
  ) || exit "$?"
  so=$tdir/$target/release/libkeepcrypt.so
  [ -f "$so" ] || fail "no $so after the build"
  scan "$target" "$so"
  # Every undefined dynamic symbol (weak ones too) defined in the API 31 stubs of this ABI.
  api=$stubs/$sysroot/31
  : > "$work/defined"
  for lib in libc.so libm.so libdl.so; do
    [ -f "$api/$lib" ] || refuse "no $api/$lib"
    names "$api/$lib" --defined-only >> "$work/defined"
  done
  LC_ALL=C sort -u "$work/defined" -o "$work/defined"
  names "$so" -u > "$work/undefined"
  missing=$(LC_ALL=C comm -23 "$work/undefined" "$work/defined")
  [ -z "$missing" ] || fail "$so: undefined symbols that NDK r30's API 31 stubs ($api) do not define: $(printf '%s ' $missing)"
  echo "$so: all $(wc -l < "$work/undefined" | tr -d ' ') undefined dynamic symbols are defined in $api's libc.so, libm.so and libdl.so"
  echo "$so: $(wc -c < "$so" | tr -d ' ') bytes, SHA-256 $(sha256_of "$so")"
  "$bin/llvm-readelf" -lW "$so" | awk '$1 == "LOAD"'
  "$bin/llvm-readelf" -dW "$so" | grep -F -e '(NEEDED)' || :
  mkdir -p "$jni/$abi" || exit 2
  cp "$so" "$jni/$abi/libkeepcrypt.so" || exit 2
  [ "$(sha256_of "$jni/$abi/libkeepcrypt.so")" = "$(sha256_of "$so")" ] || fail "the copy in $jni/$abi differs from $so"
  echo "copied to $jni/$abi/libkeepcrypt.so"
done

if [ "$flavour" = withTestRegistry ]; then
  host=x86_64-unknown-linux-gnu
  echo "== the JVM tests' host library ($host, test registry)"
  build "$host"
  so=$tdir/$host/release/libkeepcrypt.so
  [ -f "$so" ] || fail "no $so after the build"
  scan "$host" "$so"
  echo "$so: $(wc -c < "$so" | tr -d ' ') bytes, SHA-256 $(sha256_of "$so")"
fi
echo "android-rust: $flavour: built, scanned and copied into $jni"
