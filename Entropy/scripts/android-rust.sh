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
# Usage: scripts/android-rust.sh shipping | withTestRegistry | --selftest
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
#
# scripts/android-rust.sh --selftest runs this script, a fresh copy for each case, on stand-ins
# written to a temporary directory (no NDK, cargo build or scan is real): a release-artifact scan
# that finds a test-registry library's marker and key and nothing in any other; an NDK r30 tree whose
# clangs and llvm-ar do nothing, whose llvm-nm reads a library's undefined symbols from the file
# beside it and each API 31 stub's defined ones from its own, and whose llvm-readelf prints a LOAD
# segment and libc.so; a cargo that writes a stand-in library where cargo would and prints its
# arguments and the C compiler, archiver, linker and rustflags it was given; and a uname that says
# Linux x86_64. Both flavours pass, each with those settings per target as the cross legs set them,
# a copy in jniLibs of each ABI's library, a stale library there removed, and for withTestRegistry
# its own target dir and the host library. Each of these exits 1: an undefined symbol the API 31
# stubs lack, a shipping scan with a hit, a test-registry scan that is clean or has a third hit, a
# failing cargo build, a library cargo did not write, a copy into jniLibs with other bytes. Each of
# these exits 2: a sha256sum that fails or prints no SHA-256, no ANDROID_HOME, no NDK r30, another
# NDK at its path, a missing NDK tool, a host that is not Linux x86_64, another flavour and no
# argument. Exit 0 when every case behaves, 1 otherwise.
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

# selftest: the cases listed in the header, each on its own copy of this script.
selftest() {
  self=$(cd "$(dirname "$0")" && pwd) || exit 2
  realcp=$(command -v cp) || exit 2
  st=$(mktemp -d "${TMPDIR:-/tmp}/kc-android-rust-selftest.XXXXXX") || exit 2
  trap 'rm -rf "$st"' EXIT
  mkdir "$st/bin" "$st/sha-fails" "$st/sha-junk" "$st/cp-other" || exit 2
  cp "$self/$(basename "$0")" "$st/android-rust.sh" || exit 2
  cat > "$st/banned-api-check.sh" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in release-artifact scan (--artifact TARGET FILE): a library under
# target/ffi-test-registry holds the registry marker and the test key, any other nothing;
# KC_SCAN=clean finds nothing in any, KC_SCAN=hit adds an RNG symbol to each.
[ "$1" = --artifact ] || exit 2
hits=0
case "$3:${KC_SCAN:-}" in
  *ffi-test-registry*:clean) ;;
  *ffi-test-registry*)
    echo "Marker: $3: KC_TEST_REGISTRY_DO_NOT_SHIP"
    echo "TestKey: $3: the test registry public key 00"
    hits=2
    ;;
esac
if [ "${KC_SCAN:-}" = hit ]; then
  echo "Symbol: $3: undefined rand"
  hits=$((hits + 1))
fi
if [ "$hits" -eq 0 ]; then
  echo "banned-api-check --artifact $2: clean, 1 file(s)"
  exit 0
fi
echo "banned-api-check --artifact $2: $hits hit(s) in 1 file(s)"
exit 1
EOF
  cat > "$st/bin/cargo" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in cargo: a build writes a stand-in libkeepcrypt.so where cargo would, its
# undefined symbols (KC_UNDEF) in libkeepcrypt.so.undef beside it, and prints its arguments and the
# C compiler, archiver, linker and rustflags it was given. KC_CARGO=fails fails the build;
# KC_CARGO=nolib writes nothing.
echo "cargo stand-in: $* | $(env | grep -E '^(CC_|AR_|CARGO_TARGET_|RUSTFLAGS=)' | LC_ALL=C sort | tr '\n' ' ')"
[ "${KC_CARGO:-}" != fails ] || exit 101
t=
d=
while [ $# -gt 0 ]; do
  case $1 in --target) t=$2; shift ;; --target-dir) d=$2; shift ;; esac
  shift
done
[ "${KC_CARGO:-}" != nolib ] || exit 0
mkdir -p "$d/$t/release" || exit 1
echo "stand-in libkeepcrypt.so for $t in $d" > "$d/$t/release/libkeepcrypt.so"
printf '%s\n' ${KC_UNDEF:-getrandom memcpy} > "$d/$t/release/libkeepcrypt.so.undef"
EOF
  cat > "$st/bin/uname" <<'EOF' || exit 2
#!/bin/sh
# The selftest's stand-in uname: Linux (or KC_UNAME_S) on x86_64.
case $1 in -s) echo "${KC_UNAME_S:-Linux}" ;; -m) echo x86_64 ;; *) exit 1 ;; esac
EOF
  printf '#!/bin/sh\nexit 1\n' > "$st/sha-fails/sha256sum" || exit 2
  printf '#!/bin/sh\necho "no-hash  $1"\n' > "$st/sha-junk/sha256sum" || exit 2
  cat > "$st/cp-other/cp" <<EOF || exit 2
#!/bin/sh
# A cp that writes other bytes into jniLibs; any other copy is the real cp's.
case \$2 in */jniLibs/*) echo other > "\$2"; exit 0 ;; esac
exec "$realcp" "\$@"
EOF
  # ndk SDK REVISION [TOOL]: SDK/ndk/30.0.16248370 holding NDK REVISION's source.properties and the
  # stand-in tools and API 31 stubs, TOOL left out.
  ndk() {
    n=$1/ndk/30.0.16248370
    b=$n/toolchains/llvm/prebuilt/linux-x86_64/bin
    mkdir -p "$b" || exit 2
    printf 'Pkg.Desc = Android NDK\nPkg.Revision = %s\n' "$2" > "$n/source.properties" || exit 2
    for tool in llvm-ar aarch64-linux-android31-clang armv7a-linux-androideabi31-clang x86_64-linux-android31-clang; do
      printf '#!/bin/sh\nexit 0\n' > "$b/$tool" || exit 2
    done
    cat > "$b/llvm-nm" <<'EOF' || exit 2
#!/bin/sh
# llvm-nm -D -j [--defined-only | -u] FILE: the names in FILE.defined or FILE.undef.
for f; do :; done
case " $* " in
  *" --defined-only "*) [ ! -f "$f.defined" ] || cat "$f.defined" ;;
  *" -u "*) cat "$f.undef" ;;
  *) exit 1 ;;
esac
EOF
    cat > "$b/llvm-readelf" <<'EOF' || exit 2
#!/bin/sh
case $1 in
  -lW) echo '  LOAD 0x000000 0x0000000000000000 0x0000000000000000 0x001000 0x001000 R E 0x4000' ;;
  -dW) echo ' 0x0000000000000001 (NEEDED) Shared library: [libc.so]' ;;
  *) exit 1 ;;
esac
EOF
    chmod +x "$b"/* || exit 2
    [ $# -lt 3 ] || rm "$b/$3" || exit 2
    for triple in aarch64-linux-android arm-linux-androideabi x86_64-linux-android; do
      api=$n/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/$triple/31
      mkdir -p "$api" || exit 2
      : > "$api/libc.so" && : > "$api/libm.so" && : > "$api/libdl.so" || exit 2
      printf 'getrandom@LIBC\nmemcpy@@LIBC\n' > "$api/libc.so.defined" || exit 2
    done
  }
  ndk "$st/sdk" 30.0.16248370
  ndk "$st/sdk-wrong" 30.0.16248371
  ndk "$st/sdk-notool" 30.0.16248370 llvm-nm
  mkdir -p "$st/sdk-other/ndk/29.0.14206865" || exit 2
  chmod +x "$st/bin"/* "$st/sha-fails/sha256sum" "$st/sha-junk/sha256sum" "$st/cp-other/cp" || exit 2
  # run NAME ARG [VAR=VALUE...]: android-rust.sh ARG (none for "") on a fresh copy of the repo's
  # two scripts in $st/NAME/repo, with ANDROID_HOME the stand-in SDK and the stand-ins first on PATH
  # unless a VAR=VALUE sets them; its output in out and its exit status in rc. Then each of the
  # flavour's ABIs whose jniLibs copy equals its library adds "selftest: ABI copy equals", and the
  # stale library planted in the flavour's jniLibs, if still there, "selftest: a stale library stayed".
  run() {
    c=$st/$1
    arg=$2
    shift 2
    j=$c/repo/mobile/android/app/src/$arg/jniLibs
    mkdir -p "$c/repo/scripts" "$j/x86" || exit 2
    cp "$st/android-rust.sh" "$st/banned-api-check.sh" "$c/repo/scripts/" || exit 2
    echo stale > "$j/x86/stale.so" || exit 2
    # $arg unquoted: an empty one is no argument.
    env ANDROID_HOME="$st/sdk" PATH="$st/bin:$PATH" "$@" sh "$c/repo/scripts/android-rust.sh" $arg > "$c/out" 2>&1
    echo $? > "$c/rc"
    [ ! -e "$j/x86/stale.so" ] || echo "selftest: a stale library stayed" >> "$c/out"
    case $arg in withTestRegistry) td=target/ffi-test-registry ;; *) td=target ;; esac
    for pair in arm64-v8a:aarch64-linux-android armeabi-v7a:armv7-linux-androideabi x86_64:x86_64-linux-android; do
      abi=${pair%%:*}
      if [ -f "$j/$abi/libkeepcrypt.so" ] && cmp -s "$j/$abi/libkeepcrypt.so" "$c/repo/$td/${pair#*:}/release/libkeepcrypt.so"; then
        echo "selftest: $abi copy equals" >> "$c/out"
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
  # built TDIR TARGET: the line android-rust.sh prints for the stand-in library cargo wrote for
  # TARGET in TDIR, its size and SHA-256 computed here.
  built() {
    printf 'stand-in libkeepcrypt.so for %s in %s\n' "$2" "$1" > "$st/lib" || exit 2
    h=$(sha256sum "$st/lib") || exit 2
    echo "$1/$2/release/libkeepcrypt.so: $(wc -c < "$st/lib" | tr -d ' ') bytes, SHA-256 ${h%% *}"
  }
  run shipping-passes shipping
  run test-registry-passes withTestRegistry
  run undefined-symbol-the-stubs-lack shipping "KC_UNDEF=getrandom memcpy preadv2"
  run shipping-scan-with-a-hit shipping KC_SCAN=hit
  run test-registry-scan-clean withTestRegistry KC_SCAN=clean
  run test-registry-scan-third-hit withTestRegistry KC_SCAN=hit
  run cargo-fails shipping KC_CARGO=fails
  run no-library-after-the-build shipping KC_CARGO=nolib
  run copy-with-other-bytes shipping "PATH=$st/cp-other:$st/bin:$PATH"
  run sha256sum-fails shipping "PATH=$st/sha-fails:$st/bin:$PATH"
  run sha256sum-prints-no-hash shipping "PATH=$st/sha-junk:$st/bin:$PATH"
  run no-android-home shipping ANDROID_HOME=
  run no-ndk-r30 shipping "ANDROID_HOME=$st/sdk-other"
  run another-ndk-at-r30s-path shipping "ANDROID_HOME=$st/sdk-wrong"
  run ndk-tool-missing shipping "ANDROID_HOME=$st/sdk-notool"
  run not-linux shipping KC_UNAME_S=Darwin
  run another-flavour release
  run no-argument ""
  cfg='getrandom_backend="linux_getrandom"'
  b=$st/sdk/ndk/30.0.16248370/toolchains/llvm/prebuilt/linux-x86_64/bin
  reg="-p keepcrypt-jni -p keepcrypt-core --features keepcrypt-core/test-registry"
  expect shipping-passes 0 \
    "cargo stand-in: build --release --locked -p keepcrypt-jni --lib --target aarch64-linux-android --target-dir target | AR_aarch64_linux_android=$b/llvm-ar CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$b/aarch64-linux-android31-clang CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS=--cfg $cfg CC_aarch64_linux_android=$b/aarch64-linux-android31-clang " \
    "cargo stand-in: build --release --locked -p keepcrypt-jni --lib --target armv7-linux-androideabi --target-dir target | AR_armv7_linux_androideabi=$b/llvm-ar CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$b/armv7a-linux-androideabi31-clang CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS=--cfg $cfg CC_armv7_linux_androideabi=$b/armv7a-linux-androideabi31-clang " \
    "cargo stand-in: build --release --locked -p keepcrypt-jni --lib --target x86_64-linux-android --target-dir target | AR_x86_64_linux_android=$b/llvm-ar CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$b/x86_64-linux-android31-clang CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS=--cfg $cfg CC_x86_64_linux_android=$b/x86_64-linux-android31-clang " \
    "target/armv7-linux-androideabi/release/libkeepcrypt.so: all 2 undefined dynamic symbols are defined in" \
    "$(built target aarch64-linux-android)" "$(built target armv7-linux-androideabi)" "$(built target x86_64-linux-android)" \
    "selftest: arm64-v8a copy equals" "selftest: armeabi-v7a copy equals" "selftest: x86_64 copy equals" \
    "android-rust: shipping: built, scanned and copied into" "!selftest: a stale library stayed" "!x86_64-unknown-linux-gnu"
  expect test-registry-passes 0 \
    "cargo stand-in: build --release --locked $reg --lib --target aarch64-linux-android --target-dir target/ffi-test-registry | AR_aarch64_linux_android=$b/llvm-ar " \
    "cargo stand-in: build --release --locked $reg --lib --target armv7-linux-androideabi --target-dir target/ffi-test-registry | AR_armv7_linux_androideabi=$b/llvm-ar " \
    "cargo stand-in: build --release --locked $reg --lib --target x86_64-linux-android --target-dir target/ffi-test-registry | AR_x86_64_linux_android=$b/llvm-ar " \
    "cargo stand-in: build --release --locked $reg --lib --target x86_64-unknown-linux-gnu --target-dir target/ffi-test-registry | CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=--cfg $cfg " \
    "banned-api-check --artifact x86_64-unknown-linux-gnu: 2 hit(s) in 1 file(s)" \
    "$(built target/ffi-test-registry aarch64-linux-android)" "$(built target/ffi-test-registry x86_64-unknown-linux-gnu)" \
    "selftest: arm64-v8a copy equals" "selftest: armeabi-v7a copy equals" "selftest: x86_64 copy equals" \
    "android-rust: withTestRegistry: built, scanned and copied into" "!selftest: a stale library stayed"
  expect undefined-symbol-the-stubs-lack 1 \
    "FAIL: android-rust: target/aarch64-linux-android/release/libkeepcrypt.so: undefined symbols that NDK r30's API 31 stubs" \
    "do not define: preadv2" "!copied to"
  expect shipping-scan-with-a-hit 1 \
    "FAIL: android-rust: target/aarch64-linux-android/release/libkeepcrypt.so: the release-artifact scan exited 1, not 0"
  expect test-registry-scan-clean 1 \
    "FAIL: android-rust: target/ffi-test-registry/aarch64-linux-android/release/libkeepcrypt.so: the release-artifact scan exited 0, not 1 (its two hits)"
  expect test-registry-scan-third-hit 1 \
    "no line of the scan holds \"banned-api-check --artifact aarch64-linux-android: 2 hit(s) in 1 file(s)\""
  expect cargo-fails 1 "FAIL: android-rust: cargo build for aarch64-linux-android failed"
  expect no-library-after-the-build 1 "FAIL: android-rust: no target/aarch64-linux-android/release/libkeepcrypt.so after the build"
  expect copy-with-other-bytes 1 \
    "/copy-with-other-bytes/repo/mobile/android/app/src/shipping/jniLibs/arm64-v8a differs from target/aarch64-linux-android/release/libkeepcrypt.so" \
    "FAIL: android-rust: the copy in "
  expect sha256sum-fails 2 "android-rust: sha256sum cannot hash target/aarch64-linux-android/release/libkeepcrypt.so" "!copied to"
  expect sha256sum-prints-no-hash 2 "android-rust: sha256sum gave no SHA-256 for target/aarch64-linux-android/release/libkeepcrypt.so" \
    "!copied to"
  expect no-android-home 2 "android-rust: no Android SDK (ANDROID_HOME)"
  expect no-ndk-r30 2 "android-rust: no NDK 30.0.16248370"
  expect another-ndk-at-r30s-path 2 "source.properties is not NDK 30.0.16248370"
  expect ndk-tool-missing 2 "android-rust: no llvm-nm in "
  expect not-linux 2 "android-rust: a Linux x86_64 host only"
  expect another-flavour 2 "android-rust: the flavour is shipping or withTestRegistry, not release"
  expect no-argument 2 "android-rust: usage: scripts/android-rust.sh shipping | withTestRegistry"
  echo "android-rust selftest: $passed passed, $failed failed"
  [ "$failed" -eq 0 ]
}

if [ $# -eq 1 ] && [ "$1" = --selftest ]; then
  selftest
  exit
fi

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

# sha256_of FILE: FILE's SHA-256 into $sha, 64 lowercase hex digits. Called outside any command
# substitution, so a sha256sum that fails or prints anything else refuses (exit 2): no check below
# compares an empty hash.
sha256_of() {
  sha=$(sha256sum "$1") || refuse "sha256sum cannot hash $1"
  sha=${sha%% *}
  printf '%s\n' "$sha" | grep -q -x -E '[0-9a-f]{64}' || refuse "sha256sum gave no SHA-256 for $1"
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
  missing=$(LC_ALL=C comm -23 "$work/undefined" "$work/defined") || refuse "comm cannot compare the symbol lists"
  [ -z "$missing" ] || fail "$so: undefined symbols that NDK r30's API 31 stubs ($api) do not define: $(printf '%s ' $missing)"
  echo "$so: all $(wc -l < "$work/undefined" | tr -d ' ') undefined dynamic symbols are defined in $api's libc.so, libm.so and libdl.so"
  sha256_of "$so"
  built=$sha
  echo "$so: $(wc -c < "$so" | tr -d ' ') bytes, SHA-256 $built"
  "$bin/llvm-readelf" -lW "$so" | awk '$1 == "LOAD"'
  "$bin/llvm-readelf" -dW "$so" | grep -F -e '(NEEDED)' || :
  mkdir -p "$jni/$abi" || exit 2
  cp "$so" "$jni/$abi/libkeepcrypt.so" || exit 2
  sha256_of "$jni/$abi/libkeepcrypt.so"
  [ "$sha" = "$built" ] || fail "the copy in $jni/$abi differs from $so"
  echo "copied to $jni/$abi/libkeepcrypt.so"
done

if [ "$flavour" = withTestRegistry ]; then
  host=x86_64-unknown-linux-gnu
  echo "== the JVM tests' host library ($host, test registry)"
  build "$host"
  so=$tdir/$host/release/libkeepcrypt.so
  [ -f "$so" ] || fail "no $so after the build"
  scan "$host" "$so"
  sha256_of "$so"
  echo "$so: $(wc -c < "$so" | tr -d ' ') bytes, SHA-256 $sha"
fi
echo "android-rust: $flavour: built, scanned and copied into $jni"
