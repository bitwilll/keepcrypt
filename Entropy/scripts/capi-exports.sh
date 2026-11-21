#!/bin/sh
# keepcrypt-capi's exports, on the built archive (tasks/todo.md, M6 item B5 and lead decision M6-4).
# A staticlib keeps every upstream object's global symbols (libstd's, compiler-builtins', the C parts
# of secp256k1-sys), so the cdylib's rule, "exactly our symbols beside secp256k1-sys's four", cannot
# be read off the whole archive. What is ours can: the archive members of the workspace's own
# crates, keepcrypt_*, whose defined global symbols, read with the pinned toolchain's llvm-nm
# (llvm-nm --defined-only --extern-only, a Mach-O name's one leading underscore stripped), that are
# not Rust-mangled (_ZN..., _R...) nor LLVM's own (anon.*) must be exactly kc_call and kc_max_out,
# each once. And no member of any crate defines another kc_ name, so no dependency can shadow the
# header's two (include/keepcrypt.h). secp256k1-sys's four #[no_mangle] functions are counted from
# its own members and printed, not judged.
# Usage: scripts/capi-exports.sh ARCHIVE...   each a libkeepcrypt_capi.a
#        scripts/capi-exports.sh --selftest   the judge on canned llvm-nm listings, a planted extra
#                                             export among them
# Exit 0 clean, 1 a finding (each named), 2 usage or tool error. Needs rustc (for llvm-nm) unless
# --selftest.
set -u

# judge NAME: reads one archive's llvm-nm listing on stdin; prints each finding, or one summary
# line when there is none; exits 0 clean, 1 findings, 2 a listing with no member header.
judge() {
  awk -v name="$1" '
    # A member header: "member.o:" or "archive(member.o):", one field ending in a colon.
    NF == 1 && /:$/ {
      m = $1
      sub(/:$/, "", m)
      sub(/^.*\(/, "", m)
      sub(/\)$/, "", m)
      members++
      next
    }
    NF == 3 && length($2) == 1 {
      s = $3
      sub(/^_/, "", s)
      if (s ~ /^kc_/) {
        kc[s]++
        if (m !~ /^keepcrypt_/) { print "capi-exports: " name ": " s " defined in " m ", not one of the workspace'"'"'s own members"; bad = 1 }
      }
      if (s ~ /^(_ZN|_R|anon\.)/) next
      if (m ~ /^keepcrypt_/) {
        ours[s]++
        if (s != "kc_call" && s != "kc_max_out") { print "capi-exports: " name ": " m " defines " $3 ", not kc_call or kc_max_out"; bad = 1 }
      }
      if (m ~ /^secp256k1_sys-/ && s ~ /^rustsecp256k1_v0_10_0_(context_create|context_destroy|default_error_callback_fn|default_illegal_callback_fn)$/) secp[s] = 1
    }
    END {
      if (!members) { print "capi-exports: " name ": no archive member in the listing"; exit 2 }
      for (w = 1; w <= 2; w++) {
        want = w == 1 ? "kc_call" : "kc_max_out"
        if (ours[want] != 1) { print "capi-exports: " name ": " want " defined " ours[want] + 0 " times in the workspace'"'"'s members, not once"; bad = 1 }
        if (kc[want] != 1) { print "capi-exports: " name ": " want " defined " kc[want] + 0 " times in the archive, not once"; bad = 1 }
      }
      if (bad) exit 1
      n = 0
      for (s in secp) n++
      print "capi-exports: " name ": ours exactly kc_call and kc_max_out (secp256k1-sys'"'"'s: " n " of its four)"
    }'
}

selftest() {
  pass=0
  fail=0
  head='libkeepcrypt_capi.a(keepcrypt_capi-1a2b.keepcrypt_capi.x.rcgu.o):'
  clean="$head
0000000000000000 T _kc_call
0000000000000010 T _kc_max_out
0000000000000020 T __ZN14keepcrypt_capi7request17h0123456789abcdefE
0000000000000030 S _anon.0123.1.llvm.42

keepcrypt_guard-3c4d.keepcrypt_guard.y.rcgu.o:
0000000000000000 T __RNvCs1234_15keepcrypt_guard7guarded
secp256k1_sys-5e6f.secp256k1_sys.z.rcgu.o:
0000000000000000 T _rustsecp256k1_v0_10_0_context_create
0000000000000010 T _rustsecp256k1_v0_10_0_context_destroy
0000000000000020 T _rustsecp256k1_v0_10_0_default_error_callback_fn
0000000000000030 T _rustsecp256k1_v0_10_0_default_illegal_callback_fn
fce6-secp256k1.o:
0000000000000000 T _rustsecp256k1_v0_10_0_ecdsa_sign
compiler_builtins-7a8b.compiler_builtins.w.rcgu.o:
0000000000000000 T ___udivti3
0000000000000010 T _fminf16"
  # case NAME WANT LISTING: WANT 0 (clean, the summary line), 1 (a finding) or 2 (an error).
  case_() {
    out=$(printf '%s\n' "$3" | judge "$1")
    rc=$?
    ok=no
    case $2:$rc:$out in
      0:0:*"ours exactly kc_call and kc_max_out (secp256k1-sys's: 4 of its four)") ok=yes ;;
      1:1:capi-exports:*) ok=yes ;;
      2:2:*"no archive member"*) ok=yes ;;
    esac
    if [ "$ok" = yes ]; then
      pass=$((pass + 1))
      printf 'PASS %s -> %s\n' "$1" "$(printf '%s\n' "$out" | head -n 1)"
    else
      fail=$((fail + 1))
      printf 'FAIL %s: wanted %s, got exit %s:\n%s\n' "$1" "$2" "$rc" "$out"
    fi
  }
  case_ clean 0 "$clean"
  case_ planted-extra-export-in-capi 1 "$clean
$head
0000000000000040 T _kc_planted"
  case_ planted-c-export-in-capi 1 "$clean
$head
0000000000000040 T _wipe_all"
  case_ planted-export-in-guard 1 "$clean
keepcrypt_guard-3c4d.keepcrypt_guard.y.rcgu.o:
0000000000000010 T _guarded_raw"
  case_ planted-export-in-safe-layer 1 "$clean
keepcrypt_ffi-9a0b.keepcrypt_ffi.v.rcgu.o:
0000000000000000 D _KC_ABI_VERSION"
  case_ kc-name-in-a-dependency 1 "$clean
bitcoin-1c2d.bitcoin.u.rcgu.o:
0000000000000000 T _kc_call_raw"
  case_ kc-call-twice 1 "$clean
keepcrypt_capi-1a2b.keepcrypt_capi.t.rcgu.o:
0000000000000000 T _kc_call"
  case_ kc-max-out-missing 1 "$head
0000000000000000 T _kc_call"
  case_ kc-call-in-another-crate 1 "keepcrypt_capi-1a2b.keepcrypt_capi.x.rcgu.o:
0000000000000010 T _kc_max_out
std-3e4f.std.s.rcgu.o:
0000000000000000 T _kc_call"
  case_ no-member 2 "0000000000000000 T _kc_call
0000000000000010 T _kc_max_out"
  printf 'capi-exports --selftest: %s passed, %s failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case ${1:-} in
  --selftest)
    [ $# -eq 1 ] || { echo "usage: scripts/capi-exports.sh ARCHIVE... | --selftest" >&2; exit 2; }
    selftest
    exit $?
    ;;
  '' | -*)
    echo "usage: scripts/capi-exports.sh ARCHIVE... | --selftest" >&2
    exit 2
    ;;
esac

libdir=$(rustc --print target-libdir) || { echo "capi-exports: rustc --print target-libdir failed" >&2; exit 2; }
nm=$libdir/../bin/llvm-nm
[ -x "$nm" ] || { echo "capi-exports: no llvm-nm at $nm (llvm-tools-preview)" >&2; exit 2; }
status=0
for a in "$@"; do
  [ -f "$a" ] && [ -r "$a" ] || { echo "capi-exports: cannot read $a" >&2; exit 2; }
  listing=$("$nm" --defined-only --extern-only "$a") || { echo "capi-exports: llvm-nm failed on $a" >&2; exit 2; }
  printf '%s\n' "$listing" | judge "$a"
  rc=$?
  case $rc in
    0) ;;
    1) status=1 ;;
    *) exit 2 ;;
  esac
done
exit "$status"
