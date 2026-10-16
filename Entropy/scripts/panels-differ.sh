#!/bin/sh
# pi-image panels differ (tasks/todo.md, M4b B4; Q47 (a)): the image workflow's check that each
# screen type's image holds its own keepcrypt-pi. The profiles in pi/app's PROFILES differ in data,
# so two panels whose binaries have the same SHA-256 mean a name never reached the compiler, and
# both images got the profile pi/app gives when no name is set (the HAT's). The workflow runs it on
# every run that builds two or more panels, with each panel's binary SHA-256 from its own legs.
#
#   scripts/panels-differ.sh NAME=SHA256 NAME=SHA256...
#                       two or more panels, each a name of pi/os/Makefile's PANELS and the SHA-256
#                       of the keepcrypt-pi its image holds
#   scripts/panels-differ.sh --selftest
#                       two panels with the same hash must fail (the check's canary), and so must a
#                       third equal to the first; two different hashes must pass; one panel, a name
#                       given twice, a name that is not lowercase letters, digits and dashes, an
#                       empty name, a pair with no = and a hash that is not 64 lowercase hex digits
#                       must be refused
#
# Prints each panel and its hash, or one FAIL line per pair of panels with the same hash. Exit 0
# every hash differs, 1 two panels share one, 2 usage.
set -u

usage() {
  echo 'usage: scripts/panels-differ.sh NAME=SHA256 NAME=SHA256... | --selftest' >&2
  exit 2
}

# scase NAME WANT-EXIT WANT-LINE PAIR...: run this script on the PAIRs in a new process; the exit
# must be WANT-EXIT and WANT-LINE a whole line of the output.
scase() {
  name=$1
  want=$2
  line=$3
  shift 3
  out=$(sh "$self" "$@" 2>&1)
  rc=$?
  if [ "$rc" -eq "$want" ] && printf '%s\n' "$out" | grep -q -x -F -e "$line"; then
    pass=$((pass + 1))
    printf 'PASS %s -> exit %s: %s\n' "$name" "$rc" "$line"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted exit %s with "%s", got exit %s:\n' "$name" "$want" "$line" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

selftest() {
  self=$0
  h1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  h2=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
  upper=$(printf '%s' "$h1" | tr a-f A-F)
  same='have the same keepcrypt-pi SHA-256, so a panel name did not reach the compiler'
  pass=0
  fail=0
  scase equal 1 "FAIL: pi-image panels differ: st7789-240x240 and st7789-240x320 $same: $h1" \
    "st7789-240x240=$h1" "st7789-240x320=$h1"
  scase third-equal-to-first 1 "FAIL: pi-image panels differ: st7789-240x240 and c $same: $h1" \
    "st7789-240x240=$h1" "st7789-240x320=$h2" "c=$h1"
  scase different 0 'pi-image panels differ: 2 panels, 2 different keepcrypt-pi SHA-256s' \
    "st7789-240x240=$h1" "st7789-240x320=$h2"
  scase one-panel 2 'usage: scripts/panels-differ.sh NAME=SHA256 NAME=SHA256... | --selftest' \
    "st7789-240x240=$h1"
  scase name-twice 2 'panels-differ: st7789-240x240 is given twice' \
    "st7789-240x240=$h1" "st7789-240x240=$h2"
  scase empty-hash 2 'panels-differ: not a name and a SHA-256 of 64 lowercase hex digits: st7789-240x320=' \
    "st7789-240x240=$h1" 'st7789-240x320='
  scase upper-case-hash 2 "panels-differ: not a name and a SHA-256 of 64 lowercase hex digits: b=$upper" \
    "a=$h2" "b=$upper"
  scase upper-case-name 2 "panels-differ: not a name and a SHA-256 of 64 lowercase hex digits: A=$h1" \
    "A=$h1" "b=$h2"
  scase empty-name 2 "panels-differ: not a name and a SHA-256 of 64 lowercase hex digits: =$h1" \
    "=$h1" "b=$h2"
  scase no-equals 2 "panels-differ: not a name and a SHA-256 of 64 lowercase hex digits: $h1" \
    "$h1" "b=$h2"
  echo "panels-differ.sh --selftest: $pass passed, $fail failed"
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

[ $# -eq 1 ] && [ "$1" = --selftest ] && selftest
[ $# -ge 2 ] || usage
seen=
shared=0
for pair in "$@"; do
  name=${pair%%=*}
  sha=${pair#*=}
  case $pair in
    *=*) ;;
    *) sha= ;;
  esac
  case $name in
    '' | *[!a-z0-9-]*) sha= ;;
  esac
  case $sha in
    *[!0-9a-f]*) sha= ;;
  esac
  if [ "${#sha}" -ne 64 ]; then
    printf 'panels-differ: not a name and a SHA-256 of 64 lowercase hex digits: %s\n' "$pair" >&2
    exit 2
  fi
  for prev in $seen; do
    if [ "${prev%%=*}" = "$name" ]; then
      printf 'panels-differ: %s is given twice\n' "$name" >&2
      exit 2
    fi
    if [ "${prev#*=}" = "$sha" ]; then
      printf 'FAIL: pi-image panels differ: %s and %s have the same keepcrypt-pi SHA-256, so a panel name did not reach the compiler: %s\n' \
        "${prev%%=*}" "$name" "$sha"
      shared=$((shared + 1))
    fi
  done
  seen="$seen $name=$sha"
  printf '%s: %s\n' "$name" "$sha"
done
if [ "$shared" -ne 0 ]; then
  echo "pi-image panels differ: $shared pair(s) of panels share a keepcrypt-pi SHA-256"
  exit 1
fi
echo "pi-image panels differ: $# panels, $# different keepcrypt-pi SHA-256s"
exit 0
