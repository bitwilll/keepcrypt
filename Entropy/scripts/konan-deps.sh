#!/bin/sh
# Fetches the three Kotlin/Native toolchain archives the iPhone build needs on a macOS arm64 host
# (tasks/todo.md, M5 re-plan for Compose Multiplatform, "Kotlin/Native toolchain archives"; Q68)
# from download.jetbrains.com, and refuses each unless its detached signature verifies with the
# Kotlin Release key and no other, and, from commit 8r on, its SHA-256 equals the pin below.
# Kotlin/Native's own fetcher (konan's DependencyProcessor, which the Kotlin Gradle plugin runs)
# checks no hash and no signature, but it extracts an archive it finds in its cache directory
# without downloading anything. So this script puts the checked archives there, in
# mobile/android/.konan/cache/ (Kotlin/Native's data directory, lead decision M5-28), and CI then
# blocks the download hosts for the build, so the fetcher can fetch nothing itself.
#
#   llvm-21-aarch64-macos-essentials-97.tar.gz  the LLVM code generator: every machine instruction
#                                               of the iPhone app's Kotlin code comes out of it
#   lldb-4-macos.tar.gz                         the debugger
#   libffi-3.3-1-macos-arm64.tar.gz             a small helper library
#
# The key is the Kotlin Release key, whose fingerprint kotlinlang.org publishes (primary
# 2FBA29D08D2E25EE84C132C30729A0AFF8999A87; the archives are signed by its subkey
# 6F538074CCEBF35F28AF9B066A0975F8B1127B83, valid to 2027-04-11). It is read from the committed
# keyring mobile/android/gradle/verification-keyring.keys (lead decision M5-12), where the
# dependency review uses it for the Kotlin artifacts, and imported alone into a fresh gpg home: the
# import must yield exactly that primary key with that subkey. A signature by any other key, a bad
# one, one by an expired or revoked key, one over a text document, and a failed gpg each fail.
#
# The published .sha256 files are never read: libffi's lists lldb's digest (a JetBrains error,
# seen on 2026-10-20). The SHA-256 pins come from signature-checked files instead, as follows.
#
# Usage: scripts/konan-deps.sh --bootstrap   commit 8q's mode: each archive and its .asc are
#            fetched and the signature checked; only then is the archive's SHA-256 computed and
#            printed ("konan-deps: sha256 NAME HEX"). Commit 8r pins the printed values.
#        scripts/konan-deps.sh               from commit 8r: the same, and each SHA-256 must equal
#            its pin; while a pin is "-" (not pinned yet) this mode refuses.
# Either way the three archives are placed in the cache only when all three have passed. The
# script refuses to run while mobile/android/.konan/ holds an extracted tree or a cached file, so
# nothing restored or left behind is trusted (CI starts every run without .konan/; locally, remove
# it first). Run from any directory. Needs curl, gpg, and sha256sum or shasum. Exit: 0 the three
# archives checked and placed; 1 an archive failed its signature or its pin (nothing placed); 2
# usage, a missing tool or key, a fetch that failed, a pin still missing, or a .konan/ in use.
set -u

base=https://download.jetbrains.com/kotlin/native
primary=2FBA29D08D2E25EE84C132C30729A0AFF8999A87
subkey=6F538074CCEBF35F28AF9B066A0975F8B1127B83
# NAME DIRECTORY SHA256, one archive a line: DIRECTORY is its path under $base ("." for none), and
# SHA256 is "-" until commit 8r pins the value the bootstrap run printed.
archives='llvm-21-aarch64-macos-essentials-97.tar.gz resources/llvm/21-aarch64-macos -
lldb-4-macos.tar.gz . -
libffi-3.3-1-macos-arm64.tar.gz . -'

fail() {
    echo "konan-deps: $1" >&2
    exit 2
}

case $# in
    0) bootstrap=no ;;
    1) [ "$1" = --bootstrap ] || fail "usage: scripts/konan-deps.sh [--bootstrap]"; bootstrap=yes ;;
    *) fail "usage: scripts/konan-deps.sh [--bootstrap]" ;;
esac

here=$(cd "$(dirname "$0")" && pwd) || fail "cannot find the script's directory"
project=$here/../mobile/android
keyring=$project/gradle/verification-keyring.keys
data=$project/.konan
[ -f "$keyring" ] || fail "no $keyring"
for t in curl gpg; do
    command -v "$t" >/dev/null 2>&1 || fail "$t is not on PATH"
done
for d in "$data/dependencies" "$data/cache"; do
    if [ -d "$d" ] && [ -n "$(ls -A "$d")" ]; then
        fail "$d is not empty: an extracted tree or cached file is never trusted (remove $data first)"
    fi
done
if [ "$bootstrap" = no ]; then
    unpinned=$(printf '%s\n' "$archives" | awk '$3 == "-" { print $1 }')
    [ -z "$unpinned" ] || fail "no SHA-256 pinned yet for: $(echo $unpinned) (the pins land at commit 8r; run --bootstrap)"
fi

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

work=$(mktemp -d "${TMPDIR:-/tmp}/kc-konan.XXXXXX") || fail "cannot make a temporary directory"
gh=$work/gnupg
cleanup() {
    if command -v gpgconf >/dev/null 2>&1; then
        gpgconf --homedir "$gh" --kill all >/dev/null 2>&1
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

# gpg in a home of its own, with empty configuration files (no keyboxd, no key server), holding
# only the Kotlin Release key: its armored block from the keyring, after its "pub <fingerprint>" line.
mkdir "$gh" && chmod 700 "$gh" && : >"$gh/common.conf" && : >"$gh/gpg.conf" || fail "cannot make $gh"
awk -v fpr="$primary" '
    $1 == "pub" && $2 == fpr { want = 1; next }
    want && $0 == "-----BEGIN PGP PUBLIC KEY BLOCK-----" { block = 1 }
    block { print }
    block && $0 == "-----END PGP PUBLIC KEY BLOCK-----" { exit }
' "$keyring" >"$work/kotlin-release.asc" || fail "cannot read $keyring"
grep -q -e '^-----END PGP PUBLIC KEY BLOCK-----$' "$work/kotlin-release.asc" ||
    fail "$keyring holds no armored key after a pub $primary line"
gpg() {
    command gpg --homedir "$gh" --batch --no-tty --no-auto-key-retrieve "$@"
}
gpg --quiet --import "$work/kotlin-release.asc" 2>"$work/gpg.err" || {
    cat "$work/gpg.err" >&2
    fail "gpg cannot import the Kotlin Release key"
}
keys=$(gpg --with-colons --fixed-list-mode --list-keys | awk -F: '
    $1 == "pub" { kind = "pub"; next }
    $1 == "sub" { kind = "sub"; next }
    $1 == "fpr" && kind != "" { print kind, $10; kind = "" }
') || fail "gpg cannot list its keys"
[ "$(printf '%s\n' "$keys" | grep -c -e '^pub ')" -eq 1 ] && printf '%s\n' "$keys" | grep -q -x -e "pub $primary" ||
    fail "the import did not yield exactly the key $primary: $(echo $keys)"
printf '%s\n' "$keys" | grep -q -x -e "sub $subkey" || fail "the key $primary has no subkey $subkey"
echo "konan-deps: $(gpg --version | sed -n 1p); the one key: $primary, with the signing subkey $subkey"

# Fetch and check each archive into $work; nothing reaches the cache until all three pass.
bad=0
printf '%s\n' "$archives" >"$work/list"
while read -r name dir pin; do
    case $dir in
        .) url=$base/$name ;;
        *) url=$base/$dir/$name ;;
    esac
    for f in "$name" "$name.asc"; do
        # https only, redirects included (download.jetbrains.com redirects to its CDN host).
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --output "$work/$f" "${url%"$name"}$f" </dev/null || fail "cannot download ${url%"$name"}$f"
    done
    status=$(gpg --trust-model always --status-fd 1 --verify "$work/$name.asc" "$work/$name" </dev/null 2>"$work/gpg.err")
    rc=$?
    # A good signature: gpg's exit 0, one GOODSIG, and exactly one VALIDSIG, made by the subkey of
    # the primary key, over a binary document (class 00); a bad signature, an error, a missing key
    # and a signature by an expired or revoked key fail it. (KEYEXPIRED alone is not a refusal: gpg
    # prints it for any expired subkey of the key it considers, not only for the signing one.)
    verdict=$(printf '%s\n' "$status" | awk -v sub_fpr="$subkey" -v pri="$primary" '
        $1 != "[GNUPG:]" { next }
        $2 == "GOODSIG" { good++ }
        $2 == "VALIDSIG" { valid++; if (NF >= 12 && $3 == sub_fpr && $11 == "00" && $NF == pri) ok++; when = $4 }
        $2 ~ /^(BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY)$/ { refused = refused " " $2 }
        END {
            if (good == 1 && valid == 1 && ok == 1 && refused == "") print "ok " when
            else print "no" refused
        }')
    case $rc:$verdict in
        "0:ok "*)
            echo "konan-deps: $name: signature good, by $subkey of $primary, made ${verdict#ok }"
            ;;
        *)
            echo "konan-deps: FAIL $name: no good signature by $subkey of $primary (gpg exit $rc, ${verdict#no}):" >&2
            sed 's/^/    /' "$work/gpg.err" >&2
            printf '%s\n' "$status" | sed 's/^/    /' >&2
            bad=1
            continue
            ;;
    esac
    got=$(sha256_of "$work/$name") || fail "no sha256sum or shasum to hash $name"
    if [ "$bootstrap" = yes ]; then
        echo "konan-deps: sha256 $name $got"
    elif [ "$got" = "$pin" ]; then
        echo "konan-deps: $name: SHA-256 $got (pinned)"
    else
        echo "konan-deps: FAIL $name: SHA-256 $got, not the pinned $pin" >&2
        bad=1
    fi
done <"$work/list"
[ "$bad" -eq 0 ] || {
    echo "konan-deps: nothing placed in $data/cache" >&2
    exit 1
}

mkdir -p "$data/cache" || fail "cannot make $data/cache"
while read -r name dir pin; do
    mv "$work/$name" "$data/cache/$name" || fail "cannot move $name to $data/cache"
done <"$work/list"
echo "konan-deps: the three archives are in $data/cache, signature-checked$([ "$bootstrap" = yes ] && echo ' (--bootstrap: not pinned yet)' || echo ' and pinned')"
