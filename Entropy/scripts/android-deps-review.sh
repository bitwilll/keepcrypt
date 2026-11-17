#!/bin/sh
# Fetches what scripts/android-deps-review.py reviews, then runs the review (tasks/todo.md, M5 group 4;
# Q54). The Python script never opens a connection (the gate's Network rule refuses a network module in
# any .py file outside registry/): it prints the URLs it still needs, "URL<TAB>PATH", and this script
# fetches them with curl into MIRROR/PATH, an empty PATH.404 for a 404, round after round until the
# list is empty (a parent POM or a signer's key is named only by a file fetched in the round before).
# The URLs are the published .sha256, .sha1 and .asc files and, for Maven Central artifacts not found
# in GRADLE_FILES, the artifacts' bytes, from Google's Maven and Maven Central; with --write-keys also
# the signers' keys, from keyserver.ubuntu.com or keys.openpgp.org. https only, redirects included.
#
# Usage: scripts/android-deps-review.sh MIRROR [GRADLE_FILES] [-- REVIEW-OPTION...]
#        scripts/android-deps-review.sh --write-keys MIRROR
# MIRROR: a directory outside the repo for the fetched files (kept between runs: a file already there
# is not fetched again, and every file is checked again on every review). GRADLE_FILES: Gradle's
# files-2.1 cache, whose copies are used when their SHA-256 is the metadata's. REVIEW-OPTION:
# passed to the review (--skip-pgp, only where gpg cannot run).
# Needs curl and python3 (3.9+). Exit: the review's status (0 pass, 1 a check failed, 3 passed
# without signatures); 2 when a file cannot be fetched (any status but 200 or 404) or usage.
set -u

fail() {
    echo "android-deps-review: $1" >&2
    exit 2
}

here=$(cd "$(dirname "$0")" && pwd) || fail "cannot find the script's directory"
mode=review
if [ "${1:-}" = --write-keys ]; then
    mode=write-keys
    shift
fi
[ $# -ge 1 ] || fail "usage: android-deps-review.sh [--write-keys] MIRROR [GRADLE_FILES] [-- REVIEW-OPTION...]"
mirror=$1
shift
gradle=
if [ $# -ge 1 ] && [ "$1" != -- ]; then
    gradle=$1
    shift
fi
[ "${1:-}" = -- ] && shift
case $mirror in
    /*) ;;
    *) fail "MIRROR must be an absolute path: $mirror" ;;
esac
mkdir -p "$mirror" || fail "cannot create $mirror"

py() {
    python3 -I "$here/android-deps-review.py" "$@"
}

# urls: this round's list. With --write-keys the signers' keys are wanted too.
urls() {
    if [ "$mode" = write-keys ]; then
        py urls "$mirror" --keys
    elif [ -n "$gradle" ]; then
        py urls "$mirror" --gradle-files "$gradle"
    else
        py urls "$mirror"
    fi
}

work=$(mktemp -d "${TMPDIR:-/tmp}/kc-deps-fetch.XXXXXX") || fail "cannot make a temporary directory"
trap 'rm -rf "$work"' EXIT
trap 'exit 2' HUP INT TERM
tab=$(printf '\t')
round=0
while :; do
    urls >"$work/list" || fail "the urls list failed (above)"
    [ -s "$work/list" ] || break
    round=$((round + 1))
    [ "$round" -le 12 ] || fail "still files to fetch after 12 rounds"
    echo "android-deps-review: round $round: $(wc -l <"$work/list" | tr -d ' ') file(s) to fetch"
    # One curl, many transfers: a config file of url and output pairs (the Python script allows only
    # [A-Za-z0-9._+-/] in a path, and an https URL with no quote or backslash), each to PATH.part.
    : >"$work/curl.cfg"
    while IFS="$tab" read -r url path; do
        case $url$path in *'"'* | *'\'*) fail "a quote or backslash in $url" ;; esac
        printf 'url = "%s"\noutput = "%s/%s.part"\n' "$url" "$mirror" "$path" >>"$work/curl.cfg"
    done <"$work/list"
    curl --parallel --parallel-max 16 --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --create-dirs --connect-timeout 30 --max-time 600 \
        --write-out '%{http_code} %{filename_effective}\n' --config "$work/curl.cfg" >"$work/codes"
    # curl's own status is non-zero on a failed transfer; each transfer's code is judged below.
    while read -r code part; do
        file=${part%.part}
        case $code in
            200) mv "$part" "$file" || fail "cannot move $part" ;;
            404) rm -f "$part" && : >"$file.404" || fail "cannot mark $file as 404" ;;
            *) fail "HTTP $code for $file" ;;
        esac
    done <"$work/codes"
    [ "$(wc -l <"$work/codes")" -eq "$(wc -l <"$work/list")" ] || fail "curl reported fewer transfers than asked"
done
if [ "$mode" = write-keys ]; then
    py write-keys "$mirror"
elif [ -n "$gradle" ]; then
    py review "$mirror" --gradle-files "$gradle" "$@"
else
    py review "$mirror" "$@"
fi
