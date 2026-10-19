#!/bin/sh
# Gate canaries: inputs that must FAIL their gate, for the intended reason, on every run.
# A canary that passes means the gate stopped firing (principle 7: test the path, not the presence).
# Run from the repo root. Exit 0 only if every canary failed as intended, every static check and
# control passed, and the number of checks run equals the pin at the end.
# Needs cargo-deny, git, and python3 3.11 or later (tomllib, for the static checks; CI runs 3.12),
# a C compiler for the host (the release probe builds secp256k1-sys), the pinned toolchain's
# llvm-tools-preview (the artifact scan's llvm-nm), and GNU make (the image path's panel name).
# Needs the network only to fetch locked crates (deny-banned, clippy, agreement-core, cargo
# fetch); the steps that add a crate or a git source resolve and check offline.
set -u

if [ ! -f deny.toml ] || [ ! -f core/clippy.toml ] || [ ! -d scripts/testdata ]; then
    echo "FAIL: run from the repo root" >&2
    exit 1
fi
if ! python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
    echo "FAIL: scripts/canaries.sh needs python3 3.11 or later (tomllib)" >&2
    exit 1
fi
root=$(pwd)
status=0
# Checks run: every verdict, static check and identity check below counts one, pass or fail.
checks=0
# Only the canaries below choose a clippy.toml.
unset CLIPPY_CONF_DIR
# The git-source canary makes its own repo; an outer one named by the environment (as in a git
# hook) must not be the one it initialises and commits to.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_COMMON_DIR GIT_NAMESPACE
work=
trap 'if [ -n "$work" ]; then rm -rf "$work"; fi' EXIT
trap 'exit 1' HUP INT TERM
work=$(mktemp -d "${TMPDIR:-/tmp}/kc-canary.XXXXXX") || exit 1

# expect_failure NAME CMD...: CMD must exit non-zero. Its output stays in $out for need/never,
# and verdict prints the result.
expect_failure() {
    name=$1
    shift
    ok=1
    if out=$("$@" 2>&1); then
        echo "FAIL: $name passed; its gate did not fire"
        ok=0
    fi
}
# need TEXT: the output must contain TEXT (a fixed string), or the canary failed for another reason.
need() {
    if ! printf '%s\n' "$out" | grep -F -q -- "$1"; then
        echo "FAIL: $name: missing from the output: $1"
        ok=0
    fi
}
# never TEXT: the output must not contain TEXT.
never() {
    if printf '%s\n' "$out" | grep -F -q -- "$1"; then
        echo "FAIL: $name: found in the output: $1"
        ok=0
    fi
}
verdict() {
    checks=$((checks + 1))
    if [ "$ok" = 1 ]; then
        echo "PASS: $name failed as intended"
    else
        printf '%s\n' "$out" | tail -n 30
        status=1
    fi
}
# static_check NAME CMD...: a check of the gate's own configuration. CMD prints each problem and
# exits non-zero when there is one.
static_check() {
    name=$1
    shift
    checks=$((checks + 1))
    if out=$("$@" 2>&1); then
        echo "PASS: $name"
    else
        printf '%s\n' "$out" | tail -n 30
        echo "FAIL: $name"
        status=1
    fi
}

# deny.toml: one crate whose graph needs every property of the policy to hold.
expect_failure "deny-banned" cargo deny --color never \
    --manifest-path "$root/scripts/testdata/deny-banned/Cargo.toml" \
    --config "$root/deny.toml" --locked check bans
need "error[banned]: crate 'rand = 0.8.5' is explicitly banned"       # rand family, normal dep
need "error[banned]: crate 'tokio = 1.53.1' is explicitly banned"     # network, no features
need "error[banned]: crate 'log = 0.4.34' is explicitly banned"       # logging
need "error[banned]: crate 'fastrand = 2.5.0' is explicitly banned"   # dev-dependencies checked
need "error[banned]: crate 'oorandom = 11.1.5' is explicitly banned"  # no [graph] targets filter
need "error[banned]: crate 'nanorand = 0.8.0' is explicitly banned"   # all-features = true
verdict

# core/clippy.toml: every entry must fire. A path that resolves to nothing only warns, even
# with -D warnings, so a typo would silently ban nothing.
clippy_paths=$(sed -n 's/^.*{ *path *= *"\([^"]*\)".*$/\1/p' core/clippy.toml)
canary_paths=$(sed -n 's|^.*// bans: *\([^ ]*\) *$|\1|p' scripts/testdata/clippy-fallback/src/lib.rs)
expect_failure "clippy-fallback" env CLIPPY_CONF_DIR="$root/core" cargo clippy --color never \
    --manifest-path "$root/scripts/testdata/clippy-fallback/Cargo.toml" \
    --target-dir "$root/target/canaries" --locked -- -D warnings
if [ -z "$clippy_paths" ] || [ -z "$canary_paths" ]; then
    echo "FAIL: clippy-fallback: no paths read from core/clippy.toml or the canary's // bans: comments"
    ok=0
fi
# Every configured path fires, and every method the canary calls is still banned.
for p in $clippy_paths $canary_paths; do
    need "use of a disallowed method \`$p\`"
done
never "does not refer to a reachable function"
verdict

# The real crates: a fallback added to each one's lib.rs must fail clippy as CI runs it. This
# catches the lint being switched off in that crate (Cargo.toml [lints], a crate-level allow),
# which the standalone canary above cannot see. The copy leaves out target/ and .git/.
tmp="$work/repo"
mkdir "$tmp" || exit 1
for f in "$root"/* "$root"/.[!.]* "$root"/..?*; do
    [ -e "$f" ] || continue
    case ${f##*/} in
        target | .git) continue ;;
    esac
    cp -RP "$f" "$tmp/" || exit 1
done
for lib in core/src/lib.rs ffi/src/lib.rs pi/app/src/lib.rs; do
    case $lib in
        core/*) pkg=keepcrypt-core ;;
        ffi/*) pkg=keepcrypt-ffi ;;
        pi/app/*) pkg=keepcrypt-pi ;;
    esac
    cp "$root/$lib" "$tmp/$lib" || exit 1
    cat >> "$tmp/$lib" <<'EOF'

/// Gate canary (scripts/canaries.sh, temp copy only): a silent default on a parse failure.
pub fn kc_gate_canary(digits: &str) -> u8 {
    digits.parse::<u8>().unwrap_or(0)
}
EOF
    expect_failure "real-$pkg" cargo clippy --color never --manifest-path "$tmp/Cargo.toml" \
        -p "$pkg" --lib --locked --target-dir "$root/target/canary-real" -- -D warnings
    need "use of a disallowed method \`core::result::Result::unwrap_or\`"
    need "--> $lib:"
    need "#disallowed_methods"
    # Still forbid, so no #[allow] or #[expect] can make an exception.
    need "-F clippy::disallowed-methods"
    verdict
    cp "$root/$lib" "$tmp/$lib" || exit 1
done

# The other lint settings, one snippet at a time on each real crate: every snippet below must
# fail clippy in keepcrypt-core, keepcrypt-ffi and keepcrypt-pi alike, with its own lint and
# nothing else. Running it in each crate catches a crate-level #![expect(..)] of that lint in
# any one of them, which the static check of the Cargo.toml tables cannot see. The rule 3 and
# rule 5 lints (let_underscore_must_use, print_stdout, print_stderr, dbg_macro) are forbid, so
# no #[expect] anywhere, src/main.rs included, can excuse them (E0453); allow_attributes and
# allow_attributes_without_reason stay deny. Only lib targets are run.
# real_lint NAME TEXT...: appends stdin to each crate's lib.rs in the copy in turn, runs clippy on
# that crate as CI does, and restores the file. The output must contain every TEXT, point at
# that lib.rs and report exactly one error.
real_lint() {
    lint=$1
    shift
    cat > "$work/snippet.rs" || exit 1
    for lib in core/src/lib.rs ffi/src/lib.rs pi/app/src/lib.rs; do
        case $lib in
            core/*) pkg=keepcrypt-core ;;
            ffi/*) pkg=keepcrypt-ffi ;;
            pi/app/*) pkg=keepcrypt-pi ;;
        esac
        cat "$root/$lib" "$work/snippet.rs" > "$tmp/$lib" || exit 1
        expect_failure "real-$pkg-$lint" cargo clippy --color never \
            --manifest-path "$tmp/Cargo.toml" -p "$pkg" --lib --locked \
            --target-dir "$root/target/canary-real" -- -D warnings
        cp "$root/$lib" "$tmp/$lib" || exit 1
        for text in "$@"; do
            need "$text"
        done
        need "--> $lib:"
        need "could not compile \`$pkg\` (lib) due to 1 previous error"
        verdict
    done
}

real_lint let-underscore \
    "non-binding \`let\` on an expression with \`#[must_use]\` type" \
    "#let_underscore_must_use" <<'EOF'

/// Gate canary (scripts/canaries.sh, temp copy only): `let _ =` drops the error (rule 3).
pub fn kc_gate_canary() {
    let _ = "1".parse::<u8>();
}
EOF

# A bare statement drops the error too; rustc's unused_must_use, still forbid, catches it.
real_lint must-use \
    "unused \`std::result::Result\` that must be used" \
    "-F unused-must-use" <<'EOF'

/// Gate canary (scripts/canaries.sh, temp copy only): a bare statement drops the error (rule 3).
pub fn kc_gate_canary() {
    "1".parse::<u8>();
}
EOF

real_lint print-stderr "use of \`eprintln!\`" "#print_stderr" <<'EOF'

/// Gate canary (scripts/canaries.sh, temp copy only): printing (rule 5).
pub fn kc_gate_canary() {
    eprintln!("x");
}
EOF

real_lint print-stdout "use of \`println!\`" "#print_stdout" <<'EOF'

/// Gate canary (scripts/canaries.sh, temp copy only): printing (rule 5).
pub fn kc_gate_canary() {
    println!("x");
}
EOF

real_lint dbg-macro "the \`dbg!\` macro is intended as a debugging tool" "#dbg_macro" <<'EOF'

/// Gate canary (scripts/canaries.sh, temp copy only): dbg! prints its argument (rule 5).
pub fn kc_gate_canary() -> u8 {
    dbg!(1u8)
}
EOF

# With a reason, so that only allow_attributes can object: any #[allow] is refused.
real_lint allow-attributes "#[allow] attribute found" "\`-D clippy::allow-attributes\`" <<'EOF'

/// Gate canary (scripts/canaries.sh, temp copy only): a lint exception by #[allow].
#[allow(dead_code, reason = "gate canary")]
fn kc_gate_canary() {}
EOF

real_lint expect-without-reason \
    "\`expect\` attribute without specifying a reason" \
    "#allow_attributes_without_reason" <<'EOF'

/// Gate canary (scripts/canaries.sh, temp copy only): a lint exception with no reason.
#[expect(dead_code)]
fn kc_gate_canary() {}
EOF

# Verifier agreement, core's side (tasks/todo.md, M2 groups 6 and 8): one value core must compare,
# changed in the copy's vectors/agreement.json, must fail core's agreement test, naming that case
# and that field, while the other 8 tests pass. The value is the first hex digit of the first
# "seal_tag_hex" from the middle of the file on: a case's expected seal tag, which core computes
# itself. (The tamper loop's helper below would change a rolls string there, which core refuses as
# InvalidRoll before it compares any value.) The test finds the file through
# env!("CARGO_MANIFEST_DIR"), fixed when it is compiled, and cargo takes a binary built for
# another tree as fresh when the copy's files are older than it (a copy that keeps mtimes, such as
# rsync -a or git archive), so a shared binary would read the other tree's agreement.json. So the
# test builds in its own target directory, and the copy's test file is touched first, so its
# binary is rebuilt for this copy on every run. The copy's file is restored afterwards.
change_tag='
import re, sys
path = sys.argv[1]
data = open(path, "rb").read()
found = re.compile(rb"\"seal_tag_hex\": \"[0-9a-f]").search(data, len(data) // 2)
if found is None:
    sys.exit("%s: no seal_tag_hex from the middle on" % path)
name = re.compile(rb"\"name\": \"([^\"]+)\"").search(data, data.rfind(b"\n", 0, found.start()) + 1, found.start())
if name is None:
    sys.exit("%s: no case name before that seal_tag_hex" % path)
at = found.end() - 1
data = data[:at] + (b"1" if data[at:at + 1] == b"0" else b"0") + data[at + 1:]
open(path, "wb").write(data)
print(name.group(1).decode("ascii"))
'
name=agreement-core
if ! tag_case=$(python3 -I -c "$change_tag" "$tmp/vectors/agreement.json"); then
    echo "FAIL: $name: could not change a seal_tag_hex"
    status=1
else
    touch "$tmp/core/tests/agreement.rs" || exit 1
    expect_failure "$name" cargo test --color never --manifest-path "$tmp/Cargo.toml" \
        -p keepcrypt-core --locked --features test-sources --test agreement \
        --target-dir "$root/target/canary-agreement"
    need "$tag_case: seal_tag_hex"
    need "test result: FAILED. 8 passed; 1 failed;"
    verdict
    cp "$root/vectors/agreement.json" "$tmp/vectors/agreement.json" || exit 1
fi

# deny.toml on the real workspace: rand added to the real core must fail `cargo deny check bans`.
# This catches an exemption scoped to keepcrypt-core, such as wrappers = ["keepcrypt-core"] or
# a [graph] exclude of it, which the standalone deny-banned canary cannot see. rand goes into
# core only, so a [graph] exclude of another member (keepcrypt-ffi, say) is left to the static
# deny.toml check at the end, which refuses any exclude, targets, exclude-dev or
# exclude-unpublished in [graph]. The version is the one the deny-banned canary has just
# fetched, so the lockfile update and the check run offline.
# cargo fetch first downloads the committed lockfile's crates for every target (clippy above
# fetched the host's only, and the check reads every manifest, such as getrandom's r-efi).
# rand_version is read from deny-banned/Cargo.lock; an empty result fails below.
rand_version=$(python3 -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    found = [p["version"] for p in tomllib.load(f).get("package", []) if p.get("name") == "rand"]
print(found[0] if len(found) == 1 else "")
' "$root/scripts/testdata/deny-banned/Cargo.lock")
name=real-deny-bans
if [ -z "$rand_version" ]; then
    echo "FAIL: $name: no single rand version in scripts/testdata/deny-banned/Cargo.lock"
    status=1
elif ! out=$(cargo fetch --locked --manifest-path "$tmp/Cargo.toml" 2>&1); then
    printf '%s\n' "$out" | tail -n 30
    echo "FAIL: $name: could not fetch the workspace's locked crates"
    status=1
else
    cat >> "$tmp/core/Cargo.toml" <<EOF

# Gate canary (scripts/canaries.sh, temp copy only): a banned crate in the real core.
[dependencies.rand]
version = "=$rand_version"
default-features = false
EOF
    if ! out=$(cargo update --offline --workspace --manifest-path "$tmp/Cargo.toml" 2>&1); then
        printf '%s\n' "$out" | tail -n 30
        echo "FAIL: $name: could not add rand $rand_version to the copy's Cargo.lock offline"
        status=1
    else
        expect_failure "$name" cargo deny --color never --manifest-path "$tmp/Cargo.toml" \
            --config "$tmp/deny.toml" --offline --locked check bans
        need "error[banned]: crate 'rand = $rand_version' is explicitly banned"
        need "bans FAILED"
        verdict
    fi
fi

# deny.toml [[bans.features]] on the real workspace (tasks/todo.md, M4 group 2): a nix feature
# beyond the list, asked for by another member, must fail `cargo deny check bans`, naming the
# feature. Cargo merges a dependency's features across the workspace, so the ban must hold
# whichever manifest asks. The feature is reboot: net would pull in memoffset, a crate Cargo.lock
# does not hold, which could not resolve offline; reboot adds only an edge to the locked nix
# (fetched for every target by real-deny-bans above).
name=deny-nix-feature
feat="$work/features"
mkdir "$feat" || exit 1
for f in "$root"/* "$root"/.[!.]* "$root"/..?*; do
    [ -e "$f" ] || continue
    case ${f##*/} in
        target | .git) continue ;;
    esac
    cp -RP "$f" "$feat/" || exit 1
done
cat >> "$feat/pi/sim/Cargo.toml" <<'EOF'

# Gate canary (scripts/canaries.sh, temp copy only): a nix feature beyond deny.toml's list.
[target.'cfg(target_os = "linux")'.dependencies.nix]
version = "=0.31.3"
default-features = false
features = ["reboot"]
EOF
if ! out=$(cargo update --offline --workspace --manifest-path "$feat/Cargo.toml" 2>&1); then
    printf '%s\n' "$out" | tail -n 30
    echo "FAIL: $name: could not add the nix edge to the copy's Cargo.lock offline"
    status=1
else
    expect_failure "$name" cargo deny --color never --manifest-path "$feat/Cargo.toml" \
        --config "$feat/deny.toml" --offline --locked check bans
    need "error[exact-features-mismatch]: feature set for crate 'nix = 0.31.3' did not match exactly"
    need "'reboot' feature was enabled but not explicitly allowed"
    need "nix feature 'reboot'"
    need "bans FAILED"
    never "error[banned]"
    verdict
fi

# A [patch] path override must fail scripts/check-path-deps.sh and be named, even though only a
# feature pulls the patched crate in (the check reads every feature).
expect_failure "path-override" sh "$root/scripts/check-path-deps.sh" \
    "$root/scripts/testdata/path-override/Cargo.toml"
need "check-path-deps: not from crates.io: getrandom 0.4.3 from local path"
never "workspace member"
verdict

# The workspace members are pinned in scripts/check-path-deps.sh (core, ffi, pi/app, pi/sim).
# A vendored crate as a plain path dependency becomes a member unseen; it must fail as a member
# outside the pinned four.
pinned_four="core, ffi, pi/app, pi/sim"
expect_failure "path-member" sh "$root/scripts/check-path-deps.sh" \
    "$root/scripts/testdata/path-member/Cargo.toml"
need "check-path-deps: workspace member not one of $pinned_four: getrandom 0.4.3 at "
need "scripts/testdata/path-member/vendor/getrandom/Cargo.toml"
never "not from crates.io"
never "pinned workspace member missing"
verdict

# ... and so must one listed openly in the root Cargo.toml's [workspace] members: the pin does
# not read that list.
expect_failure "path-member-listed" sh "$root/scripts/check-path-deps.sh" \
    "$root/scripts/testdata/path-member-listed/Cargo.toml"
need "check-path-deps: workspace member not one of $pinned_four: secrecy 0.10.3 at "
need "scripts/testdata/path-member-listed/vendor/secrecy/Cargo.toml"
never "not from crates.io"
never "pinned workspace member missing"
verdict

# Cargo config (here directory source replacement) must fail scripts/check-path-deps.sh, at
# the workspace root and further down, under either file name. The fixture is copied to a
# temp dir, because a committed .cargo/config.toml would fail the repo itself.
cfg="$work/source-replacement"
cp -R "$root/scripts/testdata/source-replacement" "$cfg" || exit 1
mkdir "$cfg/.cargo" "$cfg/core/src/.cargo" || exit 1
cp "$cfg/cargo-config.toml" "$cfg/.cargo/config.toml" || exit 1
cp "$cfg/cargo-config.toml" "$cfg/core/src/.cargo/config" || exit 1
expect_failure "cargo-config" sh "$root/scripts/check-path-deps.sh" "$cfg/Cargo.toml"
need "check-path-deps: cargo config file found: .cargo/config.toml"
need "check-path-deps: cargo config file found: core/src/.cargo/config"
never "not from crates.io"
never "workspace member"
verdict

# The same config one directory above the workspace root must fail too: cargo reads parent
# directories, so in the keepcrypt monorepo a config at the repo root applies to Entropy/.
up="$work/parent-config"
mkdir -p "$up/.cargo" || exit 1
cp -R "$root/scripts/testdata/source-replacement" "$up/ws" || exit 1
cp "$up/ws/cargo-config.toml" "$up/.cargo/config.toml" || exit 1
expect_failure "cargo-config-parent" sh "$root/scripts/check-path-deps.sh" "$up/ws/Cargo.toml"
need "check-path-deps: cargo config file found: "
need "parent-config/.cargo/config.toml"
never "not from crates.io"
never "workspace member"
verdict

# deny.toml [sources]: a git dependency must fail `cargo deny check sources` (unknown-git). The
# git repo is a throwaway made here and fetched over file://, so no network is needed. A temp
# CARGO_HOME keeps its checkout out of the real one; git reads neither the user's nor the
# system's config, so no signing or hooks run.
name=deny-git-source
gdep="$work/git-dep"
guser="$work/git-user"
mkdir -p "$gdep/src" "$guser/src" || exit 1
cat > "$gdep/Cargo.toml" <<'EOF'
[package]
name = "kc-canary-git-dep"
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
publish = false
EOF
: > "$gdep/src/lib.rs"
cat > "$guser/Cargo.toml" <<EOF
[package]
name = "canary-deny-git-source"
version = "0.0.0"
edition = "2024"
license = "MIT OR Apache-2.0"
publish = false

[workspace]

[dependencies]
kc-canary-git-dep = { git = "file://$gdep" }
EOF
: > "$guser/src/lib.rs"
if ! out=$(
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
    export GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL
    {
        git -c init.defaultBranch=main init -q "$gdep" &&
            git -C "$gdep" add -A &&
            git -C "$gdep" -c user.name=kc-canary -c user.email=kc-canary@example.invalid \
                -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -q -m canary &&
            CARGO_HOME="$work/cargo-home" cargo generate-lockfile --manifest-path "$guser/Cargo.toml"
    } 2>&1
); then
    printf '%s\n' "$out" | tail -n 30
    echo "FAIL: $name: could not set up the local git dependency"
    status=1
else
    expect_failure "$name" env CARGO_HOME="$work/cargo-home" cargo deny --color never \
        --manifest-path "$guser/Cargo.toml" --config "$root/deny.toml" --offline --locked \
        check sources
    need "error[source-not-allowed]: detected 'git' source not explicitly allowed"
    need "kc-canary-git-dep v0.1.0"
    verdict
fi

# core, the FFI and the Pi app get the same clippy rules.
for f in ffi/clippy.toml pi/app/clippy.toml; do
    checks=$((checks + 1))
    if cmp core/clippy.toml "$f"; then
        echo "PASS: core/clippy.toml and $f are identical"
    else
        echo "FAIL: core/clippy.toml and $f differ"
        status=1
    fi
done

# ... and pinned lint tables. Each crate's [lints.clippy] and [lints.rust] must be exactly the
# tables below: an extra key (a group such as all = { level = "allow", priority = 1 }, or
# unused = "allow"), a missing one or a changed level fails, named. A real change to a table is
# a reviewed change here too.
static_check "[lints.clippy] and [lints.rust] in core, ffi and pi/app exactly as pinned" \
    python3 -I -c '
import sys, tomllib
CLIPPY = {
    "disallowed_methods": "forbid",
    "let_underscore_must_use": "forbid",
    "allow_attributes": "deny",
    "allow_attributes_without_reason": "deny",
    "print_stdout": "forbid",
    "print_stderr": "forbid",
    "dbg_macro": "forbid",
}
RUST = {
    "core/Cargo.toml": {"unsafe_code": "forbid", "unused_must_use": "forbid"},
    "ffi/Cargo.toml": {"unused_must_use": "forbid"},
    "pi/app/Cargo.toml": {"unused_must_use": "forbid"},
}

def compare(where, got, want):
    if not isinstance(got, dict):
        return ["%s: missing or not a table" % where]
    bad = []
    for key in sorted(set(got) | set(want)):
        if key not in want:
            bad.append("%s: extra key %s = %r" % (where, key, got[key]))
        elif key not in got:
            bad.append("%s: missing key %s, needs %r" % (where, key, want[key]))
        elif got[key] != want[key]:
            bad.append("%s: %s is %r, needs %r" % (where, key, got[key], want[key]))
    return bad

bad = []
for path, rust in RUST.items():
    try:
        with open(path, "rb") as f:
            lints = tomllib.load(f).get("lints")
    except (OSError, tomllib.TOMLDecodeError) as err:
        bad.append("%s: %s" % (path, err))
        continue
    if not isinstance(lints, dict):
        bad.append("%s: no [lints] table" % path)
        continue
    bad += compare(path + " [lints.rust]", lints.get("rust"), rust)
    bad += compare(path + " [lints.clippy]", lints.get("clippy"), CLIPPY)
for line in bad:
    print(line)
sys.exit(1 if bad else 0)
'

# deny.toml, pinned the same way:
# - [graph] is exactly all-features = true: an exclude (of keepcrypt-ffi, say, which the
#   real-deny-bans canary would not see), targets, exclude-dev or exclude-unpublished fails;
# - [bans] deny is exactly the list below, all plain crate names (an inline table could carry
#   wrappers, a name@version bans only some versions), so removing any entry fails; skip,
#   skip-tree and exceptions are absent or empty;
# - [[bans.features]] is exactly the two entries below (tasks/todo.md, M4 group 2): rppal with
#   no features and nix with five, both exact, so a widened list or a dropped entry fails;
# - [sources] is exactly crates.io only, with unknown registries and git sources denied (so an
#   allow-org or private key fails too).
static_check "deny.toml [graph], [bans] deny, [[bans.features]] and [sources] exactly as pinned" python3 -I -c '
import sys, tomllib
GRAPH = {"all-features": True}
DENY = [
    "rand", "rand_core", "rand_chacha", "rand_xoshiro", "rand_xorshift", "rand_pcg", "rand_hc",
    "rand_isaac", "fastrand", "oorandom", "nanorand", "tinyrand", "turborand",
    "tokio", "mio", "hyper", "h2", "reqwest", "ureq", "curl", "isahc", "axum", "async-std",
    "log", "tracing", "slog", "env_logger",
]
FEATURES = [
    {"crate": "rppal", "exact": True, "allow": []},
    {"crate": "nix", "exact": True, "allow": ["fs", "mman", "mount", "time", "uio"]},
]
SOURCES = {
    "unknown-registry": "deny",
    "unknown-git": "deny",
    "allow-registry": ["https://github.com/rust-lang/crates.io-index"],
    "allow-git": [],
}

def compare(where, got, want):
    if not isinstance(got, dict):
        return ["%s: missing or not a table" % where]
    bad = []
    for key in sorted(set(got) | set(want)):
        if key not in want:
            bad.append("%s: extra key %s = %r" % (where, key, got[key]))
        elif key not in got:
            bad.append("%s: missing key %s, needs %r" % (where, key, want[key]))
        elif got[key] != want[key]:
            bad.append("%s: %s is %r, needs %r" % (where, key, got[key], want[key]))
    return bad

try:
    with open(sys.argv[1], "rb") as f:
        cfg = tomllib.load(f)
except (OSError, tomllib.TOMLDecodeError) as err:
    print("%s: %s" % (sys.argv[1], err))
    sys.exit(1)
bad = compare("[graph]", cfg.get("graph"), GRAPH)
bans = cfg.get("bans")
if not isinstance(bans, dict):
    bad.append("[bans]: missing or not a table")
    bans = {}
deny = bans.get("deny")
if not isinstance(deny, list):
    bad.append("[bans] deny: missing or not a list")
elif deny != DENY:
    names = [entry for entry in deny if isinstance(entry, str)]
    wrong = ["[bans] deny: entry is not a plain crate name: %r" % (entry,)
             for entry in deny if not isinstance(entry, str)]
    wrong += ["[bans] deny: missing %s" % n for n in DENY if n not in names]
    wrong += ["[bans] deny: extra %r" % n for n in names if n not in DENY]
    wrong += ["[bans] deny: %s listed %d times" % (n, names.count(n))
              for n in sorted(set(names)) if names.count(n) > 1]
    bad += wrong or ["[bans] deny: the pinned names in another order; keep the pinned order"]
for key in ("skip", "skip-tree", "exceptions"):
    if key in bans and bans[key] != []:
        bad.append("[bans] %s is not empty: %r" % (key, bans[key]))
if bans.get("features") != FEATURES:
    bad.append("[[bans.features]] is %r, needs %r" % (bans.get("features"), FEATURES))
bad += compare("[sources]", cfg.get("sources"), SOURCES)
for line in bad:
    print(line)
sys.exit(1 if bad else 0)
' deny.toml

# The test features and the build profiles (CLAUDE.md rules 3 and 10; tasks/todo.md, M1 Q3 and
# Q11). Cargo merges features across every package in one build, so one dependency entry on
# keepcrypt-core with a test feature, in any workspace member and any table (a dev-dependency
# included), compiles the stubs or the test registry key into every binary that a --workspace
# build links, release builds included, and plain `cargo test --workspace` stops testing the
# release configuration. So no manifest turns either feature on; they are switched on only from
# the command line, one package at a time. Checked on the root manifest and every member's:
# - core's [features] is exactly the table below: neither test feature is a default, and
#   test-sources turns on test-registry, never the reverse;
# - no `features` list anywhere else (normal, dev, build or target-specific dependencies,
#   [workspace.dependencies], [patch]) and no other member's [features] entry names either one,
#   plain or as `dep/feature` or `dep?/feature`;
# - the root [profile] tables are exactly the ones below. Release must unwind, so a panic drops
#   and wipes the session (abort skips that wipe, and cargo test always unwinds, so no test would
#   notice a switch); core keeps overflow checks in release.
# - the Pi hardware crates, rppal and nix, are named only in pi/app/Cargo.toml's Linux
#   dependencies, with exactly the specs below (tasks/todo.md, M4 group 2; Q36 (a), (e)), so
#   neither the simulator nor core nor the FFI can take them on; deny.toml's [[bans.features]]
#   pins the features they resolve with, whichever manifest asks.
# A real change to any of these pins is a reviewed change here too.
manifest_pins='
import sys, tomllib
from pathlib import Path

TEST_FEATURES = ("test-sources", "test-registry")
CORE_FEATURES = {"default": [], "test-registry": [], "test-sources": ["test-registry"]}
PROFILE = {
    "release": {"panic": "unwind", "package": {"keepcrypt-core": {"overflow-checks": True}}},
    "dev": {"package": {"*": {"opt-level": 3}}},
}
HARDWARE_AT = ("pi/app/Cargo.toml", ["target", "cfg(target_os = \"linux\")", "dependencies"])
HARDWARE = {
    "rppal": {"version": "=0.22.1", "default-features": False},
    "nix": {"version": "=0.31.3", "default-features": False, "features": ["fs", "mman", "mount", "time"]},
}

def turns_on(value):
    return isinstance(value, str) and any(value == f or value.endswith("/" + f) for f in TEST_FEATURES)

def compare(where, got, want):
    if isinstance(want, dict):
        if not isinstance(got, dict):
            return ["%s is %r, needs a table" % (where, got)]
        bad = []
        for key in sorted(set(got) | set(want)):
            if key not in want:
                bad.append("%s: extra key %s = %r" % (where, key, got[key]))
            elif key not in got:
                bad.append("%s: missing key %s, needs %r" % (where, key, want[key]))
            else:
                bad += compare("%s.%s" % (where, key), got[key], want[key])
        return bad
    if type(got) is not type(want) or got != want:
        return ["%s is %r, needs %r" % (where, got, want)]
    return []

def feature_lists(node, path):
    """Every `features = [...]` list below node, as (dotted path, list). The top-level [features]
    table is a table of lists, not a list, so it is checked on its own below."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "features" and isinstance(value, list):
                yield ".".join(path + [key]), value
            else:
                yield from feature_lists(value, path + [key])
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from feature_lists(item, path + [str(i)])

def hardware(node, path):
    """Every dotted path below node that names a Pi hardware crate, as a key or as a package rename."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in HARDWARE or (key == "package" and isinstance(value, str) and value in HARDWARE):
                yield ".".join(path + [key])
            yield from hardware(value, path + [key])
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from hardware(item, path + [str(i)])

def load(root, rel):
    with open(root / rel, "rb") as f:
        return tomllib.load(f)

root = Path(sys.argv[1])
bad = []
try:
    top = load(root, "Cargo.toml")
    members = top.get("workspace", {}).get("members", [])
    manifests = [("Cargo.toml", top)] + [(m + "/Cargo.toml", load(root, m + "/Cargo.toml")) for m in members]
except (OSError, tomllib.TOMLDecodeError) as err:
    print("%s" % err)
    sys.exit(1)
bad += compare("Cargo.toml: profile", top.get("profile"), PROFILE)
core_seen = False
hardware_paths = [".".join(HARDWARE_AT[1] + [name]) for name in HARDWARE]
for rel, doc in manifests:
    for where, values in feature_lists(doc, []):
        bad += ["%s: %s turns on %s" % (rel, where, v) for v in values if turns_on(v)]
    bad += ["%s: %s names a Pi hardware crate, allowed only in %s under %s"
            % (rel, where, HARDWARE_AT[0], ".".join(HARDWARE_AT[1]))
            for where in hardware(doc, []) if rel != HARDWARE_AT[0] or where not in hardware_paths]
    if rel == HARDWARE_AT[0]:
        table = doc
        for key in HARDWARE_AT[1]:
            table = table.get(key) if isinstance(table, dict) else None
        for name, spec in HARDWARE.items():
            got = table.get(name) if isinstance(table, dict) else None
            bad += compare("%s: %s" % (rel, ".".join(HARDWARE_AT[1] + [name])), got, spec)
    if rel == "Cargo.toml":
        continue
    features = doc.get("features")
    if doc.get("package", {}).get("name") == "keepcrypt-core":
        core_seen = True
        bad += compare(rel + ": features", features, CORE_FEATURES)
    elif isinstance(features, dict):
        bad += ["%s: features.%s turns on %s" % (rel, name, v)
                for name, values in features.items() if isinstance(values, list) for v in values if turns_on(v)]
if not core_seen:
    bad.append("no workspace member is keepcrypt-core")
for line in bad:
    print(line)
sys.exit(1 if bad else 0)
'
static_check "core [features], the root [profile] and the Pi hardware crates exactly as pinned; no manifest turns on a test feature" \
    python3 -I -c "$manifest_pins" "$root"

# ... and the check must fire, on a copy of the five manifests. One copy carries every route by
# which a manifest could turn a test feature on, a widened nix spec and rppal outside keepcrypt-pi,
# the other both profile changes; each must be named.
fresh_manifests() {
    m="$work/manifests"
    rm -rf "$m"
    mkdir -p "$m/core" "$m/ffi" "$m/pi/app" "$m/pi/sim" || exit 1
    for f in Cargo.toml core/Cargo.toml ffi/Cargo.toml pi/app/Cargo.toml pi/sim/Cargo.toml; do
        cp "$root/$f" "$m/$f" || exit 1
    done
}
# replace FILE OLD NEW: OLD must occur in FILE exactly once.
replace() {
    python3 -I -c '
import sys
path, old, new = sys.argv[1:4]
text = open(path, encoding="utf-8").read()
if text.count(old) != 1:
    sys.exit("%s: %r occurs %d times" % (path, old, text.count(old)))
open(path, "w", encoding="utf-8").write(text.replace(old, new))
' "$@" || exit 1
}
fresh_manifests
replace "$m/Cargo.toml" 'keepcrypt-core = { path = "core" }' \
    'keepcrypt-core = { path = "core", features = ["test-sources"] }'
replace "$m/core/Cargo.toml" 'default = []' 'default = ["test-registry"]'
replace "$m/pi/app/Cargo.toml" 'features = ["fs", "mman", "mount", "time"]' \
    'features = ["fs", "mman", "mount", "reboot", "time"]'
cat >> "$m/pi/app/Cargo.toml" <<'EOF'

# Gate canary (scripts/canaries.sh, temp copy only): a test feature through a dev-dependency.
[dev-dependencies]
keepcrypt-core = { workspace = true, features = ["test-sources"] }
EOF
cat >> "$m/pi/sim/Cargo.toml" <<'EOF'

# Gate canary (scripts/canaries.sh, temp copy only): the test key through a target-specific
# normal dependency.
[target.'cfg(unix)'.dependencies]
keepcrypt-core = { workspace = true, features = ["test-registry"] }

# Gate canary (scripts/canaries.sh, temp copy only): a Pi hardware crate outside keepcrypt-pi.
[target.'cfg(target_os = "linux")'.dependencies]
rppal = { version = "=0.22.1", default-features = false }
EOF
cat >> "$m/ffi/Cargo.toml" <<'EOF'

# Gate canary (scripts/canaries.sh, temp copy only): a feature that forwards to a test feature.
[features]
probe = ["keepcrypt-core?/test-sources"]
EOF
expect_failure "test-features-in-manifests" python3 -I -c "$manifest_pins" "$m"
need "Cargo.toml: workspace.dependencies.keepcrypt-core.features turns on test-sources"
need "core/Cargo.toml: features.default is ['test-registry'], needs []"
need "pi/app/Cargo.toml: dev-dependencies.keepcrypt-core.features turns on test-sources"
need "pi/sim/Cargo.toml: target.cfg(unix).dependencies.keepcrypt-core.features turns on test-registry"
need "ffi/Cargo.toml: features.probe turns on keepcrypt-core?/test-sources"
need "pi/app/Cargo.toml: target.cfg(target_os = \"linux\").dependencies.nix.features is ['fs', 'mman', 'mount', 'reboot', 'time'], needs ['fs', 'mman', 'mount', 'time']"
need "pi/sim/Cargo.toml: target.cfg(target_os = \"linux\").dependencies.rppal names a Pi hardware crate, allowed only in pi/app/Cargo.toml under target.cfg(target_os = \"linux\").dependencies"
never "profile"
verdict

fresh_manifests
replace "$m/Cargo.toml" 'panic = "unwind"' 'panic = "abort"'
replace "$m/Cargo.toml" 'overflow-checks = true' 'overflow-checks = false'
expect_failure "release-profile" python3 -I -c "$manifest_pins" "$m"
need "Cargo.toml: profile.release.panic is 'abort', needs 'unwind'"
need "Cargo.toml: profile.release.package.keepcrypt-core.overflow-checks is False, needs True"
never "turns on"
verdict

# The dependency graph (CLAUDE.md rules 1, 5 and 11; tasks/todo.md, M1 Q1-Q4 and group 12):
# - serde, serde_core and serde_derive stay out of keepcrypt-core's normal and build graph, all
#   features and all targets: serde arrives with the test-only dev-dependencies (trybuild,
#   serde_json), never in the device build;
# - Cargo.lock holds one getrandom, and its only dependent is keepcrypt-core (rule 1: one source of
#   OS randomness). The lockfile records every edge of every feature and target, so this holds
#   for every build;
# - ed25519-dalek resolves with no features and curve25519-dalek with exactly digest, across the
#   workspace with all features, all targets and dev-dependencies, so legacy_compatibility
#   (malleable signatures), hazmat, batch and rand_core stay off (Q3);
# - poly1305 resolves with zeroize in the device build: keepcrypt-core's normal graph with default
#   features (so no test feature can be what turns it on), for each target in rust-toolchain.toml
#   (the six CI cross targets) and the host, one at a time, since --target all merges the features
#   of every target and would let an edge scoped to one target pass for all. chacha20poly1305's
#   zeroize turns on only chacha20's, so core's direct edge is what makes the dropped Poly1305
#   state wipe its one-time key r and s (tasks/todo.md, "M1: open owner items", item 6).
# graph_pins ROOT runs cargo tree (--locked) on the workspace at ROOT and reads its Cargo.lock and
# rust-toolchain.toml.
graph_pins='
import subprocess, sys, tomllib
from pathlib import Path

SERDE = ("serde", "serde_core", "serde_derive")
DALEK = {"ed25519-dalek": "", "curve25519-dalek": "digest"}
ZEROIZE = ("poly1305",)

# target None is the host, the default of cargo tree.
def tree(root, *args, all_features=True, target="all"):
    run = subprocess.run(["cargo", "tree", "--manifest-path", str(root / "Cargo.toml"), "--locked",
                          "--prefix", "none"]
                         + (["--target", target] if target else [])
                         + (["--all-features"] if all_features else []) + list(args),
                         capture_output=True, text=True)
    if run.returncode != 0:
        print("cargo tree %s failed:\n%s" % (" ".join(args), run.stderr))
        sys.exit(1)
    return sorted({line.replace(" (*)", "") for line in run.stdout.splitlines() if line})

root = Path(sys.argv[1])
bad = []
for line in tree(root, "-p", "keepcrypt-core", "-e", "normal,build", "--format", "{p}"):
    if line.split(" ")[0] in SERDE:
        bad.append("keepcrypt-core normal or build graph holds %s" % line)
with open(root / "Cargo.lock", "rb") as f:
    packages = tomllib.load(f).get("package", [])
versions = [p["version"] for p in packages if p["name"] == "getrandom"]
if len(versions) != 1:
    bad.append("Cargo.lock holds getrandom %s; needs exactly one version" % (", ".join(versions) or "none"))
dependents = sorted(p["name"] for p in packages
                    if any(d.split(" ")[0] == "getrandom" for d in p.get("dependencies", [])))
if dependents != ["keepcrypt-core"]:
    bad.append("getrandom dependents in Cargo.lock: %s; needs keepcrypt-core only" % (", ".join(dependents) or "none"))
seen = set()
for line in tree(root, "--workspace", "-e", "normal,build,dev", "--format", "{p}|{f}"):
    package, features = line.split("|", 1)
    name = package.split(" ")[0]
    if name in DALEK:
        seen.add(name)
        if features != DALEK[name]:
            bad.append("%s resolves with features [%s]; needs [%s]" % (package, features, DALEK[name]))
bad += ["%s is not in the graph" % name for name in sorted(set(DALEK) - seen)]
with open(root / "rust-toolchain.toml", "rb") as f:
    targets = tomllib.load(f)["toolchain"]["targets"]
for target in targets + [None]:
    built = target or "the host"
    wiping = set()
    for line in tree(root, "-p", "keepcrypt-core", "-e", "normal", "--format", "{p}|{f}", all_features=False,
                     target=target):
        package, features = line.split("|", 1)
        name = package.split(" ")[0]
        if name in ZEROIZE:
            wiping.add(name)
            if "zeroize" not in features.split(","):
                bad.append("%s resolves with features [%s] in the device build for %s; needs zeroize"
                           % (package, features, built))
    bad += ["%s is not in the device build for %s" % (name, built) for name in sorted(set(ZEROIZE) - wiping)]
for line in bad:
    print(line)
sys.exit(1 if bad else 0)
'
static_check "graph: no serde in core's normal or build graph; getrandom's only dependent is core; dalek features pinned; poly1305 with zeroize on every target" \
    python3 -I -c "$graph_pins" "$root"

# ... and each rule must fire, on a copy of the workspace with all four mistakes: serde as a
# normal dependency of core, getrandom as a dependency of the FFI, legacy_compatibility on
# ed25519-dalek, and poly1305 with zeroize on Linux targets only (the Pi, but not Android, iOS or
# a macOS host), which --target all would pass. Each is already in Cargo.lock, so the copy's
# lockfile updates offline.
graph="$work/graph"
mkdir "$graph" || exit 1
for f in "$root"/* "$root"/.[!.]* "$root"/..?*; do
    [ -e "$f" ] || continue
    case ${f##*/} in
        target | .git) continue ;;
    esac
    cp -RP "$f" "$graph/" || exit 1
done
replace "$graph/core/Cargo.toml" 'ed25519-dalek = { version = "3.0.0", default-features = false }' \
    'ed25519-dalek = { version = "3.0.0", default-features = false, features = ["legacy_compatibility"] }'
replace "$graph/core/Cargo.toml" 'poly1305 = { version = "0.9.1", default-features = false, features = ["zeroize"] }' \
    'poly1305 = { version = "0.9.1", default-features = false }'
cat >> "$graph/core/Cargo.toml" <<'EOT'

# Gate canary (scripts/canaries.sh, temp copy only): serde in the device build.
[dependencies.serde]
version = "1.0.229"
default-features = false

# Gate canary (scripts/canaries.sh, temp copy only): poly1305's zeroize on Linux targets only.
[target.'cfg(target_os = "linux")'.dependencies.poly1305]
version = "0.9.1"
default-features = false
features = ["zeroize"]
EOT
cat >> "$graph/ffi/Cargo.toml" <<'EOT'

# Gate canary (scripts/canaries.sh, temp copy only): a second OS randomness path.
[dependencies.getrandom]
version = "0.4.3"
EOT
name=graph-pins
if ! out=$(cargo update --offline --workspace --manifest-path "$graph/Cargo.toml" 2>&1); then
    printf '%s\n' "$out" | tail -n 30
    echo "FAIL: $name: could not update the copy's Cargo.lock offline"
    status=1
else
    expect_failure "$name" python3 -I -c "$graph_pins" "$graph"
    need "keepcrypt-core normal or build graph holds serde v1.0.229"
    need "getrandom dependents in Cargo.lock: keepcrypt-core, keepcrypt-ffi; needs keepcrypt-core only"
    need "ed25519-dalek v3.0.0 resolves with features [legacy_compatibility]; needs []"
    need "curve25519-dalek v5.0.0 resolves with features [digest,legacy_compatibility]; needs [digest]"
    for t in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android aarch64-apple-ios \
        aarch64-apple-ios-sim; do
        need "poly1305 v0.9.1 resolves with features [] in the device build for $t; needs zeroize"
    done
    never "for arm-unknown-linux-gnueabihf"
    never "cargo tree"
    verdict
fi

# Vectors tamper (lessons.md: computed values come from a committed script that CI re-runs): one
# changed byte in each JSON file vectorgen.py writes (the seven M1 sets and agreement.json) or reads
# back (the age CLI's age_cli_written.json) must fail vectorgen.py --selftest, naming that file.
# The byte is the first hex digit of the first all-hex string of 16 or more digits from the middle
# of the file on (in agreement.json, a rolls string), so the file stays valid JSON and only its
# content changes. Each file is changed in its own fresh copy of vectors/ (vectorgen.py
# --vectors-dir).
flip_hex='
import re, sys
path = sys.argv[1]
data = open(path, "rb").read()
hexstr = re.compile(rb"\"[0-9a-f]{16,}\"")
found = hexstr.search(data, len(data) // 2) or hexstr.search(data)
if found is None:
    sys.exit("%s: no hex string to change" % path)
at = found.start() + 1
data = data[:at] + (b"1" if data[at:at + 1] == b"0" else b"0") + data[at + 1:]
open(path, "wb").write(data)
'
for v in seal.json kat.json keepcrypt.json braille.json watchonly.json kcr.json backup.json \
    agreement.json age/age_cli_written.json; do
    vt="$work/vectors-tamper"
    rm -rf "$vt"
    cp -R "$root/vectors" "$vt" || exit 1
    name="vectors-tamper-$v"
    if ! out=$(python3 -I -c "$flip_hex" "$vt/$v" 2>&1); then
        printf '%s\n' "$out"
        echo "FAIL: $name: could not change a byte"
        status=1
        continue
    fi
    expect_failure "$name" python3 -I "$root/tools/verify/vectorgen.py" --selftest --vectors-dir "$vt"
    need "selftest FAILED"
    # A failing check must name the file: every check's title names its own file on its "ok" line
    # too, so only the FAIL lines count.
    case $(printf '%s\n' "$out" | grep '^FAIL ') in
        *"vectors/$v"*) ;;
        *) echo "FAIL: $name: no failing check names vectors/$v"; ok=0 ;;
    esac
    verdict
done

# The shipped verifier's own rules (tasks/todo.md, M2 groups 3, 7 and 8): a copy of verify.py with
# one change must fail check 12 (vectorgen.py --check 12 --verify-py), for the rule it breaks:
# - verifier-import: import socket, outside rule (a)'s import allowlist;
# - verifier-echo and verifier-echo-upper: the C/D mismatch refusal shows D, as lowercase hex or in
#   upper case, which the leak rule finds on the piped run with D changed;
# - verifier-tty: roll lines read with sys.stdin.readline() (read_piped) on a terminal, where they
#   echo, which rule (f)'s leak test finds in the pty transcript;
# - verifier-reach: selftest opens /dev/null for writing through getpass.io, which rule (a) finds
#   (getpass.io is not on the recorded list) and rule (e)'s audit refuses.
# verifier_canary NAME OLD NEW TEXT...: OLD must occur in verify.py exactly once; the copy with it
# replaced by NEW must fail check 12 alone, with every TEXT in the output.
verifier_canary() {
    name=$1
    old=$2
    new=$3
    shift 3
    cp "$root/tools/verify/verify.py" "$work/verify.py" || exit 1
    replace "$work/verify.py" "$old" "$new"
    expect_failure "$name" python3 -I "$root/tools/verify/vectorgen.py" --selftest --check 12 \
        --verify-py "$work/verify.py"
    need "FAIL tools/verify/verify.py ships alone"
    need "selftest FAILED: 1 of 1 checks"
    for text in "$@"; do
        need "$text"
    done
    verdict
}
verifier_canary verifier-import "import getpass" "import getpass, socket" \
    "imports socket, not on the allowlist"
verifier_canary verifier-echo 'report["refused"] = "D does not match C"' \
    'report["refused"] = "D does not match C: " + report["d"].hex()' \
    "piped mixed --words 12, D with one digit changed: stdout holds 8 consecutive hex digits of the typed D"
verifier_canary verifier-echo-upper 'report["refused"] = "D does not match C"' \
    'report["refused"] = "D does not match C: " + report["d"].hex().upper()' \
    "piped mixed --words 12, D with one digit changed: stdout holds 8 consecutive hex digits of the typed D"
verifier_canary verifier-tty "report = verification_run(length, roll_lines(read), c_text, d_text)" \
    "report = verification_run(length, roll_lines(read_piped), c_text, d_text)" \
    "rule (f): mixed --words 12: the terminal holds 12 consecutive rolls"
verifier_canary verifier-reach "    results = known_answers(KNOWN_ANSWERS)" \
    "    getpass.io.open(\"/dev/null\", \"w\").close()
    results = known_answers(KNOWN_ANSWERS)" \
    "takes getpass.io, not in the recorded list" \
    "rule (e): lone copy: audit: open for writing: '/dev/null'"

# The grep gate's Device category on the real firmware (CLAUDE.md rules 5 and 8; tasks/todo.md,
# M4 group 11): one line planted in the copy of a real pi/app file, one per rule, must fail
# scripts/banned-api-check.sh on the copy with exactly that hit, so a widened path list, a new
# exception or a dropped rule turns CI red. The copy is the one the real-* canaries use; each file
# is restored afterwards.
# device_canary NAME FILE LINE: appends LINE to the copy's FILE; the gate must report Device at
# FILE with LINE and nothing else.
device_canary() {
    name=$1
    cp "$root/$2" "$tmp/$2" || exit 1
    printf '%s\n' "$3" >> "$tmp/$2" || exit 1
    expect_failure "$name" sh "$root/scripts/banned-api-check.sh" "$tmp"
    need "Device: $2:"
    need "$3"
    need "banned-api-check: 1 hit(s) in "
    verdict
    cp "$root/$2" "$tmp/$2" || exit 1
}
device_canary device-path-literal pi/app/src/app.rs \
    'const KC_GATE_CANARY_CMDLINE: &str = "/proc/cmdline"; // gate canary (temp copy only): a path outside paths.rs'
device_canary device-file-api pi/app/src/hal.rs \
    'fn kc_gate_canary(path: &str) -> std::io::Result<std::fs::File> { std::fs::File::open(path) } // gate canary (temp copy only)'
device_canary device-hardware-crate pi/app/src/input.rs \
    'fn kc_gate_canary() -> Result<rppal::gpio::Gpio, rppal::gpio::Error> { rppal::gpio::Gpio::new() } // gate canary (temp copy only)'
device_canary device-buffered-reader pi/app/src/device/hwrng.rs \
    '// Gate canary (temp copy only): a BufReader would hold a copy of the samples.'
# The grouped shape rustfmt gives two imports, which names no item right after the ::.
device_canary device-grouped-process-use pi/app/src/app.rs \
    'use std::process::{Command, Stdio}; // gate canary (temp copy only): the module by any path'

# The image's panel profile (tasks/todo.md, M4b B3; Q47 (a)): KEEPCRYPT_PI_PANEL set to a name no
# profile in pi/app's PROFILES has, or set but empty, must stop the real keepcrypt-pi binary's
# build in PANEL's const evaluation, with select's fixed text and that one error, so a mistyped
# name never falls back to the HAT. Nothing in the tree changes; only the variable is set. The
# binary is checked in its test configuration, which compiles the device module on every host
# (off Linux, main.rs otherwise leaves it out), and rustc evaluates every const item, used or not,
# so any build that compiles the module stops the same way. Cargo tracks the variables option_env!
# reads, so each value rechecks keepcrypt-pi alone.
for panel in nonsense ""; do
    expect_failure "panel-name-${panel:-empty}" env KEEPCRYPT_PI_PANEL="$panel" cargo check \
        --color never --manifest-path "$root/Cargo.toml" -p keepcrypt-pi --bin keepcrypt-pi \
        --profile test --locked --target-dir "$root/target/canary-real"
    need "KEEPCRYPT_PI_PANEL is empty or names no profile in PROFILES"
    need "--> pi/app/src/device/panel.rs:"
    need "could not compile \`keepcrypt-pi\` (bin \"keepcrypt-pi\" test) due to 1 previous error"
    verdict
done

# The image path's panel name (tasks/todo.md, M4b B3; Q47 (a)), which never relies on the HAT that
# pi/app gives when no name is set: make image, repro-check and scan must stop while
# pi/os/Makefile is parsed, with the list, when PANEL is missing, empty or not a name in PANELS;
# a PANELS and PANEL_NAME given on the command line must not get an unlisted name past that check
# (both are override); and keepcrypt-pi.mk, read as Buildroot reads it, must stop when
# KEEPCRYPT_PI_PANEL is empty. make -n on a copy of pi/os under $work (the Makefile refuses a path
# with a space), with a KC_WORK that does not exist: a refusal that stopped firing would print
# recipe lines ("pi/os: ...") or a recipe's error ("] Error "), and not the text. The goals differ
# so that each one of the Makefile's three is held to the check. A PANEL in the caller's
# environment would be the name, so it goes.
unset PANEL
pm="$work/panel-make/Entropy/pi/os"
mkdir -p "$work/panel-make/Entropy/pi" || exit 1
cp -R "$root/pi/os" "$pm" || exit 1
# panel_make NAME GOAL TEXT [VAR=VALUE...]: make -n GOAL on the copy must stop with TEXT and the list.
# The list is pinned whole, up to the period make adds, so a name dropped from PANELS fails here:
# nothing else would see it, as the image workflow would then build the HAT's image alone and
# never run panels differ. A name that joins PANELS joins this line in the same change.
panel_make() {
    name=$1
    goal=$2
    text=$3
    shift 3
    expect_failure "$name" make -n --no-print-directory -C "$pm" "$goal" KC_WORK="$work/kc-work" "$@"
    need "*** $text; make image, repro-check and scan need PANEL=<name>, one of: st7789-240x240 st7789-240x320."
    never "pi/os: "
    never "] Error "
    verdict
}
panel_make panel-make-unset image "PANEL is not set"
panel_make panel-make-empty scan "PANEL is empty" PANEL=
panel_make panel-make-unlisted repro-check 'PANEL="nonsense" is not a name in the list' PANEL=nonsense
panel_make panel-make-override image 'PANEL="nonsense" is not a name in the list' \
    PANEL=nonsense PANELS=nonsense PANEL_NAME=nonsense
expect_failure "panel-mk-empty" make -n --no-print-directory \
    -f "$pm/package/keepcrypt-pi/keepcrypt-pi.mk" BR_BUILDING=y BR2_PACKAGE_KEEPCRYPT_PI=y \
    KC_WORK="$work/kc-work" KEEPCRYPT_PI_PANEL=
need "*** keepcrypt-pi: KEEPCRYPT_PI_PANEL is empty; build the image with Entropy/pi/os/Makefile and PANEL=<name>"
verdict

# pi-image panels differ (tasks/todo.md, M4b B4; Q47 (a)): two screen types whose keepcrypt-pi
# binaries have the same SHA-256 must fail scripts/panels-differ.sh, naming both, since equal
# binaries mean a panel name never reached the compiler. The image workflow runs the check only on
# a run that builds two or more panels, so this canary keeps it firing on every gates run.
sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
expect_failure "panels-differ-equal" sh "$root/scripts/panels-differ.sh" \
    "st7789-240x240=$sha" "st7789-240x320=$sha"
need "FAIL: pi-image panels differ: st7789-240x240 and st7789-240x320 have the same keepcrypt-pi SHA-256, so a panel name did not reach the compiler: $sha"
need "pi-image panels differ: 1 pair(s) of panels share a keepcrypt-pi SHA-256"
verdict

# The workflow hardening check (tasks/todo.md, M4 group 11; Q38 (d)): a copy of the real
# entropy-ci.yml with every rule broken once (the top-level token widened to write, which also
# loses contents: read, and a job that runs on workflow_run, uses an action by tag, pastes an
# expression into a run line and a run block, and reads a secret) must fail
# scripts/banned-api-check.sh --workflows with those seven hits, and no other: the real file
# is clean, as CI's gates job checks on every run.
name=workflow-hardening
wfd="$work/workflows"
wfc="$wfd/entropy-ci.yml"
mkdir "$wfd" || exit 1
cp "$root/../.github/workflows/entropy-ci.yml" "$wfc" || exit 1
replace "$wfc" 'permissions:
  contents: read' 'permissions:
  contents: write'
cat >> "$wfc" <<'EOF'

  canary:
    # Gate canary (scripts/canaries.sh, temp copy only): every hardening rule broken once.
    if: github.event_name == 'workflow_run'
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - run: echo "${{ github.head_ref }}"
      - env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          git diff --quiet "$base" ${{ github.event.pull_request.head.sha }}
EOF
expect_failure "$name" sh "$root/scripts/banned-api-check.sh" --workflows "$wfd"
need "Workflow: $wfc:1: missing a top-level permissions block that holds contents: read"
need "Workflow: $wfc:32:   contents: write"
need "if: github.event_name == 'workflow_run'"
need "uses: actions/checkout@v7"
need 'run: echo "${{ github.head_ref }}"'
need 'TOKEN: ${{ secrets.GITHUB_TOKEN }}'
need 'git diff --quiet "$base" ${{ github.event.pull_request.head.sha }}'
need "7 hit(s) in 1 workflow(s)"
verdict

# The OS configuration check (tasks/todo.md, M4 groups 11 and 13; commit 17a): a temp copy of
# the clean fixture, scripts/testdata/os-config/clean-pizero, must pass banned-api-check.sh
# --os-config (the control), and three copies with one change each must fail it with exactly the
# one hit of the rule broken: the inittab's wait line made a respawn line, a console= word in
# cmdline.txt, and an expected/kconfig-forbidden that no longer equals the fragment's "is not set"
# lines. Text only, so these run on every machine, as the gates job does.
osc="$work/os-config"
cp -R "$root/scripts/testdata/os-config/clean-pizero" "$osc" || exit 1
static_check "os-config: the clean fixture passes (control)" sh "$root/scripts/banned-api-check.sh" --os-config "$osc"
# osconfig_canary NAME FILE OLD NEW CATEGORY: a fresh copy of the clean fixture with OLD replaced
# by NEW in FILE must fail --os-config with exactly one hit, of CATEGORY, naming FILE.
osconfig_canary() {
    name=$1
    oc="$work/os-config-$name"
    rm -rf "$oc"
    cp -R "$root/scripts/testdata/os-config/clean-pizero" "$oc" || exit 1
    replace "$oc/$2" "$3" "$4"
    expect_failure "$name" sh "$root/scripts/banned-api-check.sh" --os-config "$oc"
    need "$5: $oc/$2"
    need "banned-api-check --os-config $oc: 1 hit(s)"
    verdict
}
osconfig_canary os-config-inittab board/pizero/rootfs-overlay/etc/inittab \
    '::wait:/usr/bin/keepcrypt-pi' '::respawn:/usr/bin/keepcrypt-pi' Inittab
osconfig_canary os-config-cmdline-console board/pizero/cmdline.txt \
    'rootwait panic=0' 'rootwait console=ttyAMA0,115200 panic=0' Cmdline
osconfig_canary os-config-kconfig-forbidden-drift expected/kconfig-forbidden \
    'CONFIG_DEVMEM' 'CONFIG_DEVPORT' Kconfig

# The release-artifact scan (CLAUDE.md rule 10; tasks/todo.md, M1 group 11 and Q3, Q8): the
# release probe (core/examples/release_probe.rs) and core's rlib, built in release mode for the
# host three ways, one package at a time (-p), in their own target directory. On a Linux host the
# build sets Q8's getrandom cfg for the host target only, as the cross job does for the Pi and
# Android, so the scan finds the getrandom import; a macOS host needs no cfg (getrandom has no
# fallback there).
# - Control: with default features the scan is clean and the probe runs to its end (exit 0), so
#   the hits below come from the features alone.
# - Positive control 1: with test-sources the scan exits 1 and names both markers and the test
#   key, in the rlib and in the probe, and nothing else.
# - Positive control 2: with test-registry alone it names the registry marker and the test key,
#   and finds no stub marker; and the probe runs to its end, so its snapshot verifies under the
#   test key.
host=$(rustc -vV | sed -n 's/^host: //p')
probe_dir="$root/target/canary-probe"
rlib="$probe_dir/$host/release/libkeepcrypt_core.rlib"
probe="$probe_dir/$host/release/examples/release_probe"
case $host in
    *-linux-*) cfg_var=CARGO_TARGET_$(printf '%s' "$host" | tr 'a-z-' 'A-Z_')_RUSTFLAGS ;;
    *) cfg_var= ;;
esac
# build_probe [FEATURES] [ROOT]: builds core's rlib and the probe for the host, from the workspace
# at ROOT (the real one by default); prints the output on failure.
build_probe() {
    set -- cargo build --release --locked --manifest-path "${2:-$root}/Cargo.toml" \
        -p keepcrypt-core --lib --example release_probe \
        --target "$host" --target-dir "$probe_dir" ${1:+--features "$1"}
    if [ -n "$cfg_var" ]; then
        set -- env "$cfg_var=--cfg getrandom_backend=\"linux_getrandom\"" "$@"
    fi
    if ! out=$("$@" 2>&1); then
        printf '%s\n' "$out" | tail -n 30
        return 1
    fi
}
# probe_clean: the scan passes and the probe exits 0.
probe_clean() {
    sh "$root/scripts/banned-api-check.sh" --artifact "$host" "$rlib" "$probe" || return 1
    "$probe" || { echo "the release probe exited $?"; return 1; }
}
name=release-probe-default
if build_probe ""; then
    static_check "$name: the scan is clean and the probe runs (control)" probe_clean
else
    echo "FAIL: $name: the build failed"
    status=1
fi
name=release-probe-test-registry
if build_probe test-registry; then
    expect_failure "$name" sh "$root/scripts/banned-api-check.sh" --artifact "$host" "$rlib" "$probe"
    for f in "$rlib" "$probe"; do
        need "Marker: $f: KC_TEST_REGISTRY_DO_NOT_SHIP"
        need "TestKey: $f: the test registry public key "
    done
    need "4 hit(s) in 2 file(s)"
    never "KC_TEST_SOURCE_DO_NOT_SHIP"
    verdict
    static_check "$name: the probe verifies its snapshot under the test key" "$probe"
else
    echo "FAIL: $name: the build failed"
    status=1
fi
name=release-probe-test-sources
if build_probe test-sources; then
    expect_failure "$name" sh "$root/scripts/banned-api-check.sh" --artifact "$host" "$rlib" "$probe"
    for f in "$rlib" "$probe"; do
        need "Marker: $f: KC_TEST_SOURCE_DO_NOT_SHIP"
        need "Marker: $f: KC_TEST_REGISTRY_DO_NOT_SHIP"
        need "TestKey: $f: the test registry public key "
    done
    need "6 hit(s) in 2 file(s)"
    verdict
else
    echo "FAIL: $name: the build failed"
    status=1
fi
# - Positive control 3 (tasks/todo.md, M4 group 12): std's random-key path. The copy's probe, with
#   a RandomState (a HashMap's hasher, whose keys std reads from the OS itself) planted at the
#   start of run(), built with default features from the copy into the same target directory
#   (the registry crates are shared, core and the probe rebuild for the copy's path), must fail
#   the scan with StdRandom hits in the probe, hashmap_random_keys among them, and none in the
#   rlib, which the copy leaves as it is. Last of the probe canaries: its build overwrites their
#   two files. black_box keeps the value alive without a must_use warning.
name=release-probe-std-random
replace "$tmp/core/examples/release_probe.rs" '    self_test().map_err(|_| 10)?;' \
    '    core::hint::black_box(std::collections::hash_map::RandomState::new()); // gate canary (temp copy only)
    self_test().map_err(|_| 10)?;'
if build_probe "" "$tmp"; then
    expect_failure "$name" sh "$root/scripts/banned-api-check.sh" --artifact "$host" "$rlib" "$probe"
    need "StdRandom: $probe: symbol "
    need "hashmap_random_keys"
    never "StdRandom: $rlib"
    never "Marker:"
    never "TestKey:"
    verdict
else
    echo "FAIL: $name: the build failed"
    status=1
fi
cp "$root/core/examples/release_probe.rs" "$tmp/core/examples/release_probe.rs" || exit 1

# The number of checks above, pinned, so a canary that is deleted, or skipped by a broken branch,
# turns CI red too. A real change to the canaries updates this pin in the same reviewed change.
want_checks=81
if [ "$checks" -ne "$want_checks" ]; then
    echo "FAIL: $checks checks ran; scripts/canaries.sh pins $want_checks"
    status=1
else
    echo "PASS: all $checks checks ran"
fi

exit "$status"
