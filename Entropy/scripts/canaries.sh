#!/bin/sh
# Gate canaries: inputs that must FAIL their gate, for the intended reason, on every run.
# A canary that passes means the gate stopped firing (principle 7: test the path, not the presence).
# Run from the repo root. Exit 0 only if every canary failed as intended, every static check and
# control passed, and the number of checks run equals the pin at the end.
# Needs cargo-deny, git, and python3 3.11 or later (tomllib, for the static checks; CI runs 3.12),
# a C compiler for the host (the release probe builds secp256k1-sys), and the pinned toolchain's
# llvm-tools-preview (the artifact scan's llvm-nm).
# Needs the network only to fetch locked crates (deny-banned, clippy, cargo fetch); the steps
# that add a crate or a git source resolve and check offline.
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
# - [sources] is exactly crates.io only, with unknown registries and git sources denied (so an
#   allow-org or private key fails too).
static_check "deny.toml [graph], [bans] deny and [sources] exactly as pinned" python3 -I -c '
import sys, tomllib
GRAPH = {"all-features": True}
DENY = [
    "rand", "rand_core", "rand_chacha", "rand_xoshiro", "rand_xorshift", "rand_pcg", "rand_hc",
    "rand_isaac", "fastrand", "oorandom", "nanorand", "tinyrand", "turborand",
    "tokio", "mio", "hyper", "h2", "reqwest", "ureq", "curl", "isahc", "axum", "async-std",
    "log", "tracing", "slog", "env_logger",
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
# A real change to either pin is a reviewed change here too.
manifest_pins='
import sys, tomllib
from pathlib import Path

TEST_FEATURES = ("test-sources", "test-registry")
CORE_FEATURES = {"default": [], "test-registry": [], "test-sources": ["test-registry"]}
PROFILE = {
    "release": {"panic": "unwind", "package": {"keepcrypt-core": {"overflow-checks": True}}},
    "dev": {"package": {"*": {"opt-level": 3}}},
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
for rel, doc in manifests:
    for where, values in feature_lists(doc, []):
        bad += ["%s: %s turns on %s" % (rel, where, v) for v in values if turns_on(v)]
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
static_check "core [features] and the root [profile] exactly as pinned; no manifest turns on a test feature" \
    python3 -I -c "$manifest_pins" "$root"

# ... and the check must fire, on a copy of the five manifests. One copy carries every route by
# which a manifest could turn a test feature on, the other both profile changes; each must be
# named.
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
#   (malleable signatures), hazmat, batch and rand_core stay off (Q3).
# graph_pins ROOT runs cargo tree (--locked) on the workspace at ROOT and reads its Cargo.lock.
graph_pins='
import subprocess, sys, tomllib
from pathlib import Path

SERDE = ("serde", "serde_core", "serde_derive")
DALEK = {"ed25519-dalek": "", "curve25519-dalek": "digest"}

def tree(root, *args):
    run = subprocess.run(["cargo", "tree", "--manifest-path", str(root / "Cargo.toml"), "--locked",
                          "--target", "all", "--all-features", "--prefix", "none"] + list(args),
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
for line in bad:
    print(line)
sys.exit(1 if bad else 0)
'
static_check "graph: no serde in core's normal or build graph; getrandom's only dependent is core; dalek features pinned" \
    python3 -I -c "$graph_pins" "$root"

# ... and each rule must fire, on a copy of the workspace with all three mistakes: serde as a
# normal dependency of core, getrandom as a dependency of the FFI, and legacy_compatibility on
# ed25519-dalek. Each is already in Cargo.lock, so the copy's lockfile updates offline.
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
cat >> "$graph/core/Cargo.toml" <<'EOT'

# Gate canary (scripts/canaries.sh, temp copy only): serde in the device build.
[dependencies.serde]
version = "1.0.229"
default-features = false
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
    never "cargo tree"
    verdict
fi

# Vectors tamper (lessons.md: computed values come from a committed script that CI re-runs): one
# changed byte in each generated JSON file must fail verify.py --selftest, naming that file. The
# byte is the first hex digit of the first all-hex string of 16 or more digits from the middle of
# the file on, so the file stays valid JSON and only its content changes. Each file is changed in
# its own fresh copy of vectors/ (verify.py --vectors-dir).
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
    age/age_cli_written.json; do
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
    expect_failure "$name" python3 -I "$root/tools/verify/verify.py" --selftest --vectors-dir "$vt"
    need "selftest FAILED"
    # A failing check must name the file: every check's title names its own file on its "ok" line
    # too, so only the FAIL lines count.
    case $(printf '%s\n' "$out" | grep '^FAIL ') in
        *"vectors/$v"*) ;;
        *) echo "FAIL: $name: no failing check names vectors/$v"; ok=0 ;;
    esac
    verdict
done

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
# build_probe [FEATURES]: builds core's rlib and the probe for the host; prints the output on failure.
build_probe() {
    set -- cargo build --release --locked -p keepcrypt-core --lib --example release_probe \
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

# The number of checks above, pinned, so a canary that is deleted, or skipped by a broken branch,
# turns CI red too. A real change to the canaries updates this pin in the same reviewed change.
want_checks=54
if [ "$checks" -ne "$want_checks" ]; then
    echo "FAIL: $checks checks ran; scripts/canaries.sh pins $want_checks"
    status=1
else
    echo "PASS: all $checks checks ran"
fi

exit "$status"
