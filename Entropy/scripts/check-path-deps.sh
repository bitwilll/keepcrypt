#!/bin/sh
# Every package outside the workspace must come from crates.io (CLAUDE.md rule 11, deny.toml
# [sources]). A [patch] or [replace] path or git override, in Cargo.toml or .cargo/config.toml,
# swaps in a local copy that cargo-deny's sources check skips and cargo vet treats as
# first-party: a vendored, edited getrandom would pass both. Coldcard's bug came in this way.
# Two more ways in, also failed here:
# - A vendored crate under the workspace root becomes a workspace member, which every gate
#   skips: silently as a plain path dependency, or openly when listed in [workspace] members.
#   So the members are pinned below, whatever the root Cargo.toml lists: exactly core, ffi,
#   pi/app and pi/sim, by manifest path. A missing one fails too (`cargo clippy --workspace`
#   would no longer lint it). Changing the set is a reviewed change to this script.
# - Cargo config can replace the crates.io source with a vendored directory, which keeps the
#   crates.io source in cargo metadata while swapping the code, and can add [patch], paths
#   overrides and rustflags. The project has no cargo config, so any .cargo/config or
#   .cargo/config.toml under the workspace root (target/ and .git/ aside) fails, and so does one
#   in any parent directory up to the filesystem root: cargo reads those too, so in the
#   keepcrypt monorepo a config at the repo root, above Entropy/, would apply just the same
#   (this also covers ~/.cargo when the checkout is under $HOME). Adding one is a reviewed
#   change to this script.
# Usage: scripts/check-path-deps.sh [MANIFEST]   (default: Cargo.toml in the current directory)
# Exit 0 clean, 1 offenders (each one named), 2 error.
# Needs python3.
set -u

manifest=${1:-Cargo.toml}
if [ ! -f "$manifest" ]; then
    echo "check-path-deps: no such manifest: $manifest" >&2
    exit 2
fi
# --locked: the lockfile is what CI builds, and cargo must not rewrite it here.
# --all-features: a path [patch] reachable only through a feature is in the graph too (deny.toml
# sets all-features = true for the same reason).
if ! meta=$(cargo metadata --locked --all-features --format-version 1 --manifest-path "$manifest"); then
    echo "check-path-deps: cargo metadata failed" >&2
    exit 2
fi

# -I: no PYTHON* variables, no user site, no script directory on sys.path.
printf '%s\n' "$meta" | python3 -I -c '
import json, os, sys

def error(msg):
    print("check-path-deps: " + msg, file=sys.stderr)
    sys.exit(2)

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
# The workspace members, pinned here rather than read from the root Cargo.toml, the file a
# vendored crate would be listed in.
PINNED = ("core", "ffi", "pi/app", "pi/sim")
try:
    meta = json.load(sys.stdin)
    member_ids = set(meta["workspace_members"])
    packages = meta["packages"]
    root = meta["workspace_root"]
    by_id = {p["id"]: p for p in packages}
    members = [by_id[i] for i in sorted(member_ids)]
except (ValueError, KeyError, TypeError) as err:
    error("unreadable cargo metadata: %r" % (err,))

# Every member must be one of the pinned manifests, and every pinned manifest a member.
pinned = {}
for d in PINNED:
    pinned[os.path.realpath(os.path.join(root, d, "Cargo.toml"))] = d + "/Cargo.toml"
unpinned, found = [], set()
for p in members:
    path = os.path.realpath(p["manifest_path"])
    if path in pinned:
        found.add(path)
    else:
        unpinned.append("%s %s at %s" % (p["name"], p["version"], p["manifest_path"]))
missing = [rel for path, rel in pinned.items() if path not in found]

foreign = []
for p in packages:
    if p["id"] in member_ids:
        continue
    if p["source"] != CRATES_IO:
        where = p["source"] if p["source"] else "local path " + p["manifest_path"]
        foreign.append("%s %s from %s" % (p["name"], p["version"], where))

# Every directory under the workspace root, except the top-level target/ and .git/. An unreadable
# directory is an error, since it could hold a config.
def unreadable(err):
    error("cannot scan %s: %s" % (err.filename, err.strerror))

configs = []
for dirpath, dirnames, _ in os.walk(root, onerror=unreadable):
    if dirpath == root:
        dirnames[:] = [d for d in dirnames if d not in ("target", ".git")]
    for name in ("config", "config.toml"):
        path = os.path.join(dirpath, ".cargo", name)
        if os.path.lexists(path):
            configs.append(os.path.relpath(path, root))

# Cargo also reads .cargo/config(.toml) in every parent of the workspace root. Reported by
# absolute path, since they are outside the workspace.
parent = os.path.dirname(os.path.realpath(root))
while True:
    for name in ("config", "config.toml"):
        path = os.path.join(parent, ".cargo", name)
        if os.path.lexists(path):
            configs.append(path)
    up = os.path.dirname(parent)
    if up == parent:
        break
    parent = up

for line in sorted(unpinned):
    print("check-path-deps: workspace member not one of %s: %s" % (", ".join(PINNED), line))
for line in sorted(missing):
    print("check-path-deps: pinned workspace member missing: " + line)
for line in sorted(foreign):
    print("check-path-deps: not from crates.io: " + line)
for line in sorted(configs):
    print("check-path-deps: cargo config file found: " + line)
if unpinned or missing or foreign or configs:
    sys.exit(1)
print("check-path-deps: clean, %d packages outside the workspace, all from crates.io; "
      "workspace members exactly %s; no cargo config files in or above the workspace"
      % (len(packages) - len(member_ids), ", ".join(PINNED)))
'
rc=$?
# 0 clean, 1 offenders; anything else (no python3, a crash) is an error.
case $rc in
    0 | 1) exit "$rc" ;;
    *) exit 2 ;;
esac
