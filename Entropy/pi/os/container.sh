#!/bin/sh
# The Pi image's pinned build host (tasks/todo.md, M7 items C1 and C2; Q38 (e)): every pi/os command
# runs in the container pi/os/container/Dockerfile describes (Debian trixie by digest, its packages
# from snapshot.debian.org at one fixed time, rustup-init by SHA-256, the toolchain of
# rust-toolchain.toml), so the build host is a pinned input like Buildroot and its downloads.
# The container is linux/amd64 on every host: the cross toolchain (Bootlin's armv6-eabihf) runs
# on x86_64 only, so an arm64 host runs it under emulation (the owner's answer to C2, 2026-11-22).
# Inside, the keepcrypt checkout is /keepcrypt and the build directory /kc-work, the same in every
# build; commands run as the calling user, so the files they write are the caller's.
#
# Usage (from Entropy/; KC_WORK, the host's build directory, absolute, is mounted at /kc-work):
#   sh pi/os/container.sh build                 build the container (needs the network)
#   sh pi/os/container.sh run CMD [ARG...]      run CMD in a fresh container, in /keepcrypt/Entropy
#   sh pi/os/container.sh tools CMD [ARG...]    the same with the build's host tools
#                                               (/kc-work/out/host/bin) first on PATH, for the scans
#   sh pi/os/container.sh repro-check           make source and image in one fresh container, make
#                                               image again in another, and compare the two images
# Exit: the command's status; 2 for usage or a missing KC_WORK.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
entropy=$(cd "$here/../.." && pwd)
repo=$(cd "$entropy/.." && pwd)
tag=keepcrypt-pi-build:local
platform=linux/amd64

usage() { sed -n '15,21p' "$0" >&2; exit 2; }
[ $# -ge 1 ] || usage
work() {
  case ${KC_WORK:-} in
    /*) [ -d "$KC_WORK" ] || { echo "pi/os/container.sh: no directory KC_WORK=$KC_WORK" >&2; exit 2; } ;;
    *) echo 'pi/os/container.sh: KC_WORK must be an absolute directory' >&2; exit 2 ;;
  esac
}
run() {
  work
  docker run --rm --platform "$platform" --user "$(id -u):$(id -g)" -e HOME=/tmp -e KC_WORK=/kc-work \
    -v "$repo:/keepcrypt" -v "$KC_WORK:/kc-work" -w /keepcrypt/Entropy "$tag" "$@"
}

cmd=$1
shift
case $cmd in
  build)
    [ $# -eq 0 ] || usage
    ctx=$(mktemp -d)
    trap 'rm -rf "$ctx"' EXIT
    cp "$here/container/Dockerfile" "$entropy/rust-toolchain.toml" "$ctx/"
    docker build --platform "$platform" -t "$tag" "$ctx"
    docker run --rm --platform "$platform" "$tag" cat /etc/keepcrypt-packages.txt
    ;;
  run)
    [ $# -ge 1 ] || usage
    run "$@"
    ;;
  tools)
    [ $# -ge 1 ] || usage
    run sh -c 'PATH="/kc-work/out/host/bin:$PATH" exec "$@"' sh "$@"
    ;;
  repro-check)
    [ $# -eq 0 ] || usage
    run make -C pi/os source image
    image=$(run make -s --no-print-directory -C pi/os print-image)
    mkdir -p "$KC_WORK/repro"
    cp "$KC_WORK/out/images/$image" "$KC_WORK/repro/first.img"
    run make -C pi/os image
    sha256sum "$KC_WORK/repro/first.img" "$KC_WORK/out/images/$image"
    cmp "$KC_WORK/repro/first.img" "$KC_WORK/out/images/$image"
    echo 'pi/os: two fresh containers gave the same image'
    ;;
  *) usage ;;
esac
