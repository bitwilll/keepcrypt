#!/bin/sh
# Runs inside Buildroot's fakeroot, on the copy of the root tree the SquashFS is packed from, after
# makedevs has applied the device tables (tasks/todo.md, M4 group 13; 15k). Buildroot's own
# system/device_table.txt makes /var/www and the four /etc/network/*.d directories, so they come
# back after post-build.sh, with /etc/network made 0777; they go here instead.
set -eu

target=$1
# Refuse anything but Buildroot's per-filesystem copy, $(BUILD_DIR)/buildroot-fs/<fs>/target, which
# sits next to the fakeroot script that runs this one (Buildroot 2026.08's fs/common.mk): an empty or
# wrong $1 must never reach the rm below.
case $target in
  /?*/buildroot-fs/*/target) ;;
  *) echo "post-fakeroot.sh: not a Buildroot filesystem copy: $target" >&2; exit 2 ;;
esac
if [ ! -f "$target/../fakeroot" ]; then
  echo "post-fakeroot.sh: no fakeroot script next to $target" >&2
  exit 2
fi

rm -rf "$target/etc/network" "$target/var/www"
