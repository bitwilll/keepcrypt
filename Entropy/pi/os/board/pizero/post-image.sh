#!/bin/sh
# Builds the SD card image (tasks/todo.md, M4 group 13). Buildroot runs it with its images
# directory as $1, BUILD_DIR and SOURCE_DATE_EPOCH in the environment and its host tools on PATH,
# once the kernel, the device tree, the firmware files and rootfs.squashfs are there.
# 1. Every partition-1 input gets the mtime SOURCE_DATE_EPOCH. genimage copies them with mtools'
#    mcopy -sp, without -m, so mtools stamps each file with SOURCE_DATE_EPOCH itself, written as
#    local time (the Makefile sets TZ=UTC); the mtimes set here matter only if partition 1 is
#    ever built with mcopy -m instead.
# 2. genimage builds boot.vfat and the image from genimage.cfg, next to this script. Its root path
#    is an empty directory: genimage only places the prebuilt rootfs.squashfs.
set -eu

images=$1
board=$(cd "$(dirname "$0")" && pwd)
: "${BUILD_DIR:?}" "${SOURCE_DATE_EPOCH:?}"

cd "$images"
touch -d "@$SOURCE_DATE_EPOCH" rpi-firmware/* zImage bcm2708-rpi-zero.dtb

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
rm -rf "$BUILD_DIR/genimage.tmp"
genimage \
  --rootpath "$root" \
  --tmppath "$BUILD_DIR/genimage.tmp" \
  --inputpath "$images" \
  --outputpath "$images" \
  --config "$board/genimage.cfg"
