#!/bin/sh
# Finishes the root tree before Buildroot packs it into the read-only SquashFS (tasks/todo.md, M4
# group 13). Buildroot runs it with its target directory as $1, after the overlay is copied.
# - /mnt/usb, the only mount point the firmware uses: the root is read-only on the device, so it
#   must exist in the image.
# - The skeleton's start-up scripts and shell profile go: BusyBox init runs only the inittab's
#   three lines, and the image has no shell. The image's file lists catch anything else.
# - Only the libraries the two programs load stay: the dynamic loader, libc, libm and libgcc_s
#   (BusyBox needs libc; keepcrypt-pi needs libc, libm and libgcc_s). The external toolchain copies
#   every glibc and GCC runtime library (libstdc++, libgomp, libnss_dns, libresolv and more).
#   usr/lib keeps os-release, which /etc/os-release links to.
# - ldd (a shell script, with no shell to run it), the network scripts and files (the kernel has
#   no network) and the skeleton's empty /var/www go.
set -eu

target=$1
# Refuse anything but Buildroot's target directory, which holds this warning file until the
# root filesystem is packed: an empty or wrong $1 must never reach the rm below.
case $target in
  /?*) ;;
  *) echo "post-build.sh: not an absolute path: $target" >&2; exit 2 ;;
esac
if [ ! -f "$target/THIS_IS_NOT_YOUR_ROOT_FILESYSTEM" ]; then
  echo "post-build.sh: not a Buildroot target directory: $target" >&2
  exit 2
fi

mkdir -p "$target/mnt/usb"
rm -rf "$target/etc/init.d" "$target/etc/profile" "$target/etc/profile.d" "$target/etc/shells"
for f in "$target"/lib/* "$target"/usr/lib/*; do
  case ${f#"$target/"} in
    lib/ld-linux-armhf.so.3 | lib/libc.so.6 | lib/libm.so.6 | lib/libgcc_s.so.1 | usr/lib/os-release) ;;
    *) rm -rf "$f" ;;
  esac
done
rm -rf "$target/usr/bin/ldd" "$target/etc/network" "$target/etc/hosts" "$target/etc/protocols" \
  "$target/etc/services" "$target/etc/nsswitch.conf" "$target/etc/resolv.conf" "$target/var/www"
