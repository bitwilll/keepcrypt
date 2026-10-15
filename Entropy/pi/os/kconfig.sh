#!/bin/sh
# The kernel config of the KeepCrypt image, as an allow-list (tasks/todo.md, M4 group 13; Q37 (b)).
# Raspberry Pi's bcmrpi_defconfig builds about 1,250 options as modules; with modules off, Kconfig
# would build every one of them in (USB serial, webcam and HID drivers, exFAT, NTFS, HFS+ and more,
# many reachable from the USB port). So, in the pinned kernel tree that Buildroot extracted and
# patched (`make linux-patch`), this script:
#   1. runs bcmrpi_defconfig;
#   2. turns every =m line off, and MODULES off;
#   3. appends board/pizero/linux.fragment, whose lines override the same symbols' earlier ones;
#   4. runs olddefconfig;
#   5. checks that every line of the fragment holds in the result (a CONFIG_X=y line is in it as
#      is; for a "# CONFIG_X is not set" line, CONFIG_X has no value) and that no =m line is left;
#   6. writes the result to OUT_CONFIG, the custom config Buildroot builds the kernel with
#      (BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE). Buildroot then applies its own fixups and runs
#      olddefconfig again; pi/os/expected/linux.config is the config the kernel was built with.
# The kernel's build directory is WORK_DIR (made afresh, outside the tree), so the tree Buildroot
# configures next is left untouched. The Makefile runs this after `make toolchain linux-patch`,
# with Buildroot's host tools (flex, bison) first on PATH; Kconfig probes the cross compiler.
#
# Usage: kconfig.sh LINUX_DIR CROSS_COMPILE FRAGMENT OUT_CONFIG WORK_DIR
# Exit 0 written; 1 a fragment line did not hold, or an =m line is left; 2 usage or build error.
set -u

die() {
  printf 'kconfig.sh: %s\n' "$1" >&2
  exit 2
}

[ $# -eq 5 ] || die 'usage: kconfig.sh LINUX_DIR CROSS_COMPILE FRAGMENT OUT_CONFIG WORK_DIR'
src=$1
cross=$2
fragment=$3
out=$4
work=$5
[ -f "$src/Makefile" ] && [ -f "$src/arch/arm/configs/bcmrpi_defconfig" ] ||
  die "not the pinned kernel tree: $src"
[ -x "${cross}gcc" ] || die "no cross compiler: ${cross}gcc"
[ -f "$fragment" ] || die "no fragment: $fragment"
case $work in /?*) ;; *) die "WORK_DIR must be an absolute path: $work" ;; esac

kmake() {
  make -s -C "$src" O="$work" ARCH=arm CROSS_COMPILE="$cross" "$@"
}

rm -rf "$work" && mkdir -p "$work" || die "cannot make $work"
config=$work/.config

# 1-4.
kmake bcmrpi_defconfig || die 'bcmrpi_defconfig failed'
sed -e 's/^\(CONFIG_[A-Za-z0-9_]*\)=m$/# \1 is not set/' \
    -e 's/^CONFIG_MODULES=y$/# CONFIG_MODULES is not set/' "$config" > "$config.new" &&
  cat "$fragment" >> "$config.new" &&
  mv "$config.new" "$config" || die "cannot edit $config"
kmake olddefconfig || die 'olddefconfig failed'

# 5. Every fragment line is a required option, a forbidden one, a comment or blank.
bad=0
while IFS= read -r line; do
  case $line in
    CONFIG_*=y)
      sym=${line%=y}
      if ! grep -qxF -e "$line" "$config"; then
        printf 'kconfig.sh: %s is not =y in the result\n' "$sym" >&2
        bad=1
      fi
      ;;
    '# CONFIG_'*' is not set')
      sym=${line#'# '}
      sym=${sym%' is not set'}
      if grep -q -e "^$sym=" "$config"; then
        printf 'kconfig.sh: %s, forbidden, is in the result: %s\n' "$sym" "$(grep -e "^$sym=" "$config")" >&2
        bad=1
      fi
      ;;
    '#'* | '') ;;
    *) die "not a required, forbidden, comment or blank line in $fragment: $line" ;;
  esac
done < "$fragment"
if grep -q -e '=m$' "$config"; then
  printf 'kconfig.sh: a module is left: %s\n' "$(grep -e '=m$' "$config" | head -n 1)" >&2
  bad=1
fi
[ "$bad" -eq 0 ] || exit 1

# 6.
cp "$config" "$out" || die "cannot write $out"
printf 'kconfig.sh: %s written, %s options built in\n' "$out" "$(grep -c -e '=y$' "$out")"
