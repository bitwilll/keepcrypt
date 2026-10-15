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
# configures next is left untouched. The Makefile runs this after `make toolchain host-flex
# host-bison linux-patch` (Kconfig's conf needs flex and bison), with Buildroot's host tools
# first on PATH; Kconfig probes the cross compiler.
#
# Usage: kconfig.sh LINUX_DIR CROSS_COMPILE FRAGMENT OUT_CONFIG WORK_DIR
# Exit 0 written; 1 a fragment line did not hold, or an =m line is left; 2 usage or build error.
#
# kconfig.sh --selftest runs the checks above on a stub kernel tree, with the committed fragment:
# its bcmrpi_defconfig writes a small config with modules, and its olddefconfig keeps each
# symbol's last line, then adds the case's lines, as a select in Kconfig would. Exit 0 needs the
# clean tree written with no =m left (so step 2's edit holds), and exit 1 with the one message,
# nothing written, for a forbidden option selected back on, a required option dropped and a
# module left; and exit 2 for a fragment line of another kind and a bad usage. Exit 0 all
# passed, 1 not.
set -u

die() {
  printf 'kconfig.sh: %s\n' "$1" >&2
  exit 2
}

# kcase NAME WANT-EXIT WANT-LINE ADD [FRAGMENT]: run this script on the stub tree, olddefconfig
# adding the lines of ADD; the exit must be WANT-EXIT and WANT-LINE a whole line of the output,
# and the config is written only on exit 0.
kcase() {
  printf '%s' "$4" >"$st/add" || exit 2
  rm -f "$st/out.config"
  out=$(sh "$self" "$st/linux" "$st/cross-" "${5:-$fragment}" "$st/out.config" "$st/work" 2>&1)
  rc=$?
  ok=no
  if [ "$rc" -eq "$2" ] && printf '%s\n' "$out" | grep -q -x -F -e "$3"; then
    if [ "$rc" -eq 0 ]; then
      [ -f "$st/out.config" ] && ! grep -q -e '=m$' "$st/out.config" && ok=yes
    else
      [ ! -e "$st/out.config" ] && ok=yes
    fi
  fi
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> exit %s: %s\n' "$1" "$rc" "$3"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted exit %s with "%s", got exit %s:\n' "$1" "$2" "$3" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

selftest() {
  self=$0
  fragment=$(cd "$(dirname "$0")" && pwd -P)/board/pizero/linux.fragment
  [ -f "$fragment" ] || die "no fragment: $fragment"
  st=$(mktemp -d "${TMPDIR:-/tmp}/kconfig-selftest.XXXXXX") || exit 2
  trap 'rm -rf "$st"' EXIT
  trap 'exit 2' HUP INT TERM
  mkdir -p "$st/linux/arch/arm/configs" || exit 2
  printf '%s\n' 'CONFIG_MODULES=y' 'CONFIG_SQUASHFS=y' 'CONFIG_I2C=m' 'CONFIG_USB_SERIAL=m' \
    'CONFIG_ZZ_STUB=m' '# CONFIG_DEVMEM is not set' >"$st/linux/arch/arm/configs/bcmrpi_defconfig" ||
    exit 2
  printf '%s\n' '{ sym = "" }' \
    '/^CONFIG_[A-Za-z0-9_]+=/ { sym = $0; sub(/=.*/, "", sym) }' \
    '/^# CONFIG_[A-Za-z0-9_]+ is not set$/ { sym = $2 }' \
    'sym != "" { if (!(sym in last)) order[n++] = sym; last[sym] = $0 }' \
    'END { for (i = 0; i < n; i++) print last[order[i]] }' >"$st/linux/olddefconfig.awk" || exit 2
  printf 'bcmrpi_defconfig:\n\tcp arch/arm/configs/bcmrpi_defconfig $(O)/.config\n' >"$st/linux/Makefile" &&
    printf 'olddefconfig:\n\tawk -f olddefconfig.awk $(O)/.config %s/add >$(O)/.new && mv $(O)/.new $(O)/.config\n' \
      "$st" >>"$st/linux/Makefile" &&
    printf '#!/bin/sh\nexit 0\n' >"$st/cross-gcc" && chmod +x "$st/cross-gcc" || exit 2
  pass=0
  fail=0
  kcase clean 0 "kconfig.sh: $st/out.config written, $(grep -c -e '=y$' "$fragment") options built in" ''
  kcase forbidden-selected-back-on 1 'kconfig.sh: CONFIG_I2C, forbidden, is in the result: CONFIG_I2C=y' \
    'CONFIG_I2C=y'
  kcase required-dropped 1 'kconfig.sh: CONFIG_SQUASHFS is not =y in the result' \
    '# CONFIG_SQUASHFS is not set'
  kcase module-left 1 'kconfig.sh: a module is left: CONFIG_ZZ_STUB=m' 'CONFIG_ZZ_STUB=m'
  { cat "$fragment" && echo 'CONFIG_ZZ_STUB=m'; } >"$st/bad.fragment" || exit 2
  kcase fragment-line-of-another-kind 2 \
    "kconfig.sh: not a required, forbidden, comment or blank line in $st/bad.fragment: CONFIG_ZZ_STUB=m" \
    '' "$st/bad.fragment"
  out=$(sh "$self" 2>&1)
  rc=$?
  if [ "$rc" -eq 2 ] && [ "$out" = 'kconfig.sh: usage: kconfig.sh LINUX_DIR CROSS_COMPILE FRAGMENT OUT_CONFIG WORK_DIR' ]; then
    pass=$((pass + 1))
    printf 'PASS usage -> exit 2: %s\n' "$out"
  else
    fail=$((fail + 1))
    printf 'FAIL usage: wanted exit 2 with the usage line, got exit %s: %s\n' "$rc" "$out"
  fi
  echo "kconfig.sh --selftest: $pass passed, $fail failed"
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

[ $# -eq 1 ] && [ "$1" = --selftest ] && selftest
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
