# The KeepCrypt Pi image (tasks/todo.md, M4 group 13; Q37, Q38; docs/pi-firmware.md "Build, flash
# and verify"): Buildroot 2026.08 with this directory as its external tree and
# configs/keepcrypt_pizero_defconfig. Linux x86_64 hosts only (Bootlin's toolchain runs on no
# other); run from the checkout, as CI's image workflow does:
#
#   make -C Entropy/pi/os source        fetch Buildroot (refused unless it has pins.txt's SHA-256),
#                                       every download of the build (Buildroot checks each by
#                                       its hash) and the crates (cargo fetch --locked): the only
#                                       target that uses the network
#   make -C Entropy/pi/os image         build the image afresh in $(KC_WORK)/out, offline (a
#                                       missing download fails it), and print its SHA-256
#   make -C Entropy/pi/os repro-check   build it twice in fresh output directories at the same
#                                       path and compare the two images
#   make -C Entropy/pi/os scan          after make image: list the built image (banned-api-check.sh
#                                       --image-lists), then scan it against expected/ (--image, with
#                                       the kernel's .config and the SHA-256 of the keepcrypt-pi
#                                       cargo built, so the packed binary is proved to be that
#                                       file), with the build's host tools first on PATH; it never
#                                       rebuilds, and refuses to run without an image or that file
#   make -C Entropy/pi/os panels        print PANELS below, one name a line: the screen types the
#                                       image workflow builds
#
# image, repro-check and scan are for one screen type and need PANEL=<name>, a name in PANELS
# below, as in make -C Entropy/pi/os image PANEL=st7789-240x240.
#
# KC_WORK (default /kc-work) holds Buildroot, its downloads, the crates and the build. It must be
# an absolute path outside Entropy/ with no spaces, and the same in every build: Buildroot's
# reproducible mode (BR2_REPRODUCIBLE) needs the same output path, and keepcrypt-pi is built at
# fixed paths instead of with path remapping. SOURCE_DATE_EPOCH comes from pins.txt and TZ is UTC,
# so equal trees give equal images whatever the commit or build time; both are printed. No step
# needs git. The image is keepcrypt-pi-0.0.0-<name>.img, one per screen type (Q47; Q43 (b) had
# keepcrypt-pi-0.0.0.img).
SHELL := /bin/sh
.SUFFIXES:

ifneq ($(words $(CURDIR)),1)
$(error the checkout's path has a space in it, which Buildroot cannot build from: $(CURDIR))
endif
ifeq ($(wildcard $(CURDIR)/pins.txt),)
$(error run this Makefile from Entropy/pi/os, as make -C Entropy/pi/os)
endif
include $(CURDIR)/pins.txt
ifneq ($(origin SOURCE_DATE_EPOCH),file)
$(error SOURCE_DATE_EPOCH comes from pins.txt only)
endif

OS := $(CURDIR)
ENTROPY := $(abspath $(OS)/../..)
KC_WORK ?= /kc-work
ifneq ($(words $(KC_WORK)),1)
$(error KC_WORK must be one absolute path with no spaces: "$(KC_WORK)")
endif
ifneq ($(patsubst /%,/,$(KC_WORK)),/)
$(error KC_WORK must be an absolute path: $(KC_WORK))
endif
# KC_WORK as the kernel resolves it, also before make source creates it: its longest existing
# ancestor with every symlink resolved, then the rest of the path ($(realpath) of a path that
# does not exist yet is empty, and $(abspath) resolves no symlink).
KC_WORK_REAL := $(abspath $(shell d=$(KC_WORK); t=; \
	while [ ! -e "$$d" ]; do t=/$$(basename "$$d")$$t; d=$$(dirname "$$d"); done; \
	cd "$$d" 2>/dev/null && printf '%s%s\n' "$$(pwd -P)" "$$t"))
ifeq ($(KC_WORK_REAL),)
$(error KC_WORK cannot be resolved: $(KC_WORK))
endif
ifneq ($(filter /,$(abspath $(KC_WORK)) $(KC_WORK_REAL)),)
$(error KC_WORK must not be /)
endif
ifneq ($(filter $(ENTROPY) $(ENTROPY)/% $(realpath $(ENTROPY)) $(realpath $(ENTROPY))/%,$(abspath $(KC_WORK)) $(KC_WORK_REAL)),)
$(error KC_WORK must be outside Entropy/: $(KC_WORK))
endif

export KC_WORK
export SOURCE_DATE_EPOCH
export TZ := UTC

BR_TARBALL := $(KC_WORK)/dl/buildroot-$(BR_VERSION).tar.xz
BR_SRC := $(KC_WORK)/buildroot-$(BR_VERSION)
OUT := $(KC_WORK)/out

# The screen types (Q47 (a); tasks/todo.md, M4b B3): one image per name, each the name of a
# profile in pi/app's PROFILES (pi/app/src/device/panel.rs). The image path never relies on the
# profile pi/app gives when no name is set: image, repro-check and scan take the name from
# PANEL=<name> and, before anything runs, refuse a PANEL that is missing, empty or not exactly one
# name of PANELS, and print the list. PANEL_NAME, the listed name, is what the build uses, never
# PANEL's own text.
PANELS := st7789-240x240
PANEL_NAME := $(if $(filter 1,$(words $(PANEL))),$(filter $(PANELS),$(PANEL)))
PANEL_USAGE := make image, repro-check and scan need PANEL=<name>, one of: $(PANELS)
ifneq ($(filter image repro-check scan,$(MAKECMDGOALS)),)
ifeq ($(PANEL_NAME),)
ifeq ($(origin PANEL),undefined)
$(error PANEL is not set; $(PANEL_USAGE))
else ifeq ($(strip $(PANEL)),)
$(error PANEL is empty; $(PANEL_USAGE))
else
$(error PANEL="$(PANEL)" is not a name in the list; $(PANEL_USAGE))
endif
endif
endif
IMAGE := keepcrypt-pi-0.0.0-$(PANEL_NAME).img
BR := BR2_DL_DIR=$(KC_WORK)/dl $(MAKE) -C $(BR_SRC) O=$(OUT) BR2_EXTERNAL=$(OS)
# make image never downloads. Buildroot takes a file already in dl/ that has its pinned hash, and
# looks for any other only at its primary site, here dl/ itself (package/pkg-download.mk's
# DOWNLOAD_URIS; support/download/dl-wrapper), so a file make source did not fetch fails the
# build instead of being fetched. Set on the command line, these override the .config's empty
# BR2_PRIMARY_SITE where Buildroot reads them.
BR_OFFLINE := $(BR) BR2_PRIMARY_SITE=file://$(KC_WORK)/dl BR2_PRIMARY_SITE_ONLY=y
# make image's builds also name the screen type: keepcrypt-pi.mk sets KEEPCRYPT_PI_PANEL to it in
# cargo's environment, pi/app's PANEL reads it when keepcrypt-pi is compiled, and the .mk refuses
# an empty one. The Buildroot tree builds keepcrypt-pi.img (board/pizero/genimage.cfg) whatever the
# name; make image then names it $(IMAGE).
BR_IMAGE := $(BR_OFFLINE) KEEPCRYPT_PI_PANEL=$(PANEL_NAME)

# check-pins DIR, PINS: each "hash file:SHA-256:file" of PINS must be a line of DIR's hash file.
define check-pins
	@for pin in $(2); do \
		f=$${pin%%:*}; rest=$${pin#*:}; sha=$${rest%%:*}; file=$${rest#*:}; \
		grep -qxF "sha256  $$sha  $$file" "$(1)/$$f" || \
			{ printf 'pi/os: %s does not pin %s at %s (pins.txt)\n' "$(1)/$$f" "$$file" "$$sha" >&2; exit 1; }; \
	done
endef

define print-time
	@printf 'pi/os: SOURCE_DATE_EPOCH=%s TZ=%s KC_WORK=%s\n' "$$SOURCE_DATE_EPOCH" "$$TZ" "$(KC_WORK)"
endef

.PHONY: source image repro-check scan panels

source:
	$(print-time)
	$(call check-pins,$(OS),$(OS_PINS))
	mkdir -p $(KC_WORK)/dl
	test -f $(BR_TARBALL) || { \
		curl -fsSL --proto '=https' --tlsv1.2 -o $(BR_TARBALL).part $(BR_URL) && \
		mv $(BR_TARBALL).part $(BR_TARBALL); }
	printf '%s  %s\n' $(BR_SHA256) $(BR_TARBALL) | sha256sum -c -
	rm -rf $(BR_SRC)
	tar -xJf $(BR_TARBALL) -C $(KC_WORK)
	$(call check-pins,$(BR_SRC),$(BR_PINS))
	rm -rf $(OUT)
	$(BR) keepcrypt_pizero_defconfig
	$(BR) source
	cd $(ENTROPY) && CARGO_HOME=$(KC_WORK)/cargo cargo fetch --locked

# Buildroot extracts and patches the kernel and builds the toolchain and Kconfig's flex and bison;
# kconfig.sh then writes the allow-list config that the full build compiles the kernel with.
image:
	$(print-time)
	test -d $(BR_SRC) || { echo 'pi/os: no Buildroot in KC_WORK; run make source first' >&2; exit 1; }
	$(call check-pins,$(OS),$(OS_PINS))
	$(call check-pins,$(BR_SRC),$(BR_PINS))
	rm -rf $(OUT)
	$(BR) keepcrypt_pizero_defconfig
	$(BR_IMAGE) toolchain host-flex host-bison linux-patch
	vars=$$($(BR) -s --no-print-directory VARS='LINUX_DIR TARGET_CROSS' printvars) && \
	linux_dir=$$(printf '%s\n' "$$vars" | sed -n 's/^LINUX_DIR=//p') && \
	cross=$$(printf '%s\n' "$$vars" | sed -n 's/^TARGET_CROSS=//p') && \
	PATH="$(OUT)/host/bin:$$PATH" sh $(OS)/kconfig.sh "$$linux_dir" "$$cross" \
		$(OS)/board/pizero/linux.fragment $(OUT)/keepcrypt-linux.config $(OUT)/kconfig
	$(BR_IMAGE)
	mv $(OUT)/images/keepcrypt-pi.img $(OUT)/images/$(IMAGE)
	cd $(OUT)/images && sha256sum $(IMAGE)

repro-check:
	$(MAKE) image
	mkdir -p $(KC_WORK)/repro
	cp $(OUT)/images/$(IMAGE) $(KC_WORK)/repro/first.img
	$(MAKE) image
	sha256sum $(KC_WORK)/repro/first.img $(OUT)/images/$(IMAGE)
	cmp $(KC_WORK)/repro/first.img $(OUT)/images/$(IMAGE)
	@echo 'pi/os: both builds gave the same image'

# The image scan (tasks/todo.md, M4 groups 14 and 15; Q38 (d)) on the image make image left in
# $(OUT): the kernel's .config is the one under $(OUT)/build/linux-*/, and the binary's SHA-256 is
# that of the keepcrypt-pi cargo wrote in the package's build directory (keepcrypt-pi.mk's
# $(@D)/target/...), before Buildroot's install and the SquashFS pack: the scan's Binary rule then
# proves the image's /usr/bin/keepcrypt-pi is the file cargo built. Taken from the image itself
# (as --image-lists prints it) the rule would compare the file with itself and could never fail.
BUILT_BIN := $(OUT)/build/keepcrypt-pi-0.0.0/target/arm-unknown-linux-gnueabihf/release/keepcrypt-pi
scan:
	test -f $(OUT)/images/$(IMAGE) || { echo 'pi/os: no $(IMAGE) in $(OUT)/images; run make image first' >&2; exit 1; }
	test -f $(BUILT_BIN) || { echo 'pi/os: no $(BUILT_BIN), the keepcrypt-pi cargo built; run make image first' >&2; exit 1; }
	set -- $(OUT)/build/linux-*/.config && [ $$# -eq 1 ] && [ -f "$$1" ] || \
		{ echo 'pi/os: not exactly one kernel .config under $(OUT)/build/linux-*/' >&2; exit 1; } && \
	PATH="$(OUT)/host/bin:$$PATH" sh $(ENTROPY)/scripts/banned-api-check.sh --image-lists $(OUT)/images/$(IMAGE) "$$1" && \
	hash=$$(sha256sum $(BUILT_BIN)) && hash=$${hash%% *} && \
	PATH="$(OUT)/host/bin:$$PATH" sh $(ENTROPY)/scripts/banned-api-check.sh --image $(OUT)/images/$(IMAGE) $(OS)/expected "$$1" "$$hash"

# The screen types, one name a line, for the image workflow's matrix (tasks/todo.md, M4b B4): its
# first job reads them from here at the commit it builds, so PANELS stays the one list.
panels:
	@printf '%s\n' $(PANELS)
