################################################################################
#
# keepcrypt-pi
#
################################################################################

# The KeepCrypt firmware (tasks/todo.md, M4 group 13; Q37 (c)), built from the Entropy/ checkout
# that holds this external tree, copied without target/ (the local site method never copies .git).
# A generic package, not Buildroot's cargo infrastructure: that builds with Buildroot's Rust
# (1.97.1 in 2026.08, older than the workspace's rust-version), forces a nightly channel override,
# sets overflow checks through the environment and adds -Wl,--allow-multiple-definition on ARM.
# Here rustup's cargo builds with toolchain 1.98.1 from the copy's rust-toolchain.toml, default
# features and the workspace's release profile (panic = "unwind", core's overflow-checks), offline,
# from the crates `make source` fetched into $(KC_WORK)/cargo with `cargo fetch --locked`. Both
# image builds run at the same KC_WORK paths, so no path remapping is needed. The binary keeps its
# symbol table (BR2_STRIP_EXCLUDE_FILES) for the scans.
KEEPCRYPT_PI_VERSION = 0.0.0
KEEPCRYPT_PI_SITE = $(abspath $(BR2_EXTERNAL_KEEPCRYPT_PATH)/../..)
KEEPCRYPT_PI_SITE_METHOD = local
KEEPCRYPT_PI_OVERRIDE_SRCDIR_RSYNC_EXCLUSIONS = --exclude /target
KEEPCRYPT_PI_LICENSE = MIT or Apache-2.0
KEEPCRYPT_PI_LICENSE_FILES = LICENSE-MIT LICENSE-APACHE

ifeq ($(BR_BUILDING)$(BR2_PACKAGE_KEEPCRYPT_PI),yy)
ifeq ($(KC_WORK),)
$(error keepcrypt-pi: KC_WORK is not set; build the image with Entropy/pi/os/Makefile)
endif
endif

# No cargo, rustc or rustup setting from the build host reaches the binary: every CARGO_* and
# RUSTC* variable, RUSTFLAGS, RUSTDOCFLAGS and RUSTUP_TOOLCHAIN is unset first (RUSTUP_HOME stays,
# so rustup finds toolchain 1.98.1), and the lines below are the build's only ones. A host's
# CARGO_ENCODED_RUSTFLAGS, for one, would replace the getrandom cfg below and bring back
# getrandom's fallback to the kernel's random device file (rule 3); a profile override, a wrapper
# or another toolchain would change the binary. The getrandom backend is set for this target alone, as CI's cross job
# sets it; C code (secp256k1-sys) and the link use Buildroot's ARMv6 toolchain.
define KEEPCRYPT_PI_BUILD_CMDS
	cd $(@D) && \
	unset $$(env | sed -nE 's/^(CARGO_[A-Z0-9_]+|RUSTC[A-Z0-9_]*|RUSTFLAGS|RUSTDOCFLAGS|RUSTUP_TOOLCHAIN)=.*/\1/p') && \
	env $(TARGET_MAKE_ENV) \
		CARGO_HOME=$(KC_WORK)/cargo \
		CC_arm_unknown_linux_gnueabihf="$(TARGET_CC)" \
		AR_arm_unknown_linux_gnueabihf="$(TARGET_AR)" \
		CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABIHF_LINKER="$(TARGET_CC)" \
		CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABIHF_RUSTFLAGS='--cfg getrandom_backend="linux_getrandom"' \
		cargo build --release --locked --offline -p keepcrypt-pi --bin keepcrypt-pi \
			--target arm-unknown-linux-gnueabihf
endef

# The installed file is the image's: it is never stripped, so its SHA-256 printed here is the one
# the image scan checks.
define KEEPCRYPT_PI_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/target/arm-unknown-linux-gnueabihf/release/keepcrypt-pi \
		$(TARGET_DIR)/usr/bin/keepcrypt-pi
	cd $(TARGET_DIR) && sha256sum usr/bin/keepcrypt-pi
endef

$(eval $(generic-package))
