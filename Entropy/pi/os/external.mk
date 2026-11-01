# The KeepCrypt external tree (tasks/todo.md, M4 group 13).
include $(sort $(wildcard $(BR2_EXTERNAL_KEEPCRYPT_PATH)/package/*/*.mk))

# mksquashfs stores no extended attributes, so none from the build host can reach the image.
# Buildroot reads this list only when it runs mksquashfs, after this file is included.
ROOTFS_SQUASHFS_ARGS += -no-xattrs

# The kernel build is given no rustc to probe, as kconfig.sh does, so the build host's default rustc
# cannot change the kernel's .config (CONFIG_RUSTC_VERSION and the rest; CONFIG_RUST is off). Buildroot
# reads LINUX_MAKE_FLAGS, for the kernel's kconfig and its build, after this file is included.
LINUX_MAKE_FLAGS += RUSTC=false
