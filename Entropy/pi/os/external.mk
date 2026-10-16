# The KeepCrypt external tree (tasks/todo.md, M4 group 13).
include $(sort $(wildcard $(BR2_EXTERNAL_KEEPCRYPT_PATH)/package/*/*.mk))

# mksquashfs stores no extended attributes, so none from the build host can reach the image.
# Buildroot reads this list only when it runs mksquashfs, after this file is included.
ROOTFS_SQUASHFS_ARGS += -no-xattrs
