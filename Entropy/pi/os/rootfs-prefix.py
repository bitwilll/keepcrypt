#!/usr/bin/env python3
"""The root filesystem prefix of a KeepCrypt Pi image (tasks/todo.md, M4 group 9; Q39 (g)).

Python 3.9+, standard library only; CI runs it with -I. At every boot the device hashes its own root
filesystem and shows a prefix of the digest on its boot screen and in About (docs/pi-firmware.md, "Honest
limits of the Pi Zero"). CI publishes the same prefix with each image, computed here from the image's
partition 2 in the steps pi/app/src/device/rootfs.rs follows on the device:
  1. the partition starts with a SquashFS 4.0 superblock: the magic hsqs at byte 0, and version 4.0 (4 and
     0, two little-endian u16s) at bytes 28-31;
  2. its bytes_used, a little-endian u64 at byte 40, covers at least the 96-byte superblock; rounded up to a
     multiple of 4,096 (mksquashfs pads its image to that size), it is the length hashed;
  3. that length lies within the partition;
  4. SHA-256 over exactly those bytes;
  5. the prefix is the digest's first 8 bytes as 16 lowercase hex digits, in four groups of four joined by
     dashes (0123-4567-89ab-cdef).
The length hashed must also equal the size of the build's rootfs.squashfs, which genimage copies into
partition 2, so the device hashes exactly that file.

  rootfs-prefix.py IMAGE ROOTFS_SQUASHFS   print the prefix of partition 2 of IMAGE, a disk image that
                                           starts with an MBR, after checking the length hashed against
                                           the size of ROOTFS_SQUASHFS
  rootfs-prefix.py --selftest              4 checks: the vector, a 4,096-byte image (the magic, version
                                           4.0, bytes_used 4,096, every other byte zero), gives the prefix
                                           that pi/app/src/device/rootfs/tests.rs pins; the vector as
                                           partition 2 of an image; the command line on files; and each
                                           refusal fires

Exit codes: 0 all good, 1 a refusal or a failed check, 2 usage error.
"""

import argparse
import contextlib
import hashlib
import io
import re
import struct
import sys
import tempfile
from pathlib import Path

# The SquashFS 4.0 superblock at the start of the partition: 96 bytes, little-endian.
SUPERBLOCK_LEN = 96
MAGIC = b"hsqs"
VERSION_AT = 28
VERSION_4_0 = b"\x04\x00\x00\x00"
BYTES_USED_AT = 40
# mksquashfs pads its image to a multiple of 4,096 bytes.
PAD = 4096
# The most one read asks for, as on the device: 64 KiB.
CHUNK = 64 * 1024
# The MBR in the image's first 512-byte sector: four 16-byte partition entries from byte 446, each holding
# its first sector and its sector count as little-endian u32s at bytes 8 and 12, then the boot signature.
SECTOR = 512
ENTRIES_AT = 446
ENTRY_LEN = 16
BOOT_SIGNATURE_AT = 510
BOOT_SIGNATURE = b"\x55\xaa"

# The device's test, which pins the vector's prefix in exactly one line.
DEVICE_TEST = Path(__file__).resolve().parent.parent / "app" / "src" / "device" / "rootfs" / "tests.rs"
PINNED_LINE = re.compile(r'^const VECTOR_PREFIX: &str = "([0-9a-f]{4}(?:-[0-9a-f]{4}){3})";$', re.MULTILINE)


class Refused(Exception):
    """The image breaks the rule: on it the device halts with "the root filesystem could not be read"."""


def read_exactly(stream, count):
    """count bytes from stream, or Refused when it ends first."""
    data = stream.read(count)
    if len(data) != count:
        raise Refused("the image ends %d bytes short" % (count - len(data)))
    return data


def hashed_length(superblock, partition_len):
    """The length the prefix hashes, from the partition's first 96 bytes (steps 1 to 3)."""
    if superblock[:4] != MAGIC:
        raise Refused("partition 2 does not start with the SquashFS magic")
    if superblock[VERSION_AT:VERSION_AT + 4] != VERSION_4_0:
        raise Refused("partition 2 is not SquashFS 4.0")
    (bytes_used,) = struct.unpack_from("<Q", superblock, BYTES_USED_AT)
    if bytes_used < SUPERBLOCK_LEN:
        raise Refused("bytes_used %d does not cover the superblock" % bytes_used)
    length = (bytes_used + PAD - 1) // PAD * PAD
    if length > partition_len:
        raise Refused("bytes_used %d rounds to %d bytes, past the partition's %d" % (bytes_used, length, partition_len))
    return length


def rootfs_prefix(stream, partition_len):
    """(the prefix, the length hashed) of the SquashFS image at stream's position, the start of a partition of
    partition_len bytes."""
    superblock = read_exactly(stream, SUPERBLOCK_LEN)
    length = hashed_length(superblock, partition_len)
    digest = hashlib.sha256(superblock)
    left = length - SUPERBLOCK_LEN
    while left:
        chunk = read_exactly(stream, min(left, CHUNK))
        digest.update(chunk)
        left -= len(chunk)
    return grouped(digest.digest()), length


def grouped(digest):
    """The first 8 bytes of a SHA-256 digest as 16 lowercase hex digits, in four groups of four joined by dashes
    (step 5)."""
    digits = digest.hex()[:16]
    return "-".join(digits[i:i + 4] for i in range(0, 16, 4))


def partition_two(image):
    """(offset, length) in bytes of partition 2 in the MBR at the start of image. An empty entry gives length 0,
    which holds no image (step 3)."""
    image.seek(0)
    mbr = read_exactly(image, SECTOR)
    if mbr[BOOT_SIGNATURE_AT:BOOT_SIGNATURE_AT + 2] != BOOT_SIGNATURE:
        raise Refused("the image does not start with an MBR")
    first, sectors = struct.unpack_from("<II", mbr, ENTRIES_AT + ENTRY_LEN + 8)
    return first * SECTOR, sectors * SECTOR


def image_prefix(image, squashfs_size):
    """The prefix of partition 2 of image, whose length hashed must be squashfs_size."""
    offset, length = partition_two(image)
    image.seek(offset)
    prefix, hashed = rootfs_prefix(image, length)
    if hashed != squashfs_size:
        raise Refused("the length hashed, %d bytes, is not the %d bytes of rootfs.squashfs" % (hashed, squashfs_size))
    return prefix


def vector(magic=MAGIC, version=VERSION_4_0, bytes_used=PAD, length=PAD):
    """The vector: a 4,096-byte image holding the magic, version 4.0 and bytes_used 4,096, every other byte
    zero. The arguments change one part of it for the refusals."""
    image = bytearray(length)
    image[:4] = magic
    image[VERSION_AT:VERSION_AT + 4] = version
    struct.pack_into("<Q", image, BYTES_USED_AT, bytes_used)
    return bytes(image)


def disk(rootfs, sectors, signature=BOOT_SIGNATURE):
    """A disk image that starts with an MBR: partition 1 in sectors 1-7, then partition 2 from sector 8,
    `sectors` sectors long, holding rootfs and then 0xa5 bytes, which change the prefix if any is hashed."""
    mbr = bytearray(SECTOR)
    struct.pack_into("<II", mbr, ENTRIES_AT + 8, 1, 7)
    struct.pack_into("<II", mbr, ENTRIES_AT + ENTRY_LEN + 8, 8, sectors)
    mbr[BOOT_SIGNATURE_AT:BOOT_SIGNATURE_AT + 2] = signature
    partition = rootfs + b"\xa5" * (sectors * SECTOR - len(rootfs))
    return bytes(mbr) + bytes(7 * SECTOR) + partition


def pinned_prefix():
    """The vector's prefix, as the device's test pins it."""
    found = PINNED_LINE.findall(DEVICE_TEST.read_text(encoding="utf-8"))
    if len(found) != 1:
        raise ValueError("%s pins the vector's prefix in %d lines, not 1" % (DEVICE_TEST, len(found)))
    return found[0]


def check_vector():
    """The vector, alone, gives the pinned prefix over exactly its 4,096 bytes."""
    pinned = pinned_prefix()
    prefix, hashed = rootfs_prefix(io.BytesIO(vector()), PAD)
    if (prefix, hashed) != (pinned, PAD):
        return ["the vector gives %s over %d bytes; the device's test pins %s over 4096" % (prefix, hashed, pinned)]
    return []


def check_image():
    """The vector as partition 2 gives the pinned prefix, whatever follows it in the partition. Images whose
    bytes_used is 96, the least the rule takes (the superblock alone), or 4,000, padded with zeros to 4,096 as
    mksquashfs pads them, give the prefix of the whole padded file, as on the device."""
    pinned = pinned_prefix()
    problems = []
    for sectors in (8, 9, 64):
        prefix = image_prefix(io.BytesIO(disk(vector(), sectors)), PAD)
        if prefix != pinned:
            problems.append("a partition 2 of %d sectors gives %s, not %s" % (sectors, prefix, pinned))
    for bytes_used in (SUPERBLOCK_LEN, 4000):
        padded = vector(bytes_used=bytes_used)
        want = grouped(hashlib.sha256(padded).digest())
        prefix = image_prefix(io.BytesIO(disk(padded, 9)), len(padded))
        if prefix != want:
            problems.append("bytes_used %d gives %s, not %s, the prefix of the padded file" % (bytes_used, prefix,
                                                                                             want))
    return problems


def check_command():
    """The command line on files: the vector's image prints the pinned prefix and exits 0; with a
    rootfs.squashfs of another size it prints nothing and exits 1."""
    pinned = pinned_prefix()
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        image, squashfs, other = Path(tmp) / "keepcrypt-pi.img", Path(tmp) / "rootfs.squashfs", Path(tmp) / "other"
        image.write_bytes(disk(vector(), 64))
        squashfs.write_bytes(vector())
        other.write_bytes(vector(length=2 * PAD))
        for files, want in (((image, squashfs), (0, pinned + "\n")), ((image, other), (1, ""))):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                status = main([str(path) for path in files])
            if (status, out.getvalue()) != want:
                problems.append("%s gives exit %d and %r, not exit %d and %r" % (files[1].name, status, out.getvalue(),
                                                                               want[0], want[1]))
    return problems


REFUSALS = (
    ("the big-endian magic", lambda: rootfs_prefix(io.BytesIO(vector(magic=b"sqsh")), PAD)),
    ("no magic", lambda: rootfs_prefix(io.BytesIO(vector(magic=bytes(4))), PAD)),
    ("version 3.0", lambda: rootfs_prefix(io.BytesIO(vector(version=b"\x03\x00\x00\x00")), PAD)),
    ("version 4.1", lambda: rootfs_prefix(io.BytesIO(vector(version=b"\x04\x00\x01\x00")), PAD)),
    ("a big-endian 4.0", lambda: rootfs_prefix(io.BytesIO(vector(version=b"\x00\x04\x00\x00")), PAD)),
    ("bytes_used 0", lambda: rootfs_prefix(io.BytesIO(vector(bytes_used=0)), PAD)),
    ("bytes_used 95", lambda: rootfs_prefix(io.BytesIO(vector(bytes_used=95)), PAD)),
    ("bytes_used 4,097 in 4,096 bytes", lambda: rootfs_prefix(io.BytesIO(vector(bytes_used=PAD + 1)), PAD)),
    ("bytes_used 2^64 - 1", lambda: rootfs_prefix(io.BytesIO(vector(bytes_used=2**64 - 1)), PAD)),
    ("an image inside the superblock", lambda: rootfs_prefix(io.BytesIO(vector()[:95]), PAD)),
    ("an image one byte short", lambda: rootfs_prefix(io.BytesIO(vector()[:-1]), PAD)),
    ("no MBR", lambda: image_prefix(io.BytesIO(disk(vector(), 8, signature=bytes(2))), PAD)),
    ("no partition 2", lambda: image_prefix(io.BytesIO(disk(vector(), 0)), PAD)),
    ("a partition 2 of 7 sectors", lambda: image_prefix(io.BytesIO(disk(vector(), 7)), PAD)),
    ("a rootfs.squashfs of another size", lambda: image_prefix(io.BytesIO(disk(vector(), 8)), 2 * PAD)),
)


def check_refusals():
    """Each part of the rule, broken, is refused."""
    problems = []
    for name, call in REFUSALS:
        try:
            call()
        except Refused:
            continue
        problems.append("%s is not refused" % name)
    return problems


def selftest():
    checks = (
        ("the vector gives the prefix pi/app/src/device/rootfs/tests.rs pins", check_vector),
        ("the vector as partition 2 of an image, whatever follows it there; bytes_used 96 and 4,000 padded to 4,096",
         check_image),
        ("the command line on files: the prefix, or a refusal for a rootfs.squashfs of another size",
         check_command),
        ("each refusal fires: magic, version, bytes_used below the superblock or past the partition, a short "
         "image, no MBR, no partition 2, the rootfs.squashfs size", check_refusals),
    )
    failed = 0
    for name, check in checks:
        try:
            problems = check()
        except (OSError, ValueError, Refused) as e:  # an unreadable or wrong pin, or a refused vector
            problems = ["%s: %s" % (type(e).__name__, e)]
        if problems:
            failed += 1
            print("FAIL %s: %s" % (name, "; ".join(problems)))
        else:
            print("ok   %s" % name)
    if failed:
        print("selftest FAILED: %d of %d checks" % (failed, len(checks)))
        return 1
    print("selftest passed: %d checks" % len(checks))
    return 0


def main(argv):
    parser = argparse.ArgumentParser(prog="rootfs-prefix.py",
                                     description="The root filesystem prefix of a KeepCrypt Pi image.")
    parser.add_argument("--selftest", action="store_true",
                        help="run the 4 checks: the vector against the device's pinned prefix, alone and as "
                        "partition 2 of an image, the command line on files, and each refusal")
    parser.add_argument("image", nargs="?", type=Path, metavar="IMAGE", help="the disk image")
    parser.add_argument("rootfs", nargs="?", type=Path, metavar="ROOTFS_SQUASHFS",
                        help="the build's rootfs.squashfs")
    args = parser.parse_args(argv)
    if args.selftest:
        if args.image is not None:
            parser.error("--selftest takes no files")
        return selftest()
    if args.rootfs is None:
        parser.error("IMAGE and ROOTFS_SQUASHFS, or --selftest")
    try:
        squashfs_size = args.rootfs.stat().st_size
        with args.image.open("rb") as image:
            prefix = image_prefix(image, squashfs_size)
    except (Refused, OSError) as e:
        print("rootfs-prefix.py: %s" % e, file=sys.stderr)
        return 1
    print(prefix)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
