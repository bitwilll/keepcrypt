#!/usr/bin/env python3
"""KeepCrypt offline verifier (M0 seed).

Python 3.9+, standard library only, one file. It never generates secrets; it only
recomputes public algorithms from the docs so anyone can check a device offline.

M0 scope: the seal derivation (docs/seal-watchonly-braille.md, "Seal derivation spec",
"The seal image", "Go-ahead code"), vectors/seal.json, the provenance hashes in
vectors/SOURCES.md, and vectors/coldcard/rolls.json re-run through Coldcard's own scripts.
M1 adds the vectors behind core's known-answer tests: vectors/kat.json (SHA-256, SHA-512 and
HMAC from the NIST and RFC 4231 examples, Ed25519 from RFC 8032), whose values are copied from
the standards listed in vectors/SOURCES.md, "Spec values".
C/E recomputation, BIP39 encoding and braille arrive in M2.

The only outside code it runs is Coldcard's public-domain rolls.py and rolls12.py, committed
unmodified under vectors/coldcard/, and only after each file's SHA-256 equals its SOURCES.md
row. Computed vector values come from a committed script that CI re-runs (tasks/lessons.md).
Every seal.json vector also has its values pinned here (vector 1 from CLAUDE.md and the docs,
vectors 2 and 3 independently reproduced), so --write-seal-vectors cannot re-baseline a bug.

Usage:
  verify.py --selftest              5 checks: seal known answers (all 3 vectors), seal.json bytes,
                                    SOURCES.md hashes and coverage, rolls.json against Coldcard's
                                    scripts, kat.json (SHA and HMAC recomputed, its bytes, then its
                                    pinned entries and Ed25519 digest)
  verify.py --write-seal-vectors    regenerate vectors/seal.json
  verify.py --write-kat-vectors     regenerate vectors/kat.json
  --vectors-dir DIR                 testing only: use DIR in place of the repo's vectors/ (made
                                    absolute); a SOURCES.md row `vectors/<p>` then means DIR/<p>

Exit codes: 0 all good, 1 a check failed, 2 usage error.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

REPO_VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "vectors"

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
OKABE_ITO = ("#000000", "#E69F00", "#56B4E9", "#009E73", "#F0E442", "#0072B2", "#D55E00", "#CC79A7")

TAG_SEAL = b"KCE/v1/seal"
TAG_SEAL_TAG = b"KCE/v1/seal-tag"
TAG_GO = b"KCE/v1/go"

# Shared interface: one row per file in vectors/SOURCES.md.
SOURCES_ROW = re.compile(r"^\| `(vectors/[^`]+)` \| `([0-9a-f]{64})` \|")
# Files under vectors/ that SOURCES.md does not list: the files this script generates, and SOURCES.md.
UNLISTED = ("seal.json", "kat.json", "SOURCES.md")
# macOS Finder metadata, written into any folder opened in Finder. .gitignore excludes it, so it
# is never committed and never present in CI. The coverage rule skips a regular file with this
# exact name only if it starts with Finder's magic bytes; any other .DS_Store needs a row, so a
# `git add -f` of arbitrary bytes under that name cannot dodge the rule.
FINDER_METADATA = ".DS_Store"
FINDER_MAGIC = b"\x00\x00\x00\x01Bud1"

# Check 4: Coldcard's scripts under vectors/, how many bytes of E each prints, and the
# rolls.json field its words must equal. rolls12.py prints only the first 16 bytes of E.
COLDCARD_SCRIPTS = (
    ("coldcard/rolls.py", 32, "words_24"),
    ("coldcard/rolls12.py", 16, "words_12"),
)
SCRIPT_TIMEOUT_SECONDS = 30
DICE_ROLLS = re.compile(r"[1-6]+")
WORD_LINE = re.compile(r" *([0-9]+): ([a-z]+)")  # the scripts print '%4d: %s'

# Known answers, one per seal.json vector, compared field by field by check 1. Check 2 only proves
# that seal.json equals what this code generates, so these pins are what stop --write-seal-vectors
# from quietly re-baselining a wrong value (tasks/lessons.md: "pin a vector").
#
# Vector 1, from the spec: CLAUDE.md "Domain constants" (seal code, T, Seal ID, go-ahead G) and
# docs/seal-watchonly-braille.md "Test vector" and "Test-vector seal" (S prefix, lookup prefix,
# colour index 3, grid).
KAT_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
KAT_NONCE_HEX = "0001020304050607"
KAT_EXPECTED = {
    "seed_prefix_hex": "5eb00bbddcf069084889a8ab91555681",
    "seal_code": "JXP3R-DXYAC-JZ1NA-X3RGQ-DJCJJN",
    "seal_code_hashed": "JXP3RDXYACJZ1NAX3RGQDJCJJN",
    "seal_tag_hex": "2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c",
    "seal_id": "5E0G7J6X",
    "lookup_prefix": "2b810",
    "colour_index": 3,
    "colour_hex": "#009E73",
    "grid": [
        "#......#",
        "...##...",
        "........",
        "..####..",
        "##....##",
        "#......#",
        "##.##.##",
        "##.##.##",
    ],
    "go_ahead": {"nonce_hex": KAT_NONCE_HEX, "code": "CF94-BCAJ", "code_compact": "CF94BCAJ"},
}

# Vectors 2 and 3, project vectors: not in CLAUDE.md or docs/. Values as first committed in
# vectors/seal.json, reproduced by two independent implementations of the spec (this file and the
# M0 review's separate stdlib script). Vector 3's T[0] = 0x46 gives colour 6 under the spec's mod 8
# but 2 under mod 4; vector 1's T[0] = 0x2b gives 3 under both, so it cannot catch that bug.
PROJECT_MNEMONIC_2 = " ".join(["abandon"] * 23 + ["art"])
PROJECT_NONCE_2_HEX = "0000000000000000"
PROJECT_EXPECTED_2 = {
    "seed_prefix_hex": "408b285c123836004f4b8842c89324c1",
    "seal_code": "83AA4-1APR2-M76DC-8D2R0-A4N7AZ",
    "seal_code_hashed": "83AA41APR2M76DC8D2R0A4N7AZ",
    "seal_tag_hex": "09c9865cfd7c244f2d8392ad9c370359216221d320227bbc3f78547ab6816491",
    "seal_id": "174RCQ7X",
    "lookup_prefix": "09c98",
    "colour_index": 1,
    "colour_hex": "#E69F00",
    "grid": [
        "##....##",
        "#..##..#",
        "#......#",
        ".##..##.",
        ".#.##.#.",
        "##....##",
        "########",
        "##.##.##",
    ],
    "go_ahead": {"nonce_hex": PROJECT_NONCE_2_HEX, "code": "6K5N-18A8", "code_compact": "6K5N18A8"},
}
PROJECT_MNEMONIC_3 = "legal winner thank year wave sausage worth useful legal winner thank yellow"
PROJECT_NONCE_3_HEX = "ffffffffffffffff"
PROJECT_EXPECTED_3 = {
    "seed_prefix_hex": "878386efb78845b3355bd15ea4d39ef9",
    "seal_code": "K73S9-DEC7T-7VPVV-DSQ7R-8393ZH",
    "seal_code_hashed": "K73S9DEC7T7VPVVDSQ7R8393ZH",
    "seal_tag_hex": "46fa1299207de4446f8442ec14084d4f1377e886fe104a43a92a39c6db8e0206",
    "seal_id": "8VX15690",
    "lookup_prefix": "46fa1",
    "colour_index": 6,
    "colour_hex": "#D55E00",
    "grid": [
        "########",
        "#.#..#.#",
        "...##...",
        "..#..#..",
        "#..##..#",
        "#..##..#",
        "..#..#..",
        "........",
    ],
    "go_ahead": {"nonce_hex": PROJECT_NONCE_3_HEX, "code": "FSPH-2M4T", "code_compact": "FSPH2M4T"},
}

# Public test mnemonics only (CLAUDE.md rule 12), each with a fixed check nonce and its known answer.
SEAL_KNOWN_ANSWERS = (
    ("vector 1 (CLAUDE.md)", KAT_MNEMONIC, KAT_NONCE_HEX, KAT_EXPECTED),
    ("vector 2 (project)", PROJECT_MNEMONIC_2, PROJECT_NONCE_2_HEX, PROJECT_EXPECTED_2),
    ("vector 3 (project)", PROJECT_MNEMONIC_3, PROJECT_NONCE_3_HEX, PROJECT_EXPECTED_3),
)
# seal.json holds exactly these, in this order, so no vector reaches it without a known answer.
SEAL_VECTOR_INPUTS = tuple((mnemonic, nonce_hex) for _, mnemonic, nonce_hex, _ in SEAL_KNOWN_ANSWERS)

SEAL_SPEC = {
    "S": 'PBKDF2-HMAC-SHA512(password = UTF-8 of NFKD(mnemonic), salt = b"mnemonic" (BIP39, empty passphrase), '
    "iterations = 2048, length = 64 bytes)",
    "seal_code": 'top 130 bits of HMAC-SHA256(key = S, msg = b"KCE/v1/seal"), most significant first, as 26 Crockford '
    "base32 chars (0123456789ABCDEFGHJKMNPQRSTVWXYZ); displayed 5-5-5-5-6 joined by '-'",
    "seal_tag": 'T = SHA256(b"KCE/v1/seal-tag" || the 26 ASCII chars of the code, uppercase, no dashes)',
    "seal_id": "first 40 bits of T as 8 Crockford base32 chars",
    "lookup_prefix": "first 5 lowercase hex chars (20 bits) of T",
    "grid": "8 rows x 8 columns; the 32 bits of T[1], T[2], T[3], T[4] (0-based), most significant first, fill "
    "columns 0-3 row by row; column 7-c mirrors column c; '#' = bit 1, '.' = bit 0",
    "colour": "index T[0] mod 8 into the Okabe-Ito palette " + ", ".join(OKABE_ITO),
    "go_ahead": 'G = first 40 bits of SHA256(b"KCE/v1/go" || T (32 raw bytes) || n (8 raw bytes)) as 8 Crockford '
    "base32 chars; displayed XXXX-XXXX",
}

# Check 5: the known answers behind core's Sha256, Sha512, Hmac and Ed25519 KAT groups
# (tasks/todo.md, M1 group 2), copied as published from the documents pinned by SHA-256 in
# vectors/SOURCES.md, "Spec values". Check 5 recomputes every SHA and HMAC value with hashlib and
# hmac, so a mistyped copy fails the self-test instead of reaching kat.json. verify.py has no
# Ed25519 until check 10 (tasks/todo.md, M1 group 7), so the RFC 8032 entry is pinned by SHA-256
# (KAT_ED25519_SHA256 below). The RFC's secret key is not copied: core only verifies signatures
# (tasks/todo.md, M1 Q3).
NIST_SHA256_EXAMPLE = "NIST CSRC FIPS 180-4 example SHA256.pdf"
NIST_SHA512_EXAMPLE = "NIST CSRC FIPS 180-4 example SHA512.pdf"
SHA256_TWO_BLOCK = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
SHA512_TWO_BLOCK = (
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
    b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
)
# (name, source, message, digest hex as published)
KAT_SHA256 = (
    ("empty", "NIST CAVP SHAVS SHA256ShortMsg.rsp, Len = 0", b"",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("abc", NIST_SHA256_EXAMPLE + ", one-block message", b"abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("two-block", NIST_SHA256_EXAMPLE + ", two-block message", SHA256_TWO_BLOCK,
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
)
KAT_SHA512 = (
    ("empty", "NIST CAVP SHAVS SHA512ShortMsg.rsp, Len = 0", b"",
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    ("abc", NIST_SHA512_EXAMPLE + ", one-block message", b"abc",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    ("two-block", NIST_SHA512_EXAMPLE + ", two-block message", SHA512_TWO_BLOCK,
     "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
     "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
)
# (name, source, key, data, HMAC-SHA-256 hex, HMAC-SHA-512 hex as published)
KAT_HMAC = (
    ("rfc4231-case-2", "RFC 4231 section 4.3, Test Case 2", b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
     "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
     "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),
)
# (name, source, public key hex, message, signature hex as published)
KAT_ED25519 = (
    ("rfc8032-test-1", "RFC 8032 section 7.1, TEST 1",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", b"",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
)
# What kat.json must hold, pinned apart from the tables above and from kat_vectors_json(), so that
# neither an edited table nor an edited generator can drop a vector or a field and still pass after
# --write-kat-vectors (tasks/lessons.md: "pin a vector"): (section, entry names in order, the exact
# keys of every entry). Check 5 reads these from the committed file.
KAT_LAYOUT = (
    ("sha256", ("empty", "abc", "two-block"), ("name", "source", "message_ascii", "message_hex", "digest_hex")),
    ("sha512", ("empty", "abc", "two-block"), ("name", "source", "message_ascii", "message_hex", "digest_hex")),
    ("hmac", ("rfc4231-case-2",),
     ("name", "source", "key_ascii", "key_hex", "data_ascii", "data_hex", "hmac_sha256_hex", "hmac_sha512_hex")),
    ("ed25519", ("rfc8032-test-1",),
     ("name", "source", "public_key_hex", "message_ascii", "message_hex", "signature_hex")),
)
# Each Ed25519 entry, pinned until check 10 verifies it: SHA-256 over its exact bytes, public key
# (32) || signature (64) || message. The digest was computed from RFC 8032 section 7.1 TEST 1 as
# parsed out of rfc8032.txt (pinned in vectors/SOURCES.md, "Spec values"), not from KAT_ED25519, so
# a mistyped key or signature fails the self-test even after --write-kat-vectors.
KAT_ED25519_SHA256 = {
    "rfc8032-test-1": "0e1d4c11a5a51315bf2daccae025f9654fd7309bf941e57dece4caeea65c280c",
}
KAT_SPEC = {
    "encoding": "every *_hex value is the exact bytes in lowercase hex; *_ascii is the same bytes as ASCII text",
    "sha256": "digest = SHA-256(message) (FIPS 180-4), 32 bytes",
    "sha512": "digest = SHA-512(message) (FIPS 180-4), 64 bytes",
    "hmac": "HMAC (RFC 2104) of data under key, with SHA-256 (32 bytes) and SHA-512 (64 bytes)",
    "ed25519": "PureEdDSA Ed25519 (RFC 8032 section 5.1): a valid signature (64 bytes) over message under "
    "public_key (32 bytes)",
}


# --- Seal derivation -------------------------------------------------------------------------


def bip39_seed(mnemonic):
    """S = PBKDF2-HMAC-SHA512(UTF-8(NFKD(mnemonic)), b"mnemonic", 2048, 64).

    BIP39 salts with b"mnemonic" + NFKD(passphrase); the seal always uses the empty passphrase
    (CLAUDE.md rule 7), so the salt is exactly the 8 bytes b"mnemonic". NFKD is a no-op for the
    ASCII English word list. The mnemonic is used as given: words joined by single spaces.
    """
    password = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, b"mnemonic", 2048, 64)


def leading_bits(data, bits):
    """The first `bits` bits of `data` as an integer, most significant bit first."""
    if not 0 < bits <= 8 * len(data):
        raise ValueError("bit count out of range")
    return int.from_bytes(data, "big") >> (8 * len(data) - bits)


def crockford_base32(value, chars):
    """`value` as exactly `chars` Crockford base32 digits, most significant first (5 bits each)."""
    if value < 0 or value >> (5 * chars):
        raise ValueError("value does not fit")
    return "".join(CROCKFORD[(value >> (5 * (chars - 1 - i))) & 31] for i in range(chars))


def grouped(code, sizes):
    """Display form: `code` split into groups of `sizes`, joined by '-'."""
    if sum(sizes) != len(code):
        raise ValueError("group sizes do not cover the code")
    parts, start = [], 0
    for size in sizes:
        parts.append(code[start : start + size])
        start += size
    return "-".join(parts)


def seal_code(seed):
    """26 chars: Crockford base32 of the top 130 bits of HMAC-SHA256(key=S, msg=b"KCE/v1/seal").

    S is the 64-byte BIP39 seed. 130 bits = 26 x 5, so there is no padding.
    """
    if len(seed) != 64:
        raise ValueError("S must be 64 bytes")
    mac = hmac.new(seed, TAG_SEAL, hashlib.sha256).digest()
    return crockford_base32(leading_bits(mac, 130), 26)


def seal_tag(code):
    """T = SHA256(b"KCE/v1/seal-tag" || code), 32 bytes.

    `code` is the 26 ASCII chars, uppercase, without the display dashes (15 + 26 = 41 bytes hashed).
    """
    if len(code) != 26 or any(c not in CROCKFORD for c in code):
        raise ValueError("seal code must be 26 uppercase Crockford chars without dashes")
    return hashlib.sha256(TAG_SEAL_TAG + code.encode("ascii")).digest()


def seal_id(tag):
    """8 chars: Crockford base32 of the first 40 bits of T."""
    return crockford_base32(leading_bits(tag, 40), 8)


def lookup_prefix(tag):
    """First 5 lowercase hex chars (20 bits) of T."""
    return tag.hex()[:5]


def seal_grid(tag):
    """8 strings of 8 chars ('#' filled, '.' empty).

    The 32 bits of T[1], T[2], T[3], T[4] (0-based), most significant first, fill columns 0-3
    row by row; column 7-c mirrors column c.
    """
    bits = int.from_bytes(tag[1:5], "big")
    rows = []
    for r in range(8):
        left = "".join("#" if (bits >> (31 - (4 * r + c))) & 1 else "." for c in range(4))
        rows.append(left + left[::-1])
    return rows


def seal_colour(tag):
    """(index, hex): index = T[0] mod 8 into the Okabe-Ito palette."""
    index = tag[0] % 8
    return index, OKABE_ITO[index]


def go_ahead_code(tag, nonce):
    """8 chars: Crockford base32 of the first 40 bits of SHA256(b"KCE/v1/go" || T || n).

    T is the 32 raw tag bytes and n the 8 raw nonce bytes (9 + 32 + 8 = 49 bytes hashed).
    """
    if len(tag) != 32 or len(nonce) != 8:
        raise ValueError("T must be 32 bytes and n 8 bytes")
    return crockford_base32(leading_bits(hashlib.sha256(TAG_GO + tag + nonce).digest(), 40), 8)


# --- Vectors ---------------------------------------------------------------------------------


def seal_vector(mnemonic, nonce_hex):
    """Every seal value for one mnemonic and check nonce, in the fixed seal.json key order."""
    seed = bip39_seed(mnemonic)
    code = seal_code(seed)
    tag = seal_tag(code)
    index, colour = seal_colour(tag)
    go = go_ahead_code(tag, bytes.fromhex(nonce_hex))
    return {
        "mnemonic": mnemonic,
        "seed_prefix_hex": seed[:16].hex(),
        "seal_code": grouped(code, (5, 5, 5, 5, 6)),
        "seal_code_hashed": code,
        "seal_tag_hex": tag.hex(),
        "seal_id": seal_id(tag),
        "lookup_prefix": lookup_prefix(tag),
        "colour_index": index,
        "colour_hex": colour,
        "grid": seal_grid(tag),
        "go_ahead": {"nonce_hex": nonce_hex, "code": grouped(go, (4, 4)), "code_compact": go},
    }


def seal_vectors_json():
    """The exact text of vectors/seal.json: indent 2, fixed key order, ASCII, trailing newline."""
    doc = {
        "description": "KeepCrypt seal and go-ahead vectors. Generated by tools/verify/verify.py "
        "--write-seal-vectors; verify.py --selftest regenerates this file and requires byte equality. "
        "Public BIP39 test mnemonics only, never a real seed.",
        "spec": SEAL_SPEC,
        "vectors": [seal_vector(m, n) for m, n in SEAL_VECTOR_INPUTS],
    }
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=True) + "\n"


def write_vectors(vectors_dir, name, text):
    """Write one generated vectors file (ASCII text) into vectors_dir, which must already exist."""
    path = vectors_dir / name
    try:
        with open(path, "wb") as f:
            f.write(text.encode("ascii"))
    except OSError as e:
        print("cannot write %s: %s" % (path, e.strerror), file=sys.stderr)
        return 1
    print("wrote " + str(path))
    return 0


def write_seal_vectors(vectors_dir):
    """Write seal.json into vectors_dir, which must already exist."""
    return write_vectors(vectors_dir, "seal.json", seal_vectors_json())


def ascii_and_hex(field, data):
    """{field_ascii, field_hex} for `data`, which must be printable ASCII (every KAT input is)."""
    if any(b < 0x20 or b > 0x7E for b in data):
        raise ValueError("%s is not printable ASCII" % field)
    return {field + "_ascii": data.decode("ascii"), field + "_hex": data.hex()}


def kat_vectors_json():
    """The exact text of vectors/kat.json: indent 2, fixed key order, ASCII, trailing newline.

    Every value is the published one from the KAT_* tables; check 5 recomputes the SHA and HMAC
    values instead of trusting them.
    """
    def sha_entries(table):
        return [
            dict({"name": name, "source": source}, **ascii_and_hex("message", message), digest_hex=digest)
            for name, source, message, digest in table
        ]

    doc = {
        "description": "KeepCrypt known-answer vectors for core's Sha256, Sha512, Hmac and Ed25519 KAT groups. "
        "Generated by tools/verify/verify.py --write-kat-vectors; verify.py --selftest recomputes every SHA and "
        "HMAC value with Python's hashlib and hmac, regenerates this file and requires byte equality, and checks "
        "its entry names, its fields and a pinned SHA-256 of the Ed25519 entry. Values are copied as published "
        "from the documents pinned in vectors/SOURCES.md, \"Spec values\".",
        "spec": KAT_SPEC,
        "sha256": sha_entries(KAT_SHA256),
        "sha512": sha_entries(KAT_SHA512),
        "hmac": [
            dict(
                {"name": name, "source": source},
                **ascii_and_hex("key", key),
                **ascii_and_hex("data", data),
                hmac_sha256_hex=mac256,
                hmac_sha512_hex=mac512,
            )
            for name, source, key, data, mac256, mac512 in KAT_HMAC
        ],
        "ed25519": [
            dict({"name": name, "source": source, "public_key_hex": public_key}, **ascii_and_hex("message", message),
                 signature_hex=signature)
            for name, source, public_key, message, signature in KAT_ED25519
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=True) + "\n"


def write_kat_vectors(vectors_dir):
    """Write kat.json into vectors_dir, which must already exist."""
    return write_vectors(vectors_dir, "kat.json", kat_vectors_json())


# --- Self-test -------------------------------------------------------------------------------


def check_known_answers():
    """Every seal.json vector against its pinned known answer. Returns a list of problems.

    The pins must cover every generated field except the input mnemonic, so a field added to
    seal_vector cannot reach seal.json unpinned.
    """
    problems = []
    for name, mnemonic, nonce_hex, expected in SEAL_KNOWN_ANSWERS:
        got = seal_vector(mnemonic, nonce_hex)
        unpinned = [key for key in got if key not in expected and key != "mnemonic"]
        problems += ["%s: %s has no known answer" % (name, key) for key in unpinned]
        problems += [
            "%s: %s: expected %r, got %r" % (name, key, want, got.get(key))
            for key, want in expected.items()
            if got.get(key) != want
        ]
    return problems


def check_generated_file(vectors_dir, name, text, flag):
    """The committed vectors/<name> must equal the regenerated `text` byte for byte."""
    path = vectors_dir / name
    if not path.is_file():
        return ["vectors/%s is missing (run %s)" % (name, flag)]
    committed = path.read_bytes()
    generated = text.encode("ascii")
    if committed == generated:
        return []
    old, new = committed.splitlines(), generated.splitlines()
    for i in range(max(len(old), len(new))):
        a = old[i].decode("utf-8", "replace") if i < len(old) else "<end of file>"
        b = new[i].decode("ascii") if i < len(new) else "<end of file>"
        if a != b:
            return ["vectors/%s line %d is %r, regenerated is %r" % (name, i + 1, a, b)]
    return ["vectors/%s differs from the regenerated text (line endings or final newline)" % name]


def check_seal_json(vectors_dir):
    """The committed seal.json must equal the regenerated text byte for byte."""
    return check_generated_file(vectors_dir, "seal.json", seal_vectors_json(), "--write-seal-vectors")


def is_lower_hex(value, length):
    """True if `value` is exactly `length` bytes as lowercase hex."""
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % (2 * length), value) is not None


def check_kat_known_answers():
    """Recompute every published SHA and HMAC value in the tables with hashlib and hmac.

    The Ed25519 table is checked through kat.json, against KAT_ED25519_SHA256 (check_kat_contents).
    """
    problems = []
    for algorithm, size, table in (("sha256", 32, KAT_SHA256), ("sha512", 64, KAT_SHA512)):
        for name, _, message, published in table:
            got = getattr(hashlib, algorithm)(message).hexdigest()
            if not is_lower_hex(published, size) or got != published:
                problems.append("kat.json %s %s: published %r, hashlib gives %s" % (algorithm, name, published, got))
    for name, _, key, data, mac256, mac512 in KAT_HMAC:
        for algorithm, size, published in (("sha256", 32, mac256), ("sha512", 64, mac512)):
            got = hmac.new(key, data, getattr(hashlib, algorithm)).hexdigest()
            if not is_lower_hex(published, size) or got != published:
                problems.append("kat.json hmac %s HMAC-%s: published %r, hmac gives %s"
                                % (name, algorithm.upper(), published, got))
    return problems


def kat_field(entry, field, size=None):
    """The bytes of `<field>_hex` in a kat.json entry, which must be lowercase hex (of `size` bytes if
    given) and, where the entry also has `<field>_ascii`, the same bytes as that text."""
    value = entry.get(field + "_hex")
    if not isinstance(value, str) or re.fullmatch("(?:[0-9a-f]{2})*", value) is None:
        raise ValueError("kat.json %s: %s_hex is not lowercase hex" % (entry.get("name"), field))
    data = bytes.fromhex(value)
    if size is not None and len(data) != size:
        raise ValueError("kat.json %s: %s_hex is %d bytes, not %d" % (entry.get("name"), field, len(data), size))
    if field + "_ascii" in entry and entry[field + "_ascii"] != data.decode("ascii", "replace"):
        raise ValueError("kat.json %s: %s_ascii and %s_hex differ" % (entry.get("name"), field, field))
    return data


def check_kat_contents(vectors_dir):
    """The committed kat.json itself: the pinned layout (KAT_LAYOUT), every SHA and HMAC value
    recomputed from the file's own inputs, and every Ed25519 entry equal to its pinned digest."""
    path = vectors_dir / "kat.json"
    if not path.is_file():
        return []  # check_generated_file reports it missing
    doc = json.loads(path.read_text(encoding="ascii"))
    if not isinstance(doc, dict):
        return ["kat.json: not a JSON object"]
    problems = []
    for section, names, keys in KAT_LAYOUT:
        entries = doc.get(section)
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            problems.append("kat.json %s: missing, or not a list of objects" % section)
            continue
        got = [e.get("name") for e in entries]
        if got != list(names):
            problems.append("kat.json %s: entries %r, pinned %r" % (section, got, list(names)))
        problems += ["kat.json %s %s: keys %r, pinned %r" % (section, e.get("name"), list(e), list(keys))
                     for e in entries if list(e) != list(keys)]
    if problems:
        return problems
    for algorithm, size in (("sha256", 32), ("sha512", 64)):
        for e in doc[algorithm]:
            got = getattr(hashlib, algorithm)(kat_field(e, "message")).digest()
            if kat_field(e, "digest", size) != got:
                problems.append("kat.json %s %s: digest_hex %s, hashlib gives %s"
                                % (algorithm, e["name"], e["digest_hex"], got.hex()))
    for e in doc["hmac"]:
        for algorithm, size in (("sha256", 32), ("sha512", 64)):
            got = hmac.new(kat_field(e, "key"), kat_field(e, "data"), getattr(hashlib, algorithm)).digest()
            if kat_field(e, "hmac_" + algorithm, size) != got:
                problems.append("kat.json hmac %s: hmac_%s_hex %s, hmac gives %s"
                                % (e["name"], algorithm, e["hmac_%s_hex" % algorithm], got.hex()))
    for e in doc["ed25519"]:
        signed = kat_field(e, "public_key", 32) + kat_field(e, "signature", 64) + kat_field(e, "message")
        got = hashlib.sha256(signed).hexdigest()
        if got != KAT_ED25519_SHA256.get(e["name"]):
            problems.append("kat.json ed25519 %s: SHA-256(public key || signature || message) is %s, pinned %s"
                            % (e["name"], got, KAT_ED25519_SHA256.get(e["name"])))
    return problems


def check_kat_json(vectors_dir):
    """Check 5: the published values recompute, the committed kat.json equals the regenerated text,
    and its contents hold the pinned layout, recomputed values and pinned Ed25519 digest."""
    return (
        check_kat_known_answers()
        + check_generated_file(vectors_dir, "kat.json", kat_vectors_json(), "--write-kat-vectors")
        + check_kat_contents(vectors_dir)
    )


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def parse_sources(text):
    """[(relative path under vectors/, sha256 hex)] from the shared SOURCES.md row regex."""
    rows = []
    for line in text.splitlines():
        m = SOURCES_ROW.match(line)
        if m:
            rows.append((m.group(1)[len("vectors/") :], m.group(2)))
    return rows


def files_under(vectors_dir):
    """(relative POSIX paths of every file under vectors_dir, symlinks found)."""
    files, links = [], []
    for root, dirs, names in os.walk(vectors_dir):
        for name in dirs + names:
            if os.path.islink(os.path.join(root, name)):
                links.append(Path(root, name).relative_to(vectors_dir).as_posix())
        for name in names:
            files.append(Path(root, name).relative_to(vectors_dir).as_posix())
    return sorted(files), sorted(links)


def is_finder_metadata(path):
    """True only for a regular file named .DS_Store whose first 8 bytes are Finder's magic.

    lstat first, so a symlink, FIFO or device under that name is never opened or exempted.
    """
    if path.name != FINDER_METADATA or not stat.S_ISREG(os.lstat(path).st_mode):
        return False
    with open(path, "rb") as f:
        return f.read(len(FINDER_MAGIC)) == FINDER_MAGIC


def check_sources(vectors_dir):
    """Every SOURCES.md row hashes right, and every file under vectors/ has a row."""
    path = vectors_dir / "SOURCES.md"
    if not path.is_file():
        return ["vectors/SOURCES.md is missing"]
    rows = parse_sources(path.read_text(encoding="utf-8"))
    if not rows:
        return ["vectors/SOURCES.md has no provenance rows"]
    problems = []
    listed = set()
    for rel, want in rows:
        if rel in listed:
            problems.append("vectors/%s is listed twice" % rel)
            continue
        listed.add(rel)
        parts = rel.split("/")
        if rel.startswith("/") or "\\" in rel or any(p in ("", ".", "..") for p in parts):
            problems.append("vectors/%s is not a plain path inside vectors/" % rel)
            continue
        target = vectors_dir.joinpath(*parts)
        if not target.is_file():
            problems.append("vectors/%s is listed but missing" % rel)
            continue
        got = sha256_file(target)
        if got != want:
            problems.append("vectors/%s sha256 is %s, SOURCES.md says %s" % (rel, got, want))
    files, links = files_under(vectors_dir)
    problems += ["vectors/%s is a symlink" % rel for rel in links]
    # Real local Finder metadata must not fail the self-test; git never carries it (see
    # FINDER_METADATA). Every other file, hidden or not, still needs a row.
    unlisted = [
        rel
        for rel in files
        if rel not in listed
        and rel not in UNLISTED
        and not is_finder_metadata(vectors_dir.joinpath(*rel.split("/")))
    ]
    problems += ["vectors/%s has no SOURCES.md row" % rel for rel in unlisted]
    return problems


def run_coldcard_script(script, rolls):
    """Run one Coldcard script the way its header says: `echo <rolls> | python3 rolls.py`.

    Isolated (-I: neither the script's directory nor user site-packages is importable), from a
    new empty directory, without PYTHON* environment variables, under a timeout. Returns
    (stdout lines, None) or (None, problem).
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    with tempfile.TemporaryDirectory() as empty_dir:
        try:
            run = subprocess.run(
                [sys.executable, "-I", str(script)],
                input=rolls + "\n",
                cwd=empty_dir,
                env=env,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=SCRIPT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return None, "no result within %d seconds" % SCRIPT_TIMEOUT_SECONDS
    if run.returncode != 0:
        return None, "exit status %d: %s" % (run.returncode, run.stderr.strip()[-300:])
    return run.stdout.splitlines(), None


def first_difference(got, want):
    """Where the printed words first differ from the rolls.json list, for the failure message."""
    if not isinstance(want, list):
        return "rolls.json has no word list"
    for i, (a, b) in enumerate(zip(got, want)):
        if a != b:
            return "word %d is %r, rolls.json says %r" % (i + 1, a, b)
    return "%d words printed, rolls.json has %d" % (len(got), len(want))


def check_coldcard_scripts(vectors_dir):
    """Re-run Coldcard's committed rolls.py and rolls12.py on every case in rolls.json.

    A script runs only if its SHA-256 equals its one SOURCES.md row, so this executes exactly
    the bytes recorded there. Its output is the hex of E (rolls12.py: E[0:16]), then one
    '%4d: word' line per word, with blank and WARNING lines between. The hex must equal
    sha256_hex (or its first 32 chars) and the words words_24 or words_12.
    """
    if not sys.executable:
        return ["cannot find the running Python interpreter to run the scripts"]
    sources = vectors_dir / "SOURCES.md"
    if not sources.is_file():
        return ["vectors/SOURCES.md is missing"]
    rows = parse_sources(sources.read_text(encoding="utf-8"))
    problems, scripts = [], []
    for rel, e_bytes, field in COLDCARD_SCRIPTS:
        script = vectors_dir.joinpath(*rel.split("/"))
        want = [digest for listed, digest in rows if listed == rel]
        if len(want) != 1:
            problems.append("vectors/%s has %d SOURCES.md rows, needs 1; not running it" % (rel, len(want)))
            continue
        if not script.is_file():
            problems.append("vectors/%s is missing" % rel)
            continue
        got = sha256_file(script)
        if got != want[0]:
            problems.append("vectors/%s sha256 is %s, SOURCES.md says %s; refusing to run it" % (rel, got, want[0]))
            continue
        scripts.append((rel, e_bytes, field, script))
    doc = json.loads((vectors_dir / "coldcard" / "rolls.json").read_text(encoding="utf-8"))
    cases = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(cases, list) or not cases:
        return problems + ["vectors/coldcard/rolls.json has no cases"]
    for n, case in enumerate(cases, 1):
        rolls = case.get("rolls") if isinstance(case, dict) else None
        e_hex = case.get("sha256_hex") if isinstance(case, dict) else None
        if not (isinstance(rolls, str) and DICE_ROLLS.fullmatch(rolls)):
            problems.append("rolls.json case %d: rolls must be a string of digits 1-6" % n)
            continue
        if not (isinstance(e_hex, str) and re.fullmatch(r"[0-9a-f]{64}", e_hex)):
            problems.append("rolls.json case %d: sha256_hex must be 64 lowercase hex chars" % n)
            continue
        for rel, e_bytes, field, script in scripts:
            where = "rolls.json case %d (%d rolls) via vectors/%s" % (n, len(rolls), rel)
            lines, error = run_coldcard_script(script, rolls)
            if error:
                problems.append("%s: %s" % (where, error))
                continue
            printed = lines[0] if lines else "<no output>"
            if printed != e_hex[: 2 * e_bytes]:
                problems.append("%s: printed %s, sha256_hex gives %s" % (where, printed, e_hex[: 2 * e_bytes]))
            numbered = [m for m in map(WORD_LINE.fullmatch, lines) if m]
            if [int(m.group(1)) for m in numbered] != list(range(1, len(numbered) + 1)):
                problems.append("%s: word lines are not numbered 1, 2, 3, ..." % where)
            words = [m.group(2) for m in numbered]
            if words != case.get(field):
                problems.append("%s: %s" % (where, first_difference(words, case.get(field))))
    return problems


def selftest(vectors_dir):
    checks = (
        ("seal known answers (CLAUDE.md vector 1, project vectors 2 and 3)", check_known_answers),
        ("vectors/seal.json matches regenerated output", lambda: check_seal_json(vectors_dir)),
        ("vectors/SOURCES.md hashes and coverage", lambda: check_sources(vectors_dir)),
        ("vectors/coldcard/rolls.json matches Coldcard's own scripts", lambda: check_coldcard_scripts(vectors_dir)),
        ("vectors/kat.json: SHA and HMAC values recomputed, file matches regenerated output, pinned entries "
         "and Ed25519 digest", lambda: check_kat_json(vectors_dir)),
    )
    failed = 0
    for name, check in checks:
        try:
            problems = check()
        except (OSError, ValueError) as e:  # unreadable or malformed input fails the check
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
    parser = argparse.ArgumentParser(prog="verify.py", description="KeepCrypt offline verifier (M0).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--selftest", action="store_true",
                      help="run the 5 checks: seal known answers (all 3 vectors), seal.json bytes, SOURCES.md "
                      "hashes and coverage, rolls.json against Coldcard's own scripts, kat.json (SHA and HMAC "
                      "recomputed, its bytes, then its pinned entries and Ed25519 digest)")
    mode.add_argument("--write-seal-vectors", action="store_true", help="regenerate vectors/seal.json")
    mode.add_argument("--write-kat-vectors", action="store_true", help="regenerate vectors/kat.json")
    parser.add_argument("--vectors-dir", type=Path, default=REPO_VECTORS_DIR, metavar="DIR",
                        help="testing only: use DIR in place of the repo's vectors/")
    args = parser.parse_args(argv)
    # Absolute, because check 4 runs the Coldcard scripts by path from a temporary cwd.
    vectors_dir = args.vectors_dir.resolve()
    if args.selftest:
        return selftest(vectors_dir)
    if args.write_seal_vectors:
        return write_seal_vectors(vectors_dir)
    if args.write_kat_vectors:
        return write_kat_vectors(vectors_dir)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
