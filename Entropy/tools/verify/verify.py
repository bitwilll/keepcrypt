#!/usr/bin/env python3
"""KeepCrypt offline verifier (M1 seed).

Python 3.9+, standard library only, one file. It never generates secrets; it only
recomputes public algorithms from the docs so anyone can check a device offline.

M0 scope: the seal derivation (docs/seal-watchonly-braille.md, "Seal derivation spec",
"The seal image", "Go-ahead code"), vectors/seal.json, the provenance hashes in
vectors/SOURCES.md, and vectors/coldcard/rolls.json re-run through Coldcard's own scripts.
M1 adds the vectors behind core's known-answer tests: vectors/kat.json (SHA-256, SHA-512 and
HMAC from the NIST and RFC 4231 examples, Ed25519 from RFC 8032), whose values are copied from
the standards listed in vectors/SOURCES.md, "Spec values"; and vectors/keepcrypt.json (pool
records and D, the SP 800-90B health tests, C, mixed and dice-only E, BIP39 words, and the
source-substitution sessions), generated here from the embedded BIP39 English list; and
vectors/braille.json (the SeedBook braille format of docs/seal-watchonly-braille.md "Braille
backup": the UEB grade 1 cells, every word's insert faces, SeedBook number, mirror flags and
read-back neighbours, insert positions, digit text and backup lines), with the docs' computed
counts re-checked from the list; and vectors/watchonly.json (the BIP84 watch-only export: account
xpubs, descriptors with BIP-380 checksums, first addresses, the v1 crypto-account CBOR and UR, and
the deterministic CBOR, Bytewords, CRC-32 and strict single-part UR rules behind the go-ahead QR),
computed with a standard-library secp256k1, RIPEMD-160 and BIP32 on public test mnemonics and
checked against values copied from BIP-84, BIP-380, BCR-2020-005, -007, -012, -015, bip32JP and RFC
8949; and vectors/kcr.json (signed registry snapshots and the KCP1 bucket proofs behind the go-ahead
QR, valid, tampered, stale and future-dated, each naming the result core must give), built with a
standard-library RFC 8032 Ed25519 that signs only with two keys derived from public labels, the
2^20-bucket Merkle tree and the .kcr and KCP1 formats, and checked by verify.py's own verifier.
The verifier's own recomputation of a device's C, E and words, and braille, arrive in M2.

The only outside code it runs is Coldcard's public-domain rolls.py and rolls12.py, committed
unmodified under vectors/coldcard/, and only after each file's SHA-256 equals its SOURCES.md
row. Computed vector values come from a committed script that CI re-runs (tasks/lessons.md).
Every seal.json vector also has its values pinned here (vector 1 from CLAUDE.md and the docs,
vectors 2 and 3 independently reproduced), so --write-seal-vectors cannot re-baseline a bug.

Usage:
  verify.py --selftest              10 checks: seal known answers (all 3 vectors), seal.json bytes,
                                    SOURCES.md hashes and coverage, Coldcard's scripts on every
                                    dice-only case (rolls.json and keepcrypt.json), kat.json (SHA and
                                    HMAC recomputed, its bytes, then its pinned entries and Ed25519
                                    digest), keepcrypt.json (the BIP39 list and encoder, its bytes,
                                    its pinned answers and session record rules), the SP 800-90B
                                    cutoffs, braille.json (its bytes, its pinned answers, the docs'
                                    counts recomputed from the list, the SeedBook PDF's SHA-256),
                                    watchonly.json (the primitives against the standard library and
                                    the copied spec values, BIP-84 and BCR-2020-015 rebuilt, its pins
                                    and decoder cases, its bytes), kcr.json (Ed25519 against RFC 8032
                                    TEST 1-3 and kat.json, the docs' snapshot and proof figures, its
                                    bytes, every case's pinned outcome, the pinned key and roots)
  verify.py --write-seal-vectors    regenerate vectors/seal.json
  verify.py --write-kat-vectors     regenerate vectors/kat.json
  verify.py --write-keepcrypt-vectors  regenerate vectors/keepcrypt.json
  verify.py --write-braille-vectors    regenerate vectors/braille.json
  verify.py --write-watchonly-vectors  regenerate vectors/watchonly.json
  verify.py --write-kcr-vectors        regenerate vectors/kcr.json
  --vectors-dir DIR                 testing only: use DIR in place of the repo's vectors/ (made
                                    absolute); a SOURCES.md row `vectors/<p>` then means DIR/<p>

Exit codes: 0 all good, 1 a check failed, 2 usage error.
"""

import argparse
import datetime
import hashlib
import hmac
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zlib
from pathlib import Path

REPO_VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "vectors"
# The owner's SeedBook (docs/), whose SHA-256 check 8 pins. It is not under vectors/, so
# --vectors-dir does not move it.
SEEDBOOK_PDF = Path(__file__).resolve().parent.parent.parent / "docs" / "KeepCrypt-SeedBook_Braille.pdf"
BRAILLE_DOCS = Path(__file__).resolve().parent.parent.parent / "docs" / "seal-watchonly-braille.md"

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
OKABE_ITO = ("#000000", "#E69F00", "#56B4E9", "#009E73", "#F0E442", "#0072B2", "#D55E00", "#CC79A7")

TAG_SEAL = b"KCE/v1/seal"
TAG_SEAL_TAG = b"KCE/v1/seal-tag"
TAG_GO = b"KCE/v1/go"

# Shared interface: one row per file in vectors/SOURCES.md.
SOURCES_ROW = re.compile(r"^\| `(vectors/[^`]+)` \| `([0-9a-f]{64})` \|")
# Files under vectors/ that SOURCES.md does not list: the files this script generates, and SOURCES.md.
UNLISTED = ("seal.json", "kat.json", "keepcrypt.json", "braille.json", "watchonly.json", "kcr.json", "SOURCES.md")
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
    # docs/seal-watchonly-braille.md "Cell alphabet" (tasks/todo.md, M1 Q6f).
    "seal_id_braille": "⠼⠑⠰⠑⠼⠚⠰⠛⠼⠛⠰⠚⠼⠋⠭",
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
    # Worked by hand from the Q6f rule: 1 7 4 after one number sign, r ends the digits, c and q
    # need no indicator, then 7 and x.
    "seal_id_braille": "⠼⠁⠛⠙⠗⠉⠟⠼⠛⠭",
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
    # By hand: 8, then v and x end the digits, then 1 5 6 9 0 after one number sign.
    "seal_id_braille": "⠼⠓⠧⠭⠼⠁⠑⠋⠊⠚",
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
    "seal_id_braille": "the Seal ID in lowercase through braille.json's text rule (UEB grade 1: a number sign opens "
    "each run of digits, the grade 1 indicator goes before a letter a-j that follows a digit), as Unicode braille",
    "lookup_prefix":"first 5 lowercase hex chars (20 bits) of T",
    "grid": "8 rows x 8 columns; the 32 bits of T[1], T[2], T[3], T[4] (0-based), most significant first, fill "
    "columns 0-3 row by row; column 7-c mirrors column c; '#' = bit 1, '.' = bit 0",
    "colour": "index T[0] mod 8 into the Okabe-Ito palette " + ", ".join(OKABE_ITO),
    "go_ahead": 'G = first 40 bits of SHA256(b"KCE/v1/go" || T (32 raw bytes) || n (8 raw bytes)) as 8 Crockford '
    "base32 chars; displayed XXXX-XXXX",
}

# Check 5: the known answers behind core's Sha256, Sha512, Hmac and Ed25519 KAT groups
# (tasks/todo.md, M1 group 2), copied as published from the documents pinned by SHA-256 in
# vectors/SOURCES.md, "Spec values". Check 5 recomputes every SHA and HMAC value with hashlib and
# hmac, so a mistyped copy fails the self-test instead of reaching kat.json. The RFC 8032 entry is
# pinned by SHA-256 (KAT_ED25519_SHA256 below), and check 10 also verifies it with verify.py's own
# Ed25519 (tasks/todo.md, M1 group 7). The RFC's secret key is not copied: core only verifies
# signatures (tasks/todo.md, M1 Q3).
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
# Each Ed25519 entry, pinned by SHA-256 over its exact bytes, public key (32) || signature (64) ||
# message; check 10 verifies it too, and refuses it with one bit flipped in the key, in R and in S. The digest was computed from RFC 8032 section 7.1 TEST 1 as
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

# Check 6 and vectors/keepcrypt.json: the device leg, the health tests, dice and the seed
# (tasks/todo.md, M1 group 3). The exact bytes are CLAUDE.md "Domain constants" and the owner's
# answers Q6a (pool records, source ids) and Q7 (health-test window, cutoffs and credit). Core's
# source, health, pool, dice and seed modules check their values against keepcrypt.json.
TAG_POOL = b"KCE/v1/pool"
TAG_COMMIT = b"KCE/v1/commit"
TAG_SEED = b"KCE/v1/seed"
# Q6a: each pool record starts with its source id as a u16, big-endian. 0x0003 is reserved for
# the M8 TRNG; the 0x01xx ids are the uncredited extras a shell may name.
SOURCE_IDS = (
    ("os", 0x0001),
    ("hwrng", 0x0002),
    ("trng", 0x0003),
    ("input_timing", 0x0101),
    ("motion", 0x0102),
    ("camera", 0x0103),
    ("microphone", 0x0104),
)
SOURCE_ID = dict(SOURCE_IDS)
OS_BYTES = 64
HWRNG_BITS_PER_BYTE = 4
REQUIRED_BITS = (("pi", 512), ("phone", 256))
# SP 800-90B health tests on raw hwrng bytes (non-binary samples), alpha = 2^-20, H = 4 until lab
# data (CLAUDE.md "Pi device quota"). Check 7 recomputes both cutoffs exactly.
HEALTH_H = 4
ALPHA_LOG2 = 20
RCT_CUTOFF = 6  # 1 + ceil(20 / H), SP 800-90B 4.4.1
APT_WINDOW = 512  # SP 800-90B 4.4.2: 512 for non-binary samples (Q7)
APT_CUTOFF = 62  # 1 + CRITBINOM(512, 2^-4, 1 - 2^-20), SP 800-90B 4.4.2
STARTUP_SAMPLES = 1024  # tested, then discarded, at the start of every hwrng intake (Q13 d)
HW_BYTES_NEEDED = STARTUP_SAMPLES + APT_WINDOW  # 1,536: the first credited window (Q7, Q13 c)
DICE = (
    ("min_rolls_12_words", 50),
    ("min_rolls_24_words", 99),
    ("min_rolls_after_collision", 99),
    ("max_rolls", 256),
    ("millibits_per_roll", 2585),
)
# The roll strings of vectors/coldcard/rolls.json, in its order (vectors/SOURCES.md, "How
# rolls.json was produced"); check 6 requires the committed file to hold exactly these.
COLDCARD_ROLLS = (
    ("coldcard-123456", "123456"),
    ("coldcard-50", ("123456" * 9)[:50]),
    ("coldcard-99", ("654321" * 17)[:99]),
    ("coldcard-100", "1" * 100),
)
DICE_ONLY_ROLLS = COLDCARD_ROLLS + (
    ("sixes-99", "6" * 99),
    ("max-256", ("1625344352614" * 20)[:256]),
)
# Known answers that check 6 compares with the committed keepcrypt.json. Computed on 2026-10-10
# with shasum over the exact bytes, apart from this script (the empty pool, C for D = 00..1f, the
# mixed E), and from Coldcard's published example (dice-only 123456). The pool and
# source-substitution answers were computed on 2026-10-10 by a separate script that does not import
# this one: it rebuilt each record list from CLAUDE.md and Q6a/Q7 (hwrng samples from index 1,024
# on, extras when added, the 64 OS bytes last, no record for empty data), then D and C. They pin the
# session record rules, which byte equality alone would let a changed generator re-baseline: an
# empty record writes nothing (so it gives the one-OS-record D), the startup samples are never
# absorbed, and the OS record goes last. The health indices follow from each stream's construction
# (see keepcrypt_health_cases).
KEEPCRYPT_PINNED = (
    ("pool", "empty", "d_hex", "872caa576626dadadc15fa497046f89cbce93dcb059b917cb2363753353d6b3b"),
    ("pool", "one-os-record", "d_hex", "2b74d8f916fca0ed465c6c7326a0fdfa1e34880f52199007b49c123a9154ed77"),
    ("pool", "empty-record-skipped", "d_hex", "2b74d8f916fca0ed465c6c7326a0fdfa1e34880f52199007b49c123a9154ed77"),
    ("commitment", "d-00-1f", "c_hex", "21778a7463cef10741413d0b80909a1045ba902d6244f519d2520e247cbe2e8c"),
    ("mixed", "d-00-1f-coldcard-50", "e_hex", "b2e18e2cdeb6f07e9dd5d3df8e315fa609fd2ebfe543387a483828553da6eee2"),
    ("dice_only", "coldcard-123456", "e_hex", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"),
    ("source_substitution", "pi", "d_hex", "21e73ab4dc62241459f7273c13a3184ce8c956ea9de8b8010dc603c1ff785a07"),
    ("source_substitution", "pi", "c_hex", "bc5c69a8d2e121dad1776f8b7d6ca6ce4f442ac90f6ac10a3fb1c7f32356bf84"),
    ("source_substitution", "phone", "d_hex", "84c6fbb7c2c977a6fd800f3c1a2888ded9e5c2b279436d000ed4149d46651266"),
    ("source_substitution", "phone", "c_hex", "c4000455431d3c852ffa311673eb034e706e4ee5588432f0957fbe531f9ac1c9"),
)
HEALTH_PINNED = (
    ("stuck", {"result": "fail", "test": "repetition_count", "stage": "startup", "sample": 5}),
    ("alternating", {"result": "fail", "test": "adaptive_proportion", "stage": "startup", "sample": 122}),
    ("counting-1536", {"result": "pass", "tested": 1536, "credited_samples": 512}),
    ("clean-4096", {"result": "pass", "tested": 4096, "credited_samples": 3072}),
    ("runs-of-5", {"result": "pass", "tested": 2048, "credited_samples": 1024}),
    ("run-of-6-startup", {"result": "fail", "test": "repetition_count", "stage": "startup", "sample": 505}),
    ("run-of-6-continuous", {"result": "fail", "test": "repetition_count", "stage": "continuous", "sample": 1505}),
    ("apt-61-per-window", {"result": "pass", "tested": 2048, "credited_samples": 1024}),
    ("apt-62-startup", {"result": "fail", "test": "adaptive_proportion", "stage": "startup", "sample": 500}),
    ("apt-62-continuous", {"result": "fail", "test": "adaptive_proportion", "stage": "continuous", "sample": 2036}),
    ("rct-and-apt-same-sample", {"result": "fail", "test": "repetition_count", "stage": "startup", "sample": 505}),
)
# Check 7: SP 800-90B Table 2 ("Example cutoff values of the Adaptive Proportion Test", page 27 of
# the document pinned in vectors/SOURCES.md, "Spec values"), the entries with whole-number H, as
# (window W, min-entropy H, cutoff C), for alpha = 2^-20.
SP800_90B_TABLE_2 = ((512, 1, 311), (512, 2, 177), (512, 4, 62), (512, 8, 13), (1024, 1, 589))
KEEPCRYPT_SPEC = {
    "encoding": "every *_hex value is the exact bytes in lowercase hex; rolls are ASCII digits 1-6",
    "counter_stream": "SHA-256 counter mode, never a PRNG: SHA256(label || i as 8 bytes big-endian) for i = 0, 1, "
    "2, ..., concatenated, then the first `length` bytes; core's StubEntropy::Stream is the same function",
    "pool": 'SHA-512 over b"KCE/v1/pool" (11 bytes, once, first), then, for each record holding at least one byte: '
    "source id (u16 big-endian) || length (u64 big-endian) || data. A record with no bytes writes nothing. D = the "
    "first 32 bytes of the digest",
    "source_ids": "os 0x0001, hwrng 0x0002, trng 0x0003 (reserved for M8), input_timing 0x0101, motion 0x0102, "
    "camera 0x0103, microphone 0x0104",
    "session_records": "Pi, Mixed mode: each hwrng chunk is health-tested whole, then gives one hwrng record of its "
    "bytes at sample index 1024 or later (the first 1,024 samples are tested, then discarded); each extra gives "
    "one record when added; the 64 OS bytes are absorbed last, at commit. Phone: the extras, then the OS record",
    "health": "SP 800-90B on raw hwrng bytes, alpha = 2^-20, H = 4. Repetition Count (4.4.1): fail when one value "
    "has appeared 6 times in a row, at the 6th. Adaptive Proportion (4.4.2): back-to-back windows of 512 samples "
    "from the first sample; fail when the window's first value has appeared 62 times in that window, itself "
    "included. On one sample the Repetition Count is checked first. sample = the 0-based index in the tester's "
    "stream; stage = startup below 1024, else continuous. A passing stream credits only post-startup samples in "
    "completed windows: floor((tested - 1024) / 512) * 512 samples, at 4 bits each",
    "commitment": 'C = SHA256(b"KCE/v1/commit" || D)',
    "mixed": 'E = SHA256(b"KCE/v1/seed" || D || len(R) as u64 big-endian || R), R = the ASCII rolls',
    "dice_only": "E = SHA256(R), R = the ASCII rolls, the same as Coldcard's rolls.py",
    "words": "words_24 = BIP39 English encoding of all 32 bytes of E; words_12 = BIP39 English encoding of E[0:16]",
}

# Check 8 and vectors/braille.json: the SeedBook braille format (docs/seal-watchonly-braille.md
# "Braille backup"; CLAUDE.md "Braille (SeedBook)"; tasks/todo.md, M1 group 5, Q6f and Q9). Unified
# English Braille grade 1, one cell per letter, no contractions. Dots are numbered as printed: 1-2-3
# down the left column, 4-5-6 down the right. Core's braille module checks its tables against
# braille.json.
BRAILLE_LETTER_DOTS = (
    ("a", "1"), ("b", "12"), ("c", "14"), ("d", "145"), ("e", "15"), ("f", "124"), ("g", "1245"),
    ("h", "125"), ("i", "24"), ("j", "245"), ("k", "13"), ("l", "123"), ("m", "134"), ("n", "1345"),
    ("o", "135"), ("p", "1234"), ("q", "12345"), ("r", "1235"), ("s", "234"), ("t", "2345"),
    ("u", "136"), ("v", "1236"), ("w", "2456"), ("x", "1346"), ("y", "13456"), ("z", "1356"),
)
# The signs of the text rule (Q6f), after the letters in the canonical table: the number sign opens
# a run of digits, the grade 1 indicator goes before a letter a-j that follows a digit, the hyphen,
# and the blank cell (U+2800) that a space becomes.
BRAILLE_SIGN_DOTS = (("number_sign", "3456"), ("grade1_indicator", "56"), ("hyphen", "36"), ("space", ""))
# Inside a run of digits, digit d is written with the cell of BRAILLE_DIGIT_LETTERS[d]: 1-9 = a-i, 0 = j.
BRAILLE_DIGIT_LETTERS = "jabcdefghi"
SEEDBOOK_FACES = 5  # faces 1-5 carry the first five letters (face 6 is the engraved sequence number)
SEEDBOOK_READBACK_FACES = 4  # the first four letters identify every word; read-back covers faces 1-4
SEEDBOOK_LIGHTER_FACE = 5  # the fifth letter is a redundancy check, drawn lighter
SEEDBOOK_INSERTS = 12  # inserts per device: one KeepCrypt Hinge or Screw
SEEDBOOK_WORDS_PER_PAGE = 24
# Known answers check 8 compares with what this file generates, so --write-braille-vectors cannot
# re-baseline a wrong table (tasks/lessons.md: "pin a vector"). The alphabet as printed in
# docs/seal-watchonly-braille.md "Cell alphabet", and its number sign, grade 1 indicator and hyphen:
BRAILLE_DOCS_ALPHABET = (
    "a ⠁  b ⠃  c ⠉  d ⠙  e ⠑  f ⠋  g ⠛  h ⠓  i ⠊  j ⠚",
    "k ⠅  l ⠇  m ⠍  n ⠝  o ⠕  p ⠏  q ⠟  r ⠗  s ⠎  t ⠞",
    "u ⠥  v ⠧  w ⠺  x ⠭  y ⠽  z ⠵",
)
BRAILLE_DOCS_SIGNS = (("number_sign", "⠼", "3456"), ("grade1_indicator", "⠰", "56"), ("hyphen", "⠤", "36"))
# docs "Metal format": "e/i, d/f, h/j and r/w are left-right mirror images, and the only such pairs".
BRAILLE_DOCS_MIRROR_PAIRS = (("e", "i"), ("d", "f"), ("h", "j"), ("r", "w"))
# CLAUDE.md "Braille cross-check vectors" and docs "Insert view examples": (word, SeedBook number,
# faces 1-5 with None for a blank face, the face drawn lighter, the faces flagged as mirror letters).
BRAILLE_SAMPLE_INSERTS = (
    ("abandon", 1, ("a", "b", "a", "n", "d"), 5, (5,)),
    ("act", 20, ("a", "c", "t", None, None), None, ()),
    ("action", 21, ("a", "c", "t", "i", "o"), 5, (4,)),
    ("metal", 1121, ("m", "e", "t", "a", "l"), 5, (2,)),
    ("wire", 2018, ("w", "i", "r", "e", None), None, (1, 2, 3, 4)),
    ("zoo", 2048, ("z", "o", "o", None, None), None, ()),
)
# The text rule (Q6f): the Seal ID and "2026" as printed in the docs; the rest worked by hand from
# the rule. A space is the blank cell U+2800.
BRAILLE_TEXT_VECTORS = (
    ("5e0g7j6x", "⠼⠑⠰⠑⠼⠚⠰⠛⠼⠛⠰⠚⠼⠋⠭"),
    ("2026", "⠼⠃⠚⠃⠋"),
    ("2026-10-09", "⠼⠃⠚⠃⠋⠤⠼⠁⠚⠤⠼⠚⠊"),
    ("cf94-bcaj", "⠉⠋⠼⠊⠙⠤⠃⠉⠁⠚"),
    ("1k", "⠼⠁⠅"),
    ("a1", "⠁⠼⠁"),
    ("1 a", "⠼⠁⠀⠁"),
    ("abandon", "⠁⠃⠁⠝⠙⠕⠝"),
    ("", ""),
)
# Q9: (seed length, position, device, devices, engraved sequence number). Both insert sets of a
# 24-word seed are engraved 01-12, so word 13 is device 2 of 2, insert 01.
BRAILLE_POSITION_PINS = (
    (12, 1, 1, 1, 1), (12, 12, 1, 1, 12),
    (24, 1, 1, 2, 1), (24, 12, 1, 2, 12), (24, 13, 2, 2, 1), (24, 24, 2, 2, 12),
)
# The plaintext backup's braille: lines (Q6e): the first line as printed in docs/build-plan.md
# "Plaintext inside the file", and the last line of each backup_lines mnemonic, by hand.
BRAILLE_BACKUP_LINE_PINS = (
    (KAT_MNEMONIC, 0, "  01 ⠁⠃⠁⠝⠙⠕⠝"),
    (KAT_MNEMONIC, 11, "  12 ⠁⠃⠕⠥⠞"),
    (" ".join(["zoo"] * 23 + ["vote"]), 23, "  24 ⠧⠕⠞⠑"),
)
# Refused in v1 (anything outside a-z, 0-9, space and hyphen): uppercase, punctuation, a tab, a
# non-ASCII letter, a braille cell.
BRAILLE_TEXT_REFUSED = ("5E0G7J6X", "a_b", "a.b", "café", "a\tb", "⠁")
# SHA-256 of braille_table_text() (UTF-8), computed on 2026-10-10 with shasum over the bytes written
# by a separate script that does not import this one. Core's Braille KAT pins the same digest.
BRAILLE_TABLE_SHA256 = "fd75c236d2ab92e0fe682d502a5b4bf2537f78d5ec5630b2bac20a963ece9c9d"
# docs/seal-watchonly-braille.md "Tests and cross-checks", "Metal format" and "Read-back from the
# metal", recomputed from the embedded list by check 8 (tasks/lessons.md): 25 sections totalling
# 2,048 words, pages 001-098 at 24 words per page (each section starts a page), 279 words one mirror
# flip from another word's first four faces, 49 three-letter words that begin longer words, four
# mirror pairs, and 2,048 distinct first-four keys (a blank face counts).
BRAILLE_DOCS_COUNTS = {
    "words": 2048,
    "sections": 25,
    "pages": 98,
    "words_per_page": 24,
    "mirror_pairs": 4,
    "mirror_flip_words": 279,
    "short_prefix_words": 49,
    "distinct_readback_keys": 2048,
}
# The SeedBook's 25 sections (no word starts with x), as counted from the embedded list. The one-time
# comparison with the PDF's printed index, page numbers, word numbers and cover glyphs is recorded in
# tasks/todo.md, Review, "M1: one-time SeedBook PDF check".
BRAILLE_SECTION_COUNTS = (
    ("a", 136), ("b", 117), ("c", 186), ("d", 112), ("e", 100), ("f", 106), ("g", 76), ("h", 64), ("i", 55),
    ("j", 20), ("k", 20), ("l", 76), ("m", 105), ("n", 41), ("o", 55), ("p", 132), ("q", 8), ("r", 108),
    ("s", 250), ("t", 121), ("u", 35), ("v", 46), ("w", 69), ("y", 6), ("z", 4),
)
# BIP39: MS words carry ENT = 32 * MS * 11 / 33 bits of entropy and CS = ENT / 32 checksum bits, so a
# wrong word passes a 12-word phrase's checksum about once in 2^CS tries (docs "Read-back from the
# metal": "about 1 such error in 16"); check 8 recomputes CS.
BIP39_CHECKED_WORDS = 12
# SHA-256 of docs/KeepCrypt-SeedBook_Braille.pdf (13,921,573 bytes), the owner's reference as committed
# in 91dc31a; check 8 re-hashes it.
SEEDBOOK_PDF_SHA256 = "af40ad894afa6cf64399e6c1771fc7b500458509f2350bd67577ce7eba5fc522"
BRAILLE_SPEC = {
    "encoding": "each cell is one Unicode braille pattern, U+2800 + the sum of 2^(d - 1) over its raised dots d "
    "(1-2-3 down the left column, 4-5-6 down the right, as printed); dots are written as their digits ascending; "
    "the JSON escapes every non-ASCII character",
    "letters": "Unified English Braille grade 1, one cell per letter, no contractions; letters are lowercase",
    "mirror": "a cell's left-right mirror swaps dots 1 and 4, 2 and 5, 3 and 6; mirror_pairs are the pairs of "
    "distinct letters whose cells mirror each other",
    "text": "a-z, 0-9, space and hyphen only, anything else refused: a digit outside a run of digits opens one "
    "with the number sign, and digit d is the cell of letter 'jabcdefghi'[d]; a letter a-j right after a digit "
    "takes the grade 1 indicator first; any letter, a space (the blank cell U+2800) or a hyphen ends the run",
    "table_text": "the canonical cell table: for a-z, then number_sign, grade1_indicator, hyphen and space, one "
    "line 'name cell dots' joined by single spaces and ended by LF, with dots '0' for the blank cell; "
    "table_sha256 is SHA-256 of its UTF-8 bytes",
    "words": "one entry per BIP39 English word: number = the SeedBook number, the 1-based list index; faces = "
    "faces 1-5, the first five letters, null for a blank face (a blank face is part of the backup); lighter_face "
    "= 5 when face 5 holds a letter (drawn lighter), else null; mirror_partners = per face, the mirror partner of "
    "its letter (e/i, d/f, h/j, r/w), else null; cells = every letter's cell; readback = the first four letters, "
    "what the user enters (three letters mean face 4 is blank); flip_neighbours = [face, word] for each mirror "
    "letter in faces 1-4 whose flip spells another word's first four faces; prefix_of = the longer words that "
    "begin with this word",
    "sections": "one section per first letter, each starting a new page of 24 words; pages and numbers 1-based",
    "positions": "per seed length, each word position with its device, the number of devices and the engraved "
    "sequence number 01-12: words 1-12 on device 1, words 13-24 on device 2 (Q9)",
    "backup_lines": "the plaintext backup's braille: lines: two spaces, the two-digit position, a space, then "
    "every letter's cell (tasks/todo.md, M1 Q6e)",
}

# Check 9 and vectors/watchonly.json: the watch-only export and the single-part UR code behind it
# (docs/seal-watchonly-braille.md "Watch-only export", "Go-ahead QR"; tasks/todo.md, M1 group 6, Q2,
# Q5 and Q6c). The values below are copied as published from the documents pinned in
# vectors/SOURCES.md, "Spec values"; check 9 requires the generator to reproduce every one, and core's
# ur and descriptor modules check their output against watchonly.json. Public test mnemonics only.
#
# RFC 8949 Appendix A (Table 6), the rows inside the subset core writes: unsigned integers, byte
# strings, arrays, maps, false, true and tags. (diagnostic as printed, item, encoding as printed.)
# An item is ("uint", n), ("bytes", hex), ("array", items), ("map", ((key, value), ...)), ("bool", b)
# or ("tag", n, item).
RFC8949_EXAMPLES = (
    ("0", ("uint", 0), "00"),
    ("1", ("uint", 1), "01"),
    ("10", ("uint", 10), "0a"),
    ("23", ("uint", 23), "17"),
    ("24", ("uint", 24), "1818"),
    ("25", ("uint", 25), "1819"),
    ("100", ("uint", 100), "1864"),
    ("1000", ("uint", 1000), "1903e8"),
    ("1000000", ("uint", 1000000), "1a000f4240"),
    ("1000000000000", ("uint", 1000000000000), "1b000000e8d4a51000"),
    ("18446744073709551615", ("uint", 18446744073709551615), "1bffffffffffffffff"),
    ("false", ("bool", False), "f4"),
    ("true", ("bool", True), "f5"),
    ("1(1363896240)", ("tag", 1, ("uint", 1363896240)), "c11a514b67b0"),
    ("23(h'01020304')", ("tag", 23, ("bytes", "01020304")), "d74401020304"),
    ("24(h'6449455446')", ("tag", 24, ("bytes", "6449455446")), "d818456449455446"),
    ("h''", ("bytes", ""), "40"),
    ("h'01020304'", ("bytes", "01020304"), "4401020304"),
    ("[]", ("array", ()), "80"),
    ("[1, 2, 3]", ("array", (("uint", 1), ("uint", 2), ("uint", 3))), "83010203"),
    ("[1, [2, 3], [4, 5]]", ("array", (("uint", 1), ("array", (("uint", 2), ("uint", 3))),
                                       ("array", (("uint", 4), ("uint", 5))))), "8301820203820405"),
    ("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]",
     ("array", tuple(("uint", n) for n in range(1, 26))),
     "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
    ("{}", ("map", ()), "a0"),
    ("{1: 2, 3: 4}", ("map", ((("uint", 1), ("uint", 2)), (("uint", 3), ("uint", 4)))), "a201020304"),
)
# BCR-2020-012, "Word List": the 256 Bytewords, byte 0x00 first (copyright 2020 Blockchain Commons,
# BSD-2-Clause-Patent; see vectors/SOURCES.md). The minimal encoding of a byte is its word's first and
# last letters.
BYTEWORDS = tuple(
    """
able acid also apex aqua arch atom aunt
away axis back bald barn belt beta bias
blue body brag brew bulb buzz calm cash
cats chef city claw code cola cook cost
crux curl cusp cyan dark data days deli
dice diet door down draw drop drum dull
duty each easy echo edge epic even exam
exit eyes fact fair fern figs film fish
fizz flap flew flux foxy free frog fuel
fund gala game gear gems gift girl glow
good gray grim guru gush gyro half hang
hard hawk heat help high hill holy hope
horn huts iced idea idle inch inky into
iris iron item jade jazz join jolt jowl
judo jugs jump junk jury keep keno kept
keys kick kiln king kite kiwi knob lamb
lava lazy leaf legs liar limp lion list
logo loud love luau luck lung main many
math maze memo menu meow mild mint miss
monk nail navy need news next noon note
numb obey oboe omit onyx open oval owls
paid part peck play plus poem pool pose
puff puma purr quad quiz race ramp real
redo rich road rock roof ruby ruin runs
rust safe saga scar sets silk skew slot
soap solo song stub surf swan taco task
taxi tent tied time tiny toil tomb toys
trip tuna twin ugly undo unit urge user
vast very veto vial vibe view visa void
vows wall wand warm wasp wave waxy webs
what when whiz wolf work yank yawn yell
yoga yurt zaps zero zest zinc zone zoom
"""
    .split()
)
# BCR-2020-012 "Example/Test Vector": the seed body, its CRC-32 and its minimal Bytewords, and the
# "Brutal Encoding" payload, its CRC-32 and minimal Bytewords.
BCR012_BODY_HEX = "d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da"
BCR012_BODY_CRC32 = "c904f40b"
BCR012_BODY_MINIMAL = "tantjzoeadgdstaslplabghydrpfmkbggufgludprfgmaosecffltnsoaawkbd"
BCR012_BRUTAL_PAYLOAD_HEX = "c7098580125e2ab0981253468b2dbc52"
BCR012_BRUTAL_CRC32 = "feac0dea"
BCR012_BRUTAL_MINIMAL = "staslplabghydrpfmkbggufgludprfgmzepsbtwd"
# BCR-2020-005 "UR CBOR Tags": the untagged seed and its single-part UR.
BCR005_SEED_CBOR_HEX = "a10150c7098580125e2ab0981253468b2dbc52"
BCR005_SEED_UR = "ur:seed/oyadgdstaslplabghydrpfmkbggufgludprfgmamdpwmox"
# BIP-84 "Test vectors": the mnemonic, the master and account public keys (zpub, SLIP-132 version
# bytes 04b24746), and three addresses with their public keys. Private keys are not copied.
BIP84_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
BIP84_ROOT_ZPUB = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"
BIP84_ACCOUNT_ZPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
BIP84_ADDRESSES = (
    ("receive_0", (0, 0), "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
    ("receive_1", (0, 1), "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
    ("change_0", (1, 0), "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"),
)
# BIP-380 "Test Vectors", the checksum and character-set cases, named as BIP-380 lists them: (name, string,
# valid). BIP-380 gives the cases no verdict, and its checksum is optional for parsing; "valid" is KeepCrypt's
# rule, the one every export meets: the string ends in '#' and its correct 8-character checksum
# (WATCHONLY_SPEC "bip380").
BIP380_CHECKSUM_VECTORS = (
    ('Valid checksum', 'raw(deadbeef)#89f8spxm', True),
    ('No checksum', 'raw(deadbeef)', False),
    ('Missing checksum', 'raw(deadbeef)#', False),
    ('Too long checksum (9 chars)', 'raw(deadbeef)#89f8spxmx', False),
    ('Too short checksum (7 chars)', 'raw(deadbeef)#89f8spx', False),
    ('Error in payload', 'raw(deedbeef)#89f8spxm', False),
    ('Error in checksum', 'raw(deedbeef)##9f8spxm', False),
    ('Invalid characters in payload', 'raw(Ü)#00000000', False),
)
# BCR-2020-015 "Example/Test Vector": the seed, its seven output descriptors, the master fingerprint,
# each crypto-hdkey (key-data, chain-code, origin components, source and parent fingerprints) with
# the script tags around it, the 773-byte CBOR and its UR. Check 9 rebuilds all of it from the
# mnemonic.
BCR015_MNEMONIC = "shield group erode awake lock sausage cash glare wave crew flame glove"
BCR015_MASTER_FINGERPRINT = 934670036
BCR015_DESCRIPTORS = (
    "pkh([37b5eed4/44'/0'/0']xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu)",
    "sh(wpkh([37b5eed4/49'/0'/0']xpub6CtR1iF4dZPkEyXDwVf3HE74tSwXNMcHtBzX4gwz2UnPhJ54Jz5unHx2syYCCDkvVUmsmoYTmcaHXe1wJppvct4GMMaN5XAbRk7yGScRSte))",
    "wpkh([37b5eed4/84'/0'/0']xpub6BkU445MSEBXbPjD3g2c2ch6mn8yy1SXXQUM7EwjgYiq6Wt1NDwDZ45npqWcV8uQC5oi2gHuVukoCoZZyT4HKq8EpotPMqGqxdZRuapCQ23)",
    "sh(cosigner([37b5eed4/45']xpub68JFLJTH96GUqC6SoVw5c2qyLSt776PGu5xde8ddVACuPYyarvSL827TbZGavuNbKQ8DG3VP9fCXPhQRBgPrS4MPG3zaZgwAGuPHYvVuY9X))",
    "sh(wsh(cosigner([37b5eed4/48'/0'/0'/1']xpub6EC9f7mLFJQoPaqDJ72Zbv67JWzmpXvCYQSecER9GzkYy5eWLsVLbHnxoAZ8NnnsrjhMLduJo9dG6fNQkmMFL3Qedj2kf5bEy5tptHPApNf)))",
    "wsh(cosigner([37b5eed4/48'/0'/0'/2']xpub6EC9f7mLFJQoRQ6qiTvWQeeYsgtki6fBzSUgWgUtAujEMtAfJSAn3AVS4KrLHRV2hNX77YwNkg4azUzuSwhNGtcq4r2J8bLGMDkrQYHvoed))",
    "tr([37b5eed4/86'/0'/0']xpub6DAvL2L5bgGSpDygSQUDpjwE47saoMk2rSRtYhN7Dma7HvnFLTXNrcSC1AmEN8G2SCD958bUwgc6Bew4sAFa2kqYynF8Rmu6P5jMt2FDPtm)",
)
# (script tags, origin components, key-data hex, chain-code hex, source fingerprint, parent fingerprint)
BCR015_OUTPUTS = (
    ((308, 403), ((44, True), (0, True), (0, True)),
     "03eb3e2863911826374de86c231a4b76f0b89dfa174afb78d7f478199884d9dd32",
     "6456a5df2db0f6d9af72b2a1af4b25f45200ed6fcc29c3440b311d4796b70b5b", 934670036, 2583285239),
    ((308, 400, 404), ((49, True), (0, True), (0, True)),
     "02c7e4823730f6ee2cf864e2c352060a88e60b51a84e89e4c8c75ec22590ad6b69",
     "9d2f86043276f9251a4a4f577166a5abeb16b6ec61e226b5b8fa11038bfda42d", 934670036, 2819587291),
    ((308, 404), ((84, True), (0, True), (0, True)),
     "03fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f",
     "72ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a88", 934670036, 224256471),
    ((308, 400, 410), ((45, True),),
     "035ccd58b63a2cdc23d0812710603592e7457573211880cb59b1ef012e168e059a",
     "88d3299b448f87215d96b0c226235afc027f9e7dc700284f3e912a34daeb1a23", 934670036, 934670036),
    ((308, 400, 401, 410), ((48, True), (0, True), (0, True), (1, True)),
     "032c78ebfcabdac6d735a0820ef8732f2821b4fb84cd5d6b26526938f90c050711",
     "7953efe16a73e5d3f9f2d4c6e49bd88e22093bbd85be5a7e862a4b98a16e0ab6", 934670036, 1505139498),
    ((308, 401, 410), ((48, True), (0, True), (0, True), (2, True)),
     "0260563ee80c26844621b06b74070baf0e23fb76ce439d0237e87502ebbd3ca346",
     "2fa0e41c9dc43dc4518659bfcef935ba8101b57dbc0812805dd983bc1d34b813", 934670036, 1505139498),
    ((308, 409), ((86, True), (0, True), (0, True)),
     "02bbb97cf9efa176b738efd6ee1d4d0fa391a973394fbc16e4c5e78e536cd14d2d",
     "4b4693e1f794206ed1355b838da24949a92b63d02e58910bf3bd3d9c242281e6", 934670036, 3469149964),
)
BCR015_CBOR_HEX = (
    "a2011a37b5eed40287d90134d90193d9012fa403582103eb3e2863911826374de86c231a4b76f0b89dfa174afb78d7f4"
    "78199884d9dd320458206456a5df2db0f6d9af72b2a1af4b25f45200ed6fcc29c3440b311d4796b70b5b06d90130a201"
    "86182cf500f500f5021a37b5eed4081a99f9cdf7d90134d90190d90194d9012fa403582102c7e4823730f6ee2cf864e2"
    "c352060a88e60b51a84e89e4c8c75ec22590ad6b690458209d2f86043276f9251a4a4f577166a5abeb16b6ec61e226b5"
    "b8fa11038bfda42d06d90130a201861831f500f500f5021a37b5eed4081aa80f7cdbd90134d90194d9012fa403582103"
    "fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f04582072ede7334d5acf91c6fda622c2"
    "05199c595a31f9218ed30792d301d5ee9e3a8806d90130a201861854f500f500f5021a37b5eed4081a0d5de1d7d90134"
    "d90190d9019ad9012fa4035821035ccd58b63a2cdc23d0812710603592e7457573211880cb59b1ef012e168e059a0458"
    "2088d3299b448f87215d96b0c226235afc027f9e7dc700284f3e912a34daeb1a2306d90130a20182182df5021a37b5ee"
    "d4081a37b5eed4d90134d90190d90191d9019ad9012fa4035821032c78ebfcabdac6d735a0820ef8732f2821b4fb84cd"
    "5d6b26526938f90c0507110458207953efe16a73e5d3f9f2d4c6e49bd88e22093bbd85be5a7e862a4b98a16e0ab606d9"
    "0130a201881830f500f500f501f5021a37b5eed4081a59b69b2ad90134d90191d9019ad9012fa40358210260563ee80c"
    "26844621b06b74070baf0e23fb76ce439d0237e87502ebbd3ca3460458202fa0e41c9dc43dc4518659bfcef935ba8101"
    "b57dbc0812805dd983bc1d34b81306d90130a201881830f500f500f502f5021a37b5eed4081a59b69b2ad90134d90199"
    "d9012fa403582102bbb97cf9efa176b738efd6ee1d4d0fa391a973394fbc16e4c5e78e536cd14d2d0458204b4693e1f7"
    "94206ed1355b838da24949a92b63d02e58910bf3bd3d9c242281e606d90130a201861856f500f500f5021a37b5eed408"
    "1acec7070c"
)
BCR015_UR = (
    "ur:crypto-account/oeadcyemrewytyaolttaadeetaadmutaaddloxaxhdclaxwmfmdeiamecsdsemgtvsjzcncygrkowt"
    "rontzschgezokstswkkscfmklrtauteyaahdcxiehfonurdppfyntapejpproypegrdawkgmaewejlsfdtsrfybdehcaflmt"
    "rlbdhpamtaaddyoeadlncsdwykaeykaeykaocyemrewytyaycynlytsnyltaadeetaadmhtaadmwtaaddloxaxhdclaostve"
    "lfemdyynwydwyaievosrgmambklovabdgypdglldvespsthysadamhpmjeinaahdcxntdllnaaeykoytdacygegwhgjsiyon"
    "pywmcmrpwphsvodsrerozsbyaxluzcoxdpamtaaddyoeadlncsehykaeykaeykaocyemrewytyaycypdbskeuytaadeetaad"
    "mwtaaddloxaxhdclaxzcfxeegdrpmogrgwkbzctlttweadkiengrwlhtprremouoluutqdpfbncedkynfhaahdcxjpwevdeo"
    "gthttkmeswzcolcpsaahcfnshkhtehytclmnteatmoteadtlwynnftloamtaaddyoeadlncsghykaeykaeykaocyemrewyty"
    "aycybthlvytstaadeetaadmhtaadnytaaddloxaxhdclaxhhsnhdrpftdwuocntilydibehnecmovdfekpjkclcslasbhkpa"
    "wsaddmcmmnahnyaahdcxlotedtndfymyltclhlmtpfsadscnhtztaolbnnkistaedegwfmmedreetnwmcycnamtaaddyoead"
    "lfcsdpykaocyemrewytyaycyemrewytytaadeetaadmhtaadmetaadnytaaddloxaxhdclaxdwkswmztpytnswtsecnblfba"
    "yajkdldeclqzzolrsnhljedsgminetytbnahatbyaahdcxkkguwsvyimjkvwteytwztyswvendtpmncpasfrrylprnhtkbln"
    "drgrmkoyjtbkrpamtaaddyoeadlocsdyykaeykaeykadykaocyemrewytyaycyhkrpnddrtaadeetaadmetaadnytaaddlox"
    "axhdclaohnhffmvsbndslrfgclpfjejyatbdpebacnzokotofxntaoemvskpaowmryfnotfgaahdcxdlnbvecentssfsssgy"
    "lnhkrstoytecrdlyadrekirfaybglahltalsrfcaeerobwamtaaddyoeadlocsdyykaeykaeykaoykaocyemrewytyaycyhk"
    "rpnddrtaadeetaadnltaaddloxaxhdclaorkrhkeytwsoykorletwstbwycagtbsotmeptjkesgwrfcmveskvdmngujzttgt"
    "dpaahdcxgrfgmuvyylmwcxjtttechplslgoegagaptdniatidmhdmebdwfryfsnsdkcplyvaamtaaddyoeadlncshfykaeyk"
    "aeykaocyemrewytyaycytostatbngmdavolk"
)
# bip32JP test_JP_BIP39.json, entry 0 (public domain): its passphrase, which NFKD changes, and the
# seed of its Japanese mnemonic under that passphrase, which pins NFKD of both inputs.
BIP32JP_PASSPHRASE = "㍍ガバヴァぱばぐゞちぢ十人十色"
BIP32JP_MNEMONIC = "あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あいこくしん\u3000あおぞら"
BIP32JP_SEED_HEX = (
    "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c"
    "467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55"
)
# Answers pinned by the plan (tasks/todo.md, M1 group 6), each first computed by the planner and now
# reproduced here: (wallet, field, value). Byte equality alone would let a changed generator
# re-baseline them (tasks/lessons.md).
WATCHONLY_PINNED = (
    ("abandon", "fingerprint", "73c5da0a"),
    ("abandon", "receive_checksum", "afwvtk2s"),
    ("abandon", "change_checksum", "vatdkr6g"),
    ("abandon", "crypto_account_cbor_bytes", 116),
    ("abandon", "crypto_account_ur_chars", 258),
    ("abandon-trezor", "fingerprint", "b4e3f5ed"),
    ("abandon-trezor", "receive_checksum", "l3mwu4e8"),
    ("abandon-bip32jp", "fingerprint", "5d00908e"),
    ("abandon-bip32jp", "unnormalized_fingerprint", "68896147"),
    ("shield", "fingerprint", "37b5eed4"),
)
# The wallets watchonly.json exports: (name, mnemonic, BIP39 passphrase or None). Public test
# mnemonics only (CLAUDE.md rule 12). "TREZOR " differs from "TREZOR": a passphrase is never trimmed.
WATCHONLY_WALLETS = (
    ("abandon", KAT_MNEMONIC, None),
    ("abandon-trezor", KAT_MNEMONIC, "TREZOR"),
    ("abandon-trezor-space", KAT_MNEMONIC, "TREZOR "),
    ("abandon-bip32jp", KAT_MNEMONIC, BIP32JP_PASSPHRASE),
    ("shield", BCR015_MNEMONIC, None),
    ("zoo-24", " ".join(["zoo"] * 23 + ["vote"]), None),
)
# Byte strings whose single-part UR (type "bytes", BCR-2020-005's test type) pins every CBOR head
# length form, and the longest such UR within 4,296 characters: 2,136 bytes give 4,295 characters.
UR_BYTES_LENGTHS = (0, 1, 23, 24, 255, 256, 771, 2136)
UR_MAX_CHARS = 4296  # the largest QR alphanumeric capacity (version 40-L); Q6c
# The CRC-32/ISO-HDLC check value, the CRC of the nine ASCII bytes "123456789" (tasks/todo.md, M1
# group 6); check 9 also compares every CRC with zlib's.
CRC32_CHECK_VALUE = "cbf43926"
WATCHONLY_SPEC = {
    "encoding": "every *_hex value is the exact bytes in lowercase hex; fingerprints are 4 bytes",
    "cbor": "deterministic CBOR (dCBOR) subset: unsigned integers, byte strings, arrays, maps, false, true and tags, "
    "each head in its shortest form, definite lengths only, map keys unique and in ascending order of their "
    "encoded bytes. An item is {\"uint\": n}, {\"bytes\": hex}, {\"array\": [items]}, {\"map\": [[key, value], ...]}, "
    "{\"bool\": b} or {\"tag\": n, \"item\": item}",
    "crc32": "CRC-32/ISO-HDLC (reflected polynomial 0xedb88320, init and final XOR 0xffffffff), written big-endian",
    "bytewords": "minimal Bytewords (BCR-2020-012): each byte as the first and last letters of its word in "
    "bytewords.words",
    "ur": "single-part UR (BCR-2020-005): 'ur:' + type + '/' + minimal Bytewords of (CBOR || CRC-32 of the CBOR, "
    "big-endian); lowercase, and QR text is the same in uppercase",
    "ur_decoder": "core's strict reader, over the UTF-8 bytes of the text, in this order: at most 4,296 bytes before "
    "any decoding, which is 4,296 characters of the ASCII a QR alphanumeric code holds (TooLong); all lowercase or all "
    "uppercase ASCII letters (MixedCase); the scheme 'ur:' and a '/' after the type (NotUr); the expected type "
    "(WrongType); exactly one path segment after the type (MultiPart); an even number of bytes (OddLength); every "
    "pair one of the 256 minimal Bytewords, so any byte of a non-ASCII character fails here (UnknownByteword); at "
    "least 4 bytes, the last 4 the CRC-32 of the rest (BadChecksum); one CBOR byte string (NotByteString, also for a "
    "reserved or cut-off head or fewer bytes than the head gives), with a definite (IndefiniteLength) shortest-form "
    "head (NonShortestHead), and nothing after it (TrailingBytes)",
    "bip32": "BIP32 from S = PBKDF2-HMAC-SHA512(UTF-8 of NFKD(mnemonic), 'mnemonic' + NFKD(passphrase), 2048, 64); "
    "account m/84h/0h/0h; fingerprints are the first 4 bytes of HASH160 of the compressed public key; xpub "
    "version bytes 0488b21e",
    "descriptors": "wpkh([fingerprint/84h/0h/0h]xpub/0/*) and wpkh(.../1/*), hardened steps written 'h', each with "
    "its BIP-380 checksum after '#'; receive_descriptor_apostrophe is the same receive descriptor written with \"'\", "
    "which core never emits (its checksum differs)",
    "addresses": "first_receive_address = m/84h/0h/0h/0/0, first_change_address = m/84h/0h/0h/1/0, P2WPKH mainnet "
    "bech32 (BIP-173)",
    "crypto_account": "BCR-2020-015 v1 crypto-account, untagged at the top level: {1: master fingerprint, 2: "
    "[308(404(303({3: key-data, 4: chain-code, 6: 304({1: [84, true, 0, true, 0, true], 2: master fingerprint}), 8: "
    "parent fingerprint})))]}; a zero source or parent fingerprint is omitted (BCR-2020-007: uint32 .ne 0)",
    "bip380": "BIP-380's checksum and character-set test cases, named as it lists them. BIP-380 gives them no "
    "verdict and makes the checksum optional for parsing; valid = true means the string ends in '#' and its correct "
    "8-character checksum, KeepCrypt's rule, which every export meets. A parser following BIP-380 may accept 'No "
    "checksum'",
    "passphrase": "the BIP39 passphrase is NFKD-normalized before PBKDF2 and never trimmed; "
    "unnormalized_fingerprint is the master fingerprint without NFKD, which core must never give",
}

# Check 10 and vectors/kcr.json: the signed registry snapshot (.kcr), the signed bucket proof (KCP1)
# behind the go-ahead QR, and the Ed25519 signature over both (docs/seal-watchonly-braille.md "Snapshot
# format", "Go-ahead QR", "Go-ahead code"; CLAUDE.md "Bucket proof", "Check nonce", "Go-ahead code";
# tasks/todo.md, M1 group 7, Q3, Q6b, Q6c). Core's seal module verifies the same bytes with
# ed25519-dalek's verify_strict and checks its results against kcr.json; the M2 verifier re-checks a
# seal against a snapshot with the same code.
TAG_BUCKET = b"KCE/v1/bucket"
BUCKET_BITS = 20  # the lookup prefix: 2^20 buckets
KCR_MAGIC = b"KCR1"
KCP_MAGIC = b"KCP1"
KCR_VERSION = 1
KCR_HEADER_BYTES = 58  # magic 4, version 2, number 8, date 4, count 8, root 32
KCR_SIGNED_BYTES = KCR_HEADER_BYTES + 64  # the header and its signature: 122
KCR_ENTRY_BYTES = 18  # T[0..16] and a u16 registration count
KCR_MAX_ENTRIES = 1 << 22  # the loader's limit (Q6b)
KCP_BASE_BYTES = len(KCP_MAGIC) + KCR_SIGNED_BYTES + 3 + 2 + 32 * BUCKET_BITS  # 771, before the k entries
KCP_UR_TYPE = "keepcrypt-proof"
FRESH_DAYS = 30  # a snapshot or proof is Stale from day 31 (docs "Freshness"; Q5)
# The "today" the freshness cases are measured against: 2026 is not a leap year, so today - 30 and
# today - 31 fall in January and pin February's 28 days.
KCR_TODAY = 20260301
# The two Ed25519 keys verify.py signs with, each derived from a public label: the 32-byte secret seed
# is SHA-256(label). The first is the test registry key that core pins under its test-registry feature
# (CLAUDE.md rule 10; Q3); the second signs the wrong-key cases. verify.py takes no key input and signs
# with nothing else; neither is, or ever becomes, a real registry key.
KCR_TEST_KEY_LABEL = b"KCE/test/registry-key/v1"
KCR_OTHER_KEY_LABEL = b"KCE/test/other-key/v1"
# RFC 8032 section 7.1, TEST 1-3 (Ed25519), copied as published from the document pinned in
# vectors/SOURCES.md, "Spec values": (name, public key hex, message hex, signature hex). The secret keys
# are not copied: verify.py signs only with the two label keys above. Check 10 verifies each and
# rejects each with L added to S.
RFC8032_TESTS = (
    ("rfc8032-test-1", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
     "d25bf5f0595bbe24655141438e7a100b"),
    ("rfc8032-test-2", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
     "387b2eaeb4302aeeb00d291612bb0c00"),
    ("rfc8032-test-3", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc659"
     "4a7c15e9716ed28dc027beceea1ec40a"),
)
# The seals kcr.json's snapshots and proofs are built around, with the check nonce of seal vector 1:
# (name, the rolls.json case or None for seal vector 1, words). The 50-roll seed is a 12-word dice-only
# session's; after its collision the restart needs 99 rolls, at either length (CLAUDE.md "Dice quota").
KCR_SEED_INPUTS = (
    ("vector-1", None, 12),
    ("dice-50-words12", "coldcard-50", 12),
    ("dice-99-words12", "coldcard-99", 12),
    ("dice-99-words24", "coldcard-99", 24),
)
# Known answers check 10 compares with what this file generates, so --write-kcr-vectors cannot
# re-baseline them (tasks/lessons.md: "pin a vector"). Computed on 2026-10-10 by a separate
# standard-library script that does not import this one (affine Edwards arithmetic, and a streaming
# Merkle pass with a stack over all 2^20 buckets): the test registry public key, the empty
# snapshot's root, and the root of the snapshot behind the vector-1 proof (kcr.json "small", read
# from its committed bytes). OpenSSL 3.6.4 derived the same public key from the same seed, and its
# Ed25519 signature of "small"'s header equals the one this file writes.
KCR_PINNED = {
    "test_public_key_hex": "42e9fa0e206d4bdf410f987ac7ded54fb02fb49ef277cc425d5fdfdb72c3b94b",
    "empty_root_hex": "b73ca0379e73400458ebe358b6aeec7a39baa7ddd8e1f78abe7436de44e4ba93",
    "vector_1_proof_root_hex": "d0d2028a28b277c2e105a1a3275c92bae1762aa43117762cf164700a7802e0ed",
}
KCR_SPEC = {
    "encoding": "every *_hex value is the exact bytes in lowercase hex; all integers are big-endian; dates are "
    "the decimal number YYYYMMDD as an integer",
    "ed25519": "PureEdDSA Ed25519 (RFC 8032 section 5.1). Verification is ed25519-dalek's verify_strict: the "
    "public key and R must decode (y below p), S must be below L, neither the key nor R may be of small order, "
    "and [S]B - [k]A must encode to R's 32 bytes exactly, k = SHA-512(R || A || message) mod L (cofactorless)",
    "keys": "each key's 32-byte secret seed is SHA-256 of its public label; test_registry is the key core pins "
    "under its test-registry feature, other signs the wrong-key cases. Release builds pin no key, so every case "
    "below gives CoreError::NoRegistryKey there, before any byte is read",
    "header": "58 bytes: magic 'KCR1', version (u16, 1), snapshot number (u64), date (u32, YYYYMMDD), entry count "
    "(u64), bucket root (32 bytes); then a pure Ed25519 signature (64 bytes) over exactly those 58 bytes",
    "entry": "18 bytes: T[0..16], then the registration count (u16, at least 1); bucket = the first 20 bits of "
    "T, written as 3 bytes for the leaf (the bucket index as a 24-bit big-endian integer: 2b810... is 02 b8 10)",
    "merkle": "leaf(i) = SHA-256(0x00 || 'KCE/v1/bucket' || i as 3 bytes || bucket i's entries in body order); "
    "node = SHA-256(0x01 || left || right); the root is over all 2^20 buckets in index order; a path holds the "
    "20 siblings leaf level first, and at level j the node is on the right when (i >> j) & 1 = 1",
    "snapshot": "header || signature || count entries, strictly ascending by T[0..16], at most 2^22 entries",
    "snapshot_checks": "in this order, each giving CoreError::Snapshot(error): length at least 122 (TooShort); "
    "magic (BadMagic); version 1 (BadVersion); the signature against the pinned key (BadSignature); a real "
    "Gregorian date, years 1-9999 (BadDate); count at most 2^22 (TooManyEntries); length exactly 122 + 18 x "
    "count (BadLength); then in entry order, each entry against the one before (equal: Duplicate, lower: "
    "Unsorted), then its count (zero: ZeroCount); the recomputed root equals the header's (RootMismatch)",
    "proof": "KCP1 = 'KCP1' || header || signature || bucket (3 bytes) || k (u16) || k entries || the 20 "
    "siblings: 771 + 18k bytes",
    "proof_checks": "in this order: length at least 771 (TooShort); magic 'KCP1' (BadMagic); then the header "
    "checks of a snapshot from magic to count (BadMagic, BadVersion, BadSignature, BadDate, TooManyEntries); "
    "bucket below 2^20 (BucketOutOfRange); length exactly 771 + 18k (BadLength); k at most the header's count "
    "(ProofCount); then in entry order, each entry's bucket (EntryOutsideBucket), its order against the one "
    "before (Duplicate, Unsorted) and its count (ZeroCount); the root recomputed from the leaf and the path "
    "equals the header's (RootMismatch)",
    "proof_qr": "a single-part 'ur:keepcrypt-proof/...' whose CBOR is one byte string holding the KCP1 bytes, "
    "read by the strict decoder of watchonly.json (spec ur_decoder); a decoder failure is Ur(UrError)",
    "negatives": "each rejected case breaks exactly one check, signed (or re-signed with the root its entries "
    "give) so that every other check passes; only a case too short, of the wrong length, or (for a snapshot) "
    "counting over 2^22 entries also spoils the checks that read past it. Each order-* case breaks two or "
    "more checks and must give the first of them, which pins the order of snapshot_checks and proof_checks",
    "freshness": "against today: Future when the date is after today, Current up to 30 days old, Stale from day "
    "31. Freshness is the shell's warning, never a refusal",
    "lookups": "a snapshot gives each seed's registration count, null when its T[0..16] is absent; a proof gives "
    "wrong_bucket when the seed's bucket is not the proof's, else collision (with the count) or clear",
    "seeds": "seal values as in seal.json (spec): S with the empty passphrase, the seal code, T, the Seal ID, "
    "the bucket and the go-ahead code G for nonce_hex",
}

# The BIP39 English word list, embedded because the M2 verifier ships as one file (docs/build-plan.md
# "Release"); copied from the bip39 3.0.0 crate's English list. Check 6 requires the 2,048 words
# joined by LF, plus a final LF, to hash to BIP39_ENGLISH_SHA256, the published SHA-256
# (docs/seal-watchonly-braille.md "Sources"). Sixteen space-separated words per line, so "random"
# (word 1,422) never stands alone on a line, where the banned-API gate's Python-import pattern
# would read it as an import.
BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
BIP39_ENGLISH = tuple(
    """
abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid
acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance
advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album
alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among
amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique
anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor
army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume
asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado
avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball
bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become
beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle
bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood
blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring
borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief
bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb
bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable
cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable
capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog
catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk
champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child
chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify
claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud
clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine
come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper
copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle
craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop
cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious
current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn
day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay
deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk
despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital
dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide
divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft
dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb
dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo
ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator
elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy
energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode
equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil
evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint
faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault
favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field
figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness
fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment
gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle
ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass
gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun
gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip
hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital
host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband
hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial
inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest
invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel
job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup
key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know
lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law
lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend
length lens leopard lesson letter level liar liberty library license life lift light like limb limit
link lion liquid list little live lizard load loan lobster local lock logic lonely long loop
lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet
maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin
marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure
meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message
metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake
mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning
mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music
must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative
neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee
noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey
object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay
old olive olympic omit once one onion online only open opera opinion oppose option orange orbit
orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over
own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper
parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut
pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical
piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet
plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony
pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare
present pretty prevent price pride primary print priority prison private prize problem process produce profit program
project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil
puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz
quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid
rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle
reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove
render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire
retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid
ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room
rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness
safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say
scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea
search season seat second secret section security seed seek segment select sell seminar senior sense sentence
series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine
ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side
siege sight sign silent silk silly silver similar simple since sing siren sister situate six size
skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan
slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social
sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup
source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin
spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium
staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting
stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject
submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme
sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim
swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target
task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that
theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger
tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token
tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist
toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree
trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try
tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical
ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown
unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful
useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle
velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view
village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave
way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat
wheel when where whip whisper wide width wife wild will win window wine wing wink winner
winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth
wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo
"""
    .split()
)


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
        "seal_id_braille": braille_text(seal_id(tag).lower()),
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


# --- Device leg, health tests, dice and seed (vectors/keepcrypt.json) ----------------------------


def counter_stream(label, length):
    """SHA-256 counter mode, never a PRNG: SHA256(label || i as 8 bytes big-endian) for i = 0, 1,
    ..., concatenated, first `length` bytes. Core's StubEntropy::Stream is the same function."""
    blocks = (length + 31) // 32
    return b"".join(hashlib.sha256(label + i.to_bytes(8, "big")).digest() for i in range(blocks))[:length]


def bip39_words(entropy):
    """BIP39 English words for 16, 20, 24, 28 or 32 bytes of entropy: the bits, then the first
    ENT/32 bits of SHA256(entropy) as checksum, cut into 11-bit indices, most significant first."""
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("BIP39 entropy must be 16 to 32 bytes, a multiple of 4")
    checksum_bits = len(entropy) // 4
    value = (int.from_bytes(entropy, "big") << checksum_bits) | (
        hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits))
    count = (8 * len(entropy) + checksum_bits) // 11
    return [BIP39_ENGLISH[(value >> (11 * (count - 1 - i))) & 0x7FF] for i in range(count)]


def rct_cutoff(h):
    """SP 800-90B 4.4.1: C = 1 + ceil(-log2(alpha) / H), alpha = 2^-20, H a whole number."""
    return 1 + -(-ALPHA_LOG2 // h)


def apt_cutoff(window, h):
    """SP 800-90B 4.4.2: C = 1 + CRITBINOM(W, 2^-H, 1 - alpha), alpha = 2^-20, in exact integers.

    CRITBINOM(n, p, q) is the smallest k with P[X <= k] >= q for X ~ Binomial(n, p). With p = 1/2^H,
    P[X <= k] = sum_{i <= k} C(n, i) (2^H - 1)^(n - i) / 2^(H n), so the test is
    2^20 * sum >= (2^20 - 1) * 2^(H n), with no rounding anywhere.
    """
    q = 2 ** h
    total = q ** window
    cumulative = 0
    for k in range(window + 1):
        cumulative += math.comb(window, k) * (q - 1) ** (window - k)
        if cumulative << ALPHA_LOG2 >= ((1 << ALPHA_LOG2) - 1) * total:
            return 1 + k
    raise ValueError("no cutoff")


def health_test(samples):
    """SP 800-90B Repetition Count and Adaptive Proportion tests over `samples`, from a fresh
    tester, with the cutoffs above. The first verdict wins: a failure names the test, the stage and
    the 0-based sample index; a pass gives the samples tested and the credited samples (only
    post-startup samples in completed windows)."""
    rct_value = apt_value = None
    rct_count = apt_count = 0
    for i, sample in enumerate(samples):
        stage = "startup" if i < STARTUP_SAMPLES else "continuous"
        if i > 0 and sample == rct_value:
            rct_count += 1
            if rct_count >= RCT_CUTOFF:
                return {"result": "fail", "test": "repetition_count", "stage": stage, "sample": i}
        else:
            rct_value, rct_count = sample, 1
        if i % APT_WINDOW == 0:
            apt_value, apt_count = sample, 1
        elif sample == apt_value:
            apt_count += 1
            if apt_count >= APT_CUTOFF:
                return {"result": "fail", "test": "adaptive_proportion", "stage": stage, "sample": i}
    return {"result": "pass", "tested": len(samples), "credited_samples": credited_samples(len(samples))}


def credited_samples(tested):
    """Post-startup samples in completed windows (Q7): floor((tested - 1024) / 512) * 512."""
    if tested < STARTUP_SAMPLES:
        return 0
    return (tested - STARTUP_SAMPLES) // APT_WINDOW * APT_WINDOW


def pool_input(records):
    """The exact bytes SHA-512 absorbs: TAG_POOL once, then id (u16 BE) || len (u64 BE) || data for
    each record that holds at least one byte (Q6a: an empty record writes nothing)."""
    out = bytearray(TAG_POOL)
    for source_id, data in records:
        if data:
            out += source_id.to_bytes(2, "big") + len(data).to_bytes(8, "big") + data
    return bytes(out)


def device_leg(records):
    """D = the first 32 bytes of SHA-512 over pool_input(records)."""
    return hashlib.sha512(pool_input(records)).digest()[:32]


def commitment(d):
    """C = SHA256(b"KCE/v1/commit" || D)."""
    return hashlib.sha256(TAG_COMMIT + d).digest()


def mixed_entropy(d, rolls):
    """E = SHA256(b"KCE/v1/seed" || D || len(R) as u64 BE || R), R = the ASCII rolls."""
    r = rolls.encode("ascii")
    return hashlib.sha256(TAG_SEED + d + len(r).to_bytes(8, "big") + r).digest()


def dice_only_entropy(rolls):
    """E = SHA256(R), the same as Coldcard's rolls.py."""
    return hashlib.sha256(rolls.encode("ascii")).digest()


def session_records(events, os_bytes):
    """One session's pool records in order (Q6a): each hwrng chunk gives one record of its bytes at
    sample index STARTUP_SAMPLES or later, each extra one record, and the OS bytes come last; an
    empty record is never written. Returns (records, hwrng samples tested). The caller has
    health-tested the hwrng stream."""
    records, tested = [], 0
    for kind, name, data in events:
        if kind == "hwrng":
            post_startup = data[max(0, STARTUP_SAMPLES - tested):]
            tested += len(data)
            if post_startup:
                records.append((SOURCE_ID["hwrng"], post_startup))
        elif data:
            records.append((SOURCE_ID[name], data))
    records.append((SOURCE_ID["os"], os_bytes))
    return records, tested


def records_json(records):
    """Pool records as JSON (a pool case may list an empty one, which must write nothing)."""
    return [{"id": source_id, "data_hex": data.hex()} for source_id, data in records]


def keepcrypt_health_cases():
    """(name, construction, samples): the streams behind every health vector. The expected verdict
    of each is pinned in HEALTH_PINNED and follows from its construction."""
    runs = bytes((i // 5) % 256 for i in range(2048))  # runs of exactly 5, values 0..255 cycling
    run6_startup = bytearray(runs)
    run6_startup[505] = runs[500]  # the run at 500..504 grows to 6 at sample 505
    run6_continuous = bytearray(runs)
    run6_continuous[1505] = runs[1500]  # the run at 1500..1504 grows to 6 at sample 1505

    def filler(i):
        return 0x55 if i % 256 == 0xAA else i % 256

    # Every window: 0xAA at offsets 0, 8, ..., 480 (61 times, the window's first value), other
    # offsets i mod 256 with 0xAA replaced by 0x55, so no run reaches 2 and no other value nears 61.
    apt61 = bytes(0xAA if (i % APT_WINDOW) % 8 == 0 and i % APT_WINDOW <= 480 else filler(i) for i in range(2048))
    apt62_startup = bytearray(apt61)
    apt62_startup[500] = 0xAA  # the 62nd 0xAA of window 0
    apt62_continuous = bytearray(apt61)
    apt62_continuous[1536 + 500] = 0xAA  # the 62nd 0xAA of the window at 1536
    # Both tests fail on sample 505: 0xAA, the first value of window 0, at offsets 0, 8, ..., 440 (56
    # times) and 500..505 (6 in a row), so the run and the window's 62nd 0xAA end on the same sample,
    # and the verdict names the Repetition Count, which is checked first.
    tie = bytearray(filler(i) for i in range(1024))
    for i in list(range(0, 441, 8)) + list(range(500, 506)):
        tie[i] = 0xAA
    return (
        ("stuck", "16 bytes of 0x00", bytes(16)),
        ("alternating", "512 bytes 0x00, 0x01, 0x00, 0x01, ...", bytes(i % 2 for i in range(512))),
        ("counting-1536", "i mod 256 for i in 0..1535", bytes(i % 256 for i in range(1536))),
        ("clean-4096", 'counter_stream(b"KCE/test/hwrng/clean", 4096)', counter_stream(b"KCE/test/hwrng/clean", 4096)),
        ("runs-of-5", "(i // 5) mod 256 for i in 0..2047", runs),
        ("run-of-6-startup", "runs-of-5 with byte 505 set to byte 500", bytes(run6_startup)),
        ("run-of-6-continuous", "runs-of-5 with byte 1505 set to byte 1500", bytes(run6_continuous)),
        ("apt-61-per-window", "2048 bytes; in every 512-sample window 0xAA at offsets 0, 8, ..., 480, else i mod 256 "
         "with 0xAA replaced by 0x55", apt61),
        ("apt-62-startup", "apt-61-per-window with byte 500 set to 0xAA", bytes(apt62_startup)),
        ("apt-62-continuous", "apt-61-per-window with byte 2036 set to 0xAA", bytes(apt62_continuous)),
        ("rct-and-apt-same-sample", "1024 bytes i mod 256 with 0xAA replaced by 0x55, then 0xAA at offsets 0, 8, "
         "..., 440 and 500..505", bytes(tie)),
    )


def keepcrypt_vectors_json():
    """The exact text of vectors/keepcrypt.json: indent 2, fixed key order, ASCII, trailing newline."""
    health = []
    for name, construction, samples in keepcrypt_health_cases():
        case = {"name": name, "construction": construction, "samples_hex": samples.hex(),
                "expect": health_test(samples)}
        if name == "clean-4096":
            case["credit_by_prefix"] = [[n, health_test(samples[:n])["credited_samples"]]
                                        for n in (0, 1023, 1024, 1535, 1536, 2047, 2048, 4096)]
        health.append(case)

    os_record = counter_stream(b"KCE/test/pool/os", OS_BYTES)
    pool_cases = (
        ("empty", []),
        ("one-os-record", [(SOURCE_ID["os"], os_record)]),
        ("empty-record-skipped", [(SOURCE_ID["input_timing"], b""), (SOURCE_ID["os"], os_record)]),
        ("split-ab-c", [(SOURCE_ID["input_timing"], b"ab"), (SOURCE_ID["input_timing"], b"c")]),
        ("split-a-bc", [(SOURCE_ID["input_timing"], b"a"), (SOURCE_ID["input_timing"], b"bc")]),
        # Every id a session absorbs; 0x0003 stays reserved until the M8 TRNG.
        ("every-source", [(source_id, counter_stream(b"KCE/test/pool/" + name.encode("ascii"), 33))
                          for name, source_id in SOURCE_IDS if name != "trng"]),
    )
    pool = [{"name": name, "records": records_json(records), "absorbed_hex": pool_input(records).hex(),
             "d_hex": device_leg(records).hex()} for name, records in pool_cases]

    commitment_cases = (
        ("d-00-1f", bytes(range(32))),
        ("d-00", bytes(32)),
        ("d-ff", b"\xff" * 32),
        ("d-stream", counter_stream(b"KCE/test/commit/d", 32)),
    )
    commitments = [{"name": name, "d_hex": d.hex(), "c_hex": commitment(d).hex()} for name, d in commitment_cases]

    rolls = dict(DICE_ONLY_ROLLS)
    mixed_cases = (
        ("d-00-1f-coldcard-50", bytes(range(32)), rolls["coldcard-50"]),
        ("d-ff-sixes-99", b"\xff" * 32, rolls["sixes-99"]),
        ("d-stream-coldcard-99", counter_stream(b"KCE/test/mixed/d", 32), rolls["coldcard-99"]),
        ("d-00-max-256", bytes(32), rolls["max-256"]),
    )
    mixed = []
    for name, d, r in mixed_cases:
        e = mixed_entropy(d, r)
        mixed.append({"name": name, "d_hex": d.hex(), "rolls": r, "e_hex": e.hex(),
                      "words_12": bip39_words(e[:16]), "words_24": bip39_words(e)})
    dice_only = []
    for name, r in DICE_ONLY_ROLLS:
        e = dice_only_entropy(r)
        dice_only.append({"name": name, "rolls": r, "e_hex": e.hex(),
                          "words_12": bip39_words(e[:16]), "words_24": bip39_words(e)})

    hw = counter_stream(b"KCE/test/subst/hwrng", 1600)
    pi_events = []
    for n in range(0, len(hw), 64):
        pi_events.append(("hwrng", None, hw[n : n + 64]))
        if n == 3 * 64:
            pi_events.append(("extra", "input_timing", counter_stream(b"KCE/test/subst/input_timing", 8)))
        if n == 20 * 64:
            pi_events.append(("extra", "camera", counter_stream(b"KCE/test/subst/camera", 32)))
    phone_events = [
        ("extra", "motion", counter_stream(b"KCE/test/subst/motion", 48)),
        ("extra", "input_timing", counter_stream(b"KCE/test/subst/input_timing", 8)),
    ]
    substitution = []
    for platform, events in (("pi", pi_events), ("phone", phone_events)):
        os_bytes = counter_stream(b"KCE/test/subst/os/" + platform.encode("ascii"), OS_BYTES)
        hw_stream = b"".join(data for kind, _, data in events if kind == "hwrng")
        verdict = health_test(hw_stream)
        if verdict["result"] != "pass":
            raise ValueError("the substitution hwrng stream must pass its health tests")
        records, tested = session_records(events, os_bytes)
        d = device_leg(records)
        substitution.append({
            "name": platform,
            "platform": platform,
            "events": [{"kind": kind, "source": name, "data_hex": data.hex()} if kind == "extra"
                       else {"kind": kind, "data_hex": data.hex()} for kind, name, data in events],
            "os_hex": os_bytes.hex(),
            "hw_bytes_tested": tested,
            "credited_samples": credited_samples(tested),
            "records": records_json(records),
            "d_hex": d.hex(),
            "c_hex": commitment(d).hex(),
        })

    doc = {
        "description": "KeepCrypt device-leg, health-test, dice and seed vectors. Generated by tools/verify/verify.py "
        "--write-keepcrypt-vectors; verify.py --selftest regenerates this file and requires byte equality (check 6), "
        "compares its pinned answers and session record rules, recomputes the health-test cutoffs (check 7) and re-runs Coldcard's scripts on "
        "every dice_only case (check 4). Test streams are SHA-256 counter mode or fixed patterns, never a PRNG; "
        "never use these seeds.",
        "spec": KEEPCRYPT_SPEC,
        "constants": {
            "pool_tag_ascii": TAG_POOL.decode("ascii"),
            "commit_tag_ascii": TAG_COMMIT.decode("ascii"),
            "seed_tag_ascii": TAG_SEED.decode("ascii"),
            "source_ids": [{"name": name, "id": source_id} for name, source_id in SOURCE_IDS],
            "os_bytes": OS_BYTES,
            "hwrng_bits_per_byte": HWRNG_BITS_PER_BYTE,
            "required_bits": dict(REQUIRED_BITS),
            "health": {
                "h": HEALTH_H,
                "alpha_log2": -ALPHA_LOG2,
                "rct_cutoff": RCT_CUTOFF,
                "apt_window": APT_WINDOW,
                "apt_cutoff": APT_CUTOFF,
                "startup_samples": STARTUP_SAMPLES,
            },
            "hw_bytes_needed": HW_BYTES_NEEDED,
            "dice": dict(DICE),
        },
        "streams": [{"label_ascii": "KCE/test/stream", "length": 100,
                     "hex": counter_stream(b"KCE/test/stream", 100).hex()}],
        "health": health,
        "pool": pool,
        "commitment": commitments,
        "mixed": mixed,
        "dice_only": dice_only,
        "source_substitution": substitution,
    }
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=True) + "\n"


def write_keepcrypt_vectors(vectors_dir):
    """Write keepcrypt.json into vectors_dir, which must already exist."""
    return write_vectors(vectors_dir, "keepcrypt.json", keepcrypt_vectors_json())


# --- Braille (vectors/braille.json) -----------------------------------------------------------


def braille_cell(dots):
    """The Unicode braille pattern with `dots` raised (a string of digits 1-6): U+2800 + sum 2^(d-1)."""
    return chr(0x2800 + sum(1 << (int(d) - 1) for d in dots))


def mirrored_dots(dots):
    """A cell's left-right mirror image: dots 1 and 4, 2 and 5, 3 and 6 swap; digits ascending."""
    return "".join(sorted(str((int(d) + 2) % 6 + 1) for d in dots))


def braille_mirror_pairs():
    """Every pair of distinct letters whose cells mirror each other, computed from the dots."""
    letter_of = {dots: letter for letter, dots in BRAILLE_LETTER_DOTS}
    return [(letter, letter_of[mirrored_dots(dots)]) for letter, dots in BRAILLE_LETTER_DOTS
            if letter_of.get(mirrored_dots(dots), letter) > letter]


def braille_mirror_partner():
    """{letter: its mirror partner} for the letters of the mirror pairs."""
    partner = {}
    for a, b in braille_mirror_pairs():
        partner[a], partner[b] = b, a
    return partner


def braille_text(text):
    """UEB grade 1 cells for `text` (Q6f): a-z, 0-9, space and hyphen, anything else a ValueError.

    A digit outside a run of digits opens one with the number sign; a letter a-j right after a digit
    takes the grade 1 indicator first, so it is not read as a digit; any letter, a space (the blank
    cell) or a hyphen ends the run.
    """
    letter_dots = dict(BRAILLE_LETTER_DOTS)
    sign = {name: braille_cell(dots) for name, dots in BRAILLE_SIGN_DOTS}
    out, in_digits = [], False
    for ch in text:
        if "0" <= ch <= "9":
            if not in_digits:
                out.append(sign["number_sign"])
                in_digits = True
            out.append(braille_cell(letter_dots[BRAILLE_DIGIT_LETTERS[int(ch)]]))
        elif "a" <= ch <= "z":
            if in_digits and ch <= "j":
                out.append(sign["grade1_indicator"])
            in_digits = False
            out.append(braille_cell(letter_dots[ch]))
        elif ch in (" ", "-"):
            in_digits = False
            out.append(sign["space" if ch == " " else "hyphen"])
        else:
            raise ValueError("braille text takes a-z, 0-9, space and hyphen only")
    return "".join(out)


def braille_table_text():
    """The canonical cell table, the bytes core's Braille KAT hashes: for a-z, then the signs, one
    line 'name cell dots' ended by LF, with dots "0" for the blank cell."""
    rows = BRAILLE_LETTER_DOTS + BRAILLE_SIGN_DOTS
    return "".join("%s %s %s\n" % (name, braille_cell(dots), dots or "0") for name, dots in rows)


def seedbook_faces(word):
    """Faces 1-5 of an insert: the first five letters, None for each blank face."""
    return [word[i] if i < len(word) else None for i in range(SEEDBOOK_FACES)]


def seedbook_sections():
    """One SeedBook section per first letter: its count, SeedBook numbers and pages, each section
    starting a new page of 24 words."""
    sections, number, page = [], 1, 1
    for letter in sorted(set(word[0] for word in BIP39_ENGLISH)):
        count = sum(1 for word in BIP39_ENGLISH if word[0] == letter)
        pages = -(-count // SEEDBOOK_WORDS_PER_PAGE)
        sections.append({"letter": letter, "count": count, "first_number": number, "last_number": number + count - 1,
                         "first_page": page, "last_page": page + pages - 1})
        number, page = number + count, page + pages
    return sections


def insert_positions(word_count):
    """Each word position of a 12- or 24-word seed with its device, the device count and the engraved
    sequence number 01-12 (Q9: both insert sets are engraved 01-12)."""
    devices = word_count // SEEDBOOK_INSERTS
    return [{"position": p, "device": (p - 1) // SEEDBOOK_INSERTS + 1, "devices": devices,
             "sequence": (p - 1) % SEEDBOOK_INSERTS + 1} for p in range(1, word_count + 1)]


def backup_braille_lines(words):
    """The plaintext backup's braille: lines (Q6e): '  NN ' then every letter's cell."""
    return ["  %02d %s" % (p, braille_text(word)) for p, word in enumerate(words, 1)]


def braille_word_entries():
    """One braille.json entry per BIP39 English word, in list order."""
    partner = braille_mirror_partner()
    key_word = {word[:SEEDBOOK_READBACK_FACES]: word for word in BIP39_ENGLISH}
    entries = []
    for number, word in enumerate(BIP39_ENGLISH, 1):
        key = word[:SEEDBOOK_READBACK_FACES]
        flips = []
        for face, letter in enumerate(key, 1):
            if letter in partner:
                other = key_word.get(key[: face - 1] + partner[letter] + key[face:])
                if other is not None:
                    flips.append([face, other])
        faces = seedbook_faces(word)
        entries.append({
            "number": number,
            "word": word,
            "faces": faces,
            "lighter_face": SEEDBOOK_LIGHTER_FACE if faces[SEEDBOOK_LIGHTER_FACE - 1] else None,
            "mirror_partners": [partner.get(f) if f else None for f in faces],
            "cells": braille_text(word),
            "readback": key,
            "flip_neighbours": flips,
            "prefix_of": longer_words_beginning_with(number - 1),
        })
    return entries


def longer_words_beginning_with(index):
    """The words that begin with BIP39_ENGLISH[index] and are longer: in a sorted list they follow it
    directly."""
    word, found = BIP39_ENGLISH[index], []
    for other in BIP39_ENGLISH[index + 1:]:
        if not other.startswith(word):
            break
        found.append(other)
    return found


def braille_counts(entries):
    """The docs' computed numbers (BRAILLE_DOCS_COUNTS), from the word entries."""
    sections = seedbook_sections()
    return {
        "words": len(entries),
        "sections": len(sections),
        "pages": sections[-1]["last_page"],
        "words_per_page": SEEDBOOK_WORDS_PER_PAGE,
        "mirror_pairs": len(braille_mirror_pairs()),
        "mirror_flip_words": sum(1 for e in entries if e["flip_neighbours"]),
        "short_prefix_words": sum(1 for e in entries if e["prefix_of"]),
        "distinct_readback_keys": len(set(e["readback"] for e in entries)),
    }


def braille_vectors_json():
    """The exact text of vectors/braille.json: indent 2, fixed key order, ASCII, trailing newline, with
    one line per word entry so the 2,048 entries stay readable."""
    entries = braille_word_entries()
    letter_dots = dict(BRAILLE_LETTER_DOTS)
    table = braille_table_text()
    doc = {
        "description": "KeepCrypt braille vectors: the SeedBook format of docs/seal-watchonly-braille.md \"Braille "
        "backup\". Generated by tools/verify/verify.py --write-braille-vectors; verify.py --selftest regenerates this "
        "file and requires byte equality, compares its pinned answers, recomputes the docs' counts from the BIP39 "
        "list and re-hashes the SeedBook PDF (check 8).",
        "spec": BRAILLE_SPEC,
        "cells": {
            "letters": [{"letter": letter, "dots": dots, "cell": braille_cell(dots)} for letter, dots in BRAILLE_LETTER_DOTS],
            "digits": [{"digit": str(d), "letter": BRAILLE_DIGIT_LETTERS[d],
                        "cell": braille_cell(letter_dots[BRAILLE_DIGIT_LETTERS[d]])} for d in range(10)],
            "signs": [{"name": name, "dots": dots, "cell": braille_cell(dots)} for name, dots in BRAILLE_SIGN_DOTS],
            "mirror_pairs": [list(pair) for pair in braille_mirror_pairs()],
            "table_text": table,
            "table_sha256": hashlib.sha256(table.encode("utf-8")).hexdigest(),
        },
        "counts": braille_counts(entries),
        "sections": seedbook_sections(),
        "positions": {"words_12": insert_positions(12), "words_24": insert_positions(24)},
        "text": [{"text": text, "cells": braille_text(text)} for text, _ in BRAILLE_TEXT_VECTORS],
        "text_refused": list(BRAILLE_TEXT_REFUSED),
        "backup_lines": [{"mnemonic": mnemonic, "lines": backup_braille_lines(mnemonic.split())}
                         for mnemonic in (KAT_MNEMONIC, " ".join(["zoo"] * 23 + ["vote"]))],
    }
    head = json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=True)
    rows = ",\n".join("    " + json.dumps(entry, sort_keys=False, ensure_ascii=True) for entry in entries)
    return head[: -len("\n}")] + ',\n  "words": [\n' + rows + "\n  ]\n}\n"


def write_braille_vectors(vectors_dir):
    """Write braille.json into vectors_dir, which must already exist."""
    return write_vectors(vectors_dir, "braille.json", braille_vectors_json())


# --- Watch-only export and single-part UR (vectors/watchonly.json) -----------------------------
# Standard library only: secp256k1 arithmetic, RIPEMD-160, BIP32, bech32, the BIP-380 checksum, a
# dCBOR writer, Bytewords and CRC-32, run on public test mnemonics only. Nothing here is constant
# time; it never sees a real secret.

SECP256K1_P = 2 ** 256 - 2 ** 32 - 977
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
XPUB_VERSION = bytes.fromhex("0488b21e")
ZPUB_VERSION = bytes.fromhex("04b24746")  # SLIP-132, used by the BIP-84 vectors
HARDENED = 0x80000000
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# BIP-380 "Checksum", the reference code's character sets and generator.
DESCRIPTOR_INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
DESCRIPTOR_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
DESCRIPTOR_GENERATOR = (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)


def ec_add(a, b):
    """Affine point addition on secp256k1; None is the point at infinity."""
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % SECP256K1_P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], SECP256K1_P - 2, SECP256K1_P)
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], SECP256K1_P - 2, SECP256K1_P)
    slope %= SECP256K1_P
    x = (slope * slope - a[0] - b[0]) % SECP256K1_P
    return x, (slope * (a[0] - x) - a[1]) % SECP256K1_P


def ec_public(k):
    """k * G by double-and-add, as a 33-byte compressed public key."""
    point, addend = None, SECP256K1_G
    while k:
        if k & 1:
            point = ec_add(point, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def ripemd160_pure(data):
    """RIPEMD-160 (Dobbertin, Bosselaers and Preneel), in pure Python for interpreters whose hashlib
    lacks it; check 9 compares it with hashlib's where hashlib has one."""
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    left_words = (
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13)
    right_words = (
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11)
    left_shifts = (
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6)
    right_shifts = (
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11)
    left_k = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
    right_k = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, "little")
    for offset in range(0, len(padded), 64):
        x = [int.from_bytes(padded[offset + 4 * i: offset + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = rol((al + f(j, bl, cl, dl) + x[left_words[j]] + left_k[j // 16]) & 0xFFFFFFFF, left_shifts[j]) + el
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t & 0xFFFFFFFF
            t = rol((ar + f(79 - j, br, cr, dr) + x[right_words[j]] + right_k[j // 16]) & 0xFFFFFFFF,
                    right_shifts[j]) + er
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t & 0xFFFFFFFF
        h = [(h[1] + cl + dr) & 0xFFFFFFFF, (h[2] + dl + er) & 0xFFFFFFFF, (h[3] + el + ar) & 0xFFFFFFFF,
             (h[4] + al + br) & 0xFFFFFFFF, (h[0] + bl + cr) & 0xFFFFFFFF]
    return b"".join(v.to_bytes(4, "little") for v in h)


def hashlib_ripemd160(data):
    """hashlib's RIPEMD-160, or None where this build of hashlib has none (OpenSSL 3 dropped it)."""
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return None


def hash160(data):
    """RIPEMD-160(SHA-256(data)), with the pure-Python RIPEMD-160 (cross-checked by check 9)."""
    return ripemd160_pure(hashlib.sha256(data).digest())


def base58check(payload):
    """Base58 of payload || first 4 bytes of SHA-256(SHA-256(payload))."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value, text = int.from_bytes(data, "big"), ""
    while value:
        value, digit = divmod(value, 58)
        text = BASE58[digit] + text
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + text


def base58check_decode(text):
    """The payload of a Base58Check string (ValueError on a bad checksum)."""
    value = 0
    for ch in text:
        value = value * 58 + BASE58.index(ch)
    data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    data = b"\x00" * (len(text) - len(text.lstrip("1"))) + data
    payload, check = data[:-4], data[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != check:
        raise ValueError("bad Base58Check checksum")
    return payload


def bip39_seed_with_passphrase(mnemonic, passphrase, normalize=True):
    """BIP39 S = PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" + NFKD(passphrase), 2048, 64). With
    normalize=False the passphrase goes in as typed, the bug core must never have."""
    salt = "mnemonic" + (unicodedata.normalize("NFKD", passphrase) if normalize else passphrase)
    password = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, salt.encode("utf-8"), 2048, 64)


def bip32_master(seed):
    """(private key, chain code) of the BIP32 master key."""
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(digest[:32], "big"), digest[32:]


def bip32_child(key, chain, index):
    """CKDpriv: (private key, chain code) of child `index` (hardened at 2^31 and above)."""
    if index >= HARDENED:
        data = b"\x00" + key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = ec_public(key) + index.to_bytes(4, "big")
    digest = hmac.new(chain, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    child = (tweak + key) % SECP256K1_N
    if tweak >= SECP256K1_N or child == 0:
        raise ValueError("invalid BIP32 child (probability below 2^-127)")
    return child, digest[32:]


def bip32_fingerprint(key):
    """The first 4 bytes of HASH160 of the compressed public key."""
    return hash160(ec_public(key))[:4]


def bip32_derive(seed, path):
    """[(index, key, chain code)] for every step of `path` from the master, master first (index None)."""
    key, chain = bip32_master(seed)
    steps = [(None, key, chain)]
    for index in path:
        key, chain = bip32_child(key, chain, index)
        steps.append((index, key, chain))
    return steps


def serialize_xpub(version, depth, parent_fingerprint, index, chain, public_key):
    """A BIP32 extended public key: version || depth || parent fingerprint || child number || chain code
    || compressed key, in Base58Check."""
    return base58check(version + bytes([depth]) + parent_fingerprint + index.to_bytes(4, "big") + chain + public_key)


def bech32_polymod(values):
    """BIP-173's checksum function."""
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]
    return chk


def p2wpkh_address(public_key):
    """The mainnet P2WPKH address (BIP-173, witness version 0) of a compressed public key."""
    program, acc, bits, data = hash160(public_key), 0, 0, [0]
    for byte in program:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    polymod = bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return "bc1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def descriptor_polymod(symbols):
    """BIP-380's checksum polynomial over GF(32)."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= DESCRIPTOR_GENERATOR[i]
    return chk


def descriptor_symbols(text):
    """BIP-380's expansion of a descriptor into checksum symbols, or None for a character outside
    the input character set."""
    groups, symbols = [], []
    for ch in text:
        position = DESCRIPTOR_INPUT_CHARSET.find(ch)
        if position < 0:
            return None
        symbols.append(position & 31)
        groups.append(position >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descriptor_checksum(text):
    """The 8-character BIP-380 checksum of a descriptor."""
    symbols = descriptor_symbols(text)
    if symbols is None:
        raise ValueError("a descriptor character outside the BIP-380 input set")
    value = descriptor_polymod(symbols + [0] * 8) ^ 1
    return "".join(DESCRIPTOR_CHECKSUM_CHARSET[(value >> (5 * (7 - i))) & 31] for i in range(8))


def descriptor_checksum_valid(text):
    """True for a descriptor that ends in '#' and its valid 8-character checksum."""
    if len(text) < 9 or text[-9] != "#" or any(c not in DESCRIPTOR_CHECKSUM_CHARSET for c in text[-8:]):
        return False
    symbols = descriptor_symbols(text[:-9])
    if symbols is None:
        return False
    return descriptor_polymod(symbols + [DESCRIPTOR_CHECKSUM_CHARSET.find(c) for c in text[-8:]]) == 1


def cbor_head(major, value):
    """A CBOR head in its shortest form: major type (0-7) and its argument."""
    if value < 24:
        return bytes([major << 5 | value])
    for size, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if value < 1 << (8 * size):
            return bytes([major << 5 | extra]) + value.to_bytes(size, "big")
    raise ValueError("a CBOR argument above 2^64 - 1")


def cbor_encode(item):
    """Deterministic CBOR of an item (WATCHONLY_SPEC "cbor"): shortest heads, definite lengths, map keys
    unique and sorted by their encoded bytes."""
    kind = item[0]
    if kind == "uint":
        return cbor_head(0, item[1])
    if kind == "bytes":
        data = bytes.fromhex(item[1])
        return cbor_head(2, len(data)) + data
    if kind == "array":
        return cbor_head(4, len(item[1])) + b"".join(cbor_encode(i) for i in item[1])
    if kind == "map":
        pairs = sorted((cbor_encode(k), cbor_encode(v)) for k, v in item[1])
        if len(set(k for k, _ in pairs)) != len(pairs):
            raise ValueError("duplicate CBOR map key")
        return cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    if kind == "bool":
        return b"\xf5" if item[1] else b"\xf4"
    if kind == "tag":
        return cbor_head(6, item[1]) + cbor_encode(item[2])
    raise ValueError("unknown CBOR item kind %r" % kind)


def cbor_json(item):
    """An item as watchonly.json writes it (WATCHONLY_SPEC "cbor")."""
    kind = item[0]
    if kind in ("uint", "bytes", "bool"):
        return {kind: item[1]}
    if kind == "array":
        return {"array": [cbor_json(i) for i in item[1]]}
    if kind == "map":
        return {"map": [[cbor_json(k), cbor_json(v)] for k, v in item[1]]}
    return {"tag": item[1], "item": cbor_json(item[2])}


def crc32_table():
    """The 256-entry table of CRC-32/ISO-HDLC (reflected polynomial 0xedb88320)."""
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c)
    return table


def crc32(data):
    """CRC-32/ISO-HDLC, table-driven (check 9 compares it with zlib's)."""
    table, c = crc32_table(), 0xFFFFFFFF
    for byte in data:
        c = table[(c ^ byte) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def bytewords_minimal(data):
    """Minimal Bytewords: each byte as its word's first and last letters."""
    return "".join(BYTEWORDS[b][0] + BYTEWORDS[b][3] for b in data)


def ur_single(ur_type, cbor):
    """A single-part UR: ur:<type>/<minimal Bytewords of CBOR || CRC-32 big-endian>."""
    return "ur:%s/%s" % (ur_type, bytewords_minimal(cbor + crc32(cbor).to_bytes(4, "big")))


def ur_decode_single(expected_type, text):
    """The strict single-part reader, rebuilt apart from core (WATCHONLY_SPEC "ur_decoder"): (the CBOR
    byte string's bytes, None), or (None, the name of the first rule the text breaks). Like core, it reads
    the UTF-8 bytes of the text: the limit and the even length count bytes, and a byte of a non-ASCII
    character (0x80 or above) is no letter, so it matches no rule."""
    raw = text.encode("utf-8")
    if len(raw) > UR_MAX_CHARS:
        return None, "TooLong"
    has_upper, has_lower = any(0x41 <= b <= 0x5A for b in raw), any(0x61 <= b <= 0x7A for b in raw)
    if has_upper and has_lower:
        return None, "MixedCase"
    raw = bytes(b + 32 if 0x41 <= b <= 0x5A else b for b in raw)
    if not raw.startswith(b"ur:") or b"/" not in raw[3:]:
        return None, "NotUr"
    ur_type, message = raw[3:].split(b"/", 1)
    if ur_type != expected_type.encode("ascii"):
        return None, "WrongType"
    if b"/" in message:
        return None, "MultiPart"
    if len(message) % 2:
        return None, "OddLength"
    byte_of = {(word[0] + word[3]).encode("ascii"): n for n, word in enumerate(BYTEWORDS)}
    pairs = [message[i:i + 2] for i in range(0, len(message), 2)]
    if any(pair not in byte_of for pair in pairs):
        return None, "UnknownByteword"
    data = bytes(byte_of[pair] for pair in pairs)
    if len(data) < 4 or crc32(data[:-4]).to_bytes(4, "big") != data[-4:]:
        return None, "BadChecksum"
    cbor = data[:-4]
    if not cbor or cbor[0] >> 5 != 2:
        return None, "NotByteString"
    info = cbor[0] & 31
    if info == 31:
        return None, "IndefiniteLength"
    size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0) if info < 28 else None
    if size is None or len(cbor) < 1 + size:
        return None, "NotByteString"
    length = int.from_bytes(cbor[1:1 + size], "big") if size else info
    if cbor_head(2, length) != cbor[:1 + size]:
        return None, "NonShortestHead"
    if len(cbor) < 1 + size + length:
        return None, "NotByteString"
    if len(cbor) > 1 + size + length:
        return None, "TrailingBytes"
    return cbor[1 + size:], None


def cbor_byte_string(data):
    """A CBOR byte string item for raw bytes."""
    return ("bytes", data.hex())


def hdkey_item(public_key, chain, components, source_fingerprint, parent_fingerprint):
    """A v1 crypto-hdkey (tag 303) with its crypto-keypath origin (tag 304); a zero fingerprint is
    omitted (BCR-2020-007: uint32 .ne 0)."""
    path = ("array", tuple(c for index, hardened in components for c in (("uint", index), ("bool", hardened))))
    keypath = [(("uint", 1), path)]
    if source_fingerprint:
        keypath.append((("uint", 2), ("uint", source_fingerprint)))
    fields = [(("uint", 3), cbor_byte_string(public_key)), (("uint", 4), cbor_byte_string(chain)),
              (("uint", 6), ("tag", 304, ("map", tuple(keypath))))]
    if parent_fingerprint:
        fields.append((("uint", 8), ("uint", parent_fingerprint)))
    return ("tag", 303, ("map", tuple(fields)))


def crypto_account_item(master_fingerprint, outputs):
    """A v1 crypto-account, untagged: {1: master fingerprint, 2: [outputs]}; each output is (script tags,
    hdkey item), the tags outermost first."""
    wrapped = []
    for tags, hdkey in outputs:
        item = hdkey
        for tag in reversed(tags):
            item = ("tag", tag, item)
        wrapped.append(item)
    return ("map", ((("uint", 1), ("uint", master_fingerprint)), (("uint", 2), ("array", tuple(wrapped)))))


def watch_only_wallet(name, mnemonic, passphrase):
    """One watchonly.json wallet: the BIP84 account export for a mnemonic and optional passphrase."""
    seed = bip39_seed_with_passphrase(mnemonic, passphrase or "")
    account_path = (84 + HARDENED, HARDENED, HARDENED)
    steps = bip32_derive(seed, account_path)
    master_fp = bip32_fingerprint(steps[0][1])
    parent_fp = bip32_fingerprint(steps[2][1])
    _, account_key, account_chain = steps[3]
    account_public = ec_public(account_key)
    xpub = serialize_xpub(XPUB_VERSION, 3, parent_fp, HARDENED, account_chain, account_public)

    def address(change):
        key, chain = bip32_child(account_key, account_chain, change)
        return p2wpkh_address(ec_public(bip32_child(key, chain, 0)[0]))

    origin = "[%s/84h/0h/0h]" % master_fp.hex()
    receive, change = "wpkh(%s%s/0/*)" % (origin, xpub), "wpkh(%s%s/1/*)" % (origin, xpub)
    apostrophe = "wpkh([%s/84'/0'/0']%s/0/*)" % (master_fp.hex(), xpub)
    hdkey = hdkey_item(account_public, account_chain, ((84, True), (0, True), (0, True)),
                       int.from_bytes(master_fp, "big"), int.from_bytes(parent_fp, "big"))
    cbor = cbor_encode(crypto_account_item(int.from_bytes(master_fp, "big"), [((308, 404), hdkey)]))
    ur = ur_single("crypto-account", cbor)
    wallet = {
        "name": name,
        "mnemonic": mnemonic,
        "passphrase": passphrase,
        "fingerprint": master_fp.hex(),
        "account_xpub": xpub,
        "account_key_hex": account_public.hex(),
        "account_chain_code_hex": account_chain.hex(),
        "account_parent_fingerprint": parent_fp.hex(),
        "receive_descriptor": receive + "#" + descriptor_checksum(receive),
        "change_descriptor": change + "#" + descriptor_checksum(change),
        "receive_descriptor_apostrophe": apostrophe + "#" + descriptor_checksum(apostrophe),
        "first_receive_address": address(0),
        "first_change_address": address(1),
        "crypto_account_cbor_hex": cbor.hex(),
        "crypto_account_ur": ur,
        "qr_text": ur.upper(),
    }
    if passphrase is not None and unicodedata.normalize("NFKD", passphrase) != passphrase:
        unnormalized = bip39_seed_with_passphrase(mnemonic, passphrase, normalize=False)
        wallet["unnormalized_fingerprint"] = bip32_fingerprint(bip32_master(unnormalized)[0]).hex()
    return wallet


def bcr015_rebuilt():
    """The BCR-2020-015 example rebuilt from its mnemonic: [(tags, components, key, chain, source fp,
    parent fp, xpub)] per output, in BCR015_OUTPUTS order."""
    seed = bip39_seed_with_passphrase(BCR015_MNEMONIC, "")
    master_fp = bip32_fingerprint(bip32_master(seed)[0])
    rebuilt = []
    for tags, components, _, _, _, _ in BCR015_OUTPUTS:
        steps = bip32_derive(seed, [index + (HARDENED if hardened else 0) for index, hardened in components])
        parent_fp = bip32_fingerprint(steps[-2][1])
        index, key, chain = steps[-1]
        public = ec_public(key)
        xpub = serialize_xpub(XPUB_VERSION, len(components), parent_fp, index, chain, public)
        rebuilt.append((tags, components, public.hex(), chain.hex(), int.from_bytes(master_fp, "big"),
                        int.from_bytes(parent_fp, "big"), xpub))
    return rebuilt


def ur_bytes_vector(length):
    """A type "bytes" UR of a counter-mode byte string of `length` bytes, as its CBOR byte string."""
    data = counter_stream(b"KCE/test/ur/bytes", length)
    cbor = cbor_encode(cbor_byte_string(data))
    return {"name": "bytes-%d" % length, "type": "bytes", "data_hex": data.hex(), "cbor_hex": cbor.hex(),
            "ur": ur_single("bytes", cbor)}


def ur_negative_vectors():
    """Texts the strict decoder must refuse, each with the UrError it must give (WATCHONLY_SPEC
    "ur_decoder"), expecting type "bytes". Each breaks one rule; the order cases pin which rule wins."""
    data = counter_stream(b"KCE/test/ur/bytes", 771)
    good = ur_single("bytes", cbor_encode(cbor_byte_string(data)))
    message = good[len("ur:bytes/"):]
    payload = cbor_encode(cbor_byte_string(data))

    def with_crc(cbor):
        return "ur:bytes/" + bytewords_minimal(cbor + crc32(cbor).to_bytes(4, "big"))

    bad_crc = payload + (crc32(payload) ^ 1).to_bytes(4, "big")
    too_long = ur_single("bytes", cbor_encode(cbor_byte_string(counter_stream(b"KCE/test/ur/bytes", 2137))))
    return [
        {"name": "too-long", "text": too_long, "error": "TooLong"},
        {"name": "too-long-and-mixed-case", "text": "U" + too_long[1:], "error": "TooLong"},
        {"name": "mixed-case", "text": "Ur:bytes/" + message, "error": "MixedCase"},
        {"name": "mixed-case-in-message", "text": "ur:bytes/" + message[:-1] + message[-1].upper(),
         "error": "MixedCase"},
        {"name": "not-a-ur", "text": "xr:bytes/" + message, "error": "NotUr"},
        {"name": "no-message", "text": "ur:bytes", "error": "NotUr"},
        {"name": "wrong-type", "text": "ur:seed/" + message, "error": "WrongType"},
        {"name": "wrong-type-before-multi-part", "text": "ur:seed/1-3/" + message, "error": "WrongType"},
        {"name": "multi-part", "text": "ur:bytes/1-3/" + message, "error": "MultiPart"},
        {"name": "odd-length", "text": good[:-1], "error": "OddLength"},
        {"name": "unknown-byteword", "text": "ur:bytes/zz" + message[2:], "error": "UnknownByteword"},
        {"name": "bad-crc", "text": "ur:bytes/" + bytewords_minimal(bad_crc), "error": "BadChecksum"},
        {"name": "shorter-than-a-crc", "text": "ur:bytes/" + bytewords_minimal(b"\x40\x00\x00"),
         "error": "BadChecksum"},
        {"name": "not-a-byte-string", "text": with_crc(bytes.fromhex("83010203")), "error": "NotByteString"},
        {"name": "empty-cbor", "text": with_crc(b""), "error": "NotByteString"},
        {"name": "non-shortest-head", "text": with_crc(b"\x5a" + len(data).to_bytes(4, "big") + data),
         "error": "NonShortestHead"},
        {"name": "non-shortest-short-head", "text": with_crc(b"\x58\x05" + data[:5]), "error": "NonShortestHead"},
        {"name": "indefinite-head", "text": with_crc(b"\x5f" + payload + b"\xff"), "error": "IndefiniteLength"},
        {"name": "truncated-byte-string", "text": with_crc(payload[:-1]), "error": "NotByteString"},
        {"name": "trailing-byte", "text": with_crc(payload + b"\x00"), "error": "TrailingBytes"},
        # Non-ASCII text, measured in UTF-8 bytes as core measures it: U+00E9 is two bytes, neither a letter.
        # The first is 4,296 characters but 4,297 bytes.
        {"name": "non-ascii-too-long", "text": "ur:bytes/" + "ae" * 2143 + "\u00e9", "error": "TooLong"},
        {"name": "non-ascii-odd-length", "text": "ur:bytes/a\u00e9", "error": "OddLength"},
        {"name": "non-ascii-byteword", "text": "ur:bytes/\u00e9", "error": "UnknownByteword"},
        {"name": "non-ascii-type", "text": "ur:byt\u00e9s/" + message, "error": "WrongType"},
    ]


_WATCHONLY_JSON = []


def watchonly_vectors_json():
    """The exact text of vectors/watchonly.json: indent 2, fixed key order, ASCII, trailing newline.
    Computed once per run (the BIP32 arithmetic takes a moment)."""
    if _WATCHONLY_JSON:
        return _WATCHONLY_JSON[0]
    wallets = [watch_only_wallet(*w) for w in WATCHONLY_WALLETS]
    abandon = wallets[0]
    zero_hdkey = hdkey_item(bytes.fromhex(abandon["account_key_hex"]), bytes.fromhex(abandon["account_chain_code_hex"]),
                            ((84, True), (0, True), (0, True)), 0, 0)
    zero_cbor = cbor_encode(crypto_account_item(0, [((308, 404), zero_hdkey)]))
    bcr015 = bcr015_rebuilt()
    bcr015_cbor = cbor_encode(crypto_account_item(
        BCR015_MASTER_FINGERPRINT, [(tags, hdkey_item(bytes.fromhex(key), bytes.fromhex(chain), components, source, parent))
                                    for tags, components, key, chain, source, parent, _ in bcr015]))
    seed_cbor = bytes.fromhex(BCR005_SEED_CBOR_HEX)
    doc = {
        "description": "KeepCrypt watch-only and UR vectors. Generated by tools/verify/verify.py --write-watchonly-vectors; "
        "verify.py --selftest regenerates this file and requires byte equality, and reproduces every value copied "
        "from BIP-84, BIP-380, BCR-2020-005, -007, -012, -015, bip32JP and RFC 8949 (check 9). Public test "
        "mnemonics only, never a real seed.",
        "spec": WATCHONLY_SPEC,
        "cbor": [{"diagnostic": diagnostic, "item": cbor_json(item), "hex": cbor_encode(item).hex()}
                 for diagnostic, item, _ in RFC8949_EXAMPLES],
        "crc32": [
            {"name": "check-value", "data_hex": b"123456789".hex(), "crc32": "%08x" % crc32(b"123456789")},
            {"name": "bcr-2020-012-body", "data_hex": BCR012_BODY_HEX,
             "crc32": "%08x" % crc32(bytes.fromhex(BCR012_BODY_HEX))},
            {"name": "bcr-2020-012-brutal", "data_hex": BCR012_BRUTAL_PAYLOAD_HEX,
             "crc32": "%08x" % crc32(bytes.fromhex(BCR012_BRUTAL_PAYLOAD_HEX))},
        ],
        "bytewords": {
            "words": list(BYTEWORDS),
            "minimal": [
                {"name": "bcr-2020-012-body", "data_hex": BCR012_BODY_HEX + "%08x" % crc32(bytes.fromhex(BCR012_BODY_HEX)),
                 "minimal": bytewords_minimal(bytes.fromhex(BCR012_BODY_HEX) + crc32(
                     bytes.fromhex(BCR012_BODY_HEX)).to_bytes(4, "big"))},
                {"name": "bcr-2020-012-brutal", "data_hex": BCR012_BRUTAL_PAYLOAD_HEX + "%08x" % crc32(
                    bytes.fromhex(BCR012_BRUTAL_PAYLOAD_HEX)),
                 "minimal": bytewords_minimal(bytes.fromhex(BCR012_BRUTAL_PAYLOAD_HEX) + crc32(
                     bytes.fromhex(BCR012_BRUTAL_PAYLOAD_HEX)).to_bytes(4, "big"))},
                {"name": "every-byte", "data_hex": bytes(range(256)).hex(), "minimal": bytewords_minimal(bytes(range(256)))},
            ],
        },
        "ur": [{"name": "bcr-2020-005-seed", "type": "seed", "cbor_hex": seed_cbor.hex(), "ur": ur_single("seed", seed_cbor)},
               {"name": "bcr-2020-015-example", "type": "crypto-account", "cbor_hex": bcr015_cbor.hex(),
                "ur": ur_single("crypto-account", bcr015_cbor)}]
        + [ur_bytes_vector(n) for n in UR_BYTES_LENGTHS],
        "ur_max_chars": UR_MAX_CHARS,
        "ur_negatives": [dict(case, expected_type="bytes") for case in ur_negative_vectors()],
        "wallets": wallets,
        "zero_fingerprints": {"master_fingerprint": 0, "key_hex": abandon["account_key_hex"],
                              "chain_code_hex": abandon["account_chain_code_hex"], "cbor_hex": zero_cbor.hex(),
                              "ur": ur_single("crypto-account", zero_cbor)},
        "bcr_2020_015": {
            "mnemonic": BCR015_MNEMONIC,
            "master_fingerprint": BCR015_MASTER_FINGERPRINT,
            "outputs": [{"tags": list(tags), "components": [[index, hardened] for index, hardened in components],
                         "key_hex": key, "chain_code_hex": chain, "source_fingerprint": source,
                         "parent_fingerprint": parent, "xpub": xpub}
                        for tags, components, key, chain, source, parent, xpub in bcr015],
            "cbor_hex": bcr015_cbor.hex(),
            "ur": ur_single("crypto-account", bcr015_cbor),
        },
        "bip84": {
            "mnemonic": BIP84_MNEMONIC,
            "root_zpub": bip84_root_zpub(),
            "account_zpub": zpub_of(abandon["account_xpub"]),
            "account_xpub": abandon["account_xpub"],
            "addresses": bip84_addresses(),
        },
        "bip380": [{"name": name, "descriptor": text, "valid": descriptor_checksum_valid(text)}
                   for name, text, _ in BIP380_CHECKSUM_VECTORS],
    }
    _WATCHONLY_JSON.append(json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=True) + "\n")
    return _WATCHONLY_JSON[0]


def zpub_of(xpub):
    """The same extended public key with SLIP-132 zpub version bytes."""
    return base58check(ZPUB_VERSION + base58check_decode(xpub)[4:])


def bip84_root_zpub():
    """The BIP-84 vector's master public key as a zpub."""
    key, chain = bip32_master(bip39_seed_with_passphrase(BIP84_MNEMONIC, ""))
    return serialize_xpub(ZPUB_VERSION, 0, bytes(4), 0, chain, ec_public(key))


def bip84_addresses():
    """[{name, path, pubkey, address}] for the BIP-84 vector's three addresses."""
    seed = bip39_seed_with_passphrase(BIP84_MNEMONIC, "")
    found = []
    for name, (change, index), _, _ in BIP84_ADDRESSES:
        key = bip32_derive(seed, (84 + HARDENED, HARDENED, HARDENED, change, index))[-1][1]
        found.append({"name": name, "path": "m/84h/0h/0h/%d/%d" % (change, index), "pubkey": ec_public(key).hex(),
                      "address": p2wpkh_address(ec_public(key))})
    return found


def write_watchonly_vectors(vectors_dir):
    """Write watchonly.json into vectors_dir, which must already exist."""
    return write_vectors(vectors_dir, "watchonly.json", watchonly_vectors_json())


# --- Ed25519, the bucket tree, .kcr snapshots and KCP1 proofs (vectors/kcr.json) ---------------
# Standard library only. Ed25519 follows RFC 8032 section 5.1 on the twisted Edwards curve
# -x^2 + y^2 = 1 + d x^2 y^2 over GF(2^255 - 19), in extended coordinates (X, Y, Z, T) with x = X/Z,
# y = Y/Z and xy = T/Z. Nothing here is constant time: it signs only with the two public-label test
# keys and verifies public data.

ED25519_P = 2 ** 255 - 19
ED25519_L = 2 ** 252 + 27742317777372353535851937790883648493
ED25519_D = -121665 * pow(121666, ED25519_P - 2, ED25519_P) % ED25519_P
ED25519_SQRT_M1 = pow(2, (ED25519_P - 1) // 4, ED25519_P)
ED25519_IDENTITY = (0, 1, 1, 0)


def ed_add(a, b):
    """The sum of two points (the complete addition law for a = -1; it also doubles)."""
    p = ED25519_P
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e1 = (y1 - x1) * (y2 - x2) % p
    e2 = (y1 + x1) * (y2 + x2) % p
    e3 = 2 * ED25519_D * t1 * t2 % p
    e4 = 2 * z1 * z2 % p
    e, f, g, h = e2 - e1, e4 - e3, e4 + e3, e2 + e1
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def ed_negate(point):
    """-P = (-x, y)."""
    x, y, z, t = point
    return (-x % ED25519_P, y, z, -t % ED25519_P)


def ed_multiply(scalar, point):
    """[scalar]P, double and add from the top bit."""
    result = ED25519_IDENTITY
    for bit in range(scalar.bit_length() - 1, -1, -1):
        result = ed_add(result, result)
        if scalar >> bit & 1:
            result = ed_add(result, point)
    return result


def ed_encode(point):
    """32 bytes: y little-endian, with the low bit of x in the top bit."""
    x, y, z, _ = point
    z_inverse = pow(z, ED25519_P - 2, ED25519_P)
    x, y = x * z_inverse % ED25519_P, y * z_inverse % ED25519_P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def ed_decode(data):
    """The point 32 bytes encode (RFC 8032 section 5.1.3), or None: y must be below p, x^2 must have a
    square root, and x = 0 must come with a clear sign bit."""
    p = ED25519_P
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(ED25519_D * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else (0, y, 1, 0)
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * ED25519_SQRT_M1 % p
    if (x * x - x2) % p:
        return None
    if x & 1 != sign:
        x = p - x
    return (x, y, 1, x * y % p)


# The base point: y = 4/5, x even.
ED25519_BASE = ed_decode((4 * pow(5, ED25519_P - 2, ED25519_P) % ED25519_P).to_bytes(32, "little"))


def ed_small_order(point):
    """True if [8]P is the identity."""
    return ed_encode(ed_multiply(8, point)) == ed_encode(ED25519_IDENTITY)


def ed25519_secret(label):
    """The secret scalar and the nonce prefix of one of the two label keys (RFC 8032 section 5.1.5):
    seed = SHA-256(label), h = SHA-512(seed), the scalar is h[0..32] clamped, the prefix h[32..64]. Any
    other label is refused: verify.py takes no key input."""
    if label not in (KCR_TEST_KEY_LABEL, KCR_OTHER_KEY_LABEL):
        raise ValueError("verify.py signs only with its two public-label test keys")
    h = hashlib.sha512(hashlib.sha256(label).digest()).digest()
    scalar = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | 1 << 254
    return scalar, h[32:]


def ed25519_public_key(label):
    """The 32-byte public key of a label key."""
    return ed_encode(ed_multiply(ed25519_secret(label)[0], ED25519_BASE))


def ed25519_sign(label, message):
    """A pure Ed25519 signature (RFC 8032 section 5.1.6) by a label key: R || S, 64 bytes."""
    scalar, prefix = ed25519_secret(label)
    public = ed_encode(ed_multiply(scalar, ED25519_BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % ED25519_L
    big_r = ed_encode(ed_multiply(r, ED25519_BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % ED25519_L
    return big_r + ((r + k * scalar) % ED25519_L).to_bytes(32, "little")


def ed25519_verify(public_key, message, signature):
    """verify_strict (KCR_SPEC "ed25519"): True only if the key and R decode, S is below L, neither the
    key nor R is of small order, and [S]B - [k]A encodes to R's bytes."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_point, r_point = ed_decode(public_key), ed_decode(signature[:32])
    if a_point is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= ED25519_L or ed_small_order(a_point) or ed_small_order(r_point):
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % ED25519_L
    check = ed_add(ed_multiply(s, ED25519_BASE), ed_negate(ed_multiply(k, a_point)))
    return ed_encode(check) == signature[:32]


def ed25519_equation_holds(public_key, message, signature):
    """Only the cofactorless equation: the key and R decode, S is below L, and [S]B - [k]A encodes to R.
    verify_strict adds the small-order rules to this; the strict cases in kcr.json pass this and fail
    ed25519_verify."""
    a_point, r_point = ed_decode(public_key), ed_decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a_point is None or r_point is None or s >= ED25519_L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % ED25519_L
    return ed_encode(ed_add(ed_multiply(s, ED25519_BASE), ed_negate(ed_multiply(k, a_point)))) == signature[:32]


def ed25519_sign_small_order_r(label, message):
    """A signature by a label key whose R is the identity point: S = k x a mod L makes [S]B - [k]A the
    identity, so the cofactorless equation holds, and only verify_strict's small-order rule refuses it."""
    scalar, _ = ed25519_secret(label)
    big_r = ed_encode(ED25519_IDENTITY)
    k = int.from_bytes(hashlib.sha512(big_r + ed25519_public_key(label) + message).digest(), "little") % ED25519_L
    return big_r + (k * scalar % ED25519_L).to_bytes(32, "little")


def ed25519_s_plus_l(signature):
    """The same signature with L added to S: the malleable twin verify_strict must refuse."""
    s = int.from_bytes(signature[32:], "little") + ED25519_L
    return signature[:32] + s.to_bytes(32, "little")


def merkle_leaf(index, entries):
    """leaf(i) = SHA-256(0x00 || "KCE/v1/bucket" || i as 3 bytes, big-endian || the bucket's entries)."""
    return hashlib.sha256(b"\x00" + TAG_BUCKET + index.to_bytes(3, "big") + entries).digest()


def merkle_node(left, right):
    """node = SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


_EMPTY_TREE = []


def merkle_empty_levels():
    """The hash of every empty subtree, precomputed once per run: levels[j] holds the 2^(20 - j) nodes of
    level j, 32 bytes each, joined (level 0 the empty leaves, level 20 the empty root). Every leaf
    hashes its own index, so empty subtrees differ by position and all 2^21 - 1 hashes are kept."""
    if _EMPTY_TREE:
        return _EMPTY_TREE
    sha256, head = hashlib.sha256, b"\x00" + TAG_BUCKET
    level = bytearray()
    for index in range(1 << BUCKET_BITS):
        level += sha256(head + index.to_bytes(3, "big")).digest()
    levels = [bytes(level)]
    for _ in range(BUCKET_BITS):
        below, level = levels[-1], bytearray()
        for start in range(0, len(below), 64):
            level += sha256(b"\x01" + below[start:start + 64]).digest()
        levels.append(bytes(level))
    _EMPTY_TREE.extend(levels)
    return _EMPTY_TREE


def merkle_tree(buckets):
    """The bucket tree where `buckets` maps each non-empty bucket index to its entries' bytes: per level,
    a dict of the nodes that differ from the empty tree. Only the paths above those buckets are hashed."""
    level = {index: merkle_leaf(index, entries) for index, entries in buckets.items() if entries}
    tree = [level]
    for j in range(BUCKET_BITS):
        level = {position: merkle_node(merkle_at(tree, j, 2 * position), merkle_at(tree, j, 2 * position + 1))
                 for position in sorted(set(index >> 1 for index in level))}
        tree.append(level)
    return tree


def merkle_at(tree, level, position):
    """The node at (level, position): from the tree where a bucket below it is filled, else empty."""
    node = tree[level].get(position)
    if node is not None:
        return node
    return merkle_empty_levels()[level][32 * position:32 * position + 32]


def merkle_root(tree):
    return merkle_at(tree, BUCKET_BITS, 0)


def merkle_path(tree, index):
    """The 20 siblings of bucket `index`, leaf level first."""
    return [merkle_at(tree, j, (index >> j) ^ 1) for j in range(BUCKET_BITS)]


def merkle_path_root(index, entries, siblings):
    """The root a leaf and its path give: at level j the node is on the right when (index >> j) & 1."""
    node = merkle_leaf(index, entries)
    for j in range(BUCKET_BITS):
        sibling = siblings[32 * j:32 * j + 32]
        node = merkle_node(sibling, node) if index >> j & 1 else merkle_node(node, sibling)
    return node


def kcr_bucket_of(tag):
    """The bucket: the first 20 bits of T (or of T[0..16])."""
    return int.from_bytes(tag[:3], "big") >> 4


def kcr_entry(tag, count):
    """One 18-byte entry: T[0..16] || count (u16)."""
    return tag[:16] + count.to_bytes(2, "big")


def kcr_buckets(body):
    """The entries of a body grouped by bucket, in body order: {index: bytes}."""
    buckets = {}
    for start in range(0, len(body), KCR_ENTRY_BYTES):
        entry = body[start:start + KCR_ENTRY_BYTES]
        index = kcr_bucket_of(entry)
        buckets[index] = buckets.get(index, b"") + entry
    return buckets


def kcr_tag16(bucket, label):
    """A test T[0..16] in `bucket`: the bucket's 20 bits, then 108 bits of SHA-256(label)."""
    rest = int.from_bytes(hashlib.sha256(label).digest()[:14], "big") >> 4
    return (bucket << 108 | rest).to_bytes(16, "big")


def kcr_header(number, date, count, root, magic=KCR_MAGIC, version=KCR_VERSION):
    """The 58-byte header."""
    return (magic + version.to_bytes(2, "big") + number.to_bytes(8, "big") + date.to_bytes(4, "big")
            + count.to_bytes(8, "big") + root)


def kcr_signed(header, label=KCR_TEST_KEY_LABEL):
    """A header followed by its signature: 122 bytes."""
    return header + ed25519_sign(label, header)


def kcr_snapshot(number, date, body, label=KCR_TEST_KEY_LABEL):
    """A signed snapshot of `body`, its count and root computed from the body as it is."""
    root = merkle_root(merkle_tree(kcr_buckets(body)))
    return kcr_signed(kcr_header(number, date, len(body) // KCR_ENTRY_BYTES, root), label) + body


def kcp1(signed, bucket, entries, siblings, k=None, magic=KCP_MAGIC):
    """A KCP1 proof: magic || header || signature || bucket (3 bytes) || k (u16) || entries || siblings."""
    k = len(entries) // KCR_ENTRY_BYTES if k is None else k
    return magic + signed + bucket.to_bytes(3, "big") + k.to_bytes(2, "big") + entries + b"".join(siblings)


def kcp1_ur(proof):
    """The go-ahead QR text of a proof: the single-part UR of one CBOR byte string."""
    return ur_single(KCP_UR_TYPE, cbor_encode(cbor_byte_string(proof)))


def kcr_date(value):
    """A header date (YYYYMMDD) as a datetime.date, or None if it is not a real Gregorian date in years
    1-9999."""
    try:
        return datetime.date(value // 10000, value // 100 % 100, value % 100)
    except ValueError:
        return None


def kcr_freshness(date, today):
    """Current up to 30 days old, Stale from day 31, Future when after today."""
    age = kcr_date(today).toordinal() - kcr_date(date).toordinal()
    if age < 0:
        return "Future"
    return "Current" if age <= FRESH_DAYS else "Stale"


def kcr_read_header(signed, key):
    """The header checks shared by snapshots and proofs, in order: (fields, None) or (None, error)."""
    header, signature = signed[:KCR_HEADER_BYTES], signed[KCR_HEADER_BYTES:KCR_SIGNED_BYTES]
    if header[:4] != KCR_MAGIC:
        return None, "BadMagic"
    if int.from_bytes(header[4:6], "big") != KCR_VERSION:
        return None, "BadVersion"
    if not ed25519_verify(key, header, signature):
        return None, "BadSignature"
    fields = {"number": int.from_bytes(header[6:14], "big"), "date": int.from_bytes(header[14:18], "big"),
              "count": int.from_bytes(header[18:26], "big"), "root": header[26:58]}
    if kcr_date(fields["date"]) is None:
        return None, "BadDate"
    if fields["count"] > KCR_MAX_ENTRIES:
        return None, "TooManyEntries"
    return fields, None


def kcr_entries_error(entries, bucket=None):
    """The first entry rule broken, in entry order (KCR_SPEC "snapshot_checks", "proof_checks"), or None."""
    previous = None
    for start in range(0, len(entries), KCR_ENTRY_BYTES):
        tag, count = entries[start:start + 16], int.from_bytes(entries[start + 16:start + 18], "big")
        if bucket is not None and kcr_bucket_of(tag) != bucket:
            return "EntryOutsideBucket"
        if previous is not None and tag == previous:
            return "Duplicate"
        if previous is not None and tag < previous:
            return "Unsorted"
        if count == 0:
            return "ZeroCount"
        previous = tag
    return None


def kcr_verify(data, key):
    """A snapshot, checked in KCR_SPEC "snapshot_checks" order: (fields with the body, None) or (None,
    error)."""
    if len(data) < KCR_SIGNED_BYTES:
        return None, "TooShort"
    fields, error = kcr_read_header(data[:KCR_SIGNED_BYTES], key)
    if error:
        return None, error
    if len(data) != KCR_SIGNED_BYTES + KCR_ENTRY_BYTES * fields["count"]:
        return None, "BadLength"
    body = data[KCR_SIGNED_BYTES:]
    error = kcr_entries_error(body)
    if error:
        return None, error
    if merkle_root(merkle_tree(kcr_buckets(body))) != fields["root"]:
        return None, "RootMismatch"
    fields["body"] = body
    return fields, None


def kcp1_verify(data, key):
    """A KCP1 proof, checked in KCR_SPEC "proof_checks" order: (fields with the bucket and its entries,
    None) or (None, error)."""
    if len(data) < KCP_BASE_BYTES:
        return None, "TooShort"
    if data[:4] != KCP_MAGIC:
        return None, "BadMagic"
    fields, error = kcr_read_header(data[4:4 + KCR_SIGNED_BYTES], key)
    if error:
        return None, error
    at = 4 + KCR_SIGNED_BYTES
    bucket, k = int.from_bytes(data[at:at + 3], "big"), int.from_bytes(data[at + 3:at + 5], "big")
    if bucket >= 1 << BUCKET_BITS:
        return None, "BucketOutOfRange"
    if len(data) != KCP_BASE_BYTES + KCR_ENTRY_BYTES * k:
        return None, "BadLength"
    if k > fields["count"]:
        return None, "ProofCount"
    entries = data[at + 5:at + 5 + KCR_ENTRY_BYTES * k]
    error = kcr_entries_error(entries, bucket)
    if error:
        return None, error
    if merkle_path_root(bucket, entries, data[at + 5 + KCR_ENTRY_BYTES * k:]) != fields["root"]:
        return None, "RootMismatch"
    fields.update(bucket=bucket, entries=entries)
    return fields, None


def kcp1_verify_ur(text, key):
    """A go-ahead QR text: the strict UR decoder, then kcp1_verify."""
    data, error = ur_decode_single(KCP_UR_TYPE, text)
    if error:
        return None, "Ur(%s)" % error
    return kcp1_verify(data, key)


def kcr_count_of(entries, tag):
    """The registration count of T[0..16] among sorted entries, or None."""
    for start in range(0, len(entries), KCR_ENTRY_BYTES):
        if entries[start:start + 16] == tag[:16]:
            return int.from_bytes(entries[start + 16:start + 18], "big")
    return None


def kcr_seed(name, rolls_name, words):
    """One kcr.json seed: its mnemonic, S, seal code, T, Seal ID, bucket and the go-ahead code for seal
    vector 1's nonce."""
    rolls = dict(COLDCARD_ROLLS)[rolls_name] if rolls_name else None
    if rolls is None:
        mnemonic = KAT_MNEMONIC
    else:
        entropy = dice_only_entropy(rolls)
        mnemonic = " ".join(bip39_words(entropy if words == 24 else entropy[:16]))
    seed = bip39_seed(mnemonic)
    code = seal_code(seed)
    tag = seal_tag(code)
    go = go_ahead_code(tag, bytes.fromhex(KAT_NONCE_HEX))
    return {"name": name, "rolls": rolls, "words": words, "mnemonic": mnemonic, "seed_hex": seed.hex(),
            "seal_code": grouped(code, (5, 5, 5, 5, 6)), "seal_code_hashed": code, "seal_tag_hex": tag.hex(),
            "seal_id": seal_id(tag), "bucket": kcr_bucket_of(tag), "nonce_hex": KAT_NONCE_HEX,
            "go_ahead": grouped(go, (4, 4)), "go_ahead_compact": go}


def kcr_days(date, days):
    """`date` (YYYYMMDD) moved by `days` days, as YYYYMMDD."""
    moved = kcr_date(date) + datetime.timedelta(days=days)
    return moved.year * 10000 + moved.month * 100 + moved.day


def kcr_flip(data, offset, mask=1):
    """`data` with the bits of `mask` flipped in the byte at `offset`."""
    return data[:offset] + bytes([data[offset] ^ mask]) + data[offset + 1:]


def kcr_strict_cases():
    """Signatures the cofactorless equation accepts and verify_strict refuses, each isolating its rule
    (KCR_STRICT_RULES): the identity as the key with R = B and S = 1 ([1]B - [k]A = B for every message),
    so only the key is of small order; a test-key signature whose R is the identity, so only R is; and
    the identity as both with S = 0."""
    message = b"KCE/test/ed25519/strict"
    identity = ed_encode(ED25519_IDENTITY)
    return [
        {"name": "small-order-key", "public_key_hex": identity.hex(), "message_hex": message.hex(),
         "signature_hex": (ed_encode(ED25519_BASE) + (1).to_bytes(32, "little")).hex()},
        {"name": "small-order-r", "public_key_hex": ed25519_public_key(KCR_TEST_KEY_LABEL).hex(),
         "message_hex": message.hex(), "signature_hex": ed25519_sign_small_order_r(KCR_TEST_KEY_LABEL, message).hex()},
        {"name": "small-order-key-and-r", "public_key_hex": identity.hex(), "message_hex": message.hex(),
         "signature_hex": (identity + bytes(32)).hex()},
    ]


def kcr_strict_small_order(case):
    """(the key is of small order, R is of small order) for a strict case."""
    public, _, signature = kcr_strict_bytes(case)
    return ed_small_order(ed_decode(public)), ed_small_order(ed_decode(signature[:32]))


def kcr_strict_bytes(case):
    """(public key, message, signature) of a strict case."""
    return [bytes.fromhex(case[field]) for field in ("public_key_hex", "message_hex", "signature_hex")]


def kcr_largest_qr_proof():
    """The largest k whose KCP1 proof still fits one QR as a single-part UR (UR_MAX_CHARS), counted
    from real URs: the UR's length depends on k only."""
    k = 0
    while len(kcp1_ur(bytes(KCP_BASE_BYTES + KCR_ENTRY_BYTES * (k + 1)))) <= UR_MAX_CHARS:
        k += 1
    return k


_KCR_JSON = []


def kcr_vectors_json():
    """The exact text of vectors/kcr.json: indent 2, fixed key order, ASCII, trailing newline. Computed
    once per run (the empty tree takes a few seconds)."""
    if _KCR_JSON:
        return _KCR_JSON[0]
    test_key, other_key = ed25519_public_key(KCR_TEST_KEY_LABEL), ed25519_public_key(KCR_OTHER_KEY_LABEL)
    seeds = [kcr_seed(*s) for s in KCR_SEED_INPUTS]
    tag = {s["name"]: bytes.fromhex(s["seal_tag_hex"]) for s in seeds}
    v1, dice50, dice99 = tag["vector-1"], tag["dice-50-words12"], tag["dice-99-words12"]
    today = KCR_TODAY

    # "small": one entry in bucket 0 and one in the last bucket; two in one bucket; and in seal vector 1's
    # bucket another tag and one that shares vector 1's first 15 bytes, so a lookup must read all 16.
    small = sorted([
        kcr_entry(kcr_tag16(0, b"KCE/test/kcr/first"), 1),
        kcr_entry(kcr_tag16(kcr_bucket_of(v1), b"KCE/test/kcr/neighbour"), 2),
        kcr_entry(v1[:15] + bytes([v1[15] ^ 1]), 65535),
        kcr_entry(kcr_tag16(0x80000, b"KCE/test/kcr/pair-a"), 1),
        kcr_entry(kcr_tag16(0x80000, b"KCE/test/kcr/pair-b"), 3),
        kcr_entry(kcr_tag16((1 << BUCKET_BITS) - 1, b"KCE/test/kcr/last"), 7),
    ])
    small_buckets = set(kcr_bucket_of(e) for e in small)
    seed_buckets = [kcr_bucket_of(t) for t in (v1, dice50, dice99, tag["dice-99-words24"])]
    if len(set(seed_buckets)) != 4 or (small_buckets & set(seed_buckets)) != {kcr_bucket_of(v1)}:
        raise ValueError("the test seeds must sit in distinct buckets, and only vector 1's may hold entries")
    small_body = b"".join(small)
    with_v1 = b"".join(sorted(small + [kcr_entry(v1, 1)]))
    with_dice50 = b"".join(sorted(small + [kcr_entry(dice50, 1)]))
    empty_root = merkle_root(merkle_tree({}))

    snapshots = []

    def snapshot_case(name, data, freshness_today=today):
        snapshots.append((name, data, freshness_today))

    small_kcr = kcr_snapshot(2, today, small_body)
    snapshot_case("empty", kcr_snapshot(1, today, b""))
    snapshot_case("small", small_kcr)
    snapshot_case("with-vector-1", kcr_snapshot(3, today, with_v1))
    snapshot_case("with-dice-50", kcr_snapshot(4, today, with_dice50))
    snapshot_case("current-day-30", kcr_snapshot(5, kcr_days(today, -30), small_body))
    snapshot_case("stale-day-31", kcr_snapshot(6, kcr_days(today, -31), small_body))
    snapshot_case("future-day-1", kcr_snapshot(7, kcr_days(today, 1), small_body))
    small_root = small_kcr[26:58]
    unsigned = kcr_header(2, today, len(small), small_root)
    snapshot_case("bad-magic", kcr_signed(kcr_header(2, today, len(small), small_root, magic=b"KCRX")) + small_body)
    snapshot_case("version-0", kcr_signed(kcr_header(2, today, len(small), small_root, version=0)) + small_body)
    snapshot_case("version-2", kcr_signed(kcr_header(2, today, len(small), small_root, version=2)) + small_body)
    snapshot_case("truncated-header", small_kcr[:KCR_HEADER_BYTES - 1])
    snapshot_case("truncated-signature", small_kcr[:KCR_SIGNED_BYTES - 1])
    snapshot_case("truncated-body", small_kcr[:-1])
    snapshot_case("trailing-byte", small_kcr + b"\x00")
    snapshot_case("flipped-signature-r", kcr_flip(small_kcr, KCR_HEADER_BYTES))
    snapshot_case("flipped-signature-s", kcr_flip(small_kcr, KCR_HEADER_BYTES + 32))
    snapshot_case("header-changed-after-signing", kcr_flip(small_kcr, 13))
    snapshot_case("wrong-key", kcr_signed(unsigned, KCR_OTHER_KEY_LABEL) + small_body)
    signature = small_kcr[KCR_HEADER_BYTES:KCR_SIGNED_BYTES]
    snapshot_case("s-plus-l", unsigned + ed25519_s_plus_l(signature) + small_body)
    snapshot_case("small-order-r", unsigned + ed25519_sign_small_order_r(KCR_TEST_KEY_LABEL, unsigned) + small_body)
    for name, count in (("count-2^22-no-body", KCR_MAX_ENTRIES), ("count-2^22+1", KCR_MAX_ENTRIES + 1),
                        ("count-2^32+1", (1 << 32) + 1), ("count-u64-max", (1 << 64) - 1)):
        snapshot_case(name, kcr_signed(kcr_header(8, today, count, empty_root)))
    unsorted = list(small)
    pair = [i for i, e in enumerate(small) if kcr_bucket_of(e) == 0x80000]
    unsorted[pair[0]], unsorted[pair[1]] = small[pair[1]], small[pair[0]]
    snapshot_case("unsorted-within-bucket", kcr_snapshot(2, today, b"".join(unsorted)))
    snapshot_case("duplicate", kcr_snapshot(2, today, b"".join([small[0]] + small)))
    zero = list(small)
    zero[1] = zero[1][:16] + b"\x00\x00"
    snapshot_case("zero-count", kcr_snapshot(2, today, b"".join(zero)))
    recount = list(small)
    recount[0] = recount[0][:16] + b"\x00\x02"
    snapshot_case("root-mismatch", kcr_signed(unsigned) + b"".join(recount))
    snapshot_case("bad-date-month-13", kcr_signed(kcr_header(2, 20261310, len(small), small_root)) + small_body)
    snapshot_case("bad-date-feb-29-2026", kcr_signed(kcr_header(2, 20260229, len(small), small_root)) + small_body)
    snapshot_case("bad-date-day-0", kcr_signed(kcr_header(2, 20260300, len(small), small_root)) + small_body)
    # The check order: each order-* case breaks two or more checks and must give the first.
    other, unsorted_body = KCR_OTHER_KEY_LABEL, b"".join(unsorted)
    snapshot_case("order-magic-before-version",
                  kcr_signed(kcr_header(2, today, len(small), small_root, magic=b"KCRX", version=2)) + small_body)
    snapshot_case("order-version-before-signature",
                  kcr_signed(kcr_header(2, today, len(small), small_root, version=2), other) + small_body)
    snapshot_case("order-signature-before-date",
                  kcr_signed(kcr_header(2, 20261310, len(small), small_root), other) + small_body)
    snapshot_case("order-signature-before-count", kcr_signed(kcr_header(8, today, KCR_MAX_ENTRIES + 1, empty_root), other))
    snapshot_case("order-signature-before-entries", kcr_signed(unsigned, other) + unsorted_body)
    snapshot_case("order-date-before-count", kcr_signed(kcr_header(8, 20261310, KCR_MAX_ENTRIES + 1, empty_root)))
    snapshot_case("order-length-before-entries", kcr_signed(unsigned) + unsorted_body + b"\x00")
    snapshot_case("order-duplicate-before-zero-count",
                  kcr_snapshot(2, today, b"".join([small[0], small[0][:16] + b"\x00\x00"] + small[1:])))
    unsorted_zero = list(unsorted)
    unsorted_zero[pair[1]] = unsorted_zero[pair[1]][:16] + b"\x00\x00"
    snapshot_case("order-unsorted-before-zero-count", kcr_snapshot(2, today, b"".join(unsorted_zero)))
    snapshot_case("order-entries-before-root", kcr_signed(unsigned) + unsorted_body)

    # Proofs. Each comes from a snapshot tree: (signed header, tree).
    def proof_of(signed, body, bucket):
        tree = merkle_tree(kcr_buckets(body))
        entries = kcr_buckets(body).get(bucket, b"")
        return kcp1(signed, bucket, entries, merkle_path(tree, bucket))

    small_signed = small_kcr[:KCR_SIGNED_BYTES]
    v1_bucket, dice50_bucket = kcr_bucket_of(v1), kcr_bucket_of(dice50)
    shared = proof_of(small_signed, small_body, v1_bucket)
    proofs = []

    def proof_case(name, data, ur=False):
        proofs.append((name, data, ur))

    proof_case("clear-empty-bucket", proof_of(small_signed, small_body, kcr_bucket_of(dice99)))
    proof_case("clear-shared-prefix", shared)
    proof_case("collision", proof_of(kcr_snapshot(3, today, with_v1)[:KCR_SIGNED_BYTES], with_v1, v1_bucket))
    proof_case("collision-dice-50",
               proof_of(kcr_snapshot(4, today, with_dice50)[:KCR_SIGNED_BYTES], with_dice50, dice50_bucket))
    for name, number, days in (("current-day-30", 5, -30), ("stale-day-31", 6, -31), ("future-day-1", 7, 1)):
        signed = kcr_snapshot(number, kcr_days(today, days), small_body)[:KCR_SIGNED_BYTES]
        proof_case(name, proof_of(signed, small_body, dice50_bucket))
    at = 4 + KCR_SIGNED_BYTES
    k_shared = len(kcr_buckets(small_body)[v1_bucket]) // KCR_ENTRY_BYTES
    siblings_at = at + 5 + KCR_ENTRY_BYTES * k_shared
    for level in range(BUCKET_BITS):
        proof_case("forged-sibling-level-%d" % level, kcr_flip(shared, siblings_at + 32 * level))
    proof_case("mixed-header-and-path", KCP_MAGIC + kcr_snapshot(3, today, with_v1)[:KCR_SIGNED_BYTES] + shared[at:])
    proof_case("flipped-signature", kcr_flip(shared, 4 + KCR_HEADER_BYTES))
    proof_case("wrong-key", KCP_MAGIC + kcr_signed(unsigned, KCR_OTHER_KEY_LABEL) + shared[at:])
    proof_case("header-changed-after-signing", kcr_flip(shared, 4 + 13))
    proof_case("bad-magic", b"KCPX" + shared[4:])
    proof_case("header-bad-magic", KCP_MAGIC + kcr_signed(kcr_header(2, today, len(small), small_root,
                                                                     magic=b"KCRX")) + shared[at:])
    proof_case("header-version-2", KCP_MAGIC + kcr_signed(kcr_header(2, today, len(small), small_root,
                                                                     version=2)) + shared[at:])
    proof_case("bad-date", KCP_MAGIC + kcr_signed(kcr_header(2, 20261310, len(small), small_root)) + shared[at:])
    proof_case("too-many-entries",
               KCP_MAGIC + kcr_signed(kcr_header(2, today, KCR_MAX_ENTRIES + 1, small_root)) + shared[at:])
    proof_case("truncated", shared[:-1])
    clear_empty = proofs[0][1]
    proof_case("truncated-below-minimum", clear_empty[:-1])
    proof_case("trailing-byte", shared + b"\x00")
    proof_case("k-mismatch", shared[:at + 3] + (k_shared + 1).to_bytes(2, "big") + shared[at + 5:])
    small_path = merkle_path(merkle_tree(kcr_buckets(small_body)), v1_bucket)

    def resigned(entries, bucket=v1_bucket, count=len(small), signer=KCR_TEST_KEY_LABEL):
        """A proof of `entries` on vector 1's path, under a header whose root is the one they and the path
        give, so the root check passes and only the rule a case breaks fails (as for the snapshots)."""
        root = merkle_path_root(bucket, entries, b"".join(small_path))
        return kcp1(kcr_signed(kcr_header(2, today, count, root), signer), bucket, entries, small_path)

    in_bucket = kcr_buckets(small_body)[v1_bucket]
    first, second = in_bucket[:KCR_ENTRY_BYTES], in_bucket[KCR_ENTRY_BYTES:]
    out_of_range = resigned(b"", bucket=1 << BUCKET_BITS)
    proof_case("bucket-out-of-range", out_of_range)
    proof_case("more-entries-than-count", resigned(in_bucket, count=1))
    outside = kcr_entry(kcr_tag16(v1_bucket + 1, b"KCE/test/kcr/outside"), 1)
    proof_case("entry-outside-bucket", resigned(first + outside))
    proof_case("unsorted", resigned(second + first))
    proof_case("duplicate", resigned(first + first))
    proof_case("zero-count", resigned(first + second[:16] + b"\x00\x00"))
    # The check order, as for the snapshots.
    path_bytes = b"".join(small_path)
    proof_case("order-magic-before-signature", b"KCPX" + kcr_signed(unsigned, other) + shared[at:])
    proof_case("order-signature-before-bucket", KCP_MAGIC + kcr_signed(unsigned, other)
               + (1 << BUCKET_BITS).to_bytes(3, "big") + b"\x00\x00" + path_bytes)
    proof_case("order-signature-before-entries", KCP_MAGIC + kcr_signed(unsigned, other) + shared[at:at + 5]
               + second + first + shared[siblings_at:])
    proof_case("order-count-before-bucket", KCP_MAGIC + kcr_signed(kcr_header(2, today, KCR_MAX_ENTRIES + 1, small_root))
               + (1 << BUCKET_BITS).to_bytes(3, "big") + b"\x00\x00" + path_bytes)
    proof_case("order-bucket-before-length", out_of_range + b"\x00")
    proof_case("order-length-before-count", resigned(in_bucket, count=1) + b"\x00")
    proof_case("order-count-before-entries", resigned(second + first, count=1))
    outside_below = kcr_entry(kcr_tag16(v1_bucket - 1, b"KCE/test/kcr/outside-below"), 1)
    proof_case("order-outside-before-unsorted", resigned(first + outside_below))
    proof_case("order-unsorted-before-zero-count", resigned(second + first[:16] + b"\x00\x00"))
    proof_case("order-entries-before-root", shared[:at + 5] + second + first + shared[siblings_at:])

    # The go-ahead QR: the clear proof as UR text in both cases, the largest proof one QR holds, and the
    # strict decoder's failures on the proof's own UR.
    shared_ur = kcp1_ur(shared)
    proof_case("ur-lowercase", shared_ur, ur=True)
    proof_case("ur-uppercase", shared_ur.upper(), ur=True)
    largest = kcr_largest_qr_proof()
    for k in (largest, largest + 1):
        body = b"".join(sorted(kcr_entry(kcr_tag16(v1_bucket, b"KCE/test/kcr/qr/%d" % i), 1) for i in range(k)))
        signed = kcr_snapshot(9 + k - largest, today, body)[:KCR_SIGNED_BYTES]
        proof_case("ur-%d-entries" % k, kcp1_ur(proof_of(signed, body, v1_bucket)), ur=True)
    cbor = cbor_encode(cbor_byte_string(shared))
    message = shared_ur[len("ur:" + KCP_UR_TYPE + "/"):]

    def with_crc(payload):
        return "ur:%s/%s" % (KCP_UR_TYPE, bytewords_minimal(payload + crc32(payload).to_bytes(4, "big")))

    proof_case("ur-bad-crc", "ur:%s/%s" % (KCP_UR_TYPE, bytewords_minimal(
        cbor + (crc32(cbor) ^ 1).to_bytes(4, "big"))), ur=True)
    proof_case("ur-multi-part", "ur:%s/1-3/%s" % (KCP_UR_TYPE, message), ur=True)
    proof_case("ur-mixed-case", "UR:" + shared_ur[3:], ur=True)
    proof_case("ur-wrong-type", "ur:crypto-account/" + message, ur=True)
    proof_case("ur-non-shortest-head", with_crc(b"\x5a" + len(shared).to_bytes(4, "big") + shared), ur=True)
    proof_case("ur-trailing-byte", with_crc(cbor + b"\x00"), ur=True)

    def lookups_of(fields):
        found = []
        for s in seeds:
            t = tag[s["name"]]
            if "body" in fields:
                found.append({"seed": s["name"], "count": kcr_count_of(fields["body"], t)})
            elif kcr_bucket_of(t) != fields["bucket"]:
                found.append({"seed": s["name"], "result": "wrong_bucket", "count": None})
            else:
                count = kcr_count_of(fields["entries"], t)
                found.append({"seed": s["name"], "result": "clear" if count is None else "collision",
                              "count": count})
        return found

    def expect_of(fields, error):
        if error:
            return {"ok": False, "error": error}
        expect = {"ok": True, "number": fields["number"], "date": fields["date"], "count": fields["count"],
                  "root_hex": fields["root"].hex(), "freshness": kcr_freshness(fields["date"], today)}
        if "bucket" in fields:
            expect.update(bucket=fields["bucket"], k=len(fields["entries"]) // KCR_ENTRY_BYTES)
        expect["lookups"] = lookups_of(fields)
        return expect

    snapshot_json = [{"name": name, "kcr_hex": data.hex(), "expect": expect_of(*kcr_verify(data, test_key))}
                     for name, data, _ in snapshots]
    proof_json = []
    for name, data, ur in proofs:
        if ur:
            proof_json.append({"name": name, "ur": data, "expect": expect_of(*kcp1_verify_ur(data, test_key))})
        else:
            proof_json.append({"name": name, "kcp1_hex": data.hex(), "expect": expect_of(*kcp1_verify(data, test_key))})
    empty = merkle_empty_levels()
    left_aligned = (v1_bucket << 4).to_bytes(3, "big")
    node_left, node_right = empty[0][:32], empty[0][32:64]
    doc = {
        "description": "KeepCrypt registry snapshot (.kcr) and bucket proof (KCP1) vectors. Generated by "
        "tools/verify/verify.py --write-kcr-vectors; verify.py --selftest regenerates this file and requires "
        "byte equality, reruns every case through its own verifier, and checks RFC 8032 TEST 1-3 and pinned "
        "answers computed apart from it (check 10). Signed only with two test keys derived from public labels; "
        "public test mnemonics only, never a real seed or a real registry key.",
        "spec": KCR_SPEC,
        "keys": {"test_registry": {"label": KCR_TEST_KEY_LABEL.decode("ascii"), "public_key_hex": test_key.hex()},
                 "other": {"label": KCR_OTHER_KEY_LABEL.decode("ascii"), "public_key_hex": other_key.hex()}},
        "rfc8032": [{"name": name, "public_key_hex": public, "message_hex": message_hex, "signature_hex": sig,
                     "signature_s_plus_l_hex": ed25519_s_plus_l(bytes.fromhex(sig)).hex()}
                    for name, public, message_hex, sig in RFC8032_TESTS],
        "ed25519_strict": [dict(case, key_small_order=kcr_strict_small_order(case)[0],
                                r_small_order=kcr_strict_small_order(case)[1],
                                equation_holds=ed25519_equation_holds(*kcr_strict_bytes(case)),
                                verify_strict=ed25519_verify(*kcr_strict_bytes(case))) for case in kcr_strict_cases()],
        "limits": {"header_bytes": KCR_HEADER_BYTES, "signed_bytes": KCR_SIGNED_BYTES,
                   "entry_bytes": KCR_ENTRY_BYTES, "max_entries": KCR_MAX_ENTRIES,
                   "max_snapshot_bytes": KCR_SIGNED_BYTES + KCR_ENTRY_BYTES * KCR_MAX_ENTRIES,
                   "proof_base_bytes": KCP_BASE_BYTES, "qr_max_chars": UR_MAX_CHARS,
                   "max_qr_proof_entries": largest, "fresh_days": FRESH_DAYS},
        "today": today,
        "seeds": seeds,
        "merkle": {
            "empty_leaves": [{"bucket": index, "leaf_hex": empty[0][32 * index:32 * index + 32].hex()}
                             for index in (0, v1_bucket, (1 << BUCKET_BITS) - 1)],
            "left_aligned_leaf": {"prefix_hex": left_aligned.hex(), "leaf_hex": hashlib.sha256(
                b"\x00" + TAG_BUCKET + left_aligned).hexdigest(), "not_used": True},
            "node": {"left_hex": node_left.hex(), "right_hex": node_right.hex(),
                     "node_hex": merkle_node(node_left, node_right).hex()},
            "empty_root_hex": empty_root.hex(),
            "vector_1_path": {"bucket": v1_bucket, "entries_hex": kcr_buckets(small_body)[v1_bucket].hex(),
                              "siblings_hex": [s.hex() for s in merkle_path(merkle_tree(kcr_buckets(small_body)),
                                                                            v1_bucket)],
                              "root_hex": small_root.hex()},
        },
        "snapshots": snapshot_json,
        "proofs": proof_json,
    }
    _KCR_JSON.append(json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=True) + "\n")
    return _KCR_JSON[0]


def write_kcr_vectors(vectors_dir):
    """Write kcr.json into vectors_dir, which must already exist."""
    return write_vectors(vectors_dir, "kcr.json", kcr_vectors_json())


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


def check_bip39_english():
    """The embedded word list: 2,048 sorted words whose LF-joined bytes (plus a final LF) hash to
    the published SHA-256, and a BIP39 encoder that reproduces every English vectors.json entry."""
    problems = []
    if len(BIP39_ENGLISH) != 2048 or list(BIP39_ENGLISH) != sorted(set(BIP39_ENGLISH)):
        problems.append("the embedded BIP39 list is not 2,048 distinct sorted words")
    got = hashlib.sha256(("\n".join(BIP39_ENGLISH) + "\n").encode("ascii")).hexdigest()
    if got != BIP39_ENGLISH_SHA256:
        problems.append("the embedded BIP39 list hashes to %s, not %s" % (got, BIP39_ENGLISH_SHA256))
    return problems


def check_bip39_vectors(vectors_dir):
    """bip39_words against all 24 English entries of vectors/bip39/vectors.json."""
    english = json.loads((vectors_dir / "bip39" / "vectors.json").read_text(encoding="utf-8")).get("english")
    if not isinstance(english, list) or len(english) != 24:
        return ["vectors/bip39/vectors.json: expected 24 English entries"]
    return ["vectors/bip39/vectors.json english %d: bip39_words gives %r" % (n, " ".join(bip39_words(bytes.fromhex(e))))
            for n, (e, mnemonic, _, _) in enumerate(english) if " ".join(bip39_words(bytes.fromhex(e))) != mnemonic]


def named(doc, section, name):
    """The entry called `name` in a keepcrypt.json section list (ValueError if not exactly one)."""
    entries = [e for e in doc.get(section, []) if isinstance(e, dict) and e.get("name") == name]
    if len(entries) != 1:
        raise ValueError("keepcrypt.json %s: %d entries named %r" % (section, len(entries), name))
    return entries[0]


def check_session_record_rules(doc):
    """The committed source_substitution records against the session record rules themselves (Q6a,
    Q7), apart from the generator: no record is empty; the one OS record is the last record and
    holds the case's 64 OS bytes; and the hwrng records hold exactly the hwrng samples from index
    1,024 on, so no startup sample is ever absorbed and no later one is left out."""
    problems = []
    for case in doc.get("source_substitution", []):
        where = "keepcrypt.json source_substitution %s" % case.get("name")
        records = [(r.get("id"), bytes.fromhex(r.get("data_hex", ""))) for r in case.get("records", [])]
        os_bytes = bytes.fromhex(case.get("os_hex", ""))
        if any(not data for _, data in records):
            problems.append("%s: a record holds no bytes" % where)
        os_at = [i for i, (source_id, _) in enumerate(records) if source_id == SOURCE_ID["os"]]
        if len(os_bytes) != OS_BYTES or os_at != [len(records) - 1] or records[-1][1] != os_bytes:
            problems.append("%s: the only OS record must be the last one and hold the %d OS bytes" % (where, OS_BYTES))
        hw_events = b"".join(bytes.fromhex(e.get("data_hex", "")) for e in case.get("events", [])
                             if e.get("kind") == "hwrng")
        hw_records = b"".join(data for source_id, data in records if source_id == SOURCE_ID["hwrng"])
        if hw_records != hw_events[STARTUP_SAMPLES:]:
            problems.append("%s: the hwrng records must hold exactly the samples from index %d on"
                            % (where, STARTUP_SAMPLES))
    return problems


def check_keepcrypt_contents(vectors_dir):
    """The committed keepcrypt.json against the pins (KEEPCRYPT_PINNED, HEALTH_PINNED), the session
    record rules, and its Coldcard roll strings and seeds equal to vectors/coldcard/rolls.json."""
    path = vectors_dir / "keepcrypt.json"
    if not path.is_file():
        return []  # check_generated_file reports it missing
    doc = json.loads(path.read_text(encoding="ascii"))
    problems = check_session_record_rules(doc)
    for section, name, key, want in KEEPCRYPT_PINNED:
        got = named(doc, section, name).get(key)
        if got != want:
            problems.append("keepcrypt.json %s %s: %s is %r, pinned %s" % (section, name, key, got, want))
    for name, want in HEALTH_PINNED:
        got = named(doc, "health", name).get("expect")
        if got != want:
            problems.append("keepcrypt.json health %s: expect is %r, pinned %r" % (name, got, want))
    names = [e.get("name") for e in doc.get("health", [])]
    if names != [name for name, _ in HEALTH_PINNED]:
        problems.append("keepcrypt.json health: entries %r, pinned %r" % (names, [name for name, _ in HEALTH_PINNED]))
    coldcard = json.loads((vectors_dir / "coldcard" / "rolls.json").read_text(encoding="utf-8")).get("cases", [])
    if [c.get("rolls") for c in coldcard] != [r for _, r in COLDCARD_ROLLS]:
        problems.append("vectors/coldcard/rolls.json rolls differ from COLDCARD_ROLLS")
    for (name, _), case in zip(COLDCARD_ROLLS, coldcard):
        mine = named(doc, "dice_only", name)
        theirs = (case.get("sha256_hex"), case.get("words_12"), case.get("words_24"))
        if (mine.get("e_hex"), mine.get("words_12"), mine.get("words_24")) != theirs:
            problems.append("keepcrypt.json dice_only %s differs from rolls.json" % name)
    return problems


def check_keepcrypt_json(vectors_dir):
    """Check 6: the embedded BIP39 list and encoder, keepcrypt.json equal to the regenerated text,
    its pinned answers and its session record rules."""
    return (
        check_bip39_english()
        + check_bip39_vectors(vectors_dir)
        + check_generated_file(vectors_dir, "keepcrypt.json", keepcrypt_vectors_json(), "--write-keepcrypt-vectors")
        + check_keepcrypt_contents(vectors_dir)
    )


def check_health_cutoffs(vectors_dir):
    """Check 7: the exact-fraction APT cutoff reproduces SP 800-90B Table 2, the RCT cutoff for H = 4
    is 6, and the constants behind keepcrypt.json are those computed values."""
    problems = ["SP 800-90B Table 2: W = %d, H = %d gives C = %d, the table says %d" % (w, h, apt_cutoff(w, h), c)
                for w, h, c in SP800_90B_TABLE_2 if apt_cutoff(w, h) != c]
    if rct_cutoff(4) != 6:
        problems.append("RCT cutoff for H = 4 is %d, not 6" % rct_cutoff(4))
    if (rct_cutoff(HEALTH_H), apt_cutoff(APT_WINDOW, HEALTH_H)) != (RCT_CUTOFF, APT_CUTOFF):
        problems.append("RCT_CUTOFF %d and APT_CUTOFF %d are not the computed %d and %d"
                        % (RCT_CUTOFF, APT_CUTOFF, rct_cutoff(HEALTH_H), apt_cutoff(APT_WINDOW, HEALTH_H)))
    path = vectors_dir / "keepcrypt.json"
    if path.is_file():
        health = json.loads(path.read_text(encoding="ascii")).get("constants", {}).get("health")
        want = {"h": HEALTH_H, "alpha_log2": -ALPHA_LOG2, "rct_cutoff": rct_cutoff(HEALTH_H), "apt_window": APT_WINDOW,
                "apt_cutoff": apt_cutoff(APT_WINDOW, HEALTH_H), "startup_samples": STARTUP_SAMPLES}
        if health != want:
            problems.append("keepcrypt.json constants.health is %r, computed %r" % (health, want))
    return problems


def check_braille_known_answers():
    """The generated tables against the pins: the docs' alphabet and signs, the mirror pairs, the six
    sample inserts, the text vectors and refusals, the Q9 insert labels, backup lines, and the
    canonical table digest."""
    problems = []
    letters = [(letter, braille_cell(dots)) for letter, dots in BRAILLE_LETTER_DOTS]
    rows = ["  ".join("%s %s" % pair for pair in letters[start:end]) for start, end in ((0, 10), (10, 20), (20, 26))]
    if tuple(rows) != BRAILLE_DOCS_ALPHABET or [letter for letter, _ in letters] != list("abcdefghijklmnopqrstuvwxyz"):
        problems.append("braille alphabet %r differs from the docs' %r" % (rows, BRAILLE_DOCS_ALPHABET))
    sign_dots = dict(BRAILLE_SIGN_DOTS)
    for name, cell, dots in BRAILLE_DOCS_SIGNS:
        if (sign_dots.get(name), braille_cell(sign_dots.get(name, ""))) != (dots, cell):
            problems.append("braille %s is not %s (dots %s)" % (name, cell, dots))
    if braille_cell(sign_dots.get("space", "x")) != "⠀":
        problems.append("braille space is not the blank cell U+2800")
    if sorted(braille_mirror_pairs()) != sorted(BRAILLE_DOCS_MIRROR_PAIRS):
        problems.append("braille mirror pairs from the dots are %r, the docs say %r"
                        % (braille_mirror_pairs(), BRAILLE_DOCS_MIRROR_PAIRS))
    entries = {e["word"]: e for e in braille_word_entries()}
    for word, number, faces, lighter, mirror_faces in BRAILLE_SAMPLE_INSERTS:
        e = entries[word]
        got = (e["number"], tuple(e["faces"]), e["lighter_face"],
               tuple(face for face, partner in enumerate(e["mirror_partners"], 1) if partner))
        if got != (number, faces, lighter, mirror_faces):
            problems.append("braille sample %s: (number, faces, lighter face, mirror faces) %r, pinned %r"
                            % (word, got, (number, faces, lighter, mirror_faces)))
    for text, cells in BRAILLE_TEXT_VECTORS:
        if braille_text(text) != cells:
            problems.append("braille text %r gives %r, pinned %r" % (text, braille_text(text), cells))
    for text in BRAILLE_TEXT_REFUSED:
        try:
            braille_text(text)
            problems.append("braille text %r is not refused" % text)
        except ValueError:
            pass
    for length, position, device, devices, sequence in BRAILLE_POSITION_PINS:
        got = insert_positions(length)[position - 1]
        want = {"position": position, "device": device, "devices": devices, "sequence": sequence}
        if got != want:
            problems.append("braille %d-word position %d is %r, pinned %r" % (length, position, got, want))
    for mnemonic, index, line in BRAILLE_BACKUP_LINE_PINS:
        if backup_braille_lines(mnemonic.split())[index] != line:
            problems.append("braille backup line %d of %r is %r, pinned %r"
                            % (index + 1, mnemonic, backup_braille_lines(mnemonic.split())[index], line))
    digest = hashlib.sha256(braille_table_text().encode("utf-8")).hexdigest()
    if digest != BRAILLE_TABLE_SHA256:
        problems.append("braille table text hashes to %s, pinned %s" % (digest, BRAILLE_TABLE_SHA256))
    return problems


def braille_recount():
    """The docs' numbers recounted straight from the embedded list, apart from the generator: the counts of
    BRAILLE_DOCS_COUNTS, the sections and the list's SHA-256."""
    sections = {}
    for word in BIP39_ENGLISH:
        sections[word[0]] = sections.get(word[0], 0) + 1
    pages = sum(-(-count // SEEDBOOK_WORDS_PER_PAGE) for count in sections.values())
    keys = set(word[:4] for word in BIP39_ENGLISH)
    swap = {"e": "i", "i": "e", "d": "f", "f": "d", "h": "j", "j": "h", "r": "w", "w": "r"}
    flip_words = sum(1 for word in BIP39_ENGLISH if any(
        word[:4][:i] + swap[c] + word[:4][i + 1:] in keys for i, c in enumerate(word[:4]) if c in swap))
    proper_prefixes = set(o[:k] for o in BIP39_ENGLISH for k in range(1, len(o)))
    prefix_words = sum(1 for word in BIP39_ENGLISH if word in proper_prefixes)
    counts = {
        "words": len(BIP39_ENGLISH),
        "sections": len(sections),
        "pages": pages,
        "words_per_page": SEEDBOOK_WORDS_PER_PAGE,
        "mirror_pairs": len(swap) // 2,
        "mirror_flip_words": flip_words,
        "short_prefix_words": prefix_words,
        "distinct_readback_keys": len(keys),
    }
    list_sha256 = hashlib.sha256(("\n".join(BIP39_ENGLISH) + "\n").encode("ascii")).hexdigest()
    return counts, sorted(sections.items()), swap, list_sha256


def check_braille_counts():
    """The docs' numbers recounted straight from the embedded list, apart from the generator: the list's
    SHA-256, the 25 section counts and 98 pages, the 279 mirror-flip words, the 49 short prefix words,
    the four mirror pairs and 2,048 distinct first-four keys."""
    problems = []
    recounted, sections, swap, got = braille_recount()
    if got != BIP39_ENGLISH_SHA256:
        problems.append("the embedded BIP39 list hashes to %s, not %s" % (got, BIP39_ENGLISH_SHA256))
    if sections != list(BRAILLE_SECTION_COUNTS):
        problems.append("SeedBook sections %r, pinned %r" % (sections, list(BRAILLE_SECTION_COUNTS)))
    if recounted != BRAILLE_DOCS_COUNTS:
        problems.append("the docs' braille counts %r, recounted from the list %r" % (BRAILLE_DOCS_COUNTS, recounted))
    if sorted(swap.items()) != sorted(braille_mirror_partner().items()):
        problems.append("the recount's mirror letters differ from the pairs computed from the dots")
    generated = braille_counts(braille_word_entries())
    if generated != recounted:
        problems.append("the generator's counts %r differ from the recount %r" % (generated, recounted))
    return problems


def braille_docs_sentences():
    """What docs/seal-watchonly-braille.md must say, word for word, built from the recount, the generated
    tables and seal vector 1: (what, the exact text)."""
    counts, sections, _, list_sha256 = braille_recount()
    entries = {e["word"]: e for e in braille_word_entries()}
    letters = [(letter, braille_cell(dots)) for letter, dots in BRAILLE_LETTER_DOTS]
    sign = dict(BRAILLE_SIGN_DOTS)
    vector = seal_vector(*SEAL_VECTOR_INPUTS[0])
    entropy_bits = 32 * BIP39_CHECKED_WORDS * 11 // 33
    checksum_bits = BIP39_CHECKED_WORDS * 11 - entropy_bits

    def first_four(word):
        return ", ".join(face or "blank" for face in entries[word]["faces"][:SEEDBOOK_READBACK_FACES])

    def number(word):
        return "%04d" % entries[word]["number"]

    sentences = [("alphabet row %d" % (n + 1), "  ".join("%s %s" % pair for pair in letters[start:end]))
                 for n, (start, end) in enumerate(((0, 10), (10, 20), (20, 26)))]
    sentences += [
        ("the mirror-flip count", "It matters because %d BIP39 words are one mirror-pair flip away from another "
         "word's first four letters" % counts["mirror_flip_words"]),
        ("the checksum odds", "the %d-word checksum would miss about 1 such error in %d"
         % (BIP39_CHECKED_WORDS, 2 ** checksum_bits)),
        ("ACT and ACTION", "ACT (%s) is %s; ACTION (%s) is %s"
         % (number("act"), first_four("act"), number("action"), first_four("action"))),
        ("the short prefix count", "%d short words are prefixes of longer ones" % counts["short_prefix_words"]),
        ("the distinct first-four keys", "The first four letters identify every one of the {:,} words"
         .format(counts["distinct_readback_keys"])),
        ("the SeedBook numbers", "the official list, 0001\u2013%04d" % counts["words"]),
        ("the number sign", "number sign %s (dots %s)" % (braille_cell(sign["number_sign"]),
                                                          "-".join(sign["number_sign"]))),
        ("the digits", "then " + " ".join("%s=%d" % (BRAILLE_DIGIT_LETTERS[d], d) for d in (1, 2, 3, 4, 5, 6, 7, 8,
                                                                                         9, 0))),
        ("2026", "(2026 = %s)" % braille_text("2026")),
        ("the grade 1 indicator", "grade 1 indicator %s (dots %s)" % (braille_cell(sign["grade1_indicator"]),
                                                                      "-".join(sign["grade1_indicator"]))),
        ("the hyphen", "a hyphen %s ends the digits" % braille_cell(sign["hyphen"])),
        ("the Seal ID", "(Seal ID %s = %s)" % (vector["seal_id"], vector["seal_id_braille"])),
        ("the sections, pages and sample numbers", "the SeedBook's %d section counts (total {:,}), its page ranges "
         "001\u2013%03d, and the sample numbers ABANDON %s, ACT %s, METAL %s, WIRE %s and ZOO %s all match the "
         "official list".format(sum(count for _, count in sections))
         % (counts["sections"], counts["pages"], number("abandon"), number("act"), number("metal"), number("wire"),
            number("zoo"))),
        ("the word-list SHA-256", "wordlist SHA-256 `%s`" % list_sha256),
    ]
    return sentences


def check_braille_docs():
    """docs/seal-watchonly-braille.md against the recount (tasks/lessons.md, "Spec verification before
    hand-off"): each computable figure must appear there exactly as recomputed, and its mirror pairs must
    be the pairs computed from the dots. Editing a figure in the docs, or a value it is computed from,
    fails the check."""
    if not BRAILLE_DOCS.is_file():
        return ["%s is missing" % BRAILLE_DOCS]
    text = BRAILLE_DOCS.read_text(encoding="utf-8")
    lines = text.splitlines()
    problems = []
    for what, sentence in braille_docs_sentences():
        found = sentence in lines if what.startswith("alphabet row") else sentence in text
        if not found:
            problems.append("%s: the docs do not say %r" % (BRAILLE_DOCS.name, sentence))
    match = re.search(r"\| Mirror pairs \| (.+?) are left-right mirror images, and the only such pairs", text)
    printed = re.findall(r"([a-z])/([a-z])", match.group(1)) if match else []
    if sorted(tuple(sorted(pair)) for pair in printed) != sorted(braille_mirror_pairs()):
        problems.append("%s: the mirror pairs %r are not the pairs computed from the dots %r"
                        % (BRAILLE_DOCS.name, printed, braille_mirror_pairs()))
    return problems


def check_braille_contents(vectors_dir):
    """The committed braille.json: its counts and table digest equal the pins, its words are the list
    in order, and the SeedBook PDF hashes to its pinned SHA-256."""
    problems = []
    path = vectors_dir / "braille.json"
    if path.is_file():  # check_generated_file reports it missing
        doc = json.loads(path.read_text(encoding="ascii"))
        if doc.get("counts") != BRAILLE_DOCS_COUNTS:
            problems.append("braille.json counts %r, pinned %r" % (doc.get("counts"), BRAILLE_DOCS_COUNTS))
        if doc.get("cells", {}).get("table_sha256") != BRAILLE_TABLE_SHA256:
            problems.append("braille.json table_sha256 is not the pinned %s" % BRAILLE_TABLE_SHA256)
        words = [(e.get("number"), e.get("word")) for e in doc.get("words", [])]
        if words != list(enumerate(BIP39_ENGLISH, 1)):
            problems.append("braille.json words are not the 2,048 list words numbered 1-2048 in order")
    if not SEEDBOOK_PDF.is_file():
        problems.append("%s is missing" % SEEDBOOK_PDF)
    elif sha256_file(SEEDBOOK_PDF) != SEEDBOOK_PDF_SHA256:
        problems.append("the SeedBook PDF sha256 is %s, pinned %s" % (sha256_file(SEEDBOOK_PDF), SEEDBOOK_PDF_SHA256))
    return problems


def check_braille_json(vectors_dir):
    """Check 8: the pinned braille answers, the docs' counts recounted from the list, the docs saying them,
    braille.json equal to the regenerated text, its contents, and the SeedBook PDF's SHA-256."""
    return (
        check_braille_known_answers()
        + check_braille_counts()
        + check_braille_docs()
        + check_generated_file(vectors_dir, "braille.json", braille_vectors_json(), "--write-braille-vectors")
        + check_braille_contents(vectors_dir)
    )


def check_watchonly_primitives():
    """The hand-written primitives against the standard library and the copied spec values: RIPEMD-160
    against hashlib's (where it has one), CRC-32 against zlib's, the RFC 8949 examples, the
    BCR-2020-012 checksums and Bytewords, the BCR-2020-005 seed UR, the BIP-380 checksum cases and
    NFKD through the bip32JP seed."""
    problems = []
    samples = [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"message digest", bytes(range(256)) * 3]
    for data in samples:
        native = hashlib_ripemd160(data)
        if native is not None and native != ripemd160_pure(data):
            problems.append("RIPEMD-160 of %d bytes: pure %s, hashlib %s" % (len(data), ripemd160_pure(data).hex(),
                                                                            native.hex()))
        if crc32(data) != zlib.crc32(data):
            problems.append("CRC-32 of %d bytes: %08x, zlib %08x" % (len(data), crc32(data), zlib.crc32(data)))
    if "%08x" % crc32(b"123456789") != CRC32_CHECK_VALUE:
        problems.append("CRC-32 of 123456789 is %08x, not %s" % (crc32(b"123456789"), CRC32_CHECK_VALUE))
    for diagnostic, item, encoded in RFC8949_EXAMPLES:
        if cbor_encode(item).hex() != encoded:
            problems.append("RFC 8949 %s encodes as %s, published %s" % (diagnostic, cbor_encode(item).hex(), encoded))
    for data_hex, crc_hex, minimal in ((BCR012_BODY_HEX, BCR012_BODY_CRC32, BCR012_BODY_MINIMAL),
                                       (BCR012_BRUTAL_PAYLOAD_HEX, BCR012_BRUTAL_CRC32, BCR012_BRUTAL_MINIMAL)):
        data = bytes.fromhex(data_hex)
        if "%08x" % crc32(data) != crc_hex or bytewords_minimal(data + bytes.fromhex(crc_hex)) != minimal:
            problems.append("BCR-2020-012 %s: CRC-32 %08x or its Bytewords differ" % (data_hex, crc32(data)))
    if len(BYTEWORDS) != 256 or len(set(w[0] + w[3] for w in BYTEWORDS)) != 256 or list(BYTEWORDS) != sorted(BYTEWORDS):
        problems.append("the Bytewords table is not 256 sorted words with distinct first-and-last letters")
    if ur_single("seed", bytes.fromhex(BCR005_SEED_CBOR_HEX)) != BCR005_SEED_UR:
        problems.append("BCR-2020-005 seed UR is %s" % ur_single("seed", bytes.fromhex(BCR005_SEED_CBOR_HEX)))
    for name, text, valid in BIP380_CHECKSUM_VECTORS:
        if descriptor_checksum_valid(text) != valid:
            problems.append("BIP-380 %s (%r): valid %s, published %s" % (name, text, not valid, valid))
    if descriptor_checksum("raw(deadbeef)") != "89f8spxm":
        problems.append("BIP-380 checksum of raw(deadbeef) is %s" % descriptor_checksum("raw(deadbeef)"))
    if bip39_seed_with_passphrase(BIP32JP_MNEMONIC, BIP32JP_PASSPHRASE).hex() != BIP32JP_SEED_HEX:
        problems.append("the bip32JP entry 0 seed differs: NFKD of the mnemonic or passphrase is wrong")
    return problems


def check_watchonly_spec_values():
    """The generated export against the copied spec values (BIP-84, BCR-2020-015) and the plan's pins."""
    problems = []
    doc = json.loads(watchonly_vectors_json())
    wallets = {w["name"]: w for w in doc["wallets"]}
    abandon = wallets["abandon"]
    if doc["bip84"]["root_zpub"] != BIP84_ROOT_ZPUB or doc["bip84"]["account_zpub"] != BIP84_ACCOUNT_ZPUB:
        problems.append("BIP-84 root or account zpub differs from the published one")
    published = [(n, p, a) for n, _, p, a in BIP84_ADDRESSES]
    if [(a["name"], a["pubkey"], a["address"]) for a in doc["bip84"]["addresses"]] != published:
        problems.append("BIP-84 address public keys or addresses differ from the published ones")
    if (abandon["first_receive_address"], abandon["first_change_address"]) != (BIP84_ADDRESSES[0][3],
                                                                              BIP84_ADDRESSES[2][3]):
        problems.append("the abandon wallet's first addresses differ from BIP-84's")
    rebuilt = doc["bcr_2020_015"]
    if rebuilt["cbor_hex"] != "".join(BCR015_CBOR_HEX) or len(bytes.fromhex(rebuilt["cbor_hex"])) != 773:
        problems.append("the rebuilt BCR-2020-015 CBOR differs from the published 773 bytes")
    if rebuilt["ur"] != "".join(BCR015_UR):
        problems.append("the rebuilt BCR-2020-015 UR differs from the published one")
    for out, (tags, components, key, chain, source, parent), descriptor in zip(rebuilt["outputs"], BCR015_OUTPUTS,
                                                                              BCR015_DESCRIPTORS):
        got = (tuple(out["tags"]), tuple(tuple(c) for c in out["components"]), out["key_hex"], out["chain_code_hex"],
               out["source_fingerprint"], out["parent_fingerprint"])
        if got != (tags, components, key, chain, source, parent) or out["xpub"] not in descriptor:
            problems.append("BCR-2020-015 output %r: derived %r or its xpub differs" % (components, got))
    if wallets["shield"]["account_xpub"] not in BCR015_DESCRIPTORS[2]:
        problems.append("the shield wallet's account xpub is not BCR-2020-015's wpkh xpub")
    for name, field, want in WATCHONLY_PINNED:
        w = wallets[name]
        got = {
            "receive_checksum": w["receive_descriptor"][-8:],
            "change_checksum": w["change_descriptor"][-8:],
            "crypto_account_cbor_bytes": len(w["crypto_account_cbor_hex"]) // 2,
            "crypto_account_ur_chars": len(w["crypto_account_ur"]),
        }.get(field, w.get(field))
        if got != want:
            problems.append("watchonly.json %s %s is %r, pinned %r" % (name, field, got, want))
    if wallets["abandon-trezor"]["fingerprint"] == wallets["abandon-trezor-space"]["fingerprint"]:
        problems.append("\"TREZOR \" and \"TREZOR\" gave the same wallet")
    if any("'" in w["receive_descriptor"] + w["change_descriptor"] for w in doc["wallets"]):
        problems.append("a descriptor is written with an apostrophe")
    for w in doc["wallets"]:
        for field in ("receive_descriptor", "change_descriptor", "receive_descriptor_apostrophe"):
            if not descriptor_checksum_valid(w[field]):
                problems.append("watchonly.json %s %s has a bad checksum" % (w["name"], field))
        if w["receive_descriptor"][-8:] == w["receive_descriptor_apostrophe"][-8:]:
            problems.append("watchonly.json %s: the apostrophe form has the same checksum" % w["name"])
    # The zero-fingerprint case, worked from the abandon export by hand: the master fingerprint becomes 0
    # (required at the top level), and the key path's source fingerprint (key 2) and the hdkey's parent
    # fingerprint (key 8) are left out, so those maps shrink from 2 to 1 and from 4 to 3 entries.
    mfp, parent = abandon["fingerprint"], abandon["account_parent_fingerprint"]
    want = (abandon["crypto_account_cbor_hex"].replace("a2011a" + mfp, "a20100", 1).replace("d9012fa4", "d9012fa3", 1)
            .replace("d90130a2", "d90130a1", 1).replace("021a" + mfp + "081a" + parent, "", 1))
    if doc["zero_fingerprints"]["cbor_hex"] != want:
        problems.append("the zero-fingerprint crypto-account is not the abandon one without its zero fingerprints")
    return problems


def check_watchonly_ur_rules():
    """The decoder cases against the rules: the reader rebuilt here decodes every bytes UR in either case
    and refuses every negative with exactly the error it names; and, apart from that reader, the
    longest UR fits 4,296 characters, the too-long ones do not (in UTF-8 bytes, as core counts), and
    only text with both ASCII cases is MixedCase."""
    problems = []
    doc = json.loads(watchonly_vectors_json())
    for u in doc["ur"]:
        if u["type"] == "bytes":
            for text in (u["ur"], u["ur"].upper()):
                if ur_decode_single("bytes", text) != (bytes.fromhex(u["data_hex"]), None):
                    problems.append("ur %s does not decode to its data: %r" % (u["name"], ur_decode_single("bytes", text)[1]))
    for case in doc["ur_negatives"]:
        got = ur_decode_single(case["expected_type"], case["text"])
        if got != (None, case["error"]):
            problems.append("ur_negatives %s: the reader gives %r, the case names %s" % (case["name"], got[1], case["error"]))
    lengths = [len(u["ur"]) for u in doc["ur"] if u["type"] == "bytes"]
    if max(lengths) > UR_MAX_CHARS or max(lengths) < UR_MAX_CHARS - 1:
        problems.append("the longest bytes UR has %d characters, not 4,295 or 4,296" % max(lengths))
    for case in doc["ur_negatives"]:
        raw, error = case["text"].encode("utf-8"), case["error"]
        too_long = len(raw) > UR_MAX_CHARS
        if (error == "TooLong") != too_long:
            problems.append("ur_negatives %s: %d bytes, error %s" % (case["name"], len(raw), error))
        # bytes.lower() and bytes.upper() change ASCII letters only, as core's case rule does.
        if not too_long and (error == "MixedCase") != (raw != raw.lower() and raw != raw.upper()):
            problems.append("ur_negatives %s: case and error %s disagree" % (case["name"], error))
    return problems


def check_watchonly_json(vectors_dir):
    """Check 9: the primitives against the standard library and the copied spec values, the export
    against BIP-84, BCR-2020-015 and the plan's pins, the decoder cases, and watchonly.json equal to
    the regenerated text."""
    return (
        check_watchonly_primitives()
        + check_watchonly_spec_values()
        + check_watchonly_ur_rules()
        + check_generated_file(vectors_dir, "watchonly.json", watchonly_vectors_json(), "--write-watchonly-vectors")
    )


# The strict cases and which point of each is of small order: (name, key, R). One case per rule and one
# with both, so dropping either rule from verify_strict lets its own case through (tasks/todo.md, M1
# group 7; review fix after commit 18).
KCR_STRICT_RULES = (
    ("small-order-key", True, False),
    ("small-order-r", False, True),
    ("small-order-key-and-r", True, True),
)


def check_ed25519(vectors_dir):
    """RFC 8032 TEST 1-3 verify and refuse L added to S; every kat.json Ed25519 entry verifies and fails
    with one bit flipped in its public key, in R and in S; each label key's signature verifies and fails
    on a changed message; each strict case isolates its small-order rule (KCR_STRICT_RULES), satisfies
    the cofactorless equation and is refused; any other label is refused."""
    problems = []
    for name, public, message, signature in RFC8032_TESTS:
        public, message, signature = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
        if not ed25519_verify(public, message, signature):
            problems.append("RFC 8032 %s does not verify" % name)
        if ed25519_verify(public, message, ed25519_s_plus_l(signature)):
            problems.append("RFC 8032 %s verifies with L added to S" % name)
    if [(n, k, m.hex(), s) for n, _, k, m, s in KAT_ED25519] != [RFC8032_TESTS[0]]:
        problems.append("KAT_ED25519 is not RFC 8032 TEST 1 as RFC8032_TESTS has it")
    path = vectors_dir / "kat.json"
    entries = json.loads(path.read_text(encoding="ascii")).get("ed25519") if path.is_file() else None
    if not isinstance(entries, list) or not entries:
        problems.append("kat.json has no ed25519 entries")
        entries = []
    for e in entries:
        public, signature, message = kat_field(e, "public_key", 32), kat_field(e, "signature", 64), kat_field(e, "message")
        if not ed25519_verify(public, message, signature):
            problems.append("kat.json ed25519 %s does not verify" % e.get("name"))
        for what, key, sig in (("its public key", kcr_flip(public, 0), signature), ("R", public, kcr_flip(signature, 0)),
                               ("S", public, kcr_flip(signature, 32))):
            if ed25519_verify(key, message, sig):
                problems.append("kat.json ed25519 %s verifies with a bit of %s flipped" % (e.get("name"), what))
    message = b"KCE/test/ed25519"
    for label in (KCR_TEST_KEY_LABEL, KCR_OTHER_KEY_LABEL):
        public, signature = ed25519_public_key(label), ed25519_sign(label, message)
        if not ed25519_verify(public, message, signature) or ed25519_verify(public, message + b".", signature):
            problems.append("the %s key's signature does not verify, or verifies a changed message" % label.decode())
    cases = kcr_strict_cases()
    if [(case["name"],) + kcr_strict_small_order(case) for case in cases] != list(KCR_STRICT_RULES):
        problems.append("strict cases %r, pinned %r: each must isolate its small-order rule"
                        % ([(case["name"],) + kcr_strict_small_order(case) for case in cases], KCR_STRICT_RULES))
    for case in cases:
        if not ed25519_equation_holds(*kcr_strict_bytes(case)) or ed25519_verify(*kcr_strict_bytes(case)):
            problems.append("strict case %s: the equation must hold and verify_strict must refuse it" % case["name"])
    try:
        ed25519_sign(b"KCE/test/any-other-key", message)
        problems.append("the signer took a key other than its two label keys")
    except ValueError:
        pass
    return problems


# What each kcr.json case must give, pinned apart from the generator and its verifier, so neither can
# change an outcome and still pass after --write-kcr-vectors (tasks/lessons.md: "pin a vector"). A
# verified case gives its freshness against KCR_TODAY; a rejected one its SnapshotError. A verified
# snapshot also names the one seed it registers (or None); a verified proof the one seed in its
# bucket and that seed's result.
KCR_SNAPSHOT_RESULTS = (
    ("empty", "Current", None), ("small", "Current", None), ("with-vector-1", "Current", "vector-1"),
    ("with-dice-50", "Current", "dice-50-words12"), ("current-day-30", "Current", None),
    ("stale-day-31", "Stale", None), ("future-day-1", "Future", None),
    ("bad-magic", "BadMagic", None), ("version-0", "BadVersion", None), ("version-2", "BadVersion", None),
    ("truncated-header", "TooShort", None), ("truncated-signature", "TooShort", None),
    ("truncated-body", "BadLength", None), ("trailing-byte", "BadLength", None),
    ("flipped-signature-r", "BadSignature", None), ("flipped-signature-s", "BadSignature", None),
    ("header-changed-after-signing", "BadSignature", None), ("wrong-key", "BadSignature", None),
    ("s-plus-l", "BadSignature", None), ("small-order-r", "BadSignature", None),
    ("count-2^22-no-body", "BadLength", None),
    ("count-2^22+1", "TooManyEntries", None), ("count-2^32+1", "TooManyEntries", None),
    ("count-u64-max", "TooManyEntries", None), ("unsorted-within-bucket", "Unsorted", None),
    ("duplicate", "Duplicate", None), ("zero-count", "ZeroCount", None), ("root-mismatch", "RootMismatch", None),
    ("bad-date-month-13", "BadDate", None), ("bad-date-feb-29-2026", "BadDate", None),
    ("bad-date-day-0", "BadDate", None),
    ("order-magic-before-version", "BadMagic", None), ("order-version-before-signature", "BadVersion", None),
    ("order-signature-before-date", "BadSignature", None), ("order-signature-before-count", "BadSignature", None),
    ("order-signature-before-entries", "BadSignature", None), ("order-date-before-count", "BadDate", None),
    ("order-length-before-entries", "BadLength", None), ("order-duplicate-before-zero-count", "Duplicate", None),
    ("order-unsorted-before-zero-count", "Unsorted", None), ("order-entries-before-root", "Unsorted", None),
)
KCR_PROOF_RESULTS = (
    ("clear-empty-bucket", "Current", "dice-99-words12", "clear"),
    ("clear-shared-prefix", "Current", "vector-1", "clear"),
    ("collision", "Current", "vector-1", "collision"),
    ("collision-dice-50", "Current", "dice-50-words12", "collision"),
    ("current-day-30", "Current", "dice-50-words12", "clear"),
    ("stale-day-31", "Stale", "dice-50-words12", "clear"),
    ("future-day-1", "Future", "dice-50-words12", "clear"),
) + tuple(("forged-sibling-level-%d" % level, "RootMismatch", None, None) for level in range(BUCKET_BITS)) + (
    ("mixed-header-and-path", "RootMismatch", None, None), ("flipped-signature", "BadSignature", None, None),
    ("wrong-key", "BadSignature", None, None), ("header-changed-after-signing", "BadSignature", None, None),
    ("bad-magic", "BadMagic", None, None), ("header-bad-magic", "BadMagic", None, None),
    ("header-version-2", "BadVersion", None, None), ("bad-date", "BadDate", None, None),
    ("too-many-entries", "TooManyEntries", None, None), ("truncated", "BadLength", None, None),
    ("truncated-below-minimum", "TooShort", None, None), ("trailing-byte", "BadLength", None, None),
    ("k-mismatch", "BadLength", None, None), ("bucket-out-of-range", "BucketOutOfRange", None, None),
    ("more-entries-than-count", "ProofCount", None, None),
    ("entry-outside-bucket", "EntryOutsideBucket", None, None), ("unsorted", "Unsorted", None, None),
    ("duplicate", "Duplicate", None, None), ("zero-count", "ZeroCount", None, None),
    ("order-magic-before-signature", "BadMagic", None, None),
    ("order-signature-before-bucket", "BadSignature", None, None),
    ("order-signature-before-entries", "BadSignature", None, None),
    ("order-count-before-bucket", "TooManyEntries", None, None),
    ("order-bucket-before-length", "BucketOutOfRange", None, None),
    ("order-length-before-count", "BadLength", None, None),
    ("order-count-before-entries", "ProofCount", None, None),
    ("order-outside-before-unsorted", "EntryOutsideBucket", None, None),
    ("order-unsorted-before-zero-count", "Unsorted", None, None),
    ("order-entries-before-root", "Unsorted", None, None),
    ("ur-lowercase", "Current", "vector-1", "clear"), ("ur-uppercase", "Current", "vector-1", "clear"),
    ("ur-75-entries", "Current", "vector-1", "clear"), ("ur-76-entries", "Ur(TooLong)", None, None),
    ("ur-bad-crc", "Ur(BadChecksum)", None, None), ("ur-multi-part", "Ur(MultiPart)", None, None),
    ("ur-mixed-case", "Ur(MixedCase)", None, None), ("ur-wrong-type", "Ur(WrongType)", None, None),
    ("ur-non-shortest-head", "Ur(NonShortestHead)", None, None), ("ur-trailing-byte", "Ur(TrailingBytes)", None, None),
)


def kcr_result(expect):
    """A case's outcome as KCR_*_RESULTS pins it: its freshness if verified, else its error."""
    return expect["freshness"] if expect.get("ok") else expect.get("error")


# Every check a case fails, not just the first (KCR_SPEC "negatives"), read apart from kcr_verify and
# kcp1_verify, which stop at the first: a single negative must fail only its own check, and an order-*
# case two or more, the first being its error (review fix after commit 18).

def kcr_header_failures(signed, key):
    """(every header check a header and its signature fail, in check order; its count; its root)."""
    header, signature = signed[:KCR_HEADER_BYTES], signed[KCR_HEADER_BYTES:KCR_SIGNED_BYTES]
    count = int.from_bytes(header[18:26], "big")
    checks = (("BadMagic", header[:4] != KCR_MAGIC),
              ("BadVersion", int.from_bytes(header[4:6], "big") != KCR_VERSION),
              ("BadSignature", not ed25519_verify(key, header, signature)),
              ("BadDate", kcr_date(int.from_bytes(header[14:18], "big")) is None),
              ("TooManyEntries", count > KCR_MAX_ENTRIES))
    return [error for error, failed in checks if failed], count, header[26:58]


def kcr_entries_failures(entries, bucket=None):
    """Every entry rule that some whole entry of `entries` breaks, in check order."""
    broken, previous = set(), None
    for start in range(0, len(entries) - len(entries) % KCR_ENTRY_BYTES, KCR_ENTRY_BYTES):
        tag, count = entries[start:start + 16], int.from_bytes(entries[start + 16:start + 18], "big")
        if bucket is not None and kcr_bucket_of(tag) != bucket:
            broken.add("EntryOutsideBucket")
        if previous is not None and tag == previous:
            broken.add("Duplicate")
        if previous is not None and tag < previous:
            broken.add("Unsorted")
        if count == 0:
            broken.add("ZeroCount")
        previous = tag
    return [rule for rule in ("EntryOutsideBucket", "Duplicate", "Unsorted", "ZeroCount") if rule in broken]


def kcr_all_failures(data, key):
    """Every check a snapshot fails, in check order; one too short for its header fails only that."""
    if len(data) < KCR_SIGNED_BYTES:
        return ["TooShort"]
    failures, count, root = kcr_header_failures(data[:KCR_SIGNED_BYTES], key)
    if len(data) != KCR_SIGNED_BYTES + KCR_ENTRY_BYTES * count:
        failures.append("BadLength")
    body = data[KCR_SIGNED_BYTES:]
    body = body[:len(body) - len(body) % KCR_ENTRY_BYTES]
    failures += kcr_entries_failures(body)
    if merkle_root(merkle_tree(kcr_buckets(body))) != root:
        failures.append("RootMismatch")
    return failures


def kcp1_all_failures(data, key):
    """Every check a KCP1 proof fails, in check order; one shorter than 771 bytes fails only that."""
    if len(data) < KCP_BASE_BYTES:
        return ["TooShort"]
    header_failures, count, root = kcr_header_failures(data[4:4 + KCR_SIGNED_BYTES], key)
    failures = ["BadMagic"] if data[:4] != KCP_MAGIC else []
    failures += [error for error in header_failures if error not in failures]
    at = 4 + KCR_SIGNED_BYTES
    bucket, k = int.from_bytes(data[at:at + 3], "big"), int.from_bytes(data[at + 3:at + 5], "big")
    if bucket >= 1 << BUCKET_BITS:
        failures.append("BucketOutOfRange")
    if len(data) != KCP_BASE_BYTES + KCR_ENTRY_BYTES * k:
        failures.append("BadLength")
    if k > count:
        failures.append("ProofCount")
    entries = data[at + 5:at + 5 + KCR_ENTRY_BYTES * k]
    failures += kcr_entries_failures(entries, bucket)
    siblings = data[at + 5 + KCR_ENTRY_BYTES * k:]
    if len(siblings) != 32 * BUCKET_BITS or merkle_path_root(bucket, entries, siblings) != root:
        failures.append("RootMismatch")
    return failures


def kcr_case_failures(section, case, key):
    """Every check a kcr.json case fails; a go-ahead QR that fails the UR decoder fails only that."""
    if section == "snapshots":
        return kcr_all_failures(bytes.fromhex(case["kcr_hex"]), key)
    if "ur" in case:
        data, error = ur_decode_single(KCP_UR_TYPE, case["ur"])
        return ["Ur(%s)" % error] if error else kcp1_all_failures(data, key)
    return kcp1_all_failures(bytes.fromhex(case["kcp1_hex"]), key)


def kcr_failures_problem(section, case, error, failures):
    """None if a rejected case fails as KCR_SPEC "negatives" says, else what is wrong. A case too short,
    of the wrong length or (a snapshot) over 2^22 entries may also fail the checks that read past it."""
    name = case["name"]
    if name.startswith("order-"):
        if len(failures) >= 2 and failures[0] == error:
            return None
        return "kcr.json %s %s must fail two or more checks, %s first; it fails %r" % (section, name, error, failures)
    spoils = ("TooShort", "BadLength") + (("TooManyEntries",) if section == "snapshots" else ())
    if failures == [error] or (error in spoils and failures[:1] == [error]):
        return None
    return "kcr.json %s %s must fail only %s; it fails %r" % (section, name, error, failures)


def check_kcr_contents(vectors_dir):
    """The committed kcr.json: every case's outcome and seed equal to the pins above, each case's
    outcome reproduced by this file's verifier from its bytes, and each rejected case failing the
    checks KCR_SPEC "negatives" allows; the pinned key and roots; the Merkle section; and its seeds
    equal to seal.json's vector 1 and to rolls.json's dice words."""
    path = vectors_dir / "kcr.json"
    if not path.is_file():
        return []  # check_generated_file reports it missing
    doc = json.loads(path.read_text(encoding="ascii"))
    problems = []
    key = bytes.fromhex(doc["keys"]["test_registry"]["public_key_hex"])
    if key.hex() != KCR_PINNED["test_public_key_hex"]:
        problems.append("kcr.json test registry key %s, pinned %s" % (key.hex(), KCR_PINNED["test_public_key_hex"]))
    for section, pins in (("snapshots", KCR_SNAPSHOT_RESULTS), ("proofs", KCR_PROOF_RESULTS)):
        cases = doc.get(section, [])
        if [c.get("name") for c in cases] != [pin[0] for pin in pins]:
            problems.append("kcr.json %s: cases %r, pinned %r" % (section, [c.get("name") for c in cases],
                                                                 [pin[0] for pin in pins]))
            continue
        for case, pin in zip(cases, pins):
            expect = case["expect"]
            if kcr_result(expect) != pin[1]:
                problems.append("kcr.json %s %s gives %r, pinned %r" % (section, case["name"], kcr_result(expect), pin[1]))
            if section == "snapshots":
                fields, error = kcr_verify(bytes.fromhex(case["kcr_hex"]), key)
                registered = [l["seed"] for l in expect.get("lookups", []) if l["count"] is not None]
                if registered != ([pin[2]] if pin[2] else []):
                    problems.append("kcr.json snapshot %s registers %r, pinned %r" % (case["name"], registered, pin[2]))
            else:
                if "ur" in case:
                    fields, error = kcp1_verify_ur(case["ur"], key)
                else:
                    fields, error = kcp1_verify(bytes.fromhex(case["kcp1_hex"]), key)
                in_bucket = [(l["seed"], l["result"]) for l in expect.get("lookups", []) if l["result"] != "wrong_bucket"]
                if in_bucket != ([(pin[2], pin[3])] if pin[2] else []):
                    problems.append("kcr.json proof %s: seeds in its bucket %r, pinned %r" % (case["name"], in_bucket,
                                                                                            pin[2:]))
            if (error or kcr_freshness(fields["date"], doc["today"])) != pin[1]:
                problems.append("kcr.json %s %s: the verifier gives %r, pinned %r" % (section, case["name"],
                                                                                    error, pin[1]))
            if not expect.get("ok"):
                problem = kcr_failures_problem(section, case, pin[1], kcr_case_failures(section, case, key))
                if problem:
                    problems.append(problem)
    merkle = doc["merkle"]
    if merkle["empty_root_hex"] != KCR_PINNED["empty_root_hex"]:
        problems.append("kcr.json empty root %s, pinned %s" % (merkle["empty_root_hex"], KCR_PINNED["empty_root_hex"]))
    path_case = merkle["vector_1_path"]
    rebuilt = merkle_path_root(path_case["bucket"], bytes.fromhex(path_case["entries_hex"]),
                               bytes.fromhex("".join(path_case["siblings_hex"])))
    if not (rebuilt.hex() == path_case["root_hex"] == KCR_PINNED["vector_1_proof_root_hex"]):
        problems.append("kcr.json vector-1 path gives root %s, pinned %s" % (rebuilt.hex(),
                                                                            KCR_PINNED["vector_1_proof_root_hex"]))
    node = merkle["node"]
    if merkle_node(bytes.fromhex(node["left_hex"]), bytes.fromhex(node["right_hex"])).hex() != node["node_hex"]:
        problems.append("kcr.json merkle node does not hash to node_hex")
    for leaf in merkle["empty_leaves"]:
        if merkle_leaf(leaf["bucket"], b"").hex() != leaf["leaf_hex"]:
            problems.append("kcr.json empty leaf %d differs" % leaf["bucket"])
    aligned = merkle["left_aligned_leaf"]
    if aligned["leaf_hex"] in [leaf["leaf_hex"] for leaf in merkle["empty_leaves"]]:
        problems.append("kcr.json: the left-aligned prefix gives the same leaf as the bucket index")
    seeds = {s["name"]: s for s in doc["seeds"]}
    vector_1 = seeds.get("vector-1", {})
    for field in ("seal_code", "seal_code_hashed", "seal_tag_hex", "seal_id"):
        if vector_1.get(field) != KAT_EXPECTED[field]:
            problems.append("kcr.json seed vector-1 %s differs from seal vector 1" % field)
    if (vector_1.get("nonce_hex"), vector_1.get("go_ahead")) != (KAT_NONCE_HEX, KAT_EXPECTED["go_ahead"]["code"]):
        problems.append("kcr.json seed vector-1 go-ahead differs from seal vector 1")
    if vector_1.get("seed_hex", "")[:32] != KAT_EXPECTED["seed_prefix_hex"]:
        problems.append("kcr.json seed vector-1 S differs from seal vector 1")
    rolls = {c["rolls"]: c for c in json.loads((vectors_dir / "coldcard" / "rolls.json").read_text(encoding="utf-8"))["cases"]}
    for name, rolls_name, words in KCR_SEED_INPUTS[1:]:
        case = rolls.get(dict(COLDCARD_ROLLS)[rolls_name], {})
        if seeds.get(name, {}).get("mnemonic", "").split() != case.get("words_%d" % words):
            problems.append("kcr.json seed %s differs from rolls.json words_%d" % (name, words))
    return problems


def kcr_docs_sentences():
    """What docs/seal-watchonly-braille.md "Snapshot format", "Checking the seal" and "Go-ahead QR" must
    say, word for word, computed here (tasks/lessons.md): (what, the exact text)."""
    vector = seal_vector(*SEAL_VECTOR_INPUTS[0])
    tag = bytes.fromhex(vector["seal_tag_hex"])
    max_bytes = KCR_SIGNED_BYTES + KCR_ENTRY_BYTES * KCR_MAX_ENTRIES
    return [
        ("the header size", "Header, exactly %d bytes" % KCR_HEADER_BYTES),
        ("the signature", "a pure Ed25519 signature (%d bytes) over exactly those %d header bytes"
         % (KCR_SIGNED_BYTES - KCR_HEADER_BYTES, KCR_HEADER_BYTES)),
        ("the entry size", "the entries, %d bytes each" % KCR_ENTRY_BYTES),
        ("the entry count", "a 16-bit registration count of at least 1"),
        ("the largest snapshot", "at most 2^%d entries (%.1f MB)" % (KCR_MAX_ENTRIES.bit_length() - 1, max_bytes / 1e6)),
        ("the bucket index", "a tag starting `%s…` is in bucket `%s`"
         % (lookup_prefix(tag), " ".join("%02x" % b for b in kcr_bucket_of(tag).to_bytes(3, "big")))),
        ("a million registrations", "A million registrations is about %d MB." % round(10 ** 6 * KCR_ENTRY_BYTES / 1e6)),
        ("the freshness", "phones warn when it is older than %d days" % FRESH_DAYS),
        ("the go-ahead vector", "n = `%s` gives G = `%s`" % (KAT_NONCE_HEX, vector["go_ahead"]["code"])),
        ("the proof's header", "the %d-byte snapshot header ‖ its %d-byte signature"
         % (KCR_HEADER_BYTES, KCR_SIGNED_BYTES - KCR_HEADER_BYTES)),
        ("the proof's bucket and count", "the bucket index (3 bytes) ‖ the entry count k (u16)"),
        ("the proof size", "leaf level first: %d + %dk bytes" % (KCP_BASE_BYTES, KCR_ENTRY_BYTES)),
        ("the QR limit", "at most {:,} characters (the largest QR alphanumeric capacity)".format(UR_MAX_CHARS)),
        ("the entries per QR", "About %d bucket entries fit one QR" % kcr_largest_qr_proof()),
    ]


def check_kcr_docs():
    """docs/seal-watchonly-braille.md against the figures computed here: editing a figure in the docs, or
    a value it is computed from, fails the check."""
    if not BRAILLE_DOCS.is_file():
        return ["%s is missing" % BRAILLE_DOCS]
    text = BRAILLE_DOCS.read_text(encoding="utf-8")
    return ["%s: the docs do not say %r (%s)" % (BRAILLE_DOCS.name, sentence, what)
            for what, sentence in kcr_docs_sentences() if sentence not in text]


def check_kcr_json(vectors_dir):
    """Check 10: Ed25519 against RFC 8032 and kat.json, the docs' figures, kcr.json equal to the regenerated
    text, and its contents against the pins."""
    return (
        check_ed25519(vectors_dir)
        + check_kcr_docs()
        + check_generated_file(vectors_dir, "kcr.json", kcr_vectors_json(), "--write-kcr-vectors")
        + check_kcr_contents(vectors_dir)
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
    """Where the printed words first differ from the case's list, for the failure message."""
    if not isinstance(want, list):
        return "the case has no word list"
    for i, (a, b) in enumerate(zip(got, want)):
        if a != b:
            return "word %d is %r, the case says %r" % (i + 1, a, b)
    return "%d words printed, the case has %d" % (len(got), len(want))


def check_coldcard_scripts(vectors_dir):
    """Re-run Coldcard's committed rolls.py and rolls12.py on every case in rolls.json and every
    dice_only case in keepcrypt.json.

    A script runs only if its SHA-256 equals its one SOURCES.md row, so this executes exactly
    the bytes recorded there. Its output is the hex of E (rolls12.py: E[0:16]), then one
    '%4d: word' line per word, with blank and WARNING lines between. The hex must equal
    sha256_hex (keepcrypt.json: e_hex), or its first 32 chars, and the words words_24 or words_12.
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
    # (label, case, the field holding E's hex): rolls.json, then keepcrypt.json's dice-only cases
    # (check 6 reports a missing keepcrypt.json).
    labelled = [("rolls.json case %d" % n, case, "sha256_hex") for n, case in enumerate(cases, 1)]
    keepcrypt = vectors_dir / "keepcrypt.json"
    if keepcrypt.is_file():
        dice_only = json.loads(keepcrypt.read_text(encoding="ascii")).get("dice_only")
        if not isinstance(dice_only, list) or not dice_only:
            problems.append("vectors/keepcrypt.json has no dice_only cases")
        else:
            labelled += [("keepcrypt.json dice_only %d" % n, case, "e_hex") for n, case in enumerate(dice_only, 1)]
    for label, case, e_field in labelled:
        rolls = case.get("rolls") if isinstance(case, dict) else None
        e_hex = case.get(e_field) if isinstance(case, dict) else None
        if not (isinstance(rolls, str) and DICE_ROLLS.fullmatch(rolls)):
            problems.append("%s: rolls must be a string of digits 1-6" % label)
            continue
        if not (isinstance(e_hex, str) and re.fullmatch(r"[0-9a-f]{64}", e_hex)):
            problems.append("%s: %s must be 64 lowercase hex chars" % (label, e_field))
            continue
        for rel, e_bytes, field, script in scripts:
            where = "%s (%d rolls) via vectors/%s" % (label, len(rolls), rel)
            lines, error = run_coldcard_script(script, rolls)
            if error:
                problems.append("%s: %s" % (where, error))
                continue
            printed = lines[0] if lines else "<no output>"
            if printed != e_hex[: 2 * e_bytes]:
                problems.append("%s: printed %s, %s gives %s" % (where, printed, e_field, e_hex[: 2 * e_bytes]))
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
        ("Coldcard's own scripts on every dice-only case (rolls.json, keepcrypt.json)",
         lambda: check_coldcard_scripts(vectors_dir)),
        ("vectors/kat.json: SHA and HMAC values recomputed, file matches regenerated output, pinned entries "
         "and Ed25519 digest", lambda: check_kat_json(vectors_dir)),
        ("vectors/keepcrypt.json: embedded BIP39 list and encoder, file matches regenerated output, pinned answers, "
         "session record rules",
         lambda: check_keepcrypt_json(vectors_dir)),
        ("SP 800-90B health-test cutoffs: Table 2 reproduced exactly, RCT 6 and APT 62 at H = 4",
         lambda: check_health_cutoffs(vectors_dir)),
        ("vectors/braille.json: pinned cells, inserts and text, the docs' counts recounted from the list and "
         "found in docs/seal-watchonly-braille.md, file matches regenerated output, SeedBook PDF SHA-256",
         lambda: check_braille_json(vectors_dir)),
        ("vectors/watchonly.json: RIPEMD-160, CRC-32, dCBOR, Bytewords, UR, BIP-380 and NFKD against the standard "
         "library and the copied spec values, BIP-84 and BCR-2020-015 rebuilt, pinned answers, decoder cases, file "
         "matches regenerated output", lambda: check_watchonly_json(vectors_dir)),
        ("vectors/kcr.json: Ed25519 against RFC 8032 TEST 1-3 and kat.json, the docs' snapshot and proof figures, "
         "file matches regenerated output, every case's pinned outcome reproduced, each negative failing only its "
         "check and each order case its first, pinned key and roots",
         lambda: check_kcr_json(vectors_dir)),
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
    parser = argparse.ArgumentParser(prog="verify.py", description="KeepCrypt offline verifier (M1 seed).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--selftest", action="store_true",
                      help="run the 10 checks: seal known answers (all 3 vectors), seal.json bytes, SOURCES.md "
                      "hashes and coverage, Coldcard's own scripts on every dice-only case, kat.json (SHA and HMAC "
                      "recomputed, its bytes, then its pinned entries and Ed25519 digest), keepcrypt.json (BIP39 "
                      "list and encoder, its bytes, its pinned answers and session record rules), the SP 800-90B "
                      "cutoffs, braille.json (its pinned answers, the docs' counts and their sentences in the docs, its "
                      "bytes, the SeedBook PDF), "
                      "watchonly.json (the primitives and spec values, BIP-84 and BCR-2020-015 rebuilt, its pins and "
                      "decoder cases, its bytes), kcr.json (Ed25519 against RFC 8032 and kat.json, the docs' figures, "
                      "its bytes, its pinned outcomes, key and roots)")
    mode.add_argument("--write-seal-vectors", action="store_true", help="regenerate vectors/seal.json")
    mode.add_argument("--write-kat-vectors", action="store_true", help="regenerate vectors/kat.json")
    mode.add_argument("--write-keepcrypt-vectors", action="store_true", help="regenerate vectors/keepcrypt.json")
    mode.add_argument("--write-braille-vectors", action="store_true", help="regenerate vectors/braille.json")
    mode.add_argument("--write-watchonly-vectors", action="store_true", help="regenerate vectors/watchonly.json")
    mode.add_argument("--write-kcr-vectors", action="store_true", help="regenerate vectors/kcr.json")
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
    if args.write_keepcrypt_vectors:
        return write_keepcrypt_vectors(vectors_dir)
    if args.write_braille_vectors:
        return write_braille_vectors(vectors_dir)
    if args.write_watchonly_vectors:
        return write_watchonly_vectors(vectors_dir)
    if args.write_kcr_vectors:
        return write_kcr_vectors(vectors_dir)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
