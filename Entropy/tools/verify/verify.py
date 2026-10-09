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
source-substitution sessions), generated here from the embedded BIP39 English list.
The verifier's own recomputation of a device's C, E and words, and braille, arrive in M2.

The only outside code it runs is Coldcard's public-domain rolls.py and rolls12.py, committed
unmodified under vectors/coldcard/, and only after each file's SHA-256 equals its SOURCES.md
row. Computed vector values come from a committed script that CI re-runs (tasks/lessons.md).
Every seal.json vector also has its values pinned here (vector 1 from CLAUDE.md and the docs,
vectors 2 and 3 independently reproduced), so --write-seal-vectors cannot re-baseline a bug.

Usage:
  verify.py --selftest              7 checks: seal known answers (all 3 vectors), seal.json bytes,
                                    SOURCES.md hashes and coverage, Coldcard's scripts on every
                                    dice-only case (rolls.json and keepcrypt.json), kat.json (SHA and
                                    HMAC recomputed, its bytes, then its pinned entries and Ed25519
                                    digest), keepcrypt.json (the BIP39 list and encoder, its bytes,
                                    its pinned answers), the SP 800-90B cutoffs
  verify.py --write-seal-vectors    regenerate vectors/seal.json
  verify.py --write-kat-vectors     regenerate vectors/kat.json
  verify.py --write-keepcrypt-vectors  regenerate vectors/keepcrypt.json
  --vectors-dir DIR                 testing only: use DIR in place of the repo's vectors/ (made
                                    absolute); a SOURCES.md row `vectors/<p>` then means DIR/<p>

Exit codes: 0 all good, 1 a check failed, 2 usage error.
"""

import argparse
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
UNLISTED = ("seal.json", "kat.json", "keepcrypt.json", "SOURCES.md")
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
# mixed E), and from Coldcard's published example (dice-only 123456). The health indices follow
# from each stream's construction (see keepcrypt_health_cases).
KEEPCRYPT_PINNED = (
    ("pool", "empty", "d_hex", "872caa576626dadadc15fa497046f89cbce93dcb059b917cb2363753353d6b3b"),
    ("commitment", "d-00-1f", "c_hex", "21778a7463cef10741413d0b80909a1045ba902d6244f519d2520e247cbe2e8c"),
    ("mixed", "d-00-1f-coldcard-50", "e_hex", "b2e18e2cdeb6f07e9dd5d3df8e315fa609fd2ebfe543387a483828553da6eee2"),
    ("dice_only", "coldcard-123456", "e_hex", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"),
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
        "compares its pinned answers, recomputes the health-test cutoffs (check 7) and re-runs Coldcard's scripts on "
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


def check_keepcrypt_contents(vectors_dir):
    """The committed keepcrypt.json against the pins: KEEPCRYPT_PINNED, HEALTH_PINNED, and its
    Coldcard roll strings and seeds equal to vectors/coldcard/rolls.json."""
    path = vectors_dir / "keepcrypt.json"
    if not path.is_file():
        return []  # check_generated_file reports it missing
    doc = json.loads(path.read_text(encoding="ascii"))
    problems = []
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
    and its pinned answers."""
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
        ("vectors/keepcrypt.json: embedded BIP39 list and encoder, file matches regenerated output, pinned answers",
         lambda: check_keepcrypt_json(vectors_dir)),
        ("SP 800-90B health-test cutoffs: Table 2 reproduced exactly, RCT 6 and APT 62 at H = 4",
         lambda: check_health_cutoffs(vectors_dir)),
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
                      help="run the 7 checks: seal known answers (all 3 vectors), seal.json bytes, SOURCES.md "
                      "hashes and coverage, Coldcard's own scripts on every dice-only case, kat.json (SHA and HMAC "
                      "recomputed, its bytes, then its pinned entries and Ed25519 digest), keepcrypt.json (BIP39 "
                      "list and encoder, its bytes, its pinned answers), the SP 800-90B cutoffs")
    mode.add_argument("--write-seal-vectors", action="store_true", help="regenerate vectors/seal.json")
    mode.add_argument("--write-kat-vectors", action="store_true", help="regenerate vectors/kat.json")
    mode.add_argument("--write-keepcrypt-vectors", action="store_true", help="regenerate vectors/keepcrypt.json")
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
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
