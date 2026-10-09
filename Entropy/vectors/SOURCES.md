# Test vector sources

Every file in `vectors/` that came from outside this repo, or was made by running an outside
tool, has one row below: SHA-256, source, upstream commit or retrieval date, and licence. All
were retrieved on 2026-10-09. `python3 tools/verify/verify.py --selftest` re-hashes every row
and re-runs Coldcard's committed scripts on every case in `coldcard/rolls.json`;
`shasum -a 256 <path>` checks one by hand.

`vectors/seal.json` has no row. `tools/verify/verify.py` generates it from the constants in
`CLAUDE.md`, and the self-test regenerates and compares it.

`vectors/kat.json` has no row either. `tools/verify/verify.py --write-kat-vectors` generates it
from values copied as published from the documents in "Spec values" below, which are not
committed. Self-test check 5 recomputes every SHA and HMAC value with Python's `hashlib` and
`hmac`, regenerates the file and requires byte equality, then checks the file's entry names and
fields against a pinned layout and its Ed25519 entry against a pinned SHA-256 (below).

`vectors/keepcrypt.json` has no row either. `tools/verify/verify.py --write-keepcrypt-vectors`
generates it from the domain constants in `CLAUDE.md`, the owner's answers Q6a and Q7 in
`tasks/todo.md`, and the BIP39 English list embedded in `verify.py`. Self-test check 6 checks that
list (2,048 sorted words whose LF-joined bytes plus a final LF hash to the published
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`) and the BIP39 encoder against
every English entry of `bip39/vectors.json`, regenerates the file and requires byte equality, and
compares its pinned answers; check 7 recomputes the SP 800-90B cutoffs against Table 2 (below);
check 4 re-runs Coldcard's scripts on its dice-only cases. The embedded list was copied from the
`bip39` 3.0.0 crate (fetched by cargo, the same list core uses) and matched the published hash.

## Provenance

| File | SHA-256 | Source | Upstream commit or date | Licence | Notes |
| --- | --- | --- | --- | --- | --- |
| `vectors/bip39/vectors.json` | `fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8` | https://raw.githubusercontent.com/trezor/python-mnemonic/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json | b57a5ad77a981e743f4167ab2f7927a55c1e82a8 | MIT | Unmodified. All 24 English entries recomputed (mnemonic from entropy, seed via PBKDF2, passphrase TREZOR). |
| `vectors/coldcard/rolls.json` | `4f9d6d4308d3b2b0be51512c10e7d4ebb2ae8e972d3139946a8868aef5b0b2ac` | https://coldcard.com/docs/rolls.py and https://coldcard.com/docs/rolls12.py | retrieved 2026-10-09 | Generated here (scripts say public domain) | Outputs of the two scripts, run offline; see notes below. Both scripts are committed unmodified (next two rows), and `verify.py --selftest` re-runs them on every case. |
| `vectors/coldcard/rolls.py` | `4348a520e57df665e0ab57baa369a95ace0f9b5fba355b3f22b0b9b2c2e6cd30` | https://coldcard.com/docs/rolls.py | retrieved 2026-10-09 (Last-Modified 2026-10-01 18:48:08 GMT) | Public domain, as stated in the file header | Unmodified. The header names https://coldcardwallet.com/docs/rolls.py as its home. Produced `sha256_hex` and `words_24` in rolls.json. |
| `vectors/coldcard/rolls12.py` | `533daff58437cdc9a482d16cd181ba9b0fe6f86a6839b792343d39b496034c85` | https://coldcard.com/docs/rolls12.py | retrieved 2026-10-09 (Last-Modified 2026-10-01 18:48:08 GMT) | Public domain, as stated in the file header | Unmodified. The header names https://coldcardwallet.com/docs/rolls12.py as its home. Produced `words_12` in rolls.json. |
| `vectors/age/scrypt/armor_scrypt` | `b747417cda8ce1ff0b980d7b60e8171d41236df941cbbb0d39d1aecc7f941083` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/armor_scrypt | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: success; armored. |
| `vectors/age/scrypt/scrypt` | `4eedf64d8e648634bfe3345bc45ee71b1cee5dab32b90211fb1c3a61a1eda15e` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: success. |
| `vectors/age/scrypt/scrypt_and_x25519` | `b7d9a55b3d9a990fdbc6589ff56be66c83274235e6ffc4bc9b16a5d722ec896c` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_and_x25519 | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_bad_tag` | `45f0fb65f887dec449f12c65bb532ccf12e5dc9a7d4c39085dfb6636f3f0ba7f` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_bad_tag | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: no match. |
| `vectors/age/scrypt/scrypt_double` | `4e077d31f798a2b2be806f745ee2fa0896a3876b1154dac49ffa9ed3f78a6a08` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_double | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_extra_argument` | `08e55082ccc699783624a4c22ba3870bd811be8db9936ae9b65b213974c39742` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_extra_argument | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_long_file_key` | `619178c5678bd897701acf8bc04419663d0f1da6b2ca90ebf4ee963b8eed74f5` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_long_file_key | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_no_match` | `d250b7a8bd09804576e211223d7ca982148dd5ad9792c7b5299b7529ca84a7b9` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_no_match | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: no match. |
| `vectors/age/scrypt/scrypt_not_canonical_body` | `7fe6d2ddf6ec83fcb7e66e9cc1c5e98269c1843db7e3ba89b19f8a47b09cc8de` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_not_canonical_body | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_not_canonical_salt` | `6cd09483286de4be9c881e079c87db684aace4538218c0fbe3092d751339a76e` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_not_canonical_salt | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_salt_long` | `03a02da288669bfdbe89d448a8d168bfdaf2735ca20069def0858bc7a9df6628` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_salt_long | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_salt_missing` | `8e934a32e7b435f494f018f4a3c4c9b612cc478aad5e79d9e0305364ed360dbb` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_salt_missing | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_salt_short` | `cba4cb2c682bc1c1ce2b7a1a8c4d024b352b9e0c2a03d80590e8e0be958cd5fb` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_salt_short | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_uppercase` | `ae3055bc7568594c7dcf506d9c1599d8df7f9e699152358be35fcb20cf8a8087` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_uppercase | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: no match. |
| `vectors/age/scrypt/scrypt_work_factor_23` | `d2cc2863cd0fedb99265871b8cea654d41997de37f660699fbc4d8d3c5391770` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_23 | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_hex` | `701f161e64f6a43c9c34b22890d84911eb9b4135296c197ecf1fa625d6d9cd1f` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_hex | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_leading_garbage` | `3d3e86bc8c40a3b4341d4f7a674e7bacccb6d480088cce066c4869403ec5e8ce` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_leading_garbage | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_leading_plus` | `fc8699a2263765b5e38f0435941f3a8578c3acb81091137bf2068f0f34bc7046` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_leading_plus | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_leading_zero_decimal` | `4d76c4758cfaf4a89d41902e2d0dfe5be6137bf7ea17f549f15b31ef23115f3f` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_leading_zero_decimal | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_leading_zero_octal` | `c1a94feeab19a89f7d4c2f72ec5039b2ea88f4854da32d1e82f3da75d55fcb25` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_leading_zero_octal | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_missing` | `e60129370690a5c33f9831535608133da7be1ed17071511340fababd76abb21a` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_missing | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_negative` | `a89a9d5f038666b226ec188f815f043a6517794fa1d01c1ddca385f0fbe69bf1` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_negative | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_overflow` | `532fdb8afca25916c724da9b991569340752068cc8d47fa26c643331e133ec7e` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_overflow | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |
| `vectors/age/scrypt/scrypt_work_factor_trailing_garbage` | `3d3e86bc8c40a3b4341d4f7a674e7bacccb6d480088cce066c4869403ec5e8ce` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_trailing_garbage | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure; byte-identical to scrypt_work_factor_leading_garbage upstream. |
| `vectors/age/scrypt/scrypt_work_factor_wrong` | `565290c68accd2b94dbcf434927049d4fcfc8ab8fe169a6c33e546606e5cf65c` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_wrong | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: no match. |
| `vectors/age/scrypt/scrypt_work_factor_zero` | `bdac47d76667aa0f14270df58573b873c806ea838b2e026d62789287f0413239` | https://raw.githubusercontent.com/C2SP/CCTV/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/age/testdata/scrypt_work_factor_zero | 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 | 0BSD OR CC0-1.0 OR Unlicense | Unmodified. expect: header failure. |

## Spec values

Values copied into `tools/verify/verify.py` (and from there into `vectors/kat.json`) from
published standards. The documents themselves are not committed; each row pins the exact bytes
read, by SHA-256. All were downloaded on 2026-10-09 with a generic User-Agent, each into its own
new empty directory, and downloaded a second time the same day with the same size and SHA-256.
They were read as data only: the RFCs as text, the PDFs through a standard-library extraction of
their compressed text streams, and the zip through Python's `zipfile` without extracting it.
SP 800-90B was downloaded the same way on 2026-10-10, twice, with the same size and SHA-256; its
Table 2 was parsed out of the extracted text and compared entry by entry with `SP800_90B_TABLE_2`.

| Standard | Document | SHA-256 | Retrieved | Licence | Values copied |
| --- | --- | --- | --- | --- | --- |
| FIPS 180-4 (SHA-256) | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf (NIST CSRC "Examples with Intermediate Values"), 99090 bytes | `7006b6549dad2fc8c6f29417a921f2e48208157ef496a7e1e1d7d17c5cc1e7db` | 2026-10-09 (Last-Modified 2024-09-29 23:15:40 GMT) | U.S. Government work, not subject to copyright in the U.S. (17 U.S.C. 105) | `kat.json` sha256 `abc` and `two-block`: "One Block Message Sample" (`"abc"`) and "Two Block Message Sample" (`"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"`), message and final "Message Digest is" value |
| FIPS 180-4 (SHA-512) | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf (same series), 159262 bytes | `84ce867c99bad5a7b05abc74bb1dfc9de8486f49a160653cc8b15272cc532115` | 2026-10-09 (Last-Modified 2024-09-29 23:15:40 GMT) | U.S. Government work, not subject to copyright in the U.S. (17 U.S.C. 105) | `kat.json` sha512 `abc` and `two-block`: the one-block (`"abc"`) and two-block (`"abcdefghbcdefghi…nopqrstu"`, 112 bytes) samples, message and final digest |
| FIPS 180-4 (SHAVS byte-oriented vectors) | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip (NIST CAVP), 4909729 bytes; members `shabytetestvectors/SHA256ShortMsg.rsp` (SHA-256 `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c`) and `shabytetestvectors/SHA512ShortMsg.rsp` (SHA-256 `e53a36c03609e5a3e3cc4b6e117a499db7864c23ec825c6cec99503a45f40764`), "CAVS 11.0", generated 2011-03-15 | `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8` | 2026-10-09 (Last-Modified 2024-09-29 23:13:50 GMT) | U.S. Government work, not subject to copyright in the U.S. (17 U.S.C. 105) | `kat.json` sha256 and sha512 `empty`: the `Len = 0` entry of each file, whose `Msg = 00` is the placeholder for the empty message, and its `MD` |
| RFC 4231 (HMAC-SHA-224/256/384/512 test vectors) | https://www.rfc-editor.org/rfc/rfc4231.txt, 17725 bytes | `72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b` | 2026-10-09 | Copyright (C) The Internet Society (2005), subject to BCP 78; only the test values are copied | `kat.json` hmac `rfc4231-case-2`: section 4.3, Test Case 2: Key (`"Jefe"`), Data (`"what do ya want for nothing?"`), HMAC-SHA-256 and HMAC-SHA-512 |
| NIST SP 800-90B (entropy sources) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf, 1043696 bytes | `9b0dd77131ade3617a91cd8457fa09e0dc354c273bb2220a6afeaca16e5defe7` | 2026-10-10 (Last-Modified 2018-01-10 14:24:12 GMT) | U.S. Government work, not subject to copyright in the U.S. (17 U.S.C. 105) | `verify.py` `SP800_90B_TABLE_2` (check 7): Table 2 "Example cutoff values of the Adaptive Proportion Test", page 27, the whole-number entries for alpha = 2^-20: non-binary data, W = 512, H = 1, 2, 4, 8 give C = 311, 177, 62, 13; binary data, W = 1024, H = 1 gives C = 589. The test steps of sections 4.4.1 and 4.4.2 and the window rule (1024 for binary samples, 512 otherwise) behind `health_test` and core's `health` module. |
| RFC 8032 (EdDSA) | https://www.rfc-editor.org/rfc/rfc8032.txt, 103210 bytes | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` | 2026-10-09 | Copyright (c) 2017 IETF Trust and the document authors, subject to BCP 78 and the IETF Trust's Legal Provisions; only the test values are copied | `kat.json` ed25519 `rfc8032-test-1`: section 7.1, TEST 1: PUBLIC KEY, the empty MESSAGE and SIGNATURE. Its SECRET KEY is not copied, because core only verifies signatures |

Every copied value was compared mechanically with the value parsed back out of its document
(one throwaway script, not committed), and that comparison failed when any value was altered.
The SHA and HMAC values are recomputed by every self-test run. verify.py has no Ed25519 until
check 10 (tasks/todo.md, M1 group 7), so the Ed25519 entry is pinned instead: check 5 requires
SHA-256(public key (32 bytes) || signature (64 bytes) || message) to equal
`0e1d4c11a5a51315bf2daccae025f9654fd7309bf941e57dece4caeea65c280c`. That digest was computed on
2026-10-09 from TEST 1 as parsed out of a fresh download of RFC 8032 (same size and SHA-256 as the
row above), not from verify.py's table; a separate RFC 8032 verify accepted the signature and
rejected it with one bit flipped.

## What each set is for

- `bip39/vectors.json`: BIP39 known answers for core, run every build and at session start.
  Each entry is `[entropy hex, mnemonic, seed hex, xprv]`, and the seed uses the passphrase
  `TREZOR`. There are 12 languages with 24 entries each; KeepCrypt uses `english` (8 entries
  each of 12, 18 and 24 words).
- `coldcard/rolls.json`: dice-only mode, `E = SHA256(R)`, must match Coldcard, the de facto
  standard. Core and the verifier check it every build.
- `kat.json` (generated; see "Spec values"): the published answers behind core's Sha256,
  Sha512, Hmac and Ed25519 known-answer groups, which run at every session start. Core's tests
  check each KAT constant against this file.
- `keepcrypt.json` (generated; see above): the exact bytes of the device leg (pool records and D,
  by source id), the SP 800-90B health-test cases (verdict, stage and sample index) and the credit
  per window, C, mixed and dice-only E with their 12- and 24-word mnemonics, and the Pi and phone
  source-substitution sessions mapped to D and C. Core's source, health, pool, dice and seed tests
  read it.
- `coldcard/rolls.py` and `coldcard/rolls12.py`: Coldcard's own scripts that produced
  `rolls.json`. The verifier self-test re-runs them on every case, so the values come from a
  committed script that CI re-runs.
- `age/scrypt/`: the backup reader (M1) must reach exactly the result in each file's `expect`
  header: 2 `success`, 4 `no match`, 20 `header failure`. The accepting files use scrypt work
  factor 10; KeepCrypt writes 18.

## How the downloads were checked

- GitHub files: each commit was the head of the default branch on 2026-10-09 (`gh api`), and
  each file came from `raw.githubusercontent.com/<owner>/<repo>/<commit>/<path>`. The git blob
  hash of every download (`git hash-object`) equals the blob SHA in that commit's tree, so the
  bytes are exactly what upstream committed.
- `bip39/vectors.json`: all 24 English entries were recomputed with the Python standard
  library. Mnemonic from entropy uses the word list from the `bip39` 3.0.0 crate, checked
  against the official list hash `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
  Seed is `hashlib.pbkdf2_hmac("sha512", mnemonic, "mnemonicTREZOR", 2048)`.

## How rolls.json was produced

- Scripts, committed unmodified as `vectors/coldcard/rolls.py` and `vectors/coldcard/rolls12.py`
  (rows above). At first only their outputs were committed; both headers say "Public domain",
  so that choice no longer applies.
  - `https://coldcard.com/docs/rolls.py`: 14508 bytes, SHA-256
    `4348a520e57df665e0ab57baa369a95ace0f9b5fba355b3f22b0b9b2c2e6cd30`
  - `https://coldcard.com/docs/rolls12.py`: 14473 bytes, SHA-256
    `533daff58437cdc9a482d16cd181ba9b0fe6f86a6839b792343d39b496034c85`
  - Both served with `Last-Modified: Thu, 01 Oct 2026 18:48:08 GMT`. Their headers say
    "Public domain" and name `https://coldcardwallet.com/docs/rolls.py` and
    `https://coldcardwallet.com/docs/rolls12.py` as their home.
  - Downloaded a second time on 2026-10-09 to commit them, each into its own new empty
    directory: same size, SHA-256 and `Last-Modified` as the first download. Read in full
    again, then copied byte for byte, mode 644 (not executable).
- Both were read in full before running. Each imports only `from hashlib import sha256`, reads
  one line with `input().strip()`, prints, and does nothing else: no files, no network. Each
  embeds the official English word list (hash above).
- Run offline from an empty working directory, with network denied by the macOS sandbox (a
  probe under the same profile had DNS and TCP refused):
  `echo <rolls> | sandbox-exec -p '(version 1)(allow default)(deny network*)' python3 -I rolls.py`
- Roll strings: `123456` (Coldcard's published example), `("123456"*9)[:50]`,
  `("654321"*17)[:99]` and `"1"*100`.
- `rolls12.py` prints only the first 16 bytes of E; its 12 words encode those 16 bytes.
- Every output matched an independent standard-library computation (`E = SHA256(ASCII rolls)`,
  24 words = BIP39(E), 12 words = BIP39(E[0:16])), and the `123456` case matched the
  published hash and words exactly.
- Trailing newline: `input()` drops the line ending and `.strip()` drops surrounding
  whitespace, so R is the digits only. rolls.py gives `8d969eef...` for `123456`, `123456\n`,
  `123456\r\n` and `  123456\t\n` alike; `SHA256("123456\n")` would be `e150a1ec...`.

## How to reproduce rolls.json

- `shasum -a 256 vectors/coldcard/rolls.py vectors/coldcard/rolls12.py` must print the two
  hashes in the rows above.
- One case by hand: `echo 123456 | python3 -I vectors/coldcard/rolls.py` prints `8d969eef...`
  and 24 numbered words; `rolls12.py` prints the first 16 bytes of E and 12 words.
- Every case: `python3 tools/verify/verify.py --selftest`, check 4. It first requires each
  script's SHA-256 to equal its row above and refuses to run a script that differs. Then, for
  every case in `rolls.json`, it runs `python3 -I <script>` (the interpreter running the
  verifier) with stdin = rolls plus a newline, from a new empty temporary directory, without
  `PYTHON*` environment variables, under a 30-second timeout. The printed hex must equal
  `sha256_hex` (`rolls12.py`: its first 32 hex chars) and the printed words `words_24`
  (`rolls.py`) or `words_12` (`rolls12.py`).

## CCTV age test file format

From `age/README.md` at the pinned commit. Each file is one test: a header of `key: value`
lines, an empty line, then the age file. Keys:

- `expect`: `success`, `no match`, `HMAC failure`, `header failure`, `payload failure` or
  `armor failure`
- `payload`: SHA-256 hex of all plaintext the API would release, checked even when decryption
  later fails
- `passphrase` (scrypt) and `identity` (X25519 or hybrid): may repeat
- `armored: yes`: the age file is ASCII-armored (only `armor_scrypt` here)
- `compressed: zlib`: the age file is zlib-compressed (none here)
- `file key` and `comment`: debugging aids, ignored
- Files with unknown keys are skipped.

Licence: the README offers the test data under 0BSD, CC0-1.0 or Unlicense, at the user's
choice, with no attribution required. The CCTV repository has no top-level licence file.

Upstream quirks: 25 file names start with `scrypt`; the 26th scrypt case is `armor_scrypt`.
`scrypt_work_factor_trailing_garbage` is byte-identical to
`scrypt_work_factor_leading_garbage` (both use work factor `aaaa10`), and the comment in
`scrypt_extra_argument` repeats the one from `scrypt_not_canonical_body`.
