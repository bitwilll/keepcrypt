# Test vector sources

Every file in `vectors/` that came from outside this repo, or was made by running an outside
tool, has one row below: SHA-256, source, upstream commit or retrieval date, and licence. All
were retrieved on 2026-10-09. `python3 tools/verify/verify.py --selftest` re-hashes every row
and re-runs Coldcard's committed scripts on every case in `coldcard/rolls.json`;
`shasum -a 256 <path>` checks one by hand.

`vectors/seal.json` has no row. `tools/verify/verify.py` generates it from the constants in
`CLAUDE.md`, and the self-test regenerates and compares it.

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

## What each set is for

- `bip39/vectors.json`: BIP39 known answers for core, run every build and at session start.
  Each entry is `[entropy hex, mnemonic, seed hex, xprv]`, and the seed uses the passphrase
  `TREZOR`. There are 12 languages with 24 entries each; KeepCrypt uses `english` (8 entries
  each of 12, 18 and 24 words).
- `coldcard/rolls.json`: dice-only mode, `E = SHA256(R)`, must match Coldcard, the de facto
  standard. Core and the verifier check it every build.
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
