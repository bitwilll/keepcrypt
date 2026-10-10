# Pi firmware

## What the device does

KeepCrypt-Pi is a stateless, radio-less seed generator: it boots from a read-only card, runs one ceremony, shows the words, optionally writes an encrypted backup to a USB stick, and forgets everything at power-off.

| Does | Does not |
| --- | --- |
| Generate 12- or 24-word BIP39 seeds from the hardware RNG plus physical dice, or dice only | Connect to any network; the board has no radios |
| Check the new seal against a signed registry snapshot from a USB stick, or show a check QR for the website or the offline checker app and accept its go-ahead code | Show or export a seed whose seal matched the registry, or whose check started without a verified go-ahead |
| Show words in print and braille, face by face for KeepCrypt titanium inserts, and check the punched metal by read-back | Store seeds, passphrases or logs anywhere |
| Show the commitment and, on request, the device value for offline verification | Sign transactions (out of scope for v1) |
| Show the wallet fingerprint, first receive address and watch-only QR codes for Sparrow and Bitcoin Core | Write any plaintext file |
| Write an age-encrypted backup to a USB stick, check older backups and re-check their seals | Update itself; new versions are flashed to a new card |

## Hardware bill of materials

Phase 1 uses the same proven parts as SeedSigner, so builders can buy them anywhere ([SeedSigner hardware](https://seedsigner.com/hardware)). Phase-2 parts are optional extras.

| Part | Purpose | Notes |
| --- | --- | --- |
| Raspberry Pi Zero v1.3 | Main board | No Wi-Fi or Bluetooth hardware; needs a soldered 40-pin header |
| [Waveshare 1.3-inch LCD HAT](https://www.waveshare.com/product/displays/lcd-oled/lcd-oled-3/1.3inch-lcd-hat.htm) | Screen and controls | ST7789 over SPI, 240x240; joystick plus 3 keys |
| microSD card, 8 GB or more | Holds the read-only image | Use a new card for each release |
| Micro-USB OTG adapter and a USB stick (FAT32) | Encrypted backup export | The Zero has one data USB port |
| 5 V micro-USB power bank | Power | Keeps the device off any computer's USB port |
| 5 casino-grade six-sided dice | User entropy leg | Precision-edged dice roll more evenly than rounded toy dice |
| Phase 2: [Infinite Noise TRNG](https://tindie.com/products/WaywardGeek/infinite-noise) and a small USB hub | External open-hardware noise source | Hub needed because the TRNG and the USB stick share the one port |
| Phase 2: Pi camera (OV5647), I2S MEMS mic, I2C IMU | Uncredited extras | Camera lens covered; all three default off |
| KeepCrypt Hinge or Screw (12 titanium inserts) with its jig, punch and Allen key, plus the SeedBook | Braille backup | One device per 12-word phrase; a 24-word seed needs two |

**Pin map used by the firmware** (from the Waveshare spec):

| Signal | BCM pin |
| --- | --- |
| KEY1, KEY2, KEY3 | 21, 20, 16 |
| Joystick up, down, left, right, press | 6, 19, 5, 26, 13 |
| SPI SCLK, MOSI, CS (CE0) | 11, 10, 8 |
| Display data/command | 25 |

## OS image

The image is a minimal Buildroot Linux whose only job is to start `keepcrypt-pi`; there is no shell, no network stack and nothing writable on the card.

| Layer | Configuration |
| --- | --- |
| Build system | Buildroot external tree in `pi/os/`, `keepcrypt_pizero_defconfig`, pinned Buildroot and Raspberry Pi kernel versions |
| Kernel | All drivers built in, module loading off; SPI, GPIO, BCM2835 hwrng, USB host mass storage and VFAT on; Wi-Fi, Bluetooth, USB networking and debugfs off; networking disabled wherever the kernel allows |
| Root filesystem | SquashFS, read-only; `/tmp` and `/run` on tmpfs; no swap; no persistent writable partition |
| Init | BusyBox init with one respawn entry: `/usr/bin/keepcrypt-pi` |
| Consoles | No getty on serial or HDMI in release builds; a separately named dev image may enable serial for debugging |
| USB stick | Never automounted; mounted only during backup export, backup checks or snapshot import, at `/mnt/usb` with `nodev,nosuid,noexec`, then synced and unmounted |

**Honest limits of the Pi Zero.** It boots through closed Broadcom GPU firmware and has no secure boot, so the device cannot prove its own image is genuine. Users must check the image signature before flashing and keep the card physically under their control. The boot screen shows a hash prefix of the root filesystem; that catches corruption, not a deliberately altered image.

## Firmware application architecture

`keepcrypt-pi` is one Rust binary built on a `Hal` trait with two implementations, real hardware and a desktop simulator, so Claude Code can build and test every screen before touching a Pi.

| Component | Responsibility | Implementation |
| --- | --- | --- |
| `hal::Display` | Draw 240x240 frames | `rppal` SPI plus `mipidsi` ST7789 driver; simulator uses `embedded-graphics-simulator` |
| `hal::Buttons` | Joystick and 3 keys | `rppal` GPIO inputs with pull-ups, edge interrupts, 20 ms debounce; each event carries a `CLOCK_MONOTONIC` nanosecond timestamp |
| `hal::HwRng` | Raw hardware samples | Reads `/dev/hwrng` in 64-byte blocks for the core's health tests |
| `hal::Usb` | Backup export and snapshot import | Detects a stick under `/sys/block`, mounts, writes, syncs, unmounts |
| `ceremony` | Drives the core session | Owns the typestate `Session`; nothing else can reach it |
| `ui` | Screens and navigation | A screen state machine on `embedded-graphics`; large fonts; insert view shows one word per page with its five braille faces |
| `games` | Optional waiting screen | Snake and Tetris; pieces drawn from core's separate game-randomness call (its own `getrandom` call), never from the pool |
| `extras` | Write-only entropy input | An `ExtraSink` that forwards button timestamps to `Session::add_extra`; games receive only this sink |
| `qr` | Seal, registration, collision-report and watch-only QR codes | qrcodegen for static codes, including the account QR, a single-frame BC-UR string from the core |

**Process rules.**

- Lock memory with `mlockall` at start; secrets never leave RAM.
- Wipe the session after 10 minutes without input, on any error, and before power-off.
- The simulator is for development only and is never part of the image; CI checks the image contains no simulator symbols.

## User flow

A ceremony is fifteen screens in a fixed order; the core's typestate makes it impossible to skip ahead. Dice-only mode skips steps 4, 5 and 14.

1. **Boot and self-test.** Version, root filesystem hash prefix, known-answer tests and the hwrng startup test. Any failure shows a red stop screen; no seed can be made.
2. **Home.** New seed, Dice-only seed, Check a backup, Load registry snapshot, About.
3. **Length.** 12 words (default; fills one KeepCrypt Hinge or Screw) or 24.
4. **Device entropy.** Progress bar of health-tested hwrng bytes toward 1,536 (the 1,024 discarded startup samples, then one 512-sample window); the first window credits 2,048 bits, more than the 512 required, all at once at the end, and `getrandom` is read at the commitment; "Play while you wait" opens Snake or Tetris.
5. **Commitment.** C shown as 16 groups of 4 hex characters, with a note that only verification runs need to write it down.
6. **Dice.** Joystick picks 1 to 6, press confirms, KEY1 undoes; the screen shows the count and bits so far ("37 / 50 rolls, 95.6 bits") but never the roll history, so a bystander cannot read it.
7. **Check for collisions.** The cautionary prompt: "Check now" or "Skip". With a loaded snapshot the check runs on the device. Otherwise the device shows the seal card (8×8 seal image, Seal ID, check QR); the user scans it with the registry website or the offline checker app and types the 8-character go-ahead code with the joystick (a phase-2 camera can scan the go-ahead QR instead). Only a verified go-ahead reveals the words. On a Stop the user presses "Match found": the session is wiped unseen, a collision-report QR is shown, and "Add fresh entropy" starts a new ceremony that needs at least 99 rolls.
8. **Seed words.** One word per page in insert view: sequence number, word, SeedBook number and five face cells, with blank faces and mirror pairs flagged. KEY1 switches to a four-word overview; KEY2 and KEY3 page back and forward.
9. **Read-back from the metal.** The user enters the first four letters of every punched insert, in order; the device compares each with the seed and names any mismatch. Users without metal re-enter their paper words the same way.
10. **Wallet summary.** Fingerprint and first receive address, to compare after restoring.
11. **Encrypted backup (optional).** See the USB section below.
12. **Watch-only export (optional).** Account QR for Sparrow and descriptor QR for Bitcoin Core; asks for the BIP39 passphrase first if the user uses one.
13. **Register seal (optional, once).** Registration QR for a second device.
14. **Reveal D (optional).** For verification runs only, with a warning that D plus the rolls recreates the seed.
15. **Finish.** The SeedBook "before you walk away" checklist, then the session is wiped and "Safe to power off" is shown.

## Games, sensors and the entropy pool

Snake and Tetris stay in the product as an optional waiting screen and a source of uncredited button timing; they can add bytes to the pool but can never read from it. Extras reach the pool only until the commitment, because C fixes D.

- **Input timing:** every button press before the commitment, game or not, sends its nanosecond timestamp through the `ExtraSink`. The core mixes these bytes in and credits them zero.
- **Game randomness:** falling pieces and food positions come from core's separate game-randomness call, which makes its own `getrandom` call and never touches the pool; the games never call `getrandom` themselves. Nothing derived from the pool is ever drawn on screen, including the braille-style block characters.
- **Game scope:** games run only during step 4; they close automatically before the commitment screen.
- **Phase-2 sensors:** camera (lens covered, raw frames), I2S microphone and IMU feed the same sink when enabled in settings; all default off and are credited zero.
- **Phase-2 TRNG:** an Infinite Noise TRNG read in raw mode is health-tested like `/dev/hwrng` and may count toward the device quota only after its credit is backed by `ea_non_iid` data (milestone M8).

## Encrypted backup to a USB stick

The device writes exactly one kind of file, an age-encrypted backup (format in the build plan), and proves it decrypts before saying it worked.

**Reading a registry snapshot.** The same port accepts a stick holding a `.kcr` snapshot before the ceremony. The device mounts it read-only, checks the Ed25519 signature against the pinned key, loads it into RAM and unmounts it. Besides KeepCrypt's own .age backups, a snapshot is the only file the device ever reads.

1. **Passphrase.** The core generates an 8-word backup passphrase. The screen shows it four words at a time with the label "Backup passphrase: store apart from the USB stick."
2. **Confirm.** The user picks 2 random passphrase words from four choices each.
3. **Insert stick.** FAT32 stick in the OTG port; the device waits until it appears.
4. **Encrypt and write.** scrypt at log2 N = 18 takes noticeable time on a Pi Zero, so a progress screen stays up. The file `keepcrypt-backup-<8 hex>.age` is written, synced, and the stick unmounted.
5. **Read back.** Remount read-only, decrypt in RAM, compare the fingerprint, unmount. Only then: "Backup verified. Remove the stick."
6. **On failure.** Delete the partial file if possible, show the error, and keep the ceremony open so the user can retry or skip.

**Restoring later, without KeepCrypt:** on an offline computer, run `age -d keepcrypt-backup-xxxxxxxx.age` and type the 8-word passphrase. The KeepCrypt apps and the Pi's "Check a backup" tool do the same check and show only the fingerprint unless the user asks for the words.

## Build, flash and verify

Builders either reproduce the image from source or verify a signed release; both paths end with a disposable verification run before any real seed is made.

```bash
# Build from source on a Linux x86_64 host (a pinned Docker image is provided)
git clone https://github.com/<your-org>/keepcrypt && cd keepcrypt
make -C pi/os image          # Buildroot with BR2_EXTERNAL=pi/os, keepcrypt_pizero_defconfig
make -C pi/os repro-check    # builds twice in clean containers and compares SHA-256

# Or verify a release download
minisign -Vm keepcrypt-pi-1.0.0.img -P <release-public-key>
sha256sum keepcrypt-pi-1.0.0.img   # must match SHA256SUMS in the release

# Flash (double-check the device name first)
sudo dd if=keepcrypt-pi-1.0.0.img of=/dev/sdX bs=4M conv=fsync status=progress
```

**First-boot checklist.**

- [ ] Self-tests pass and the hash prefix on screen matches the release notes
- [ ] One disposable ceremony, checked with `tools/verify/verify.py` on an offline computer; never fund it
- [ ] One test backup restored with `age -d` on the offline computer
- [ ] Only then, a real ceremony with fresh dice rolls

## Sources

- [SeedSigner hardware list](https://seedsigner.com/hardware)
- [Waveshare 1.3-inch LCD HAT specifications and pin map](https://www.waveshare.com/product/displays/lcd-oled/lcd-oled-3/1.3inch-lcd-hat.htm)
- [Infinite Noise TRNG](https://tindie.com/products/WaywardGeek/infinite-noise)
- [age v1 specification (C2SP)](https://age-encryption.org/v1)
- [NIST SP800-90B Entropy Assessment tool](https://github.com/usnistgov/SP800-90B_EntropyAssessment)
