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
| Display reset | 27 |
| Backlight (active high) | 24 |

The keys and joystick switch to ground; config.txt sets their pull-ups and the firmware sets them again. MISO is not wired and the firmware does not read the panel back, so a dead panel is not detected; only SPI write errors are display faults.

## OS image

The image is a minimal Buildroot Linux whose only job is to start `keepcrypt-pi`; there is no shell, no network stack and nothing writable on the card.

| Layer | Configuration |
| --- | --- |
| Build system | Buildroot external tree in `pi/os/`, `keepcrypt_pizero_defconfig`, pinned Buildroot and Raspberry Pi kernel versions |
| Kernel | An allow-list: only what the board, the display, the buttons, the BCM2835 hwrng, the SD card and one USB stick need (SPI, GPIO, USB host mass storage, VFAT and SquashFS), all built in, with module loading off. Networking (and with it Wi-Fi, Bluetooth and USB networking), USB gadget mode, extra USB drivers (serial adapters, cameras, keyboards), other disk formats (exFAT, NTFS, Mac and the rest), swap, crash dumps and debugging hooks (debugfs included) are left out. The final kernel config is one committed file, reviewed line by line, and any difference from it fails CI |
| Root filesystem | SquashFS, read-only; `/tmp` and `/run` on tmpfs; no swap; no persistent writable partition |
| Init | BusyBox init with no shell and no respawn: it mounts the fstab entries, runs `/usr/bin/keepcrypt-pi` once and waits for it; if that process ever ends, it runs `/usr/bin/keepcrypt-pi --stopped` once, which only shows the stop screen until a power cycle (see Finish and halts) |
| Consoles | No getty on serial or HDMI in release builds; a separately named dev image may enable serial for debugging |
| USB stick | Never automounted; mounted only during backup export, backup checks or snapshot import, at `/mnt/usb` with `nodev,nosuid,noexec`, then synced and unmounted |

**Honest limits of the Pi Zero.** It boots through closed Broadcom GPU firmware and has no secure boot, so the device cannot prove its own image is genuine. Users must check the image signature before flashing and keep the card physically under their control. At every boot the firmware hashes its own root filesystem: SHA-256 over the SquashFS image on the root partition, its first `bytes_used` bytes rounded up to a multiple of 4,096 (the size mksquashfs pads it to). The boot screen and About show the digest's first 8 bytes as 16 lowercase hex characters in four dash-separated groups of four, and CI publishes the same prefix with each image. That catches corruption, not a deliberately altered image.

## Firmware application architecture

`keepcrypt-pi` is one Rust binary built on a `Hal` trait with two implementations, real hardware and a desktop simulator, so Claude Code can build and test every screen before touching a Pi.

| Component | Responsibility | Implementation |
| --- | --- | --- |
| `hal::Display` | Draw 240x240 frames | `rppal` SPI plus KeepCrypt's own ST7789 driver, which sends Waveshare's full start-up settings, blanks all of the panel's frame memory before the panel turns on and again on a crash, and wipes its transfer buffer after every frame; the simulator receives the same frames, exactly the pixels the panel gets, and writes them as PNG files itself, headless, with no display or image crate |
| `hal::Buttons` | Joystick and 3 keys | `rppal` GPIO inputs with pull-ups and both-edge interrupts, read without a thread; the firmware's own 20 ms debounce, the same as the simulator's; each event carries the kernel's `CLOCK_MONOTONIC` timestamp of its edge, in nanoseconds |
| `hal::HwRng` | Raw hardware samples | Reads `/dev/hwrng` in non-blocking mode, in 64-byte blocks for the core's health tests; a block still incomplete 2 seconds after it was asked for halts the device with "hwrng read fault". A wait inside the kernel driver can still stall the screen past that, and still makes no seed |
| `hal::Usb` | Backup export and snapshot import | Detects a stick under `/sys/block`, mounts, writes, syncs, unmounts |
| `ceremony` | Drives the core session | Owns the typestate `Session`; nothing else can reach it |
| `ui` | Screens and navigation | A screen state machine on `embedded-graphics`; large fonts; insert view shows one word per page with its five braille faces |
| `games` | Optional waiting screen | Snake (Tetris later); food drawn from core's `game_random` (its own `getrandom` call), never from the pool; the games run in the firmware's one process but hold no session and no sink |
| `extras` | Write-only entropy input | Picks the button timestamps that go to `Session::add_extra`: every press before the commitment in Mixed mode, game or not; the ceremony loop forwards them, and the games get no sink and never the session |
| `qr` | Seal, registration, collision-report and watch-only QR codes | `qrcodegen-no-heap` for static codes, including the account QR, a single-frame BC-UR string from the core; it encodes into buffers the app owns and wipes after drawing |

**Process rules.**

- Lock all memory with `mlockall` at start, before any secret exists; if that fails, the device halts with "memory could not be locked". With no swap and no crash dumps, and freed memory zeroed by the kernel, secrets never leave RAM.
- Wipe the session after 10 minutes without input, on any failure, and at Finish, before "Safe to power off" is shown. Any failure, at boot or later, then halts the device until a power cycle; only refusals of what the user or a stick supplied return to their screen (see Finish and halts).
- The simulator is for development only and is never part of the image; CI checks the image contains no simulator symbols.
- Besides the `.age` backups and `.kcr` snapshots on the stick, the firmware touches only device and kernel interfaces, each at a fixed path or pattern: it reads `/dev/hwrng`, its root partition `/dev/mmcblk0p2` (for the boot hash), `/proc/cpuinfo` and `/sys/firmware/devicetree/base/{compatible,model}` (which `rppal` reads to identify the board) and `/sys/block/**` (to find the stick); it drives the GPIO and SPI device nodes `/dev/gpiomem`, `/dev/gpiochip*` and `/dev/spidev0.0`; and it mounts only the stick's `/dev/sdX1`, or the whole `/dev/sdX` when it has no first partition, at `/mnt/usb`. Four of these are patterns, not single paths: `/sys/firmware/devicetree/base/{compatible,model}` is two files, the kernel numbers `/dev/gpiochip*` and the stick's `/dev/sdX`, `/sys/block/**` is the tree searched for the stick, and the stick may have no first partition. The runtime makes a few reads of its own as well: the dynamic loader reads its own files (`/etc/ld.so.cache` and `/etc/ld.so.preload`, where they exist, and the shared libraries the binary links); glibc reads `/proc/self/maps` before `main`; Rust's standard library opens `/dev/null` in place of a standard descriptor that is closed at start; and `rppal` tries `/dev/mem` when `/dev/gpiomem` cannot be opened, an attempt the kernel's `CONFIG_DEVMEM=n` makes fail. The grep gate covers the paths our code and `rppal` name, not those runtime reads: it holds the firmware's own path literals to this list, and `rppal`'s paths were read from its source and are all on it.

## User flow

A ceremony is fifteen screens in a fixed order: the typestate orders steps 1-8, core's read-back gate holds back the five exports until step 9 completes, and the firmware runs steps 10-15 in order, each optional one with a Skip. Dice-only mode skips steps 4, 5 and 14.

1. **Boot and self-test.** Version, the root filesystem's hash prefix (16 hex characters, also shown in About), known-answer tests and the hwrng startup test. Any failure shows a red stop screen that no key leaves; no seed can be made until a power cycle reruns these tests. The same screen ends any later failure (see Finish and halts).
2. **Home.** New seed, Dice-only seed, Check a backup, Load registry snapshot, About.
3. **Length.** 12 words (default; fills one KeepCrypt Hinge or Screw) or 24.
4. **Device entropy.** Progress bar of health-tested hwrng bytes toward 1,536 (the 1,024 discarded startup samples, then one 512-sample window); the first window credits 2,048 bits, more than the 512 required, all at once at the end, and `getrandom` is read at the commitment; "Play while you wait" opens Snake.
5. **Commitment.** C shown as 16 groups of 4 hex characters, with a note that only verification runs need to write it down.
6. **Dice.** Joystick picks 1 to 6, press confirms, KEY1 undoes; the screen shows the count and bits so far ("37 / 50 rolls, 95.6 bits") but never the roll history, so a bystander cannot read it.
7. **Check for collisions.** The cautionary prompt: "Check now" or "Skip". With a loaded snapshot, Check now first asks the user to confirm the snapshot's date, every time, since the Pi has no clock: "Snapshot No. \<number>, dated \<date>, \<count> entries. Use it for this check?" Yes runs the check on the device; No keeps the check open and shows the seal card, with the same nonce. Otherwise the device shows the seal card: three pages (the 8×8 seal image with the Seal ID; the Seal ID large, with its braille; the check QR), then an actions page with "Enter go-ahead code", "Match found" and "Cannot check". The user scans the check QR with the registry website or the offline checker app and types the 8-character go-ahead code with the joystick (a phase-2 camera can scan the go-ahead QR instead). KEY2 on the code entry goes back to the actions page, clearing what was typed but keeping the check and its nonce, so a user who opened the entry before scanning, or whose checker answered Stop, can still reach the check QR, "Match found" and "Cannot check". Only a verified go-ahead reveals the words. On a Stop the user presses "Match found": the session is wiped unseen, a collision-report QR is shown, and "Add fresh entropy" starts a new ceremony that needs at least 99 rolls. On "Cannot check" the user presses "Start again": the session is wiped unseen and a new ceremony starts. Both buttons restart through `Wiped::restart`, never a fresh `Session::new`, so the core sets the next dice minimum, including the 99 rolls after a collision ("Add fresh entropy" in Seal, watch-only and braille).
8. **Seed words.** One word per page in insert view: sequence number, word, SeedBook number and five face cells, with blank faces and mirror pairs flagged. KEY1 switches to a four-word overview; KEY2 and KEY3 page back and forward. Press on the last insert starts the read-back.
9. **Read-back from the metal.** The user enters the first four letters of every punched insert, in order; the device compares each with the seed and names any mismatch. Users without metal re-enter their paper words the same way.
10. **Wallet summary.** Fingerprint and first receive address, to compare after restoring.
11. **Encrypted backup (optional).** See the USB section below.
12. **Watch-only export (optional).** Account QR for Sparrow and descriptor QR for Bitcoin Core; asks for the BIP39 passphrase first if the user uses one; KEY2 on the passphrase entry goes back to the question whether the user has one, wiping what was typed. The Pi takes BIP39 passphrases of printable ASCII (0x20 to 0x7E), up to 100 characters; a wallet whose passphrase uses other characters gets no watch-only export from the Pi, and its user builds the watch-only wallet in their coordinator after restoring.
13. **Register seal (optional, once).** Registration QR for a second device.
14. **Reveal D (optional).** For verification runs only, with a warning that D plus the rolls recreates the seed. D is shown as 16 groups of 4 hex characters, like C. On the offline computer, type each value into verify.py only after its prompt appears: anything typed earlier is dropped, though the terminal may already have shown it.
15. **Finish.** The SeedBook "before you walk away" checklist, then the session is wiped and "Safe to power off" is shown.

### Buttons

One press is one event: presses are debounced, with no auto-repeat. A press made before the current screen was fully drawn, or while the device was busy (starting up, computing, or reading or writing the stick), does nothing, so presses queued on the one-core Pi Zero cannot skip a screen, a privacy gate included, before it was seen; before the commitment in Mixed mode such a press still feeds its timing to `Session::add_extra`. A screen that only redraws itself (dice entry, step 4's progress bar, Snake) keeps every press. A footer on every screen names each key's action there.

| Screen kind | Up / Down | Left / Right | Press | KEY1 | KEY2 | KEY3 |
| --- | --- | --- | --- | --- | --- | --- |
| Menus, offers | move | - | select | back, only where nothing is lost | - | - |
| Dice | pick 1 to 6 (blank after each confirm) | - | confirm | undo | - | Done, once the minimum is met |
| Words | - | - | read-back, on the last insert (back to entry when reviewing a mismatch) | overview on/off | previous | next |
| Entry grids | cursor | cursor | type | delete | back, on the go-ahead code, backup-passphrase and BIP39-passphrase entry | done |
| Read-back mismatch | - | - | re-enter | show the insert | - | - |
| Snake | steer | steer | play again, after a round ends | leave | - | - |
| QR and info pages | - | - | continue | back, only on About, the re-check QR and the wait for a stick | previous page | next page |

- **Entry grids:** the go-ahead code uses the 32 Crockford symbols in 8×4; read-back and backup-passphrase words use a-z plus "blank" in 7×4; the BIP39 passphrase uses printable ASCII in three 8×4 pages. KEY2 on the go-ahead code goes back to the seal card's actions page with the same check and nonce, and clears what was typed; on the backup passphrase of "Check a backup" it returns Home and drops the backup the device read, leaving the file on the stick; on the BIP39 passphrase it goes back to the question whether the user has one, and wipes what was typed. The read-back alone has no KEY2.
- **Confirmations:** confirm is disabled at 256 rolls, and the one-way choices (Skip, Match found, Cannot check) each take a confirm screen.

### Protected screens and idle

Every screen is Protected or Public. Protected screens show a secret: the words in insert view and overview (in the ceremony and in "Check a backup"), the read-back entry and mismatch screens, the backup passphrase with its confirm and wrong-pick screens, BIP39-passphrase entry and backup-passphrase entry, D, the registration QR, the collision-report QR (it carries the destroyed seed's seal code), and the account and descriptor QRs. Every other screen is Public, including the wallet summary, the watch-only summary, the dice screen and the check QR (T and a nonce), as on the phones.

- **Privacy gate:** entering a Protected screen from a Public one passes one gate, "No person or camera can see this screen", like the phones' "I'm alone, show words".
- **Cover:** after 30 seconds without input a Protected screen is covered. The first press only uncovers it and the session stays, so slow punching or scanning is never cut short.
- **Warning:** at 9 minutes without input, a warning appears on any screen while a session or a checked backup is held; any key keeps everything.
- **Wipe:** at 10 minutes the session or checked backup is wiped, and the device says so and returns Home. A loaded snapshot survives, and so does a pending 99-roll minimum after a collision ("Add fresh entropy" in Seal, watch-only and braille).

### Finish and halts

- **Finish:** step 15 is terminal. After the checklist the session is wiped, the screen goes black and "Safe to power off" stays; no key leaves it, so the next ceremony starts only after a power cycle. A loaded snapshot stays in RAM until power-off.
- **Halts:** any failure, at boot or later, ends on the red stop screen of step 1. Everything secret the firmware holds is wiped first, the screen names the failure in fixed text, and no key leaves it; only a power cycle does, and it reruns the boot self-test and the hwrng startup test before any new seed. There is no retry and no other source, so an intermittent hwrng fault cannot pass on a second try, and a dice-only seed cannot follow straight after an hwrng failure.
- **What halts:** every error that ended a session; every known-answer-test, entropy-source, health-test, internal or export-self-check error from any core call, `game_random` included; and every display, button or hwrng fault.
- **What does not:** only refusals of what the user or a stick supplied return to their own screen, naming the refusal in fixed text: a wrong go-ahead code, a read-back mismatch, a wrong backup passphrase or unrecognised entry, an empty BIP39 passphrase, a refused snapshot, and USB faults.
- **Crashes:** a crash of the firmware ends on the same stop screen, and nothing restarts on its own. The screen goes black, the process ends, which wipes any open session as power-off would, and init starts a separate stop mode that holds nothing and shows "the firmware stopped unexpectedly" until a power cycle. A crash prints nothing anywhere, since a crash message could hold secrets. If Linux itself crashes, it does not reboot (`panic=0`): the screen freezes on whatever it showed until power-off.
- **The 99-roll minimum:** a power cycle or a crash forgets a pending 99-roll minimum after a collision, as power-off always has.

## Games, sensors and the entropy pool

Snake (Tetris later) stays in the product as an optional waiting screen and a source of uncredited button timing. The game holds no path to the pool: the ceremony loop forwards its key timing, and the game can neither add to the pool nor read from it. Extras reach the pool only until the commitment, because C fixes D.

- **Input timing:** for every button press before the commitment in Mixed mode, game or not, the ceremony loop passes its nanosecond timestamp to `Session::add_extra`. The core mixes these bytes in and credits them zero.
- **Game randomness:** food positions, and later Tetris's falling pieces, come from core's `game_random`, which makes its own `getrandom` call and never touches the pool; the games never call `getrandom` themselves. Nothing derived from the pool is drawn by a game or the extras, including the braille-style block characters.
- **Game scope:** games run only during step 4; they close automatically before the commitment screen.
- **Phase-2 sensors:** camera (lens covered, raw frames), I2S microphone and IMU feed `Session::add_extra` the same way when enabled in settings; all default off and are credited zero.
- **Phase-2 TRNG:** an Infinite Noise TRNG read in raw mode is health-tested like `/dev/hwrng` and may count toward the device quota only after its credit is backed by `ea_non_iid` data (milestone M8).

## Encrypted backup to a USB stick

The device writes exactly one kind of file, an age-encrypted backup (format in the build plan), and proves it decrypts before saying it worked.

**Reading a registry snapshot.** The same port accepts a stick holding a `.kcr` snapshot before the ceremony. The device mounts it read-only, checks the Ed25519 signature against the pinned key, loads it into RAM and unmounts it. Besides KeepCrypt's own .age backups, a snapshot is the only file the device ever reads (device and kernel interfaces aside).

1. **Passphrase.** The core generates an 8-word backup passphrase. The screen shows it four words at a time with the label "Backup passphrase: store apart from the USB stick."
2. **Confirm.** The user picks 2 random passphrase words from four choices each.
3. **Insert stick.** FAT32 stick in the OTG port; the device waits until it appears.
4. **Encrypt and write.** scrypt at log2 N = 18 takes noticeable time on a Pi Zero, so a wait screen stays up. The file `keepcrypt-backup-<8 hex>.age` is written as a new file, never over an existing one, then synced, and the stick unmounted.
5. **Read back.** Remount read-only, decrypt in RAM, compare the fingerprint, unmount. Only then: "Backup verified. Remove the stick."
6. **On failure.** Delete the partial file if possible, show the error, and keep the ceremony open so the user can retry or skip.

**Restoring later, without KeepCrypt:** on an offline computer, run `age -d keepcrypt-backup-xxxxxxxx.age` and type the 8-word passphrase. The KeepCrypt apps and the Pi's "Check a backup" tool do the same check and show only the fingerprint unless the user asks for the words. On the Pi the passphrase is typed as the first four letters of each word, or the whole word for a three-letter word, as in the read-back; KEY2 on that entry returns Home and drops the backup the device read, and the file stays on the stick.

## Build, flash and verify

Builders either reproduce the image from source or verify a signed release; both paths end with a disposable verification run before any real seed is made.

```bash
# Build from source on a Linux x86_64 host, as CI does on GitHub's hosted runners
# (a pinned build container and rebuilds in clean containers come with M7's outside reproduction)
git clone https://github.com/bitwilll/keepcrypt && cd keepcrypt
export KC_WORK=/kc-work              # build directory: outside Entropy/, no spaces, the same path in every build
make -C Entropy/pi/os source         # fetches every pinned input; the only step with network access
make -C Entropy/pi/os image          # Buildroot with BR2_EXTERNAL=Entropy/pi/os, keepcrypt_pizero_defconfig, offline
make -C Entropy/pi/os repro-check    # builds twice in fresh output directories at the same path and compares SHA-256

# Or verify a release download
minisign -Vm keepcrypt-pi-1.0.0.img -P <release-public-key>
sha256sum keepcrypt-pi-1.0.0.img   # must match SHA256SUMS in the release

# Flash on Linux (double-check the device name first)
sudo dd if=keepcrypt-pi-1.0.0.img of=/dev/sdX bs=4M conv=fsync status=progress
# Flash on macOS (diskutil list names the card; double-check N first)
diskutil unmountDisk /dev/diskN
sudo dd if=keepcrypt-pi-1.0.0.img of=/dev/rdiskN bs=4m
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
