# KeepCrypt-Entropy user guide

Draft for review (M7 H1). Sources: mobile-apps.md, pi-firmware.md, seal-watchonly-braille.md, design.md, release.md, mobile/screens.json.

This guide covers the Raspberry Pi device, the Android app and the iPhone app. The phone ceremony mirrors the Pi screen for screen, so one guide covers all three. Where a platform differs, a short note says so.

## 1. What KeepCrypt is and is not

KeepCrypt-Entropy makes a new Bitcoin seed phrase (12 or 24 words) offline. It mixes two sources: randomness from the device and rolls of physical dice that you make yourself. Your seed is safe if either your device or your dice are honest.

KeepCrypt does not sign transactions. It does not store your seed. When a ceremony ends, everything is wiped.

**What no phone app can stop.** Malware with control of the phone's operating system, a second camera pointed at the screen, or a rooted or jailbroken phone. The apps say this on their first screen.

**Use the Pi for life savings.** A phone is a networked, general-purpose computer. The Pi has no radios, boots from a read-only card and forgets everything at power-off. The docs recommend:

- **A phone app** for smaller or everyday wallets, for checking a Pi or Coldcard ceremony, and for checking that an encrypted backup restores.
- **The Pi** for life savings and inheritance wallets, for anyone whose threat model includes an attacker in control of the operating system, and for anyone who cannot keep a phone offline during the ceremony.

**Pre-releases.** Versions before 1.0.0 are pre-releases. They are not for real funds until the fixes from the independent audit are published.

## 2. Before you start

### Get and verify the download

Every release publishes a file called `SHA256SUMS`, signed with the KeepCrypt release key using minisign. The public key is `keepcrypt.pub`, and its key ID is printed in `SECURITY.md`.

1. Download the files you need from the release, plus `SHA256SUMS` and `SHA256SUMS.minisig`.
2. Check the signature first:

   ```bash
   minisign -Vm SHA256SUMS -p keepcrypt.pub
   ```

3. Then check the hashes of the files you downloaded:

   ```bash
   sha256sum -c --ignore-missing SHA256SUMS
   ```

4. If either check fails, stop. Do not use the files.

**On Android:** the release includes a signed APK, `keepcrypt-X.Y.Z.apk`. The SHA-256 of the Android release certificate is printed in `SECURITY.md` beside the minisign key ID, so you can compare it. F-Droid is the preferred Android channel. It builds the app from source and publishes it only when its build matches the release apart from the signature.

**On iPhone:** an iPhone build cannot be reproduced, because the App Store re-signs every binary. The project publishes the source, the exact Xcode version and the build steps instead. For the highest assurance, use the Pi or Android.

### Prepare your phone

1. Turn airplane mode on.
2. Turn Wi-Fi off. Wi-Fi can come back on inside airplane mode, so check it.
3. Bluetooth may stay on if you use a braille display.

The app will not start a ceremony until it sees the phone offline. **On Android:** if Wi-Fi comes on during a ceremony, the session is wiped.

### Gather what you need

- **Dice.** Six-sided dice. For the Pi the docs list 5 casino-grade dice, because precision-edged dice roll more evenly than rounded toy dice.
- **Something to write on**, for the words and, if you make one, the backup passphrase.
- **A KeepCrypt Hinge or Screw** (12 titanium inserts) with its jig, punch and Allen key, plus the SeedBook, if you make a braille metal backup. One device holds one 12-word phrase. A 24-word seed needs two.
- **A FAT32 USB stick** and a micro-USB OTG adapter, if you want an encrypted backup from the Pi.
- **A private place.** No other person and no camera should see the screen or your dice.

### Set up the Pi

The Pi build uses a Raspberry Pi Zero v1.3 (no Wi-Fi or Bluetooth hardware), a Waveshare 1.3-inch LCD HAT with a joystick and 3 keys, a microSD card of 8 GB or more, and a 5 V micro-USB power bank. Power it from the power bank, not from a computer's USB port.

**Flash the image.** Use a new card for each release. Check the device name twice before you write: writing to the wrong disk destroys its contents.

On Linux:

```bash
sudo dd if=keepcrypt-pi-X.Y.Z-st7789-240x240.img of=/dev/sdX bs=4M conv=fsync status=progress
```

On macOS (`diskutil list` names the card):

```bash
diskutil unmountDisk /dev/diskN
sudo dd if=keepcrypt-pi-X.Y.Z-st7789-240x240.img of=/dev/rdiskN bs=4m
```

The Pi cannot prove its own image is genuine. Check the signature before flashing, and keep the card under your control.

**First-boot checklist.**

1. The self-tests pass, and the hash prefix on the boot screen matches the release notes.
2. You make one disposable ceremony and check it with `verify.py` on an offline computer (section 7). Never fund it.
3. You restore one test backup with `age -d` on the offline computer.
4. Only then do you make a real seed, with fresh dice rolls.

**Pi buttons.** A footer on every screen names what each key does there. One press is one event. Presses made while the screen is still drawing or the device is busy do nothing.

## 3. The ceremony, step by step

### First launch

The app explains what it does, what no phone app can protect against, and points you to the Pi build for life savings.

**On the Pi:** there is no first-launch screen. The Pi starts with its boot screen and self-test.

### Self-test

The device runs its known-answer tests. If any test fails, no ceremony can start.

**On the Pi:** the boot screen shows the version and the root filesystem's hash prefix (16 hex characters, in four groups of four). Compare it with the release notes. The Pi also tests its hardware random number generator. A failure shows a red stop screen that no key leaves.

### Go offline

The app shows the airplane-mode and Wi-Fi state. The **Start** button stays disabled until both say offline.

**On the Pi:** there is no such screen. The Pi has no radios.

### Home

Choose one:

- **New seed**: the default mode, device randomness plus dice.
- **Dice-only seed**: your dice alone. The screen says no device randomness is used. The seed is only as good as your dice. The result matches Coldcard's dice math.
- **Check a backup**: see section 5.
- **Load registry snapshot**: load a signed `.kcr` snapshot for the collision check (section 4).
- **Verify another device's ceremony**: phones only; see section 7.
- **About**.

**On the Pi:** Home has no **Verify another device's ceremony**. About also shows the hash prefix.

### How many words?

Choose **12 words** (the default; it fills one KeepCrypt Hinge or Screw) or **24**. A 24-word seed needs two Hinges or Screws.

### Device entropy

The device gathers its own randomness. Touch timing and motion sensors are mixed in as extras that count for nothing. You may play Snake or Tetris while you wait. The games never touch your seed's randomness.

**On the Pi:** a progress bar fills as the hardware generator's bytes pass their health tests. **Play while you wait** opens Snake.

In **Dice-only seed** mode this step, **Commitment C** and **Reveal D** do not happen: you go straight to the dice.

### Commitment C

The device shows C, a commitment to its own random value, as 16 groups of 4 hex characters. It shows C before you roll any dice, so the device cannot change its value after seeing your rolls.

You only need to write C down on a verification run (section 7). For a real seed, do not.

### Dice

Roll your dice and enter each roll. The screen shows the count and the bits so far, never the rolls themselves, so a bystander cannot read them.

The minimum number of rolls:

- 50 rolls for 12 words.
- 99 rolls for 24 words.
- 99 rolls for either length after a collision (section 4).

**On the Pi:** the joystick picks 1 to 6, press confirms, and KEY1 undoes. KEY3 means Done once you reach the minimum. The Pi stops accepting rolls at 256.

**On Android and iPhone:** a 1 to 6 pad with undo. **Done** becomes available once you reach the minimum.

### Check for collisions

The device offers to compare your new wallet's seal with the public registry before you see any word. See section 4.

### Seed words

The words appear one per page in insert view. See section 5.

### Read-back

You enter the first four letters of every word from your metal or paper. This step is mandatory. See section 5.

### Wallet summary

The device shows the wallet fingerprint and the first receive address. Keep these to compare after you restore the wallet, or when you set up a watch-only wallet.

### Encrypted backup (optional)

An age-encrypted backup file with a generated 8-word passphrase. See section 5.

### Watch-only export (optional)

QR codes for Sparrow and Bitcoin Core. See section 6.

### Register seal (optional, once)

The device shows a **Registration QR** for a second device. Scanning it opens the registry's page, which adds your seal to the public registry. Register once only. Never register from a restored seed: a second registration of the same seed looks like a collision. The docs recommend Tor Browser for registration.

The registration QR carries your seal code. Anyone who has the code can file a false collision report against you, so never post it.

### Reveal D (optional)

Use this only on a verification run. The device shows its random value D as 16 groups of 4 hex characters, like C. D plus your rolls recreates the seed, so never reveal D for a seed you will fund.

### Before you walk away

The last screen is the SeedBook checklist:

1. Every face read back.
2. Inserts put back together in sequence order, 01 first.
3. Device fastened shut and back in place.
4. Whole phrase test-restored from the metal.
5. Every paper copy destroyed.
6. No photograph of the inserts anywhere.

Then the session is wiped. **On the Pi:** the screen goes black and shows "Safe to power off". No key leaves it. **On Android and iPhone:** the app returns to Home.

### Privacy rules on every screen

Screens that show a secret are Protected: the words, the read-back, the backup passphrase, BIP39 passphrase entry, D, the registration QR, the collision-report QR and the watch-only QRs.

- **Privacy gate.** Before a Protected screen you confirm you are alone. On phones the button is **I'm alone, show words**. On the Pi the gate says "No person or camera can see this screen".
- **Cover.** After 30 seconds without input, a Protected screen is covered. One tap or press uncovers it, and the session stays.
- **Idle.** After 9 minutes without input a warning appears. At 10 minutes the session is wiped.
- **Leaving the app (phones).** Leaving the app on a Protected screen, or on a privacy gate, discards the seed at once. On other screens the app shows a cover and wipes after 60 seconds in the background.
- **On iPhone:** a screenshot during a ceremony ends the session. You start again with a new seed. The seed is not yet funded, so you lose only a few minutes.
- **Screen readers.** TalkBack and VoiceOver speak the words, the passphrases and D aloud. Every privacy gate warns you to use headphones.

## 4. The collision check

The check is optional and recommended. It compares your new wallet's seal with the public KeepCrypt registry before you see any word. If someone has already registered the same seal, your seed is not unique. The device destroys it unseen, and you make a new one.

The registry is an alarm for badly broken generators. It does not prove a seed is strong.

### Choose to check or skip

The prompt reads "Check for collisions before you see your words?" Choose **Check now (recommended)** or **Skip**. Skip takes a confirm screen, **Skip the check?**. If you skip, the words appear with a note that you can check the seal later.

**Once you choose to check, there is no Skip.** Only a verified go-ahead shows the words. Every other exit wipes the seed unseen.

### With a loaded snapshot (recommended)

Before the ceremony, download the signed daily snapshot `keepcrypt-registry-YYYY-MM-DD.kcr` on any computer. Load it with **Load registry snapshot**: from the file picker on a phone (this works in airplane mode), or from a USB stick on the Pi. The device checks its signature. Nothing leaves the device.

The check then runs on the device by itself.

- **On Android and iPhone:** the check is automatic. The app warns if the snapshot is older than 30 days.
- **On the Pi:** the Pi has no clock, so it asks you to confirm the snapshot's number, date and entry count every time. **Yes** runs the check. **No** keeps the check open and shows the seal card instead.

### Without a snapshot: the seal card

The device shows the **Seal card**: the seal image (an 8×8 pattern), the Seal ID, and a **Check QR**. The check QR carries a public tag and a fresh one-time number. It holds nothing secret.

1. On a second device, scan the check QR with the registry website (online), or with the offline checker app (which holds a cached snapshot).
2. Compare the seal image the checker draws with the one on your device.
3. The checker answers **Go ahead**, **Stop**, or cannot check.

The website's server learns only a small prefix of the tag, not your seal.

### Go ahead: the go-ahead code

On Go ahead, the checker shows an 8-character go-ahead code in two groups of four, and a go-ahead QR. The code proves the checker looked up this exact seal during this ceremony. An old or borrowed code will not work.

- **On the Pi:** choose **Enter go-ahead code** and type it with the joystick. KEY2 goes back to the actions page and keeps the check open.
- **On Android and iPhone:** scan the go-ahead QR with the camera (**Scan go-ahead QR**; this works in airplane mode), or type the code on the **Go-ahead code** pad.

The device checks the code. A typo can be re-entered. Once the code is verified, the words appear. If you only typed the code, the device says the result holds "as of the date your checker showed".

The go-ahead QR and a loaded snapshot are checked on the device against the registry's signature, so they need no trust in the checker. Use one of them when that matters.

### Stop: a match

The checker says a collision was found. Do not use this seed.

1. Choose **Match found** and confirm on **Match found?**.
2. The seed is wiped unseen. You never see the other wallet's words.
3. The device offers a **Report collision** QR. Registering it warns the earlier owner at their next re-check. Sharing it is harmless, because that seed is never used.
4. Choose **Add fresh entropy**. A new ceremony starts with fresh device randomness and fresh dice, and needs at least 99 rolls for either length.

A real collision means this device's randomness or firmware is suspect. The device suggests a verification run (section 7) and suggests reporting the device and firmware version to the KeepCrypt security address.

**On the Pi:** a power cycle forgets the 99-roll minimum.

### Cannot check

If the checker cannot answer, choose **Cannot check** and confirm on **Cannot check?**. The seed is wiped. Choose **Start again** to begin a new ceremony. If the ceremony you could not check was itself the restart after a collision, the 99-roll minimum stays.

### Re-checking later

The verifier, the Pi's **Check a backup** tool and the phone apps can compute your seal later from the words or the encrypted backup and look it up again. The re-check QR shows the registration count but never a go-ahead code.

- A count of 1 means only you.
- A count of 2 or more, when you registered once, means someone else has the same seed. Move your funds to a new seed now.

Re-check every 3 months, and after any news of a weak-randomness wallet bug.

## 5. Recording your seed

### Writing the words down

Words on paper or metal are your primary backup.

The **Seed words** screen shows one word per page in insert view: the word, its SeedBook number, and its five braille faces. Blank faces and mirror pairs are flagged. **Seed words: overview** shows four words per page for a paper copy.

**On the Pi:** each page also shows the sequence number. KEY1 switches to the overview. KEY2 and KEY3 page back and forward. Press on the last insert starts the read-back.

The SeedBook number only helps you find the word in the SeedBook. Never back it up instead of the word.

### The braille SeedBook and the metal inserts

Each word goes on one hexagonal titanium insert:

1. **Faces 1 to 5**: the first five letters, one braille cell per face, in UEB grade 1 with no contractions.
2. **Blank faces count.** A three- or four-letter word leaves the remaining faces blank. A blank face is part of the backup. Leave it blank.
3. **Face 6**: the pre-engraved sequence number 01 to 12, the word's place in the phrase.
4. **Letters 4 and 5.** The first four letters identify every word. The fifth is a check, drawn lighter on screen.
5. **Mirror pairs.** e/i, d/f, h/j and r/w are mirror images of each other. Read them twice.

**SeedBook safety rules.**

- The SeedBook is a public reference. Never write your real phrase in it, and never store a marked copy with the wallet.
- Work one word at a time, in order, alone and offline.
- Rehearse on a spare insert first.
- Never use a computer-driven embosser or printer for a real seed.

**24-word seeds.** Words 1 to 12 go on device 1 of 2, and words 13 to 24 on device 2 of 2. Both sets of inserts are numbered 01 to 12. Every insert screen, the read-back prompt and the final checklist say which device holds words 1 to 12. After word 12 a **Device swap** screen says that words 13-24 go on device 2 of 2; **Continue** goes on.

### The read-back from the metal (mandatory)

Before the session ends, read every punched insert back, in order.

1. On the **Read-back** screen, enter the first four letters of each word, as you read them from the metal. If you have no metal, enter your paper words the same way.
2. The device completes each word and compares it with the seed it still holds.
3. If a word does not match, **Read-back mismatch** names it. Check the insert and enter it again.
4. When every word matches, **Read-back complete** appears.

This step catches misreads, such as a mirror-pair flip, that a later restore might not catch. The encrypted backup, the watch-only export, seal registration and Reveal D stay locked until every word reads back correctly.

**On the Pi:** on the mismatch screen, press re-enters the word and KEY1 shows the insert.

### The encrypted backup (optional)

KeepCrypt can save exactly one kind of file: an age-encrypted backup.

1. **Backup passphrase.** The device makes an 8-word passphrase for you. Write it on paper. Store it apart from the backup file.
2. **Check your copy.** You confirm 2 of the passphrase words. **On the Pi:** you pick each from four choices.
3. **Save the backup.**
   - **On the Pi:** insert a FAT32 stick in the OTG port. Encryption takes a while on a Pi Zero, so a wait screen stays up. The file `keepcrypt-backup-<8 hex>.age` is written as a new file, never over an old one.
   - **On Android:** the system "create document" picker opens. **On iPhone:** the document picker opens. You choose where to save. A cloud folder is allowed: the passphrase is what protects the file, so keep the passphrase on paper, away from the file.
4. **Backup verified.** The device reads the file back, decrypts it in memory and compares the fingerprint. Only then does it say "Backup verified."
5. **If it fails.** The device says so. **On the Pi:** it deletes the partial file if it can and keeps the ceremony open so you can retry or skip. **On phones:** delete the partial file yourself, since the app cannot always delete it.

**Restoring without KeepCrypt.** On an offline computer, run `age -d keepcrypt-backup-<8 hex>.age` and type the 8-word passphrase.

### Checking a backup later

Choose **Check a backup** on Home.

1. Open the `.age` file. **On the Pi:** from a USB stick. **On phones:** from the file picker.
2. Enter the passphrase as the first four letters of each word on the letter pad. **On the Pi:** type the whole word for a three-letter word. KEY2 returns Home and leaves the file on the stick.
3. The device shows the fingerprint. **On phones:** "Backup OK." appears.
4. Words appear only if you ask: **Show words** opens them through the privacy gate.

## 6. Watch-only export

After the backups, the device can show your wallet's public account data as QR codes. Sparrow, Bitcoin Core or another descriptor wallet can then watch your balance and build unsigned transactions. Nothing private is exported, and nothing is written as a file.

- **Account QR for Sparrow**: for Sparrow and other coordinators that read UR codes.
- **Descriptor QR for Bitcoin Core**: two output descriptors (receive and change) for Bitcoin Core and other descriptor wallets.

**BIP39 passphrase.** The device first asks **BIP39 passphrase?**. If you use one, enter it on **BIP39 passphrase**. The device then exports that wallet and shows its own fingerprint and first receive address. An empty passphrase is refused.

**On the Pi:** the passphrase may use printable ASCII only, up to 100 characters. KEY2 goes back to the question and wipes what you typed. If your passphrase uses other characters, the Pi gives no watch-only export. Build the watch-only wallet in your coordinator after restoring.

**In Sparrow:** New wallet, then single signature, native SegWit, then Airgapped Hardware Wallet, then scan the account QR, then Apply.

**In Bitcoin Core:** create a blank wallet with no private keys, then import the two descriptors from the descriptor QR.

**Before you fund the wallet:** check that the first receive address in Sparrow or Bitcoin Core matches the device's **Wallet summary**. If you used a BIP39 passphrase, compare it with the address shown for that wallet instead.

Treat the account key as private. It reveals every address and balance.

## 7. Checking a ceremony with the offline verifier

The offline verifier, `verify.py`, recomputes a disposable run so you can check the device without trusting it. It never makes a secret. Never use it with a real wallet's values.

You need Python 3.9 or later on a separate offline computer, ideally a Tails boot with no network and no disk.

1. **While online,** download `verify.py` from the release and compare its SHA-256 with the one in the release notes:
   - macOS: `shasum -a 256 verify.py`
   - Linux or Tails: `sha256sum verify.py`
2. **Move to the offline computer.**
3. **Make a full disposable run on the device.**
   - In the default mode, write down C before the first roll, then D (from **Reveal D**) and the rolls.
   - In dice-only mode, write down only the rolls.
4. **Run the verifier** with the right length. There is no default, and the wrong length gives eleven matching words and a wrong last one.

   ```bash
   python3 -I verify.py mixed --words 12
   python3 -I verify.py dice --words 12
   ```

   Use `--words 24` for a 24-word run.
5. **Wait for each prompt before you type.** Anything typed earlier is dropped, though the terminal may already show it. Nothing you type is shown. C is printed back to proofread. An empty line or Ctrl-D ends the rolls.
6. **Compare every line** it prints with what the device showed: that C matches D, the roll count, the seal, one braille insert line per word, and the seal code.
7. **Never fund the test wallet.** Close the terminal and shut the computer down.
8. **Make your real wallet** with fresh rolls that never leave the device.

Never pipe the values in with `echo`: that leaves the rolls in your shell history.

`python3 -I verify.py selftest` runs the built-in known answers alone. If a known answer fails, your copy is broken or changed: get a fresh one.

**On Android and iPhone:** **Verify another device's ceremony** runs the same verifier inside the app. Enter C, D and the rolls from a disposable KeepCrypt Pi run, or only the rolls from a Coldcard dice-only run, and compare the words.

## 8. What KeepCrypt will never do, and what to do if it fails

### Never offered

The apps never offer a share sheet, copy, a QR code of the words (SeedQR), an image, Photos, email, a plaintext text file, or any other export of the words themselves.

The apps have no network access. They never write to the clipboard, never back up to the phone's cloud, and contain no analytics, crash or ad tools. The only file they ever save is the encrypted backup you choose to save. The only files they read are `.age` backups and signed `.kcr` snapshots.

The Pi stores no seeds, passphrases or logs, writes no plaintext file, and never updates itself. New versions are flashed to a new card.

### If something fails

KeepCrypt fails closed. It has no fallback and no retry around its randomness or its tests.

- **A failure halts and wipes.** Any self-test, randomness, health-test or internal error wipes everything secret and shows a stop screen that names the failure.
  - **On the Pi:** the red stop screen. No key leaves it. Power-cycle the device. The self-tests run again before any new seed.
  - **On Android and iPhone:** the **KeepCrypt stopped** screen. Its only action closes the app. The next start reruns the self-test.
- **Your mistakes do not halt.** A wrong go-ahead code, a read-back mismatch, a wrong backup passphrase, an empty BIP39 passphrase, or a refused backup file or snapshot returns you to the same screen with a message. **On the Pi:** USB faults also return you to their screen.
- **Start again.** Nothing from a wiped session can be recovered. Begin a new ceremony with fresh dice. The seed was never funded, so you lose nothing but time.
- **It keeps failing.** Stop using that device or copy, and report the failure, the screen's text and the version to the KeepCrypt security address in `SECURITY.md`.
