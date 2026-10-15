#!/bin/sh
# Banned-API grep gate: CLAUDE.md security rules 1, 3, 5 and 9 (plan: tasks/todo.md, M0; the Shell
# category and the hash ban: M3 group 13), and the release-artifact scan for rules 1 and 10
# (tasks/todo.md, M1 group 11).
#
#   scripts/banned-api-check.sh             scan the repo this script lives in
#   scripts/banned-api-check.sh DIR         scan DIR as if it were the repo root
#   scripts/banned-api-check.sh --artifact TARGET FILE...
#                                           scan built release artifacts for TARGET (see "Artifact
#                                           mode" below)
#   scripts/banned-api-check.sh --workflows DIR
#                                           check every DIR/entropy-*.yml and entropy-*.yaml GitHub
#                                           workflow's hardening (see "Workflow mode" below)
#   scripts/banned-api-check.sh --image-lists IMG KCONFIG
#                                           unpack the Pi image IMG and print its lists, with the
#                                           kernel config KCONFIG (see "Image lists mode" below)
#   scripts/banned-api-check.sh --image IMG EXPECTED_DIR KCONFIG BIN_SHA256
#                                           scan the Pi image IMG against the reviewed lists in
#                                           EXPECTED_DIR (pi/os/expected), its kernel config KCONFIG
#                                           and the SHA-256 of its keepcrypt-pi (see "Image scan
#                                           mode" below)
#   scripts/banned-api-check.sh --selftest-image IMG KCONFIG
#                                           the image scan's positive controls, as mutations of the
#                                           built image IMG (see "Image selftest mode" below)
#   scripts/banned-api-check.sh --os-config OS_DIR
#                                           the text-only checks of the image's configuration in
#                                           OS_DIR (pi/os; see "OS configuration mode" below)
#   scripts/banned-api-check.sh --selftest  every fixture in scripts/testdata/banned-api/ must trip the
#                                           gate for its category; every clean-* fixture must pass; the
#                                           artifact fixtures in scripts/testdata/artifact/ must give
#                                           exactly their pinned hits (needs the pinned toolchain); the
#                                           workflow fixtures in scripts/testdata/workflows/ must trip
#                                           or pass the workflow check as their names say; the
#                                           image lists' built-in cases must be refused before any
#                                           host tool runs; the OS configuration fixtures in
#                                           scripts/testdata/os-config/ must pass or fail as their
#                                           names say; and the image scan's built-in cases must be
#                                           refused, or, on a stub image, give exactly their one hit
#
# Prints "<category>: <file>:<line>: <text>" per hit, then a summary. Exit 0 clean, 1 hits,
# 2 usage or read error: a file that cannot be read fails the gate, it is never skipped.
#
# Artifact mode (docs/build-plan.md "Security rules enforced in CI", rows "One RNG path in shipped
# binaries" and "Test stubs never ship"; tasks/todo.md, M1 Q3, Q8 and group 11; M4 group 12). Prints
# "<category>: <file>: <detail>" per hit, then a summary; exit 0 clean, 1 hits, 2 error (an
# unreadable file, a file llvm-nm cannot read, no llvm-nm, a TARGET with no rule, bad usage).
#   Marker     any file holding KC_TEST_SOURCE_DO_NOT_SHIP or KC_TEST_REGISTRY_DO_NOT_SHIP (rule 10),
#              or KC_SIMULATOR_DO_NOT_SHIP, which pi/sim embeds so no simulator code ships
#              (tasks/todo.md, M3 Q31 (d))
#   TestKey    any file holding the 32 bytes of the test registry public key (rule 10; pinned below
#              and checked against vectors/kcr.json by the selftest)
#   Format     a file that is not an ELF, Mach-O or ar file (an rlib is an ar file): its symbols
#              cannot be checked, so it fails. So does a thin ar file (!<thin>), which holds only its
#              members' paths: the marker and key searches would never see the members' bytes. And
#              so does a stripped ELF or Mach-O file (M4 group 12): any object or linked file for
#              which llvm-nm lists no symbol at all (the operative test: a stripped ELF lists none
#              too, since llvm-nm reads .symtab, not .dynsym), and an ELF with no .symtab section,
#              which names the cause. A stripped file prints no symbols, so the symbol rules below
#              would pass it silently
#   Symbol     read with the pinned toolchain's llvm-nm (llvm-tools-preview), in every object file,
#              linked file and archive member: an undefined rand, random, srand, srandom, rand_r,
#              random_r, srandom_r, *rand48, seed48, lcong48, initstate or setstate (these six also
#              with glibc's reentrant _r), arc4random* or SecRandomCopyBytes, and getentropy on
#              Linux and Android (each with a leading _ on Apple targets); any symbol, demangled, in
#              the 13 RNG crates of deny.toml's rule-1 block (rng_crate_names below; the selftest
#              checks the two lists agree); and any symbol in
#              getrandom's fallback modules, backends::use_file and
#              backends::linux_android_with_fallback (Q8: the Linux and Android artifacts are built
#              with --cfg getrandom_backend="linux_getrandom", which has no fallback)
#   StdRandom  std's own OS read, the random keys behind HashMap's RandomState (rule 1; M4 group
#              12: the grep gate's hash ban covers the shipped sources, this covers what was
#              linked): in every file, a symbol, demangled, that holds hashmap_random_keys,
#              RandomState, std::sys::random or the mangled module path 3std3sys6random, and the
#              byte string /dev/urandom or /dev/random, which std's fallback reads. One exception,
#              on *-linux-gnueabihf in an object or linked file (never an archive): the three
#              statics of std::sys::random::linux::getrandom (DEVICE, GETRANDOM_AVAILABLE (.0),
#              GRND_INSECURE_AVAILABLE (.0)) pass when llvm-nm types each of them d (local data)
#              only, since LLVM's global-merge keeps them beside data every binary uses (Q52); the
#              function itself stays a hit
#   OSImport   an object or linked file (not an archive: core's rlib calls the getrandom crate,
#              whose own rlib imports the OS call) without the OS import for TARGET: getrandom on
#              Linux and Android, _CCRandomGenerateBytes on iOS (Q8), and _getentropy on macOS,
#              which getrandom uses there (a host rule, for scripts/canaries.sh on a Mac)
# The byte searches run on an od dump, one "xx" per byte, so they match whole bytes of any value
# with plain fixed-string greps.
#
# Workflow mode (tasks/todo.md, M4 group 11; Q38 (d): CI checks that the workflows keep their
# hardening, which until M4 lived only in a comment in entropy-ci.yml). Every DIR/entropy-*.yml
# and DIR/entropy-*.yaml (GitHub runs both extensions; none at all is an error) is read line by
# line; comments count. Prints "Workflow: <file>:<line>: <text>" per hit, then a summary; exit 0
# clean, 1 hits, 2 error. Each file must have:
#   - a top-level permissions block that holds "contents: read", exactly so (missing: reported at
#     line 1), and no write permission anywhere: no line holding write, in any letter case, inside
#     any permissions block (so "contents: write", a quoted "write", a value on the line after its
#     scope, and a flow mapping on its own line all hit) and no write on a "permissions:" key's
#     own line (write-all, { contents: write });
#   - every "uses:" one of actions/checkout, actions/cache or actions/upload-artifact, pinned to
#     the one commit SHA approved for it (checkout v7.0.1, cache v6.1.0, upload-artifact v7.0.1,
#     Q38 (c); pi/os/pins.txt): a tag, a branch, a short SHA, another SHA (another release, or a
#     fork's commit, which GitHub serves under the action's name) or any other action is a hit;
#   - no secrets as a word anywhere (secrets.X, secrets[X], toJSON(secrets), and prose: write "a
#     secret") and no github.token (the same token as secrets.GITHUB_TOKEN), also as
#     github['token'];
#   - no pull_request_target and no workflow_run anywhere (the triggers that run with the base
#     repository's token on a fork's code);
#   - no "${{" inside a run: step, on its line or in its block scalar (every line indented past
#     the run key until the next line that is not): expressions reach scripts through env: and
#     with: only, so no event data is pasted into a shell. The key may follow a dash of any width
#     ("-   run:"), be quoted ("run":) or sit in a flow mapping ({name: x, run: "..."}), and a
#     run: key with no value (defaults.run) is read the same way, so an expression under it is a
#     hit too.
#
# Image lists mode (tasks/todo.md, M4 groups 14 and 15; Q38 (d)): the image workflow's "hash and
# list" step prints with it what commit 16 commits to pi/os/expected/ for review and the image
# scan compares from commit 17. It lists, it does not judge: exit 0 listed, 2 an image it cannot
# read or list. IMG is a disk image that starts with an MBR, KCONFIG the kernel's .config. The MBR
# must hold the boot signature and exactly the image's two partitions: 1 FAT32 with LBA (type
# 0x0c) and 2 Linux (0x83), each non-empty, after the MBR and inside the image, 2 after 1, and
# entries 3 and 4 empty; partition 2 must start with SquashFS's magic hsqs. These checks need no
# tool. Then, with the build's host mcopy, mdir and unsquashfs on PATH (KC_WORK/out/host/bin)
# and the pinned toolchain's llvm-nm, it extracts partition 1 with mcopy -s, unpacks partition
# 2 with unsquashfs, and prints, each part under a "== " heading:
#   - the partition table: the disk signature, and each partition's type, boot flag, first
#     sector and sector count;
#   - "sha256 <name> <hex>" for the image, partition-1, partition-2 and keepcrypt-pi (the
#     image's /usr/bin/keepcrypt-pi);
#   - the boot file list, "<path> <dir|file>" (FAT has no mode and no link);
#   - mdir -a of partition 1;
#   - the root file list, "<path> <mode>[ -> <target>]", read from the SquashFS's own metadata
#     (unsquashfs -lln), so setuid bits and links are listed as built, not as an unprivileged
#     unpack leaves them; the mode string's first letter is the type; owners, sizes and times
#     are left out;
#   - keepcrypt-pi's dynamic imports, "<type> <symbol>@<version>" (llvm-nm -D -u);
#   - KCONFIG as it stands.
#
# Image scan mode (tasks/todo.md, M4 groups 11, 13 and 14; Q38 (d); rule 10): the image workflow
# runs it on each leg's image against pi/os/expected/, the lists the lead reviewed line by line
# (commit 16), and pi/os/Makefile's scan target runs it by hand. It unpacks IMG as the lists mode
# does (the same layout refusals, the same host tools) and makes the same lists, then judges.
# Prints "<Category>: <file>: <detail>" per hit, the file named by its path inside the image
# ("/usr/bin/keepcrypt-pi", "partition-1:/config.txt") or as given, then a one-line count; exit 0
# clean, 1 hits, 2 anything that cannot be read, unpacked or run. Nothing passes vacuously: a
# missing or empty EXPECTED_DIR file, a BIN_SHA256 that is not 64 hex digits, a tool missing
# from PATH, an ELF llvm-nm cannot read or a missing board file is exit 2, never a pass.
# EXPECTED_DIR holds boot.list and root.list (the exact text --image-lists prints under its two
# file-list headings), linux.config (the .config the kernel was built with), kconfig-required and
# kconfig-forbidden (one CONFIG_ symbol per line: the =y lines and the "# ... is not set" lines
# of pi/os/board/pizero/linux.fragment, in its order, so the three cannot drift) and
# keepcrypt-pi.imports (the exact text of the imports heading). The rules:
#   List       boot.list and root.list equal EXPECTED_DIR's byte for byte (the diff on stderr).
#   Deny       whether or not the lists match, the root list holds no path or link target whose
#              base name is sh, ash, hush, getty, login, dropbear, sshd, telnetd or udhcpc, nothing
#              under /lib/modules, /usr/lib/modules or /etc/init.d, no setuid, setgid or sticky
#              mode (an s or t among the nine permission letters) but /tmp's own drwxrwxrwt, and no
#              name that ends .age or holds seed, backup or mnemonic.
#   Boot       partition 1 holds exactly one start/fixup pair, start.elf and fixup.dat, and no
#              other start*.elf or fixup*.dat; its cmdline.txt and config.txt equal
#              pi/os/board/pizero's, found from this script's path, byte for byte.
#   Inittab    the root's /etc/inittab is a file holding exactly Q35's three lines (below).
#   Kconfig    KCONFIG equals EXPECTED_DIR/linux.config byte for byte; kconfig-required and
#              kconfig-forbidden equal the fragment's lists; and KCONFIG has every required option
#              at =y, no forbidden option at y or m, and CONFIG_HW_RANDOM_BCM2835=y as the only
#              CONFIG_HW_RANDOM_* driver.
#   Marker, TestKey
#              the raw image (SquashFS is compressed, so this alone would miss the root's files),
#              every file of partition 1 (the VideoCore start.elf and zImage among them) and every
#              file of the root, as in the artifact scan.
#   Format, Symbol
#              every ELF file of the root other than keepcrypt-pi (found by its magic, not its
#              name; Buildroot strips them all but the loader, todo.md [S10]) must list dynamic symbols
#              (llvm-nm -D; a stripped static ELF lists none and is a Format hit) and, among its
#              undefined ones, no banned RNG import (the artifact scan's list: rand, random, srand,
#              the rand48 family, arc4random and the rest, getentropy), and no rand-crate or
#              getrandom-fallback symbol. glibc's libc.so.6 and ld-linux define rand and the rest
#              rather than import them, so only undefined symbols count against them.
#   Binary     /usr/bin/keepcrypt-pi gets the whole artifact scan for arm-unknown-linux-gnueabihf
#              (Marker, TestKey, Format with a .symtab required, Symbol, StdRandom with Q52's
#              passengers allowed exactly as there, OSImport: getrandom), and then: no symbol or
#              byte string keepcrypt_pi_sim (one hit), imports equal to keepcrypt-pi.imports, and
#              a SHA-256 equal to BIN_SHA256.
#
# Image selftest mode (tasks/todo.md, M4 group 14): the image workflow runs it on the image each
# leg built, where the host tools (mcopy, mdir, unsquashfs, mksquashfs in KC_WORK/out/host/bin)
# and the pinned toolchain's llvm tools are on PATH; it exits 2 where they are not, and where a
# control cannot be built. The built image is the clean fixture: a stand-in EXPECTED_DIR is made
# from --image-lists' own output on IMG plus the fragment's two lists, and --image must pass on it
# (the control). Then each of group 14's 14 positive controls is a mutation of the image (the
# root unpacked afresh, edited and repacked with mksquashfs -no-xattrs; partition 1 copied and a
# file replaced with mcopy -o; the pieces reassembled under a fresh MBR sized to them), of KCONFIG
# or of BIN_SHA256, isolated so that the named rule alone fires: a mutated root's lists stand in
# for expected/ (so only the deny-list, marker, key or ELF rule can fail it), and a mutated
# KCONFIG is also the stand-in linux.config except in the one-line-off case. The ELF controls (a
# stripped shared object importing rand, a stripped static executable) are built from
# scripts/testdata/image/controls.rs with rustc, rust-lld and llvm-objcopy alone, so no cross
# compiler is needed. Prints PASS or FAIL per control and a count; exit 0 all passed, 1 not.
#
# OS configuration mode (tasks/todo.md, M4 groups 11 and 13): text only, runs anywhere, on
# OS_DIR/board/pizero/{rootfs-overlay/etc/inittab, rootfs-overlay/etc/fstab, cmdline.txt,
# config.txt, busybox.config, linux.fragment} and OS_DIR/expected/{linux.config,
# kconfig-required, kconfig-forbidden}; a missing expected/ or a missing or empty file is exit 2.
# Prints "<Category>: <file>[:<line>]: <detail>" per hit, then a count; exit 0 clean, 1 hits.
#   Inittab    exactly the three lines ::sysinit:/bin/mount -a, ::wait:/usr/bin/keepcrypt-pi and
#              ::once:/usr/bin/keepcrypt-pi --stopped (Q35).
#   Fstab      every proc and sysfs line carries ro, nosuid, nodev and noexec; every tmpfs line
#              nosuid, nodev, noexec and a size=; no line of another filesystem type; at least
#              one line.
#   Cmdline    no console= and no init= word; the words ro, panic=0 and init_on_free=1.
#   ConfigTxt  no enable_uart=1, dtoverlay, start_file, fixup_file or plain gpu_mem= line; the
#              gpu_mem_* lines are gpu_mem_256=100, gpu_mem_512=100 and gpu_mem_1024=100, each
#              once (comments skipped).
#   Kconfig    expected/kconfig-required and kconfig-forbidden equal the fragment's =y and
#              "is not set" lines, and expected/linux.config keeps them with exactly one
#              CONFIG_HW_RANDOM_* driver, BCM2835, as in the image scan.
#   BusyBox    only init and mount: CONFIG_INIT, FEATURE_USE_INITTAB, MOUNT, FEATURE_MOUNT_FSTAB,
#              FEATURE_MOUNT_FLAGS, SH_IS_NONE and BASH_IS_NONE at =y; none of the denied applets
#              (busybox_denied below: the shells, getty, login, su, the network, module, power,
#              swap and loop tools, seedrng, vi) at =y; no CONFIG_SH_IS_* or CONFIG_BASH_IS_*
#              selector at =y but the two _NONE ones.
#
# Categories (main patterns; the full lists are in the check functions below; comments count
# everywhere):
#   RNG        rule 1: any PRNG, and any OS RNG outside core: Math.random, java.util.Random, a bare
#              Random( (Kotlin has no "new"), SecureRandom, SplittableRandom, SecRandomCopyBytes,
#              arc4random, GameplayKit GK*Random* and GK*Distribution, Python random through any
#              module path (tasks/todo.md, M4 group 11: "import random", "import jax.random",
#              "import numpy.random as r", "import os, jax.random", "from random import x", "from
#              jax.random import x", "from a.random.b import x": any import whose dotted module
#              path has a random component; also "import (random, ..." and, in a .py file, a
#              wrapped import line that holds only names and such a module, such as "    random,",
#              "    jax.random as r," or "    random \", and a line starting "    random import" or
#              "    jax.random import" after "from \"), C rand(), rand_r(), random(), drand48, C++
#              mt19937, *_random_engine, random_device, minstd_rand, Rust rand:: and rand_core::,
#              Kotlin/Swift .random( and .shuffled(. Rule 1 allows one source of OS randomness, so
#              every file except core/src/source.rs and core/src/source/ is also barred from the OS
#              RNG itself: /dev/urandom, /dev/random, getentropy, CCRandomGenerateBytes and
#              BCryptGenRandom. /dev/hwrng passes (pi/app reads it raw for the health tests).
#              Python os.urandom and secrets pass too: docs/design.md endorses them for Python
#              tooling ("In Python use os.urandom or secrets only").
#   Network    rule 9, skipped in registry/ (the one networked component): URLSession, URLRequest,
#              NWConnection, NWListener, NWBrowser, contentsOf: a URL made from a string
#              (URL(string:), URL.init(string:), .init(string:)), a hard-coded remote URL built in
#              app code (URL(string: "http..., URLComponents(string: "http... or .init(string:
#              "http... in Swift, URL("http... and Uri.parse("http... in Kotlin, any letter case),
#              CFNetwork, WKWebView, java.net., okhttp, ktor, std::net, std::{..net..}, a net::
#              path segment (rustfmt puts "    net::TcpListener," on its own line), TcpStream,
#              TcpListener, UdpSocket. Not banned: "import Network" and NWPathMonitor (the offline
#              check), and reading back a picked .age or .kcr file (rule 8):
#              Data(contentsOf: URL(fileURLWithPath: path)), Data(contentsOf: pickedURL).
#              In a .py file (tasks/todo.md M2 group 2, Q23; completed by the stage-A review,
#              2026-10-10, and by M3's Q31 (h)), an import of socket, ssl (or their C modules
#              _socket and _ssl), socketserver, urllib, urllib3, http, ftplib, smtplib, smtpd,
#              poplib, imaplib, nntplib, telnetlib, xmlrpc, asyncio, asyncore, asynchat, wsgiref,
#              webbrowser, requests, httpx, aiohttp, multiprocessing.connection,
#              multiprocessing.managers, logging.handlers or logging.config (these four by their
#              own names, as "from logging import handlers" brings one in), in the shapes Python
#              random has under RNG, and also as the last part of a dotted name ("import
#              gevent.socket", "from gevent.socket import x", "import logging.config"). Anchored on
#              the import, so a URL string such as "https://registry.invalid" passes.
#   Clipboard  rule 5 and docs/mobile-apps.md ("Never offered: share sheet, copy"): clipboard APIs,
#              plus UI that copies or shares: .textSelection( unless it is exactly
#              .textSelection(.disabled), which the docs require (spaces around .disabled are
#              fine; .enabled, a variable, a custom static such as .dragToCopy, or an argument on
#              the next line all hit), EnabledTextSelectability (the type such a static needs),
#              ShareLink, UIActivityViewController, SelectionContainer, Intent.ACTION_SEND (and
#              _MULTIPLE, SENDTO), and any line that names textIsSelectable, setTextIsSelectable
#              or isTextSelectable, unless each one's value is the literal false: ="false",
#              ">false<", (false) or "= false". In a .py file (Q23; completed by the stage-A review,
#              2026-10-10, and by M3's Q31 (h)): an import of the clipboard module, in the shapes of
#              the Python network imports; anywhere a word starts with one, pyperclip,
#              win32clipboard, tkinter's clipboard_append, clipboard_get, selection_get and
#              selection_own, pandas' to_clipboard, read_clipboard and clipboard_set, and the tools
#              pbcopy, pbpaste, xclip, xsel, wl-copy, wl-paste, PowerShell's Get-Clipboard and
#              Set-Clipboard, clip.exe (never a bare clip) and osascript's "the clipboard" (these
#              last three in any letter case); a string that starts with the word clipboard, as
#              Tcl's clipboard command does (root.tk.call('clipboard', 'append', x)); and any
#              attribute or dotted module named clipboard (QApplication.clipboard(),
#              app.clipboard()). In any file (Q31 (h)): JXA's theClipboard (and
#              setTheClipboardTo), and PowerShell's aliases gcb and scb as whole words in any
#              letter case, in a .ps1 or .psm1 file and on any line that names powershell or pwsh
#              (a subprocess or shell line that starts PowerShell); elsewhere gcb and scb are
#              ordinary names.
#   Rule1      rule 1 path check: getrandom in any .rs file is a hit, except in the core module
#              core/src/source, in either file layout: source.rs or anything under source/. A
#              look-alike such as core/src/sourcex.rs is another module. The games are no
#              exception: they get their bytes from core's separate game_random call
#              (docs/pi-firmware.md, "Game randomness").
#              std's OS-seeded hashing (tasks/todo.md, M3 group 13): HashMap, HashSet, RandomState,
#              DefaultHasher, hash_one or BuildHasherDefault, as words, in any .rs file under
#              core/src, ffi/src or pi/app/src (the shipped crates; their tests use BTreeSet and
#              BTreeMap). The artifact scan cannot see it: std reads the OS for the hash keys.
#              core/src/lib.rs must hold the exact line #![forbid(unsafe_code)], and so must
#              pi/app/src/lib.rs and pi/app/src/main.rs whenever pi/app exists (a missing line is
#              reported at line 1).
#   Shell      the shells' paths to core (tasks/todo.md, M3 group 13; rule 1 and Q27, Q26). In the
#              games' code (pi/app/src/games/, and pi/app/src/games.rs, the module's other
#              layout), any of the words Session, Wiped, add_extra, add_hw_samples, ceremony,
#              SystemTime or Instant, or of the app's holders of the session and the HAL's clock,
#              Stage, Held, App, Clock or now_ns: a game holds no session and no pool input, and
#              keeps no clock. game_random in any file outside core/src/source.rs, core/src/lib.rs,
#              core/tests/, core/examples/release_probe.rs and pi/app/src/games/. Session::new
#              (spaces around :: allowed, and with the state named, Session::<Collecting>::new or
#              <Session<Collecting>>::new) in any file under pi/app/src but pi/app/src/app.rs, and
#              each match after its first in app.rs: pi/app starts sessions in one place, so a kept
#              Wiped's 99-roll minimum cannot be skipped. And whenever core exists,
#              core/examples/release_probe.rs must call game_random outside every // and /* */
#              comment (the stage-A review's finding 9), so dropping the call fails the gate,
#              although the scan of the probe would not change (tasks/todo.md, M3 group 1); a
#              missing call is reported at line 1.
#   FailOpen   rule 3, only in .rs files under core/, ffi/ and pi/app/ (the crates under the
#              fail-closed lints): a discarded result. That is an assignment to _ or to an _name
#              ("_ = f()", "_x = f()") and an underscore binding ("let _ = f()", "let _x = f()",
#              "let mut _x = f()", "let _x: T = f()"). rustc never warns about an unused _name and
#              clippy's let_underscore_must_use only catches "let _ =", so this check covers the
#              rest (and backs that lint up). A __name is an _name too. Not hits: "_ =>",
#              "let (_, b) =", "|_|", "for _ in", "const _: () =", "x_ = 3", "self._x = 3".
#              An RAII guard gets a real name and an explicit drop, never an _name:
#              "let guard = lock(); ...; drop(guard);". Also hits: drop( or forget( applied to a
#              call expression ("drop(source::fill(&mut b))", "core::mem::forget(f())", a
#              turbofish "drop::<T>(", or "drop(" with its argument on the next line), which
#              discards the result just as "_ =" does; "drop(guard)" passes, and so does
#              "fn drop(&mut self)". "drop(self.pool.take())" hits too: assign None instead.
#              clippy used as a cfg predicate (#[cfg(not(clippy))], #[cfg(clippy)],
#              #![cfg_attr(clippy, ...)], cfg!(clippy), r#clippy, any(test, clippy), and a wrapped
#              "    clippy," line): cargo build compiles the code clippy never sees, so every lint
#              is off for it. clippy::lint paths pass ("#[allow(clippy::x)]"); a comment that
#              lists ", clippy," hits. And /dev/stdout, /dev/stderr or /dev/tty (any tty, such as
#              the Pi's serial /dev/ttyAMA0): rule 5, secrets are never printed.
#   Include    any .rs file: include!( (any delimiter), the path attribute (#[path = ...],
#              #![path = ...], and path = ... inside #[cfg_attr(...)], also on its own line where
#              rustfmt wraps a long one), and the include macro reached by path or alias:
#              std::include or core::include as a word, "include as <name>" (use std::include as
#              pull; use core::{include as x}), and include passed bare to a macro
#              (call!(include, "x.rs"), whose $m:ident expands to include!). Both compile another
#              file as Rust, and that file may sit where this scan never looks: docs/, tasks/,
#              scripts/testdata/, or a binary extension. include_str! and include_bytes! (data,
#              not code) pass. In any file: a C/C++ #include (also %:include, #include_next,
#              #import) of a name with a binary extension ("#include "lut.png""), any letter case,
#              since that file is never scanned.
#   Device     rule 8 as Q40 and Q51 amended it, and rule 5 (tasks/todo.md, M4 group 11): the Pi
#              firmware's files, device paths and processes, in pi/app only. Path literals: every
#              string literal that starts with / in a .rs file under pi/app/src ("/..., b"/...,
#              r"/...) lives in pi/app/src/device/paths.rs and is one of /dev/hwrng,
#              /dev/mmcblk0p2, /dev, /sys/block and /mnt/usb, the paths docs/pi-firmware.md's
#              Process rules list for our own code (rppal builds its own /dev/spidev*, /dev/gpio*
#              and /proc paths, read from its source and on that list too). File APIs: the fs
#              module (fs::, std::fs, std::{.. fs ..} and a wrapped "    fs," or "    fs as f,"),
#              File::, OpenOptions, read_dir, read_link and remove_file appear only under
#              pi/app/src/device/; create_new only in pi/app/src/device/usb.rs (the one file the
#              firmware ever creates, the backup); and .create(true), .truncate(, .append(,
#              fs::write, fs::copy, rename, create_dir*, remove_dir*, set_permissions and symlink*
#              appear nowhere in pi/app, except that a device test file may use create_dir,
#              fs::write and remove_dir_all for its temp-dir fixtures (an in-place overwrite
#              through .write(true).open( of an existing file, .create( with a non-literal flag and
#              fs::hard_link are not on that list: review of the device module holds them, not the
#              gate). That test file is
#              pi/app/src/device/**/tests.rs whose parent (X.rs or X/mod.rs for X/tests.rs) holds
#              "#[cfg(test)]" on the line right before "mod tests;"; any other tests.rs is an
#              ordinary device file, and the exception never covers path literals. Crates and
#              mounts: rppal:: and nix:: appear only under pi/app/src/device/, and so does extern
#              crate (which could bring either in under another name); MNT_FORCE nowhere in pi/app
#              and MNT_DETACH only in pi/app/src/device/usb.rs. Processes, threads, buffering: the
#              process and thread modules by any path (process::, thread::, std::process,
#              std::thread, inside a std::{..} group, a wrapped "    process," or "    thread as
#              t," line), so a grouped use std::process::{Command, Stdio} or thread::scope hits
#              too, appear nowhere in pi/app but as std::process::id() (a temp-dir name in the
#              device tests) and, in pi/app/src/device/linux.rs alone, use std::thread; with
#              thread::park() and thread::sleep( (the parked stop screen and the panel's init
#              delays); and BufReader appears nowhere in pi/app (a buffered reader would hold a copy
#              of hwrng samples or stick bytes). std::net is the Network category's, which already
#              bans it in pi/app as everywhere outside registry/.
#
# Fail-closed noise, not bypasses (rename or spell it out instead): a named format argument called
# path that rustfmt wraps onto its own line ("        path = \"seed.age\",") is an Include hit in
# any .rs file (name it file = ...), and a ": _ =" type placeholder ("let n: _ = f()?;") or an _name
# type alias ("type _Unused = u8;") is a FailOpen hit in core/, ffi/ and pi/app/ (write the type).
# A field or variable named include passed bare ("Filter { include, exclude }") is an Include hit.
# In a .py file, prose that says "the clipboard" (AppleScript's phrase) is a Clipboard hit (write
# "a clipboard"), and so is a string that starts with the word clipboard ("clipboard.txt"); an
# import of any module or name called connection, managers, handlers or config (the names
# multiprocessing.connection, multiprocessing.managers, logging.handlers and logging.config come in
# under), also as the last part of a dotted name ("from app import config", "import app.config"),
# is a Network hit; and a wrapped line that holds only names, one of them a banned module's name
# or clipboard, also as the last part of a dotted name ("    requests,", "    clipboard," or
# "    args.config," as a call's argument), is a hit like a wrapped import line (rename the
# variable). Comments count for the Shell category too: a test or comment that
# names game_random outside core and the games is a hit (call it the game call), and so is a
# comment under pi/app/src that names Session::new (write "core's constructor"). Under pi/app, a
# comment that names BufReader, process::Command, thread::spawn or a quoted "/path" is a Device hit
# (name the path constant instead); so is a Vec's .truncate( or .append( (write the loop or use
# extend), and so is use std::process; or use std::{io, thread}; even where std::process::id() or
# use std::thread; passes (write those).
#
# Portable on purpose: POSIX sh, POSIX ERE (no \b \s \< \>, no -P -w), POSIX sed (BRE, in
# selectable() and textselection(); ERE with -E, which BSD and GNU sed share, in threads_by_path())
# and LC_ALL=C, so BSD grep and sed (macOS) and GNU grep and sed (ubuntu CI) agree.
# Not scanned: .git/ target/ docs/ tasks/ CLAUDE.md scripts/testdata/, this script, and files with
# a binary extension (the list at $binext below).
#
# Symlinks: a file symlink is scanned under its link name. A directory symlink fails the gate
# (exit 2, naming the link): its target may be outside the repo or under an excluded path, where
# nothing would ever scan it.
#
# Every other file is read as text (grep -a), whatever bytes it holds. grep -I used to skip any file
# with a NUL byte near its start, so one NUL in a comment hid a whole source file, and BSD and GNU
# grep differ on how far they look for one. Skipping goes by file extension instead, matched in any
# case (grep -i: under LC_ALL=C both greps fold ASCII letters only).
#
# The patterns match API shapes (rand::, rand_core::, rand(), Math.random), not crate names:
# "rand_core" in a string or comment passes, because cargo-deny bans the crate itself.

set -u
unset CDPATH
LC_ALL=C # bytes, not characters: any byte is text, and the same [A-Za-z] ranges in both greps
export LC_ALL
nl='
'

here=$(cd "$(dirname "$0")" && pwd -P) || exit 2
self=$here/$(basename "$0")

usage() {
  cat <<'EOF'
usage: scripts/banned-api-check.sh [--selftest | DIR | --artifact TARGET FILE... | --workflows DIR |
                                   --image-lists IMG KCONFIG | --image IMG EXPECTED_DIR KCONFIG BIN_SHA256 |
                                   --selftest-image IMG KCONFIG | --os-config OS_DIR]
  (none)      scan the repo this script lives in
  DIR         scan DIR as if it were the repo root
  --artifact  scan release artifacts built for TARGET: test markers, the test registry key, RNG
              symbols other than TARGET's OS import, std's random-key path, a stripped file, and
              that import (see the script header)
  --workflows check every DIR/entropy-*.yml and .yaml workflow's hardening: read-only permissions, three
              actions at their approved SHAs, no secrets, no fork-trusting trigger, no expression
              in a run step
  --image-lists
              unpack the Pi image IMG (an MBR, a FAT32 boot partition, a SquashFS root) with the
              build's host tools and print its partition table, SHA-256s, boot and root file lists,
              mdir -a listing, keepcrypt-pi's imports and the kernel config KCONFIG; a listing,
              not a scan
  --image     scan the Pi image IMG: its boot and root lists and keepcrypt-pi's imports equal
              EXPECTED_DIR's (pi/os/expected), no denied program, module, start-up script,
              setuid file or seed file, start.elf and fixup.dat alone, the board's cmdline.txt and
              config.txt, Q35's inittab, KCONFIG equal to the expected kernel config and keeping
              the fragment's required and forbidden lists with one hwrng driver, no marker or test
              key in the image or any file, dynamic symbols and no RNG import in every other ELF,
              and keepcrypt-pi under the artifact rules with no simulator name and SHA-256
              BIN_SHA256
  --selftest-image
              the image scan's positive controls as mutations of the built image IMG (needs the
              build's host tools and the pinned toolchain on PATH)
  --os-config the text-only checks of OS_DIR (pi/os): Q35's inittab, the fstab's options,
              cmdline.txt, config.txt, expected/linux.config against the fragment's lists (which
              expected/kconfig-required and kconfig-forbidden must equal) and BusyBox's applets
  --selftest  run the fixtures in scripts/testdata/banned-api/, scripts/testdata/artifact/,
              scripts/testdata/workflows/ and scripts/testdata/os-config/, the image lists' built-in
              cases and the image scan's, on a stub image
Hits: RNG APIs (and the OS RNG read outside core/src/source), network APIs, Python network imports
and hard-coded http URLs (outside registry/), clipboard, copy and share APIs and Python clipboard
modules, tools and calls, getrandom in a .rs file outside core/src/source, std's OS-seeded hashing
in core/src, ffi/src or pi/app/src, a core/src/lib.rs (and pi/app's lib.rs and main.rs) without
#![forbid(unsafe_code)], in Rust under core/, ffi/ or pi/app/ a discarded result (_ =, an _name
binding, drop or forget of a call), clippy as a cfg predicate and /dev/stdout, /dev/stderr or
/dev/tty, include! (by any path or alias) or a path attribute in any .rs file, a C #include of a
file with a binary extension, the shells' paths to core: a session, pool input or clock named
in the games, game_random named outside core and the games, a second Session::new in pi/app, and
a release probe that does not call game_random; and in pi/app the firmware's device rules: a
path literal outside device/paths.rs or off its list, a file API outside device/, a file created
outside device/usb.rs or any truncating, appending, renaming or directory API, rppal or nix
outside device/, MNT_FORCE, MNT_DETACH outside device/usb.rs, a process, a thread or BufReader.
A directory symlink is refused. Exit 0 clean, 1 hits, 2 usage or read error.
EOF
}

# Word boundaries, since POSIX ERE has no \b: getrandom:: and brand( do not match rand.
L='(^|[^A-Za-z0-9_])'
R='([^A-Za-z0-9_]|$)'

# Binary formats: files whose name ends in one of these, in any case, are not scanned (and so a C
# #include of one is a hit, cinclude() below).
binext='png|jpg|jpeg|gif|webp|ico|icns|pdf|zip|gz|xz|bz2|zst|tar|jar|aar|apk|aab|ipa|so|dylib|a|rlib|o|class|dex|ttf|otf|woff|woff2|mp3|mp4|wav|car'
binary="[.]($binext)\$"

# A dotted module path's leading components ("jax." in jax.random, "a." and "b." in a.b.c), for
# the Python import shapes below and in pyimport().
dotted='([A-Za-z0-9_]+[.])*'
# A module path whose last component is random, with any components after it: random, jax.random,
# a.random.b (tasks/todo.md, M4 group 11: any import whose path has a random component).
pyrandmod="${dotted}random([.][A-Za-z0-9_]+)*"

# Each check runs grep -n on one file: prints "<line>:<text>", exits 0 hit, 1 none, 2 error.
# Rule 1 covers app code too: only core reads the OS RNG, so SecureRandom and SecRandomCopyBytes
# are banned like the PRNGs. A bare Random( is java.util.Random in Kotlin after import java.util.*;
# the word boundary keeps SecureRandom( and RandomAccessFile( out of it. Python imports: "import
# random", "import jax.random", "import numpy.random as r", "import os, random", "import os,
# jax.random" and "from numpy import(array, random)" (the comma pattern), "from numpy import
# (random, array)" (random first inside the parenthesis), "from random import x" and "from
# jax.random import x" (the from pattern, any dotted path with a random component). Anchored on
# the import, so randomize, randomart and a random word in a string pass.
rng() {
  grep -n -a -E \
    -e 'Math[.]random' \
    -e 'java[.]util[.]Random' \
    -e 'java[.]util[.]random' \
    -e "${L}Random[[:space:]]*[(]" \
    -e 'ThreadLocalRandom' \
    -e 'SecureRandom' \
    -e 'SplittableRandom' \
    -e 'SecRandomCopyBytes' \
    -e 'kotlin[.]random' \
    -e 'arc4random' \
    -e 'SystemRandomNumberGenerator' \
    -e 'GK[A-Za-z0-9_]*Random' \
    -e 'GK[A-Za-z0-9_]*Distribution' \
    -e '[.]random[[:space:]]*[(]' \
    -e '[.]randomElement[[:space:]]*[(]' \
    -e '[.]shuffled[[:space:]]*[(]' \
    -e '[.]shuffle[[:space:]]*[(]' \
    -e "${L}import[[:space:]]+$pyrandmod$R" \
    -e "${L}import[[:space:](][(A-Za-z0-9_.,[:space:]]*,[[:space:]]*$pyrandmod$R" \
    -e "${L}import[[:space:]]*[(][[:space:]]*random$R" \
    -e "${L}from[[:space:]]+$pyrandmod$R" \
    -e 'numpy[.]random' \
    -e 'np[.]random' \
    -e 'mt19937' \
    -e '_random_engine' \
    -e 'random_device' \
    -e 'minstd_rand' \
    -e "${L}rand[[:space:]]*[(]" \
    -e "${L}rand_r[[:space:]]*[(]" \
    -e 'srand[[:space:]]*[(]' \
    -e '(^|[^A-Za-z0-9_.])random[[:space:]]*[(]' \
    -e "${L}srandom[[:space:]]*[(]" \
    -e '[a-z]rand48' \
    -e "${L}rand[[:space:]]*::" \
    -e "${L}rand_core[[:space:]]*::" \
    -- "$1"
}

# Rule 1, one source of OS randomness: only core/src/source reads the OS RNG, so every other file is
# barred from the device files and the platform calls behind getrandom. /dev/hwrng is the raw
# hardware RNG that pi/app reads for the health tests, not the kernel CSPRNG; Python os.urandom and
# secrets are the endorsed tooling calls (docs/design.md), so neither is banned.
osrng() {
  grep -n -a -E \
    -e '/dev/u?random' \
    -e "${L}getentropy$R" \
    -e 'CCRandomGenerateBytes' \
    -e 'BCryptGenRandom' \
    -- "$1"
}

# .py files only: a line that holds nothing but names and random, as an import wraps it inside
# "from numpy import (" ... ")" or after a backslash: "    random,", "    random)", "    random as
# r,", "    array, random", "    random \" or a bare "    random", random being any module path
# with a random component ("    jax.random as r,"). The other names must be comma-separated
# words or dotted names, so a word list such as "ranch random range" passes; a word list one word
# per line belongs in a .txt file. After "from \" the next line starts with the module:
# "    random import choice", "    jax.random import key".
pyrandom() {
  grep -n -a -E \
    -e "^[[:space:]]*$pyrandmod[[:space:]]+import$R" \
    -e "^[[:space:]]*([A-Za-z0-9_.]+([[:space:]]+as[[:space:]]+[A-Za-z0-9_]+)?[[:space:]]*,[[:space:]]*)*$pyrandmod([[:space:]]+as[[:space:]]+[A-Za-z0-9_]+)?[[:space:]]*([,)#]|\\\\|\$)" \
    -- "$1"
}

# Not banned: Swift "import Network" (the offline check needs NWPathMonitor) and java.nio.channels
# (FileChannel is file I/O). The std::{ pattern catches grouped Rust imports such as std::{io, net};
# the net:: pattern catches the same import once rustfmt splits it one item per line. It skips a
# net:: after ':' or '.', which std::net already covers. contentsOf: with URL(string:) (or
# URL.init(string:), or .init(string:) where the type is implied) is a Foundation fetch; a URL from
# fileURLWithPath: or from the file picker is a local read of a picked .age or .kcr file. A remote
# URL written into app code is a hit wherever it goes (a variable passed to contentsOf: later, a
# link): Swift URL(string: "http (also NSURL, URLComponents, .init(string:) and a #"raw"# string),
# and Kotlin URL("http and Uri.parse("http (also a """raw""" string), http in any letter case.
network() {
  grep -n -a -E \
    -e 'URLSession' \
    -e 'URLRequest' \
    -e 'NSURLConnection' \
    -e 'NWConnection' \
    -e 'NWListener' \
    -e 'NWBrowser' \
    -e 'contentsOf:[[:space:]]*(URL[[:space:]]*)?([.][[:space:]]*init[[:space:]]*)?[(][[:space:]]*string[[:space:]]*:' \
    -e '(URL[A-Za-z]*|[.][[:space:]]*init)[[:space:]]*[(][[:space:]]*string[[:space:]]*:[[:space:]]*#*"[Hh][Tt][Tt][Pp]' \
    -e 'URL[[:space:]]*[(][[:space:]]*"+[Hh][Tt][Tt][Pp]' \
    -e 'Uri[[:space:]]*[.][[:space:]]*parse[[:space:]]*[(][[:space:]]*"+[Hh][Tt][Tt][Pp]' \
    -e 'CFNetwork' \
    -e 'WKWebView' \
    -e 'Alamofire' \
    -e 'java[.]net[.]' \
    -e 'HttpURLConnection' \
    -e 'okhttp' \
    -e 'io[.]ktor' \
    -e 'retrofit2' \
    -e 'std[[:space:]]*::[[:space:]]*net' \
    -e 'std[[:space:]]*::[[:space:]]*[{]([^;]*[^A-Za-z0-9_])?net([^A-Za-z0-9_]|$)' \
    -e '(^|[^A-Za-z0-9_:.])net[[:space:]]*::' \
    -e 'TcpStream' \
    -e 'TcpListener' \
    -e 'UdpSocket' \
    -- "$1"
}

# pyimport MODULES FILE, for .py files: an import of a module in MODULES (an ERE group), in the
# shapes rng() and pyrandom() give random: "import socket", "import os, ssl", "import http.client",
# "from urllib.request import urlopen", "from gevent import (socket, x)", "from gevent import(x,
# socket)", a wrapped import line that holds only names and one of them ("    urllib.request"
# after "import json, \", "    socket," inside "from gevent import (", or "    socket \"), and the
# line after "from \" ("    socket import create_connection"). Each shape but the parenthesised
# list, whose names cannot be dotted, also takes the module as the last part of a dotted name
# (tasks/todo.md, M3 Q31 (h)): "import gevent.socket", "from gevent.socket import x", "import os,
# gevent.socket", "    gevent.socket import x" after "from \" and "    eventlet.green.socket" on a
# wrapped line. Anchored on the import, so the names pass in a URL such as
# "https://registry.invalid", in other strings, as attributes and inside longer names.
pyimport() {
  grep -n -a -E \
    -e "${L}import[[:space:]]+$dotted$1$R" \
    -e "${L}import[[:space:](][(A-Za-z0-9_.,[:space:]]*,[[:space:]]*$dotted$1$R" \
    -e "${L}import[[:space:]]*[(][[:space:]]*$1$R" \
    -e "${L}from[[:space:]]+$dotted$1$R" \
    -e "^[[:space:]]*$dotted$1([.][A-Za-z0-9_]+)*[[:space:]]+import$R" \
    -e "^[[:space:]]*([A-Za-z0-9_.]+([[:space:]]+as[[:space:]]+[A-Za-z0-9_]+)?[[:space:]]*,[[:space:]]*)*$dotted$1([.][A-Za-z0-9_]+)*([[:space:]]+as[[:space:]]+[A-Za-z0-9_]+)?[[:space:]]*([,)#]|\\\\|\$)" \
    -- "$2"
}

# .py files only, outside registry/ like network() (tasks/todo.md M2 group 2, Q23; completed by the
# stage-A review, 2026-10-10): an import of a network module, in pyimport()'s shapes. _socket and
# _ssl are the C modules behind socket and ssl, with the same calls. multiprocessing and logging
# run offline, but multiprocessing.connection (Listener and Client over TCP),
# multiprocessing.managers (BaseManager serves over TCP), logging.handlers (SocketHandler,
# SysLogHandler, SMTPHandler, HTTPHandler) and logging.config (listen() opens a socket server) do
# not. Each is listed by its own name, which "from multiprocessing import connection" and "from
# logging import config" bring in, and the dotted shapes take the full name ("import
# logging.config"), so any import of a module or name called connection, managers, handlers or
# config is a hit (managers and config since M3's Q31 (h)).
# Grep cannot see __import__("socket") or importlib.import_module("socket"), an attribute path
# such as getpass.os.system, or a subprocess running a network tool. For verify.py, tasks/todo.md
# M2 group 3's check 12 (vectorgen.py --selftest) closes all four; vectorgen and scripts/ keep this
# gate only.
pynet='(socket|ssl|_socket|_ssl|socketserver|urllib|urllib3|http|ftplib|smtplib|smtpd|poplib|imaplib|nntplib|telnetlib|xmlrpc|asyncio|asyncore|asynchat|wsgiref|webbrowser|requests|httpx|aiohttp|connection|managers|handlers|config)'
pynetwork() {
  pyimport "$pynet" "$1"
}

# Clipboard APIs, and UI that hands the words to copy or share (docs/mobile-apps.md, "Never offered:
# share sheet, copy"). EnabledTextSelectability is the type a custom static such as .dragToCopy
# needs. ACTION_SEND also matches _MULTIPLE and SENDTO. JXA's theClipboard and setTheClipboardTo
# (tasks/todo.md, M3 Q31 (h)) run through "osascript -l JavaScript" from a .js file or a subprocess
# string, so they hit in any file; JavaScript keeps letter case, so theclipboard passes.
# .textSelection( and textIsSelectable have their own checks, textselection() and selectable()
# below.
clipboard() {
  grep -n -a -E \
    -e 'setPrimaryClip' \
    -e 'ClipboardManager' \
    -e 'ClipData' \
    -e 'LocalClipboard' \
    -e 'UIPasteboard' \
    -e 'NSPasteboard' \
    -e 'EnabledTextSelectability' \
    -e 'ShareLink' \
    -e 'UIActivityViewController' \
    -e 'SelectionContainer' \
    -e 'ACTION_SEND' \
    -e '[Tt]heClipboard' \
    -- "$1"
}

# .py files only (Q23; completed by the stage-A review, 2026-10-10, and by M3's Q31 (h)): pyperclip,
# win32clipboard, tkinter's clipboard_append, clipboard_get, selection_get and selection_own,
# pandas' to_clipboard, read_clipboard and clipboard_set (pandas.io.clipboard's copy call), and the
# clipboard tools pbcopy, pbpaste, xclip, xsel, wl-copy, wl-paste, PowerShell's Get-Clipboard and
# Set-Clipboard, clip.exe and AppleScript's "the clipboard" (run by osascript), anywhere on a line,
# since a subprocess names its tool in a string. Each must start a word, so idxsel and maxclip
# pass, while a longer name such as pyperclip3 or xclipboard hits.
# PowerShell, Windows file names and AppleScript ignore letter case, so the last three match in
# any case. clip hits only as clip.exe, since clip is a common word; a bare clip passes.
# selection_get and selection_own hit whatever their selection: CLIPBOARD may sit on the next line
# or in a variable, and the default, PRIMARY, is X11's other clipboard. Tcl's clipboard command
# hits as any string that starts with the word clipboard, whatever passes it and wherever a
# formatter wraps the call: root.tk.call('clipboard', 'append', x), tk.eval("clipboard append
# x"). The last pattern is any attribute or dotted module named clipboard:
# QApplication.clipboard() or QGuiApplication.clipboard(), app.clipboard() on a Qt application
# object, pandas.io.clipboard.
pyclipboard() {
  grep -n -a -E \
    -e "${L}pyperclip" \
    -e "${L}win32clipboard" \
    -e "${L}clipboard_(append|get|set)" \
    -e "${L}selection_(get|own)" \
    -e "${L}(to|read)_clipboard" \
    -e "${L}(pbcopy|pbpaste|xclip|xsel|wl-copy|wl-paste)" \
    -e "${L}[GgSs][Ee][Tt]-[Cc][Ll][Ii][Pp][Bb][Oo][Aa][Rr][Dd]" \
    -e "${L}[Cc][Ll][Ii][Pp][.][Ee][Xx][Ee]" \
    -e "${L}[Tt][Hh][Ee][[:space:]]+[Cc][Ll][Ii][Pp][Bb][Oo][Aa][Rr][Dd]" \
    -e "['\"]clipboard$R" \
    -e "[.][[:space:]]*clipboard$R" \
    -- "$1"
}

# PowerShell's aliases for Get-Clipboard and Set-Clipboard (tasks/todo.md, M3 Q31 (h)), as whole
# words in any letter case, as PowerShell reads them: anywhere in a PowerShell script (psclip, for
# .ps1 and .psm1 files) and, in any other file, on a line that names powershell or pwsh in any
# case (psline: a subprocess call or a shell line that starts PowerShell). Elsewhere gcb and scb
# are ordinary names.
psalias="${L}[GgSs][Cc][Bb]$R"
psclip() {
  grep -n -a -E -e "$psalias" -- "$1"
}

psline() {
  t=$(grep -n -a -E -e "$psalias" -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  t=$(printf '%s\n' "$t" | grep -i -E -e 'powershell|pwsh')
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  printf '%s\n' "$t"
}

# .py files only: an import of the clipboard module (PyPI's clipboard), in pyimport()'s shapes.
pyclipimport() {
  pyimport clipboard "$1"
}

# Selection fails closed: a line that names textIsSelectable (XML), setTextIsSelectable or
# isTextSelectable is a hit unless every one of them takes the literal false: ="false" (an XML
# attribute), ">false<" (a styles.xml item), (false) (a call), or "= false" followed by ; , ) } or
# the end of the line. A variable, @bool/x, true, "(false || debug)" and a second name on the line
# all hit. sed keeps the line (h), deletes each allowed form, drops the line if no name is left,
# and prints the line as it was (x), so the "<line>:<text>" output and the 0/1/2 exit codes match
# the grep checks.
selectable() {
  t=$(grep -n -a -E -e '[tT]extIsSelectable|isTextSelectable' -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  t=$(printf '%s\n' "$t" | sed \
    -e h \
    -e 's/isTextSelectable/textIsSelectable/g' \
    -e 's/[tT]extIsSelectable[[:space:]]*=[[:space:]]*"false"//g' \
    -e 's/[tT]extIsSelectable"[[:space:]]*>[[:space:]]*false[[:space:]]*<//g' \
    -e 's/[tT]extIsSelectable[[:space:]]*([[:space:]]*false[[:space:]]*)//g' \
    -e 's/[tT]extIsSelectable[[:space:]]*=[[:space:]]*false[[:space:]]*[;,)}]//g' \
    -e 's/[tT]extIsSelectable[[:space:]]*=[[:space:]]*false[[:space:]]*$//' \
    -e '/[tT]extIsSelectable/!d' \
    -e x
  ) || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

# .textSelection( passes only as exactly .textSelection(.disabled), as the docs require (spaces
# inside the parentheses are fine). .enabled, a variable, a custom static such as .dragToCopy
# (.d is not enough), ".disabled ?? x" and an argument on the next line all hit, and so does a line
# with a second .textSelection( that is not .disabled. Same sed h/x shape as selectable().
textselection() {
  t=$(grep -n -a -E -e 'textSelection[[:space:]]*[(]' -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  t=$(printf '%s\n' "$t" | sed \
    -e h \
    -e 's/textSelection[[:space:]]*([[:space:]]*[.]disabled[[:space:]]*)//g' \
    -e '/textSelection[[:space:]]*(/!d' \
    -e x
  ) || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

getrandom_use() {
  grep -n -a -E -e 'getrandom' -- "$1"
}

# Rule 1, for .rs files under core/src, ffi/src and pi/app/src (tasks/todo.md, M3 group 13): std's
# HashMap and HashSet default to RandomState, whose keys std reads from the OS, a second OS read
# outside core/src/source; DefaultHasher, hash_one and BuildHasherDefault reach the same hashing
# without the collections. As words, so a name such as hash_one_record passes.
hashing() {
  grep -n -a -E \
    -e "${L}(HashMap|HashSet|RandomState|DefaultHasher|hash_one|BuildHasherDefault)$R" \
    -- "$1"
}

# Shell (tasks/todo.md, M3 group 13), for the games' code: a game holds no session (Session,
# Wiped, and the app's Stage, Held and App, which hold it), feeds no pool (add_extra,
# add_hw_samples), reaches into no ceremony and keeps no clock (SystemTime, Instant, and the HAL's
# Clock and now_ns). As words: Sessions or instantly pass.
games_names() {
  grep -n -a -E \
    -e "${L}(Session|Wiped|Stage|Held|App|add_extra|add_hw_samples|ceremony|SystemTime|Instant|Clock|now_ns)$R" \
    -- "$1"
}

# Shell, outside core and the games: game_random anywhere in a name, like getrandom under Rule1.
game_random_use() {
  grep -n -a -E -e 'game_random' -- "$1"
}

# Shell, under pi/app/src: Session::new, the one constructor that ignores a kept Wiped, also with
# its state named, as a turbofish (Session::<Collecting>::new) or a qualified path
# (<Session<Collecting>>::new). The state's brackets hold no ; = ( or ), so a session's type before
# another call on the line ("let s: Session<Collecting> = Box::<u8>::new(x)") passes; Session as
# another constructor's last type argument (Box::<Session<Collecting>>::new) is a hit too.
session_new() {
  grep -n -a -E -e "${L}Session[[:space:]]*((::)?[[:space:]]*<[^;=()]*>[[:space:]]*)?::[[:space:]]*new$R" -- "$1"
}

# Shell, in pi/app/src/app.rs: every Session::new after the first, which new_session holds.
session_new_again() {
  t=$(session_new "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  t=$(printf '%s\n' "$t" | sed 1d) || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

# probe_calls_game_random: core/examples/release_probe.rs calls game_random outside every comment.
# The awk pass drops each // comment to the end of its line and each /* */ comment, nested and over
# lines as Rust's are, so a doc line, a commented-out call and a call after // or inside a block
# comment do not count. A // or /* inside a string literal is read as a comment too, which can only
# drop a call (fail closed). A file that cannot be read counts as no call, so it fails closed.
probe_calls_game_random() {
  [ -f core/examples/release_probe.rs ] || return 1
  t=$(awk '
    {
      code = ""
      rest = $0
      while (rest != "") {
        opens = index(rest, "/*")
        if (depth > 0) {
          closes = index(rest, "*/")
          if (opens > 0 && (closes == 0 || opens < closes)) {
            depth++
            rest = substr(rest, opens + 2)
          } else if (closes > 0) {
            depth--
            rest = substr(rest, closes + 2)
          } else {
            rest = ""
          }
        } else {
          slashes = index(rest, "//")
          if (slashes > 0 && (opens == 0 || slashes < opens)) {
            code = code substr(rest, 1, slashes - 1)
            rest = ""
          } else if (opens > 0) {
            code = code substr(rest, 1, opens - 1) " "
            depth = 1
            rest = substr(rest, opens + 2)
          } else {
            code = code rest
            rest = ""
          }
        }
      }
      print code
    }' core/examples/release_probe.rs) || return 1
  printf '%s\n' "$t" | grep -q -a -E -e "${L}game_random[[:space:]]*[(]"
}

# Rule 3, for Rust under core/, ffi/ and pi/app/: the first pattern is an assignment to _ or to an
# _name ("_ = f()", "_x = f()" after "let _x;", and so "let _x = f()" and "let mut _x = f()"), but
# not "_ =>" (a match arm), "==", "x_ =" or "self._x =". The second is a typed underscore binding,
# "let _x: T", whatever follows, so a type that rustfmt wraps over several lines still hits. Tuple
# patterns ("let (_, b) =") are not checked. The third is clippy as a cfg predicate: a clippy word
# right after '(' or ',' or at the start of a line (rustfmt's wrapped "    clippy,"), followed by
# ')' or ',' or the end of the line, so clippy::lint paths pass. The fourth is drop or forget of a
# call: "drop(" whose argument holds a '(' before any ')', "drop(" at the end of a line, or any
# turbofish "drop::<". The fifth is the terminal and the standard streams as files (rule 5).
failopen() {
  grep -n -a -E \
    -e '(^|[^A-Za-z0-9_.])_[A-Za-z0-9_]*[[:space:]]*=([^=>]|$)' \
    -e "${L}let[[:space:]]+(mut[[:space:]]+)?_[A-Za-z0-9_]*[[:space:]]*:" \
    -e '(^|[(,])[[:space:]]*(r#)?clippy[[:space:]]*([),]|$)' \
    -e "${L}(drop|forget)[[:space:]]*(::[[:space:]]*<|[(]([^()]*[(]|[[:space:]]*$))" \
    -e '/dev/(stdout|stderr|tty)' \
    -- "$1"
}

# include! (any delimiter: rustfmt writes "include! {") and the path attribute compile another file
# as Rust. The second pattern is #[path = ...], #![path = ...] and #[cfg_attr(..., path = ...)]; the
# third is the line rustfmt gives path when it wraps a long cfg_attr. rustc only takes a string
# literal there, and a line that ends in ';' is an assignment such as path = "x";, not an attribute.
# The last three reach the same macro under another name: std::include or core::include as a word
# (std::include_str passes), "include as pull" in a use line or a wrapped use group, and include
# passed bare to a macro, after '(' '{' '[' or ',' or alone at the start of a wrapped line, and
# before ')' '}' ']' ',' or the end of the line ("include (for each case)" in a comment passes).
include_code() {
  grep -n -a -E \
    -e "${L}include[[:space:]]*![[:space:]]*[[({]" \
    -e '#[[:space:]]*!?[[:space:]]*\[([^]]*[(,])?[[:space:]]*path[[:space:]]*=' \
    -e '^[[:space:]]*path[[:space:]]*=[[:space:]]*(r#*)?".*[^;[:space:]][[:space:]]*$' \
    -e "${L}(std|core)[[:space:]]*::[[:space:]]*include$R" \
    -e "${L}include[[:space:]]+as[[:space:]]+(r#)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*([,;}]|$)" \
    -e '(^|[({[,])[[:space:]]*(r#)?include[[:space:]]*([]),}]|$)' \
    -- "$1"
}

# Any file: a C/C++ (or Objective-C) #include of a name with a binary extension compiles a file that
# the scan skips by extension, such as #include "lut.png" holding rand(). %: is the C digraph for #.
# Case-insensitive like the skip list (LUT.PNG is skipped too).
cinclude() {
  grep -n -a -i -E \
    -e "(#|%:)[[:space:]]*(include|include_next|import)[[:space:]]*[\"<][^\">]*[.]($binext)[\">]" \
    -- "$1"
}

# --- Device (tasks/todo.md, M4 group 11; rule 8 as Q40 and Q51 amended it, rule 5) ---------------

# Rule 8, for .rs files under pi/app/src but device/paths.rs: a string literal that starts with /
# ("/dev/x", b"/dev/x", r"/dev/x", r#"/dev/x"#) names a device or kernel path, and every such path
# is a constant in pi/app/src/device/paths.rs. A "/" inside a longer string ("a/b") and a '/' char
# pass.
device_paths() {
  grep -n -a -E -e '"/' -- "$1"
}

# The constants of pi/app/src/device/paths.rs: the five paths docs/pi-firmware.md's Process rules
# give the firmware's own code. sed deletes each allowed literal, with its quotes, and a line with
# any other "/ left is a hit (same h/x shape as selectable()).
device_paths_list() {
  t=$(grep -n -a -E -e '"/' -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  t=$(printf '%s\n' "$t" | sed \
    -e h \
    -e 's|"/dev/hwrng"||g' \
    -e 's|"/dev/mmcblk0p2"||g' \
    -e 's|"/dev"||g' \
    -e 's|"/sys/block"||g' \
    -e 's|"/mnt/usb"||g' \
    -e '/"\//!d' \
    -e x
  ) || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

# Rule 8, for pi/app files outside pi/app/src/device/: the file APIs only the device module may
# call. The fs module by any path (fs::, std::fs, a grouped std::{io, fs} and the "    fs," or
# "    fs as f," line rustfmt wraps it to, with or without the trailing comma), File::,
# OpenOptions, read_dir, read_link and remove_file, as words.
device_file_api() {
  grep -n -a -E \
    -e "${L}fs[[:space:]]*::" \
    -e "${L}std[[:space:]]*::[[:space:]]*fs$R" \
    -e "${L}std[[:space:]]*::[[:space:]]*[{]([^;]*[^A-Za-z0-9_])?fs$R" \
    -e '^[[:space:]]*fs([[:space:]]+as[[:space:]]+[A-Za-z_][A-Za-z0-9_]*)?[[:space:]]*,?[[:space:]]*$' \
    -e "${L}File[[:space:]]*::" \
    -e "${L}(OpenOptions|read_dir|read_link|remove_file)$R" \
    -- "$1"
}

# Rule 8, for pi/app files but pi/app/src/device/usb.rs: create_new is the one open that creates a
# file, and the backup's open in usb.rs is the only one.
device_create_new() {
  grep -n -a -E -e "${L}create_new$R" -- "$1"
}

# Rule 8, for every pi/app file: the listed APIs that write over, grow, move or remove what is
# already on the stick, or make directories or links (tasks/todo.md, M4 group 11); the firmware
# only ever creates one new file. .create(true) opens for writing whether or not the file exists;
# .truncate( and .append( are OpenOptions' and also Vec's, which hit too (write the loop).
# create_dir and remove_dir take their _all forms with them; symlink takes symlink_metadata (fail
# closed). Not on the list, so held by review of pi/app/src/device/ and not by this gate: an
# in-place overwrite through OpenOptions .write(true).open( of an existing file, .create( with a
# flag that is not the literal true, and fs::hard_link; usb.rs's one .write(true) is the
# create_new open above, and nothing else under device/ opens for writing.
device_write_api() {
  grep -n -a -E \
    -e '[.][[:space:]]*create[[:space:]]*[(][[:space:]]*true' \
    -e '[.][[:space:]]*(truncate|append)[[:space:]]*[(]' \
    -e "${L}fs[[:space:]]*::[[:space:]]*(write|copy)$R" \
    -e "${L}(rename|set_permissions)$R" \
    -e "${L}(create_dir|remove_dir|symlink)" \
    -- "$1"
}

# The same, for a device test file (tests_rs_declared below), which may use create_dir, fs::write
# and remove_dir_all for its temp-dir fixtures: create_dir_all, remove_dir and the rest still hit.
device_write_api_in_tests() {
  grep -n -a -E \
    -e '[.][[:space:]]*create[[:space:]]*[(][[:space:]]*true' \
    -e '[.][[:space:]]*(truncate|append)[[:space:]]*[(]' \
    -e "${L}fs[[:space:]]*::[[:space:]]*copy$R" \
    -e "${L}(rename|set_permissions)$R" \
    -e "${L}(create_dir_|remove_dir($|[^_])|symlink)" \
    -- "$1"
}

# tests_rs_declared FILE, FILE being pi/app/src/device/**/tests.rs: true if its parent module file
# (X.rs or X/mod.rs for X/tests.rs) declares it with "#[cfg(test)]" on the line right before
# "mod tests;", so the file is compiled for cargo test alone. A missing or unreadable parent, or
# a blank line or another attribute between the two, means no exception (fail closed).
tests_rs_declared() {
  x=${1%/tests.rs}
  for parent in "$x.rs" "$x/mod.rs"; do
    [ -f "$parent" ] || continue
    if awk '
      prev ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ && $0 ~ /^[[:space:]]*mod tests;[[:space:]]*$/ { found = 1 }
      { prev = $0 }
      END { exit !found }' "$parent" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

# Rule 8 and Q36 (e), for pi/app files outside pi/app/src/device/: the hardware crates are the
# device module's, and so is extern crate, which could bring one in under another name (extern
# crate rppal as hw; hw::gpio::Gpio::new()); the 2018 edition needs it for nothing else.
device_crates() {
  grep -n -a -E -e "${L}(rppal|nix)[[:space:]]*::" -e "${L}extern[[:space:]]+crate$R" -- "$1"
}

# The mount flags (tasks/todo.md, M4 group 8): MNT_FORCE nowhere in pi/app (it abandons writes),
# MNT_DETACH only in pi/app/src/device/usb.rs, which chooses it for a removed stick.
mnt_force() {
  grep -n -a -E -e 'MNT_FORCE' -- "$1"
}

mnt_detach() {
  grep -n -a -E -e 'MNT_DETACH' -- "$1"
}

# Rule 5, for every pi/app file: no child process, no thread (the Pi Zero has one core, and the
# firmware has one loop; Q39 (b)), and no BufReader, which would hold a copy of hwrng samples or
# stick bytes outside the buffer the app wipes. The process and thread modules are matched by any
# path, as device_file_api matches fs (a grouped use std::process::{Command, Stdio} or
# use std::thread::{scope} names no item right after the ::): process:: and thread::, std::process
# and std::thread as words, either inside a std::{...} group, and a wrapped "    process," or
# "    thread as t," line. sed first deletes the calls the firmware makes (same h/x shape as
# device_paths_list, so a line that holds one of them and anything else still hits):
# std::process::id( anywhere (a temp-dir name in the device tests) and, in pi/app/src/device/
# linux.rs alone, "use std::thread;" with thread::park( and thread::sleep( (the parked stop screen
# and the panel's init delays).
device_threads() {
  threads_by_path "$1" \
    -e 's/std[[:space:]]*::[[:space:]]*process[[:space:]]*::[[:space:]]*id[[:space:]]*\(//g'
}

device_threads_in_linux_rs() {
  threads_by_path "$1" \
    -e 's/std[[:space:]]*::[[:space:]]*process[[:space:]]*::[[:space:]]*id[[:space:]]*\(//g' \
    -e 's/std[[:space:]]*::[[:space:]]*thread[[:space:]]*;//g' \
    -e 's/thread[[:space:]]*::[[:space:]]*(park|sleep)[[:space:]]*\(//g'
}

# threads_by_path FILE SED-EXPRESSION...: device_threads over FILE with the given deletions.
threads_by_path() {
  f=$1
  shift
  t=$(grep -n -a -E -e "${L}(process|thread)$R" -e 'BufReader' -- "$f")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  t=$(printf '%s\n' "$t" | sed -E \
    -e h \
    "$@" \
    -e '/(^|[^A-Za-z0-9_])(process|thread)[[:space:]]*::|(^|[^A-Za-z0-9_])std[[:space:]]*::[[:space:]]*(process|thread)([^A-Za-z0-9_]|$)|(^|[^A-Za-z0-9_])std[[:space:]]*::[[:space:]]*\{([^;]*[^A-Za-z0-9_])?(process|thread)([^A-Za-z0-9_]|$)|^[0-9]+:[[:space:]]*(process|thread)([[:space:]]+as[[:space:]]+[A-Za-z_][A-Za-z0-9_]*)?[[:space:]]*,?[[:space:]]*$|BufReader/!d' \
    -e x
  ) || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

# report CATEGORY CHECK FILE: print and count each hit of CHECK in FILE.
report() {
  out=$("$2" "$3")
  case $? in
    0) ;;
    1) return ;;
    *) printf 'banned-api-check: cannot read %s\n' "$3" >&2; exit 2 ;;
  esac
  while IFS= read -r line; do
    printf '%s: %s:%s: %s\n' "$1" "$3" "${line%%:*}" "${line#*:}"
    hits=$((hits + 1))
  done <<EOF
$out
EOF
}

# list [FIND-TESTS]: paths to scan, one per line. Symlinks count, so a linked file is checked under
# its link name, and scan() refuses a link to a directory.
list() {
  find . \( -path ./.git -o -path ./target -o -path ./docs -o -path ./tasks -o -path ./scripts/testdata \) -prune \
    -o \( -type f -o -type l \) ! -path ./CLAUDE.md ! -path ./scripts/banned-api-check.sh ${1+"$@"} -print
}

scan() {
  cd "$1" || exit 2
  # A newline in a name would split it in the list and leave it unscanned: refuse instead.
  odd=$(list -name "*$nl*") || exit 2
  if [ -n "$odd" ]; then
    echo 'banned-api-check: a file name contains a newline; rename it' >&2
    exit 2
  fi
  all=$(list) || exit 2
  all=$(printf '%s\n' "$all" | sort)
  # find lists only files and symlinks, so a directory here is a symlink to one. Its target may be
  # outside the repo or under an excluded path and would never be scanned: refuse it.
  while IFS= read -r f; do
    [ -n "$f" ] && [ -d "$f" ] || continue
    printf 'banned-api-check: %s is a symlink to a directory, which is never scanned; replace it with the files (file symlinks are scanned)\n' "${f#./}" >&2
    exit 2
  done <<EOF
$all
EOF
  # grep exits 1 when it selects no line: that is a valid outcome here, only 2 is an error.
  files=$(printf '%s\n' "$all" | grep -v -i -E -e "$binary")
  [ $? -le 1 ] || exit 2
  skipped=$(printf '%s\n' "$all" | grep -c -i -E -e "$binary")
  [ $? -le 1 ] || exit 2
  hits=0
  n=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    rel=${f#./}
    n=$((n + 1))
    report RNG rng "$rel"
    # Rule 1: only core/src/source reads the OS RNG.
    case $rel in
      core/src/source.rs | core/src/source/*) ;;
      *) report RNG osrng "$rel" ;;
    esac
    case $rel in *.py) report RNG pyrandom "$rel" ;; esac
    case $rel in registry/*) ;; *) report Network network "$rel" ;; esac
    case $rel in registry/*) ;; *.py) report Network pynetwork "$rel" ;; esac
    report Clipboard clipboard "$rel"
    case $rel in *.py) report Clipboard pyclipboard "$rel" ;; esac
    case $rel in *.py) report Clipboard pyclipimport "$rel" ;; esac
    report Clipboard textselection "$rel"
    report Clipboard selectable "$rel"
    case $rel in
      *.[Pp][Ss]1 | *.[Pp][Ss][Mm]1) report Clipboard psclip "$rel" ;;
      *) report Clipboard psline "$rel" ;;
    esac
    # Rule 1: only core/src/source may name getrandom ('*' in case also matches '/').
    case $rel in
      core/src/source.rs | core/src/source/*) ;;
      *.rs) report Rule1 getrandom_use "$rel" ;;
    esac
    case $rel in core/src/*.rs | ffi/src/*.rs | pi/app/src/*.rs) report Rule1 hashing "$rel" ;; esac
    # Shell: the games' code, in either module layout; game_random outside core's allowed files and
    # the games; Session::new under pi/app/src, where only its first in app.rs passes.
    case $rel in pi/app/src/games.rs | pi/app/src/games/*) report Shell games_names "$rel" ;; esac
    case $rel in
      core/src/source.rs | core/src/lib.rs | core/tests/* | core/examples/release_probe.rs | pi/app/src/games/*) ;;
      *) report Shell game_random_use "$rel" ;;
    esac
    case $rel in
      pi/app/src/app.rs) report Shell session_new_again "$rel" ;;
      pi/app/src/*) report Shell session_new "$rel" ;;
    esac
    case $rel in core/*.rs | ffi/*.rs | pi/app/*.rs) report FailOpen failopen "$rel" ;; esac
    case $rel in *.rs) report Include include_code "$rel" ;; esac
    report Include cinclude "$rel"
    # Device: the firmware's paths, file APIs, hardware crates, mount flags, processes and
    # threads, in pi/app only ('*' matches '/', so pi/app/src/device/* is the whole module).
    case $rel in
      pi/app/*)
        case $rel in
          pi/app/src/device/paths.rs) report Device device_paths_list "$rel" ;;
          pi/app/src/*.rs) report Device device_paths "$rel" ;;
        esac
        case $rel in
          pi/app/src/device/*) ;;
          *) report Device device_file_api "$rel"; report Device device_crates "$rel" ;;
        esac
        case $rel in
          pi/app/src/device/usb.rs) ;;
          *) report Device device_create_new "$rel"; report Device mnt_detach "$rel" ;;
        esac
        case $rel in
          pi/app/src/device/tests.rs | pi/app/src/device/*/tests.rs)
            if tests_rs_declared "$rel"; then
              report Device device_write_api_in_tests "$rel"
            else
              report Device device_write_api "$rel"
            fi
            ;;
          *) report Device device_write_api "$rel" ;;
        esac
        report Device mnt_force "$rel"
        case $rel in
          pi/app/src/device/linux.rs) report Device device_threads_in_linux_rs "$rel" ;;
          *) report Device device_threads "$rel" ;;
        esac
        ;;
    esac
  done <<EOF
$files
EOF
  # The unsafe-code ban in core's lib.rs, and in pi/app's lib.rs and main.rs once pi/app exists.
  forbid=core/src/lib.rs
  [ -e pi/app ] && forbid="$forbid pi/app/src/lib.rs pi/app/src/main.rs"
  for f in $forbid; do
    if ! { [ -f "$f" ] && grep -q -a -x -F -e '#![forbid(unsafe_code)]' "$f"; }; then
      echo "Rule1: $f:1: missing the line #![forbid(unsafe_code)]"
      hits=$((hits + 1))
    fi
  done
  if [ -e core ] && ! probe_calls_game_random; then
    echo 'Shell: core/examples/release_probe.rs:1: missing a call to game_random outside a comment'
    hits=$((hits + 1))
  fi
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check: $hits hit(s) in $n files scanned ($skipped binary by extension, not scanned)"
    exit 1
  fi
  echo "banned-api-check: clean, $n files scanned ($skipped binary by extension, not scanned)"
  exit 0
}

# fresh: new repo-like dir $d holding only what the tree-wide checks need: core/src/lib.rs,
# pi/app/src/lib.rs and pi/app/src/main.rs with the unsafe-code ban, and a release probe that
# calls game_random. A fixture's file at one of these paths replaces it.
fresh() {
  i=$((i + 1))
  d=$tmp/$i
  mkdir -p "$d/core/src" "$d/core/examples" "$d/pi/app/src" || exit 2
  for f in core/src/lib.rs pi/app/src/lib.rs pi/app/src/main.rs; do
    echo '#![forbid(unsafe_code)]' >"$d/$f" || exit 2
  done
  echo 'fn main() -> Result<(), u8> { game_random(&mut [0; 32]).map_err(|_| 20) }' \
    >"$d/core/examples/release_probe.rs" || exit 2
}

# expect NAME DIR WANT [FILE]: scan DIR in a new process. WANT=clean needs exit 0 and no hit,
# WANT=error needs exit 2 and output containing FILE (if given, the expected message), any other
# WANT needs exit 1 and exactly one hit "<WANT>: <FILE>:<line>: <text>", where <text> is line
# <line> of FILE as it stands (the messages for a missing line or call, "missing ...", are the
# exception).
expect() {
  out=$(sh "$self" "$2" 2>&1)
  rc=$?
  cats='^(RNG|Network|Clipboard|Rule1|FailOpen|Include|Shell|Device): '
  hit=$(printf '%s\n' "$out" | grep -E "$cats")
  count=$(printf '%s\n' "$out" | grep -c -E "$cats")
  ok=no
  if [ "$3" = clean ]; then
    [ "$rc" -eq 0 ] && [ "$count" -eq 0 ] && ok=yes
  elif [ "$3" = error ]; then
    if [ "$rc" -eq 2 ]; then
      case $out in *"${4:-}"*) ok=yes; hit="exit 2: ${out##*$nl}" ;; esac
    fi
  elif [ "$rc" -eq 1 ] && [ "$count" -eq 1 ]; then
    case $hit in
      "$3: $4:"[0-9]*)
        at=${hit#"$3: $4:"}
        case ${at#*: } in
          'missing '*) ok=yes ;;
          *) [ "${at#*: }" = "$(sed -n "${at%%:*}p" "$2/$4")" ] && ok=yes ;;
        esac
        ;;
    esac
  fi
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> %s\n' "$1" "${hit:-clean}"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted %s %s, got exit %s:\n' "$1" "$3" "${4:-}" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

selftest() {
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/banned-api.XXXXXX") || exit 2
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 2' HUP INT TERM
  i=0
  pass=0
  fail=0
  seen=
  for fx in "$here/testdata/banned-api"/*/; do
    [ -d "$fx" ] || continue
    fx=${fx%/}
    name=${fx##*/}
    case $name in
      rng-*) want=RNG ;;
      network-*) want=Network ;;
      clipboard-*) want=Clipboard ;;
      rule1-*) want=Rule1 ;;
      failopen-*) want=FailOpen ;;
      include-*) want=Include ;;
      shell-*) want=Shell ;;
      device-*) want=Device ;;
      clean-*) want=clean ;;
      *) fail=$((fail + 1)); printf 'FAIL %s: unknown prefix\n' "$name"; continue ;;
    esac
    seen="$seen $want"
    file=
    if [ "$want" != clean ]; then
      # The file the hit must name; .DS_Store is Finder noise (and git-ignored).
      file=$(cd "$fx" && find . -type f ! -name .DS_Store) || exit 2
      case $file in
        '' | *"$nl"*) fail=$((fail + 1)); printf 'FAIL %s: a fixture holds exactly one file\n' "$name"; continue ;;
      esac
      file=${file#./}
    fi
    fresh
    cp -R "$fx/." "$d/" || exit 2
    expect "$name" "$d" "$want" "$file"
    if [ "$want" = Network ]; then
      fresh
      mkdir -p "$d/registry" && cp -R "$fx/." "$d/registry/" || exit 2
      expect "$name under registry/" "$d" clean
    fi
    # FailOpen covers core/, ffi/ and pi/app/ only, and Device covers pi/app/ only: the same file
    # in pi/sim/src/ passes.
    if [ "$want" = FailOpen ] || [ "$want" = Device ]; then
      fresh
      mkdir -p "$d/pi/sim/src" && cp "$fx/$file" "$d/pi/sim/src/" || exit 2
      expect "$name in pi/sim/" "$d" clean
    fi
  done
  # The device test-file exception needs the test file and its parent, so these cases are built
  # here (a fixture holds one file): fs::write in device/usb/tests.rs passes only when usb.rs (or
  # usb/mod.rs) declares it with #[cfg(test)] on the line right before "mod tests;"; a parent
  # without the attribute, with a blank line between the two, or with the attribute on the same
  # line gives no exception, and neither does a missing parent (the device-fs-write-in-tests-rs-
  # without-parent fixture). The exception never covers path literals or the other write APIs.
  tests_rs='pi/app/src/device/usb/tests.rs'
  declared='#[cfg(test)]
mod tests;'
  for parent in pi/app/src/device/usb.rs pi/app/src/device/usb/mod.rs; do
    fresh
    mkdir -p "$d/pi/app/src/device/usb" || exit 2
    printf '%s\n' "$declared" >"$d/$parent" || exit 2
    echo 'fs::write(dir.join("b.age"), b"b").expect("a file");' >"$d/$tests_rs" || exit 2
    expect "clean-device-tests-rs-declared-in-${parent##*/}" "$d" clean
  done
  for case in 'without-cfg-test:mod tests;' 'cfg-test-blank-line-before-mod:#[cfg(test)]

mod tests;' 'cfg-test-on-same-line:#[cfg(test)] mod tests;'; do
    fresh
    mkdir -p "$d/pi/app/src/device/usb" || exit 2
    printf '%s\n' "${case#*:}" >"$d/pi/app/src/device/usb.rs" || exit 2
    echo 'fs::write(dir.join("b.age"), b"b").expect("a file");' >"$d/$tests_rs" || exit 2
    expect "device-tests-rs-${case%%:*}" "$d" Device "$tests_rs"
  done
  for case in 'path-literal:let dir = Path::new("/tmp/kc");' 'remove-dir:fs::remove_dir(dir.join("folder.age")).expect("removed");' \
    'create-dir-all:fs::create_dir_all(dir.join("a/b")).expect("folders");' 'rename:fs::rename(dir.join("a.age"), dir.join("b.age")).expect("moved");'; do
    fresh
    mkdir -p "$d/pi/app/src/device/usb" || exit 2
    printf '%s\n' "$declared" >"$d/pi/app/src/device/usb.rs" || exit 2
    printf '%s\n' "${case#*:}" >"$d/$tests_rs" || exit 2
    expect "device-declared-tests-rs-${case%%:*}" "$d" Device "$tests_rs"
  done
  # The regression review's probe: core/src/source.rs may name getrandom, so FailOpen is the only
  # hit for the two discards clippy lets through. Kept here, not in git: a fixture's pi/sim/ copy
  # would be a Rule1 hit.
  fresh
  echo 'pub fn discard_assign(buf: &mut [u8]) { _ = getrandom::fill(buf); }' >"$d/core/src/source.rs" || exit 2
  expect 'failopen-probe-discard-assign' "$d" FailOpen core/src/source.rs
  fresh
  echo '    let _unused = getrandom::fill(buf);' >"$d/core/src/source.rs" || exit 2
  expect 'failopen-probe-named-binding' "$d" FailOpen core/src/source.rs
  # Cases kept out of git: it cannot hold .git/ or (ignored) target/, and Claude Code would read a
  # nested CLAUDE.md as instructions.
  fresh
  mkdir -p "$d/.git" "$d/target" || exit 2
  for x in .git/x.kt target/x.kt CLAUDE.md; do
    echo 'Math.random()' >"$d/$x" || exit 2
  done
  expect 'clean-git-target-claude-md' "$d" clean
  fresh
  ln -s nowhere "$d/dangling.kt" || exit 2
  expect 'error-unreadable-file' "$d" error
  # Symlinks stay out of git fixtures (a fixture holds one regular file), so they are made here.
  # A linked file is scanned under its link name, even when its target sits in excluded docs/.
  fresh
  mkdir -p "$d/docs/snippets" "$d/mobile/ios/KeepCrypt" || exit 2
  echo 'let face = Int.random(in: 1...6)' >"$d/docs/snippets/Dice.swift" || exit 2
  ln -s ../../../docs/snippets/Dice.swift "$d/mobile/ios/KeepCrypt/Dice.swift" || exit 2
  expect 'rng-file-symlink-into-docs' "$d" RNG mobile/ios/KeepCrypt/Dice.swift
  # A linked directory is refused: nothing would scan its target.
  fresh
  mkdir -p "$d/docs/snippets" "$d/mobile/ios/KeepCrypt" || exit 2
  echo 'let face = Int.random(in: 1...6)' >"$d/docs/snippets/Dice.swift" || exit 2
  ln -s ../../../docs/snippets "$d/mobile/ios/KeepCrypt/Shared" || exit 2
  expect 'error-directory-symlink' "$d" error 'mobile/ios/KeepCrypt/Shared is a symlink to a directory'
  # Also when the link's name has a binary extension, which keeps it out of the scan list.
  fresh
  mkdir -p "$d/docs/snippets" || exit 2
  echo 'let face = Int.random(in: 1...6)' >"$d/docs/snippets/Dice.swift" || exit 2
  ln -s docs/snippets "$d/assets.png" || exit 2
  expect 'error-directory-symlink-binary-name' "$d" error 'assets.png is a symlink to a directory'
  fresh
  # Read one path per line, "x.kt<newline>" would pass as x.kt and hide its content.
  : >"$d/x.kt" && echo 'Math.random()' >"$d/x.kt$nl" || exit 2
  expect 'error-newline-in-file-name' "$d" error
  i=$((i + 1))
  d=$tmp/$i
  mkdir "$d" || exit 2
  expect 'rule1-lib-rs-absent' "$d" Rule1 core/src/lib.rs
  # pi/app's lib.rs and main.rs are checked whenever pi/app exists, so a missing one is a hit and
  # a tree without pi/app is clean; whenever core exists, so is a missing release probe.
  for m in lib main; do
    fresh
    rm "$d/pi/app/src/$m.rs" || exit 2
    expect "rule1-pi-app-$m-rs-absent" "$d" Rule1 "pi/app/src/$m.rs"
  done
  fresh
  rm -r "$d/pi" || exit 2
  expect 'clean-no-pi-app' "$d" clean
  fresh
  rm "$d/core/examples/release_probe.rs" || exit 2
  expect 'shell-release-probe-absent' "$d" Shell core/examples/release_probe.rs
  for want in RNG Network Clipboard Rule1 FailOpen Include Shell Device clean; do
    case "$seen " in *" $want "*) ;; *) fail=$((fail + 1)); echo "FAIL no $want fixture" ;; esac
  done
  artifact_selftest
  workflows_selftest
  image_lists_selftest
  os_config_selftest
  image_selftest
  echo "selftest: $pass passed, $fail failed"
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

# --- Artifact mode -----------------------------------------------------------------------------

# The test registry public key: core/src/seal/registry_key.rs, vectors/kcr.json "keys"
# "test_registry" (the selftest checks it against kcr.json; the positive controls in
# scripts/canaries.sh check it against a real test-registry build).
testkey=42e9fa0e206d4bdf410f987ac7ded54fb02fb49ef277cc425d5fdfdb72c3b94b
# core's two test markers, and the simulator's (pi/sim/src/lib.rs; tasks/todo.md, M3 Q31 (d)).
markers='KC_TEST_SOURCE_DO_NOT_SHIP KC_TEST_REGISTRY_DO_NOT_SHIP KC_SIMULATOR_DO_NOT_SHIP'
# The RNG crates of deny.toml's rule-1 block, in its order (the selftest checks the two lists
# agree): any symbol of one of them in an artifact is a hit.
rng_crate_names='rand rand_core rand_chacha rand_xoshiro rand_xorshift rand_pcg rand_hc rand_isaac
fastrand oorandom nanorand tinyrand turborand'

# dump FILE: FILE's bytes as " xx xx ..." on one line (od -v writes every byte; tr joins the lines
# and squeezes the spaces BSD and GNU od lay out differently). Any byte value is two hex digits,
# so a fixed-string search for " 4b 43 ..." can only match whole bytes, in order.
dump() {
  od -An -v -tx1 "$1" | tr -s ' \n' '  '
}

# toolchain_bin: the bin/ of the pinned toolchain's llvm-tools-preview (rust-toolchain.toml), found
# through rustc run from the repo root, so rustup picks the pinned toolchain.
toolchain_bin() {
  repo=$(cd "$here/.." && pwd -P) || exit 2
  sysroot=$(cd "$repo" && rustc --print sysroot) || {
    echo 'banned-api-check: rustc --print sysroot failed (is the pinned toolchain installed?)' >&2
    exit 2
  }
  host=$(cd "$repo" && rustc -vV | sed -n 's/^host: //p')
  [ -n "$host" ] || { echo 'banned-api-check: rustc -vV names no host' >&2; exit 2; }
  bin=$sysroot/lib/rustlib/$host/bin
  [ -x "$bin/llvm-nm" ] || {
    echo "banned-api-check: no llvm-nm in $bin (rust-toolchain.toml lists llvm-tools-preview)" >&2
    exit 2
  }
}

# ahit CATEGORY FILE DETAIL: print and count one artifact hit.
ahit() {
  printf '%s: %s: %s\n' "$1" "$2" "$3"
  hits=$((hits + 1))
}

# symbols FILE OUT [LLVM-NM OPTION...]: the symbol names llvm-nm prints for FILE, one per line,
# without an archive's member headers ("lib.rmeta:") and blank lines, and without ELF version
# suffixes ("getrandom@GLIBC_2.25"). llvm-nm failing on FILE is an error.
symbols() {
  sf=$1
  sout=$2
  shift 2
  if ! "$bin/llvm-nm" -j "$@" "$sf" >"$atmp/nm" 2>"$atmp/nm-err"; then
    printf 'banned-api-check: llvm-nm cannot read %s:\n' "$sf" >&2
    sed 's/^/    /' "$atmp/nm-err" >&2
    exit 2
  fi
  sed -e '/^$/d' -e '/:$/d' -e 's/@.*$//' "$atmp/nm" | sort -u >"$sout" || exit 2
}

# from_list CATEGORY FILE PREFIX LIST: one hit per line of LIST.
from_list() {
  while IFS= read -r line; do
    [ -n "$line" ] && ahit "$1" "$2" "$3$line"
  done <"$4"
}

# artifact_rules TARGET: the rules of the artifact scan for TARGET, as the variables artifact_file
# reads (the image scan sets them for the Pi target too): the platform symbol prefix p, the OS
# import, the undefined-RNG, rand-crate, getrandom-fallback and std-random patterns, std's
# passengers (written to $atmp/passengers, so $atmp is set first) and the test key's bytes.
artifact_rules() {
  target=$1
  # The OS import each target's getrandom backend calls (Q8), and the platform symbol prefix.
  case $target in
    *-linux-gnu | *-linux-gnueabihf | *-linux-android | *-linux-androideabi)
      p= import=getrandom extra='|getentropy' ;;
    *-apple-ios | *-apple-ios-sim) p=_ import=_CCRandomGenerateBytes extra= ;;
    *-apple-darwin) p=_ import=_getentropy extra= ;;
    *) printf 'banned-api-check: no OS-import rule for target %s\n' "$target" >&2; exit 2 ;;
  esac
  # libc's draws and seeders, with glibc's reentrant _r forms (the Pi links glibc).
  undefined_rng="^$p(rand|random|srand|srandom|rand_r|random_r|srandom_r|([A-Za-z0-9_]*rand48|seed48|lcong48|initstate|setstate)(_r)?|arc4random[A-Za-z0-9_]*|SecRandomCopyBytes$extra)\$"
  rng_crates="(^|[^A-Za-z0-9_])($(printf '%s\n' $rng_crate_names | tr '\n' '|' | sed 's/|$//'))::"
  fallback='(^|[^A-Za-z0-9_])getrandom::backends::(use_file|linux_android_with_fallback)::'
  std_random='hashmap_random_keys|RandomState|std::sys::random|3std3sys6random'
  # std's passengers on the Pi target (tasks/todo.md, M4 group 12, Q52): on
  # arm-unknown-linux-gnueabihf, LLVM's global-merge pass packs these three statics of std's
  # getrandom into std's 24-byte .data..L_MergedGlobals block with the thread-local destructor
  # list (DTORS) and __dso_handle. Every binary uses that block through std's thread-local
  # destructor registration, so --gc-sections keeps it but drops every function that reads the
  # three statics. As exactly these names, typed d (local data) in an object or linked file, they
  # are not hits; the reader function (type t), hashmap_random_keys, RandomState and the device
  # file byte strings still are. Empty on every other target.
  case $target in
    *-linux-gnueabihf)
      std_passengers='std::sys::random::linux::getrandom::DEVICE
std::sys::random::linux::getrandom::GETRANDOM_AVAILABLE (.0)
std::sys::random::linux::getrandom::GRND_INSECURE_AVAILABLE (.0)'
      ;;
    *) std_passengers= ;;
  esac
  if [ -n "$std_passengers" ]; then
    printf '%s\n' "$std_passengers" >"$atmp/passengers" || exit 2
  fi
  keybytes=$(printf '%s\n' "$testkey" | sed 's/../ &/g')
}

# hexbytes TEXT: TEXT's bytes as dump() lays them out, for a fixed-string search of a dump.
hexbytes() {
  printf '%s' "$1" | od -An -v -tx1 | tr -s ' \n' '  ' | sed 's/ $//'
}

# byte_scan FILE NAME: FILE's bytes into $atmp/dump, then the Marker and TestKey rules on them,
# reported under NAME (the image scan names a file by its path inside the image).
byte_scan() {
  dump "$1" >"$atmp/dump" || { printf 'banned-api-check: cannot read %s\n' "$2" >&2; exit 2; }
  for m in $markers; do
    if grep -q -F -e "$(hexbytes "$m")" "$atmp/dump"; then
      ahit Marker "$2" "$m"
    fi
  done
  if grep -q -F -e "$keybytes" "$atmp/dump"; then
    ahit TestKey "$2" "the test registry public key $testkey"
  fi
}

# artifact_file FILE [NAME]: every artifact rule on FILE, reported under NAME (FILE by default),
# with artifact_rules' variables set and $atmp a scratch directory. Returns 0 when every rule
# ran, 1 when a Format hit stopped the symbol rules (a thin archive, a file of another format, a
# stripped file). Counts linked files and archives.
artifact_file() {
  f=$1
  aname=${2:-$1}
  if [ ! -f "$f" ] || [ ! -r "$f" ]; then
    printf 'banned-api-check: cannot read %s\n' "$aname" >&2
    exit 2
  fi
  byte_scan "$f" "$aname"
  # The device files std's random-key fallback reads, as bytes in any file (the symbol half of
  # the StdRandom rule follows the symbol rules below).
  for path in /dev/urandom /dev/random; do
    if grep -q -F -e "$(hexbytes "$path")" "$atmp/dump"; then
      ahit StdRandom "$aname" "byte string $path"
    fi
  done
  magic=$(od -An -N8 -tx1 "$f" | tr -d ' \n')
  case $magic in
    213c617263683e0a) kind=archive ;;
    213c7468696e3e0a)
      ahit Format "$aname" "a thin archive, which holds its members' paths, not their bytes"
      return 1
      ;;
    7f454c46* | feedface* | feedfacf* | cefaedfe* | cffaedfe* | cafebabe*) kind=object ;;
    *)
      ahit Format "$aname" 'not an ELF, Mach-O or ar file, so its symbols cannot be checked'
      return 1
      ;;
  esac
  symbols "$f" "$atmp/all" -C
  symbols "$f" "$atmp/undefined" -u
  # A stripped file: any object or linked file whose symbol list is empty (llvm-nm says "no
  # symbols" and exits 0), which is the operative test, since llvm-nm reads .symtab and not
  # .dynsym, so a stripped linked ELF lists nothing too; the .symtab check names the cause for
  # an ELF. Nothing below could check such a file.
  if [ "$kind" = object ]; then
    stripped=no
    case $magic in
      7f454c46*)
        "$bin/llvm-readobj" --section-headers "$f" >"$atmp/sections" 2>/dev/null || exit 2
        grep -q -F -e 'Name: .symtab' "$atmp/sections" || stripped=yes
        ;;
    esac
    [ -s "$atmp/all" ] || stripped=yes
    if [ "$stripped" = yes ]; then
      ahit Format "$aname" 'a stripped file with no symbol table (.symtab), so its symbols cannot be checked'
      return 1
    fi
  fi
  grep -E -e "$undefined_rng" "$atmp/undefined" >"$atmp/hits"
  [ $? -le 1 ] || exit 2
  from_list Symbol "$aname" 'undefined ' "$atmp/hits"
  grep -E -e "$rng_crates" "$atmp/all" >"$atmp/hits"
  [ $? -le 1 ] || exit 2
  from_list Symbol "$aname" 'rand-family symbol ' "$atmp/hits"
  grep -E -e "$fallback" "$atmp/all" >"$atmp/hits"
  [ $? -le 1 ] || exit 2
  from_list Symbol "$aname" "getrandom's fallback " "$atmp/hits"
  # std's random-key path: its symbols, demangled (a name llvm-nm cannot demangle stays mangled,
  # where 3std3sys6random is the module path); the byte strings were searched above.
  grep -E -e "$std_random" "$atmp/all" >"$atmp/hits"
  [ $? -le 1 ] || exit 2
  # std's passengers (Q52, see std_passengers above): in an object or linked file only, a hit
  # that is exactly one of the names, and that llvm-nm types d on every line that names it
  # (-P prints "name type value size"; a name followed by any other type, or by more text, is
  # kept), is dropped. awk tells the files apart by name, so no pattern file is ever empty.
  if [ -n "$std_passengers" ] && [ "$kind" = object ] && [ -s "$atmp/hits" ]; then
    if ! "$bin/llvm-nm" -C -P --defined-only "$f" >"$atmp/defined" 2>"$atmp/nm-err"; then
      printf 'banned-api-check: llvm-nm cannot read %s:\n' "$aname" >&2
      sed 's/^/    /' "$atmp/nm-err" >&2
      exit 2
    fi
    awk '
      FILENAME == ARGV[1] { want[$0] = 1; next }
      FILENAME == ARGV[2] {
        for (n in want)
          if (index($0, n " ") == 1) {
            split(substr($0, length(n) + 2), fld, " ")
            if (fld[1] == "d") typed_d[n] = 1
            else other[n] = 1
          }
        next
      }
      !(($0 in typed_d) && !($0 in other))
    ' "$atmp/passengers" "$atmp/defined" "$atmp/hits" >"$atmp/kept" || exit 2
    mv "$atmp/kept" "$atmp/hits" || exit 2
  fi
  from_list StdRandom "$aname" 'symbol ' "$atmp/hits"
  if [ "$kind" = archive ]; then
    archives=$((archives + 1))
  else
    linked=$((linked + 1))
    grep -q -x -F -e "$import" "$atmp/undefined" ||
      ahit OSImport "$aname" "no undefined $import, the OS import on $target"
  fi
  return 0
}

artifact() {
  target=$1
  shift
  [ $# -ge 1 ] || { usage >&2; exit 2; }
  toolchain_bin
  atmp=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-artifact.XXXXXX") || exit 2
  trap 'rm -rf "$atmp"' EXIT
  trap 'exit 2' HUP INT TERM
  artifact_rules "$target"
  hits=0
  n=0
  linked=0
  archives=0
  for f in "$@"; do
    n=$((n + 1))
    artifact_file "$f" || :
  done
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check --artifact $target: $hits hit(s) in $n file(s)"
    exit 1
  fi
  echo "banned-api-check --artifact $target: clean, $n file(s): no marker, no test key, no other RNG symbol, no std random-key path, no stripped file; $import imported by all $linked object or linked file(s) ($archives archive(s), which need no import)"
  exit 0
}

# --- Workflow mode -------------------------------------------------------------------------------

# The only actions a workflow may use, each at the one commit SHA approved for it (Q38 (c);
# pi/os/pins.txt records upload-artifact's): actions/checkout v7.0.1, actions/cache v6.1.0 and
# actions/upload-artifact v7.0.1, an ERE alternation. A new release is a reviewed change here.
approved_actions='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
approved_actions="$approved_actions|actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
approved_actions="$approved_actions|actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"

# workflow_check FILE: the hardening rules of the script header, as "<line>:<text>" lines on
# stdout, in file order, each line at most once; exit 0 hits, 1 none, 2 unreadable. The awk pass
# follows two kinds of block: a run: step (its own line, then every following line indented past
# the run key, blank lines included, is the script: "${{" anywhere there is a hit) and a
# permissions: block (any line holding write, in any letter case, is a hit, so a quoted value, a
# value on the line after its scope and a flow mapping on its own line are read as GitHub reads
# them; the top-level block must hold an unquoted contents: read, or the file is reported at line
# 1). A permissions value on the key's own line (write-all, read-all, { contents: read }) is read
# there. A block key (run, permissions) may follow a dash of any width and may be quoted; a run
# key inside a flow mapping ({run: ..., or , run: ...) is read for "${{" on its line. Keys inside
# a run block are script text, not YAML. The other rules are plain greps over every line: uses:
# not one of the three actions at its approved SHA ($approved_actions), the word secrets,
# github.token (also github['token']), pull_request_target, workflow_run.
workflow_check() {
  wf=$1
  [ -f "$wf" ] && [ -r "$wf" ] || return 2
  t=$(awk '
    function indent(s) { match(s, /^ */); return RLENGTH }
    {
      line = $0
      sub(/\r$/, "", line)
      blank = (line ~ /^[[:space:]]*$/)
      ind = indent(line)
      hit = 0
      if (inrun && !blank && ind <= runind) inrun = 0
      if (inperm && !blank && ind <= permind) inperm = 0
      if (inrun) {
        if (index(line, "${{")) print NR ":" line
        next
      }
      if (inperm && !blank) {
        if (tolower(line) ~ /write/) hit = 1
        if (permind == 0 && line ~ /^[[:space:]]+contents:[[:space:]]*read[[:space:]]*(#.*)?$/) top_ok = 1
      }
      keyind = ind
      if (match(line, /^[[:space:]]*-[[:space:]]+/)) keyind = RLENGTH
      if (match(line, /^[[:space:]]*(-[[:space:]]+)?["'\'']?run["'\'']?:/)) {
        rest = substr(line, RLENGTH + 1)
        sub(/^[[:space:]]+/, "", rest)
        if (index(rest, "${{")) hit = 1
        inrun = 1
        runind = keyind
      } else if (line ~ /[{,][[:space:]]*["'\'']?run["'\'']?[[:space:]]*:/ && index(line, "${{")) {
        hit = 1
      } else if (match(line, /^[[:space:]]*(-[[:space:]]+)?["'\'']?permissions["'\'']?:/)) {
        rest = substr(line, RLENGTH + 1)
        sub(/^[[:space:]]+/, "", rest)
        sub(/[[:space:]]+#.*$/, "", rest)
        if (rest == "" || rest ~ /^#/) {
          inperm = 1
          permind = keyind
        } else {
          if (tolower(rest) ~ /write/) hit = 1
          if (keyind == 0 && rest ~ /^\{[[:space:]]*contents:[[:space:]]*read[[:space:]]*\}$/) top_ok = 1
        }
      }
      if (hit) print NR ":" line
    }
    END { if (!top_ok) print "1:missing a top-level permissions block that holds contents: read" }
  ' "$wf") || return 2
  u=$(grep -n -a -E -e '^[[:space:]]*(- )?uses:' -- "$wf" |
    grep -v -E -e "^[0-9]+:[[:space:]]*(- )?uses:[[:space:]]*($approved_actions)[[:space:]]*(#.*)?\$")
  [ $? -le 1 ] || return 2
  g=$(grep -n -a -E -e "${L}secrets$R" -e "${L}github[[:space:]]*[.[][[:space:]]*['\"]?token$R" \
    -e "${L}(pull_request_target|workflow_run)$R" -- "$wf")
  [ $? -le 1 ] || return 2
  t=$(printf '%s\n%s\n%s\n' "$t" "$u" "$g" | sed '/^$/d' | sort -t : -k 1,1n -s)
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

workflows() {
  dir=${1%/}
  [ -d "$dir" ] || { printf 'banned-api-check: --workflows: %s is not a directory\n' "$1" >&2; exit 2; }
  hits=0
  n=0
  for wf in "$dir"/entropy-*.yml "$dir"/entropy-*.yaml; do
    [ -e "$wf" ] || continue
    n=$((n + 1))
    out=$(workflow_check "$wf")
    case $? in
      0) ;;
      1) continue ;;
      *) printf 'banned-api-check: cannot read %s\n' "$wf" >&2; exit 2 ;;
    esac
    while IFS= read -r line; do
      printf 'Workflow: %s:%s: %s\n' "$wf" "${line%%:*}" "${line#*:}"
      hits=$((hits + 1))
    done <<EOF
$out
EOF
  done
  if [ "$n" -eq 0 ]; then
    printf 'banned-api-check: --workflows: no entropy-*.yml or entropy-*.yaml in %s\n' "$dir" >&2
    exit 2
  fi
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check --workflows $dir: $hits hit(s) in $n workflow(s)"
    exit 1
  fi
  echo "banned-api-check --workflows $dir: clean, $n workflow(s): read-only permissions, pinned actions, no secrets, no fork-trusting trigger, no expression in a run step"
  exit 0
}

# --- Image lists mode ----------------------------------------------------------------------------

# The image mode running (--image-lists, --image or --selftest-image), for the messages below.
imode=--image-lists

# ifail MESSAGE: IMG cannot be listed or scanned (exit 2).
ifail() {
  printf 'banned-api-check: %s: %s: %s\n' "$imode" "$img" "$1" >&2
  exit 2
}

# itool MESSAGE: a tool failed; its output ($iw/log) goes with the message.
itool() {
  sed 's/^/    /' "$iw/log" >&2
  ifail "$1"
}

# sha256 FILE: FILE's SHA-256 as 64 lowercase hex digits (sha256sum on Linux, shasum on macOS).
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    s=$(sha256sum <"$1") || exit 2
  elif command -v shasum >/dev/null 2>&1; then
    s=$(shasum -a 256 <"$1") || exit 2
  else
    echo 'banned-api-check: no sha256sum or shasum' >&2
    exit 2
  fi
  printf '%s\n' "${s%% *}"
}

# icopy P START COUNT: partition P, COUNT sectors from sector START of IMG, into $iw/pP.img.
icopy() {
  dd if="$img" of="$iw/p$1.img" bs=512 skip="$2" count="$3" 2>/dev/null || ifail "cannot copy partition $1"
  got=$(wc -c <"$iw/p$1.img") || exit 2
  [ $((got)) -eq $(($3 * 512)) ] || ifail "partition $1 copied $((got)) bytes, not $(($3 * 512))"
}

# image_unpack IMG: refuses any layout but the image's (see "Image lists mode"), copies the two
# partitions to $iw/p1.img and $iw/p2.img, extracts partition 1 into $iw/boot (mcopy -s) and
# lists it ($iw/mdir, mdir -a), lists partition 2's SquashFS metadata ($iw/root.lln, unsquashfs
# -lln) and unpacks it into $iw/root. Sets $iw (a temporary directory, removed on exit) and the
# partition table: $mbr_sig, and the boot flag, first sector and sector count of partition 1
# ($f1 $s1 $n1) and partition 2 ($f2 $s2 $n2). Every check that needs no tool comes first.
image_unpack() {
  img=$1
  [ -f "$img" ] && [ -r "$img" ] || { printf 'banned-api-check: %s: cannot read %s\n' "$imode" "$img" >&2; exit 2; }
  isize=$(wc -c <"$img") || exit 2
  isize=$((isize))
  [ "$isize" -ge 512 ] || ifail "$isize bytes, shorter than an MBR (512)"
  # The MBR: the disk signature at bytes 440-443, four 16-byte partition entries from byte 446
  # (the boot flag at +0, the type at +4, the first sector and the sector count as little-endian
  # u32s at +8 and +12), the boot signature 55 aa at byte 510. awk prints "ok <signature> <flag>
  # <first> <count> <flag> <first> <count>" or "error <reason>".
  layout=$(dd if="$img" bs=512 count=1 2>/dev/null | od -An -v -tx1 | awk -v sectors=$((isize / 512)) '
    function hex(h,    i, v) {
      v = 0
      for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1
      return v
    }
    function u32(at) { return hex(b[at + 3] b[at + 2] b[at + 1] b[at]) }
    { for (i = 1; i <= NF; i++) b[n++] = $i }
    END {
      if (n != 512) { print "error its MBR read " n " bytes, not 512"; exit }
      if (b[510] != "55" || b[511] != "aa") { print "error no MBR boot signature (55 aa at byte 510)"; exit }
      for (e = 3; e <= 4; e++)
        for (i = 0; i < 16; i++)
          if (b[446 + 16 * (e - 1) + i] != "00") { print "error partition entry " e " is not empty"; exit }
      want[1] = "0c"; kind[1] = "FAT32 with LBA"
      want[2] = "83"; kind[2] = "Linux"
      out = "ok 0x" b[443] b[442] b[441] b[440]
      for (e = 1; e <= 2; e++) {
        at = 446 + 16 * (e - 1)
        first[e] = u32(at + 8)
        count[e] = u32(at + 12)
        if (b[at + 4] != want[e]) {
          print "error partition " e " has type 0x" b[at + 4] ", not " kind[e] " (0x" want[e] ")"
          exit
        }
        if (count[e] == 0) { print "error partition " e " is empty"; exit }
        if (first[e] == 0) { print "error partition " e " starts at sector 0, the MBR"; exit }
        if (first[e] + count[e] > sectors) {
          print "error partition " e " ends at sector " first[e] + count[e] ", past the image (" sectors " sectors)"
          exit
        }
        out = out " " b[at] " " first[e] " " count[e]
      }
      if (first[1] + count[1] > first[2]) {
        print "error partition 2 (first sector " first[2] ") does not start after partition 1 (sectors " first[1] "-" first[1] + count[1] - 1 ")"
        exit
      }
      print out
    }')
  case $layout in
    'ok '*) ;;
    'error '*) ifail "${layout#error }" ;;
    *) ifail 'cannot read its MBR' ;;
  esac
  set -- $layout
  mbr_sig=$2 f1=$3 s1=$4 n1=$5 f2=$6 s2=$7 n2=$8
  iw=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-image.XXXXXX") || exit 2
  trap 'rm -rf "$iw"' EXIT
  trap 'exit 2' HUP INT TERM
  icopy 1 "$s1" "$n1"
  icopy 2 "$s2" "$n2"
  magic=$(dd if="$iw/p2.img" bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
  [ "$magic" = 68737173 ] || ifail 'partition 2 does not start with the SquashFS magic hsqs'
  for tool in mcopy mdir unsquashfs; do
    command -v "$tool" >/dev/null 2>&1 ||
      ifail "no $tool on PATH (the build's host tools are in KC_WORK/out/host/bin)"
  done
  # MTOOLS_SKIP_CHECK=1 as genimage sets it when it writes partition 1 with the same mtools.
  mkdir "$iw/boot" || exit 2
  MTOOLS_SKIP_CHECK=1 mcopy -s -n -i "$iw/p1.img" '::*' "$iw/boot/" >"$iw/log" 2>&1 ||
    itool 'mcopy -s could not extract partition 1'
  MTOOLS_SKIP_CHECK=1 mdir -a -i "$iw/p1.img" '::' >"$iw/mdir" 2>"$iw/log" ||
    itool 'mdir -a could not list partition 1'
  unsquashfs -lln "$iw/p2.img" >"$iw/root.lln" 2>"$iw/log" ||
    itool 'unsquashfs -lln could not list partition 2'
  unsquashfs -no-progress -d "$iw/root" "$iw/p2.img" >"$iw/log" 2>&1 ||
    itool 'unsquashfs could not unpack partition 2'
}

# image_boot_list: the boot list, $iw/boot.list, from the extracted files (FAT has no mode and no
# link): "<path> <dir|file>", sorted.
image_boot_list() {
  (cd "$iw/boot" && find . -print) >"$iw/boot.find" || exit 2
  while IFS= read -r p; do
    f=$iw/boot/${p#./}
    if [ -h "$f" ]; then
      ifail "mcopy extracted a symlink from partition 1: $p"
    elif [ -d "$f" ]; then
      t=dir
    elif [ -f "$f" ]; then
      t=file
    else
      ifail "mcopy extracted neither a file nor a directory from partition 1: $p"
    fi
    case $p in
      .) printf '/ %s\n' "$t" ;;
      *) printf '/%s %s\n' "${p#./}" "$t" ;;
    esac
  done <"$iw/boot.find" >"$iw/boot.unsorted"
  sort "$iw/boot.unsorted" >"$iw/boot.list" || exit 2
}

# image_root_list: the root list, $iw/root.list: "<path> <mode>[ -> <target>]" from unsquashfs
# -lln ($iw/root.lln), whose lines are "<mode> <uid>/<gid> <size, or major,minor> <yyyy-mm-dd>
# <hh:mm> squashfs-root<path>[ -> <target>]". The mode string's first letter is the type. Owners,
# sizes and times are left out. Sorted.
image_root_list() {
  awk -v badf="$iw/root.bad" '
    function bad() { print > badf; failed = 1; exit }
    {
      if (!match($0, / [0-9]+-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9] /)) bad()
      mode = $1
      path = substr($0, RSTART + RLENGTH)
      target = ""
      if (substr(mode, 1, 1) == "l") {
        at = index(path, " -> ")
        if (!at) bad()
        target = substr(path, at)
        path = substr(path, 1, at - 1)
      }
      if (path == "squashfs-root") path = "/"
      else if (index(path, "squashfs-root/") == 1) path = substr(path, 14)
      else bad()
      print path " " mode target
    }
    END { if (failed) exit 1 }
  ' "$iw/root.lln" >"$iw/root.unsorted" ||
    ifail "unsquashfs -lln printed a line this script cannot read: $(cat "$iw/root.bad")"
  [ -s "$iw/root.unsorted" ] || ifail 'unsquashfs -lln listed nothing'
  sort "$iw/root.unsorted" >"$iw/root.list" || exit 2
}

# image_imports: keepcrypt-pi's imports, $iw/imports.list: "<type> <symbol>@<version>" from
# llvm-nm -D -u (U, or w for weak), sorted without duplicates. Sets $kp, the unpacked
# /usr/bin/keepcrypt-pi, and $bin (toolchain_bin).
image_imports() {
  kp=$iw/root/usr/bin/keepcrypt-pi
  [ -f "$kp" ] && [ ! -h "$kp" ] || ifail 'partition 2 holds no file /usr/bin/keepcrypt-pi'
  toolchain_bin
  "$bin/llvm-nm" -D -u "$kp" >"$iw/nm" 2>"$iw/log" || itool 'llvm-nm -D -u cannot read /usr/bin/keepcrypt-pi'
  awk 'NF == 2 { print $1, $2; next } NF { exit 1 }' "$iw/nm" >"$iw/imports.unsorted" ||
    ifail 'llvm-nm -D -u printed a line that is not "<type> <symbol>"'
  sort -u "$iw/imports.unsorted" >"$iw/imports.list" || exit 2
}

# image_lists IMG KCONFIG: unpack IMG and print its lists, under "== " headings (see "Image lists
# mode").
image_lists() {
  kconfig=$2
  [ -f "$kconfig" ] && [ -r "$kconfig" ] || { printf 'banned-api-check: --image-lists: cannot read %s\n' "$kconfig" >&2; exit 2; }
  image_unpack "$1"
  image_boot_list
  image_root_list
  image_imports
  h_img=$(sha256 "$img") || exit 2
  h_p1=$(sha256 "$iw/p1.img") || exit 2
  h_p2=$(sha256 "$iw/p2.img") || exit 2
  h_kp=$(sha256 "$kp") || exit 2
  echo "== banned-api-check --image-lists $img $kconfig"
  echo '== partition table (MBR)'
  echo "disk signature $mbr_sig"
  echo "partition 1: type 0x0c, boot flag 0x$f1, first sector $s1, $n1 sectors"
  echo "partition 2: type 0x83, boot flag 0x$f2, first sector $s2, $n2 sectors"
  echo '== SHA-256'
  echo "sha256 image $h_img"
  echo "sha256 partition-1 $h_p1"
  echo "sha256 partition-2 $h_p2"
  echo "sha256 keepcrypt-pi $h_kp"
  echo '== boot files (partition 1, FAT: path, type)'
  cat "$iw/boot.list"
  echo '== boot mdir -a (partition 1)'
  cat "$iw/mdir"
  echo '== root files (partition 2, SquashFS: path, mode, link target)'
  cat "$iw/root.list"
  echo '== keepcrypt-pi imports (/usr/bin/keepcrypt-pi, llvm-nm -D -u: type, symbol)'
  cat "$iw/imports.list"
  echo '== kernel config (KCONFIG)'
  cat "$kconfig" || exit 2
  echo "banned-api-check --image-lists $img: listed, not scanned"
  exit 0
}

# --- OS configuration and image scan: the shared rules -------------------------------------------

# The image's inittab (tasks/todo.md, M4 group 13; Q35): the whole file is these three lines.
inittab_lines='::sysinit:/bin/mount -a
::wait:/usr/bin/keepcrypt-pi
::once:/usr/bin/keepcrypt-pi --stopped'

# BusyBox (tasks/todo.md, M4 groups 11 and 13): the applets the image must build, as CONFIG_
# symbols at =y (init reading /etc/inittab; mount reading /etc/fstab, with the flags that give it
# nosuid, nodev and noexec; no shell as sh or bash), and the ones it must not: shells, logins,
# network, module, power, swap and loop tools, seedrng and vi.
busybox_required='INIT FEATURE_USE_INITTAB MOUNT FEATURE_MOUNT_FSTAB FEATURE_MOUNT_FLAGS SH_IS_NONE BASH_IS_NONE'
busybox_denied='ASH HUSH SH_IS_ASH SH_IS_HUSH GETTY LOGIN SU SULOGIN TELNETD HTTPD FTPD TFTP WGET NC
UDHCPC UDHCPD IFCONFIG IP ROUTE PING SYSLOGD KLOGD CROND MODPROBE INSMOD RMMOD HALT REBOOT POWEROFF
SWAPON SWAPOFF LOSETUP SEEDRNG VI SH'

# The programs the root must not hold, as a path's or a link target's base name.
denied_programs='sh|ash|hush|getty|login|dropbear|sshd|telnetd|udhcpc'

# readable FILE MODE: FILE must be a readable, non-empty regular file (through a symlink or not),
# or MODE exits 2: a missing or empty list is an error, never a pass.
readable() {
  [ -f "$1" ] && [ -r "$1" ] && [ -s "$1" ] ||
    { printf 'banned-api-check: %s: cannot read %s, or it is empty\n' "$2" "$1" >&2; exit 2; }
}

# lines_as_hits CATEGORY NAME TEXT: one hit per line of TEXT, each "<line>: <detail>" reported as
# "CATEGORY: NAME:<line>: <detail>" (the file's line, as the repo scan reports).
lines_as_hits() {
  [ -n "$3" ] || return 0
  while IFS= read -r line; do
    ahit "$1" "$2:${line%%:*}" "${line#*: }"
  done <<EOF
$3
EOF
}

# show_diff EXPECTED GOT: the difference between two lists, indented, on stderr.
show_diff() {
  diff "$1" "$2" | sed 's/^/    /' >&2
}

# fragment_lists FRAGMENT REQUIRED FORBIDDEN MODE: the symbols of FRAGMENT's CONFIG_X=y lines into
# the file REQUIRED and of its "# CONFIG_X is not set" lines into FORBIDDEN, one per line in the
# fragment's order: the exact content expected/kconfig-required and kconfig-forbidden must hold,
# so the three cannot drift. A line of another kind (anything but those two, a comment or a blank
# line, as pi/os/kconfig.sh refuses it), or a fragment with no line of either kind, is exit 2.
fragment_lists() {
  readable "$1" "$4"
  : >"$2" && : >"$3" || exit 2
  bad=$(awk -v req="$2" -v forb="$3" '
    /^CONFIG_[A-Za-z0-9_]+=y$/ { sub(/=y$/, ""); print > req; next }
    /^# CONFIG_[A-Za-z0-9_]+ is not set$/ { print $2 > forb; next }
    /^#/ || /^[[:space:]]*$/ { next }
    { print NR ": " $0; exit 1 }
  ' "$1") || {
    printf 'banned-api-check: %s: %s: a fragment line of another kind at line %s\n' "$4" "$1" "$bad" >&2
    exit 2
  }
  [ -s "$2" ] && [ -s "$3" ] || {
    printf 'banned-api-check: %s: %s: has no CONFIG_X=y line, or no "# CONFIG_X is not set" line\n' "$4" "$1" >&2
    exit 2
  }
}

# lists_match EXPECTED FRAGMENT WORK MODE: expected/kconfig-required and kconfig-forbidden equal
# FRAGMENT's two lists byte for byte (Kconfig hits otherwise); the lists stay in WORK/required and
# WORK/forbidden for kconfig_check.
lists_match() {
  fragment_lists "$2" "$3/required" "$3/forbidden" "$4"
  cmp -s "$3/required" "$1/kconfig-required" ||
    ahit Kconfig "$1/kconfig-required" "does not equal the CONFIG_X=y lines of $2, one symbol per line in its order"
  cmp -s "$3/forbidden" "$1/kconfig-forbidden" ||
    ahit Kconfig "$1/kconfig-forbidden" "does not equal the \"# CONFIG_X is not set\" lines of $2, one symbol per line in its order"
}

# kconfig_check CONFIG NAME REQUIRED FORBIDDEN: the kernel config rules (tasks/todo.md, M4 groups
# 11, 13 and 14) on the config file CONFIG, reported as NAME: every symbol of the file REQUIRED at
# =y, no symbol of FORBIDDEN at y or m, and CONFIG_HW_RANDOM_BCM2835=y the only CONFIG_HW_RANDOM_*
# driver set.
kconfig_check() {
  kout=$(awk -v req="$3" -v forb="$4" '
    BEGIN {
      while ((getline s < req) > 0) { need[s] = 1; order[n++] = s }
      while ((getline s < forb) > 0) ban[s] = 1
      close(req)
      close(forb)
    }
    /^CONFIG_[A-Za-z0-9_]+=/ {
      sym = $0
      sub(/=.*/, "", sym)
      val = substr($0, length(sym) + 2)
      if (sym in need && val == "y") have[sym] = 1
      if (sym in ban && (val == "y" || val == "m")) print "forbidden option " sym " is set (=" val ")"
      if (sym ~ /^CONFIG_HW_RANDOM_/ && (val == "y" || val == "m")) {
        if (sym == "CONFIG_HW_RANDOM_BCM2835") { if (val == "y") bcm = 1 }
        else print "a hwrng driver other than BCM2835 is set: " sym "=" val
      }
    }
    END {
      for (i = 0; i < n; i++) if (!(order[i] in have)) print "required option " order[i] " is not =y"
      if (!bcm) print "CONFIG_HW_RANDOM_BCM2835=y, the one hwrng driver, is not set"
    }
  ' "$1") || exit 2
  [ -n "$kout" ] || return 0
  while IFS= read -r line; do
    ahit Kconfig "$2" "$line"
  done <<EOF
$kout
EOF
}

# inittab_check FILE NAME: FILE is exactly Q35's three lines.
inittab_check() {
  if [ -h "$1" ]; then
    ahit Inittab "$2" 'is a symlink, not a file'
  elif [ ! -f "$1" ]; then
    ahit Inittab "$2" 'is missing'
  elif ! printf '%s\n' "$inittab_lines" | cmp -s - "$1"; then
    ahit Inittab "$2" "is not exactly the three lines ::sysinit:/bin/mount -a, ::wait:/usr/bin/keepcrypt-pi and ::once:/usr/bin/keepcrypt-pi --stopped (Q35)"
  fi
}

# fstab_check FILE NAME: every proc and sysfs line carries ro, nosuid, nodev and noexec, every
# tmpfs line nosuid, nodev, noexec and a size=, and there is no line of another filesystem type
# (and at least one line; comments and blank lines are skipped).
fstab_check() {
  fout=$(awk '
    /^[[:space:]]*(#|$)/ { next }
    {
      n++
      opts = "," $4 ","
      if ($3 == "proc" || $3 == "sysfs") {
        split("ro nosuid nodev noexec", want, " ")
        for (i = 1; i <= 4; i++) if (!index(opts, "," want[i] ",")) print NR ": " $3 " on " $2 " lacks " want[i]
      } else if ($3 == "tmpfs") {
        split("nosuid nodev noexec", want, " ")
        for (i = 1; i <= 3; i++) if (!index(opts, "," want[i] ",")) print NR ": tmpfs on " $2 " lacks " want[i]
        if (!index(opts, ",size=")) print NR ": tmpfs on " $2 " has no size="
      } else print NR ": a filesystem of another type, " $3 ", on " $2
    }
    END { if (!n) print "1: no filesystem line" }
  ' "$1") || exit 2
  lines_as_hits Fstab "$2" "$fout"
}

# cmdline_check FILE NAME: no console= or init= word, and the words ro, panic=0 and init_on_free=1.
cmdline_check() {
  cout=$(awk '
    {
      for (i = 1; i <= NF; i++) {
        seen[$i] = 1
        if ($i ~ /^(console|init)=/) print NR ": " $i
      }
    }
    END {
      split("ro panic=0 init_on_free=1", want, " ")
      for (i = 1; i <= 3; i++) if (!(want[i] in seen)) print "1: no " want[i]
    }
  ' "$1") || exit 2
  lines_as_hits Cmdline "$2" "$cout"
}

# config_txt_check FILE NAME: no enable_uart=1, dtoverlay, start_file, fixup_file or plain
# gpu_mem= line, and the gpu_mem_* lines exactly gpu_mem_256=100, gpu_mem_512=100 and
# gpu_mem_1024=100, each once (the default start.elf and fixup.dat pair boots them; comments are
# skipped).
config_txt_check() {
  cout=$(awk '
    /^[[:space:]]*(#|$)/ { next }
    /^enable_uart=1[[:space:]]*$/ { print NR ": " $0 }
    /^dtoverlay/ { print NR ": " $0 }
    /^(start_file|fixup_file)/ { print NR ": " $0 }
    /^gpu_mem=/ { print NR ": " $0 " (a plain gpu_mem selects other firmware files)" }
    /^gpu_mem_/ {
      if ($0 == "gpu_mem_256=100" || $0 == "gpu_mem_512=100" || $0 == "gpu_mem_1024=100") have[$0]++
      else { print NR ": " $0; key = $0; sub(/=.*/, "", key); off[key] = 1 }
    }
    END {
      split("gpu_mem_256=100 gpu_mem_512=100 gpu_mem_1024=100", want, " ")
      for (i = 1; i <= 3; i++) {
        key = want[i]
        sub(/=.*/, "", key)
        if (have[want[i]] != 1 && !(key in off)) print "1: " want[i] " does not appear exactly once"
      }
    }
  ' "$1") || exit 2
  lines_as_hits ConfigTxt "$2" "$cout"
}

# busybox_check FILE NAME: every $busybox_required symbol at =y, no $busybox_denied symbol at =y,
# and no CONFIG_SH_IS_* or CONFIG_BASH_IS_* shell selector at =y but the two _NONE ones.
busybox_check() {
  bout=$(awk -v req="$(printf '%s' "$busybox_required" | tr '\n' ' ')" \
    -v deny="$(printf '%s' "$busybox_denied" | tr '\n' ' ')" '
    BEGIN {
      nr = split(req, r, " ")
      nd = split(deny, d, " ")
      for (i = 1; i <= nd; i++) denied["CONFIG_" d[i]] = 1
    }
    /^CONFIG_[A-Za-z0-9_]+=y$/ {
      sym = $0
      sub(/=y$/, "", sym)
      have[sym] = 1
      if (sym in denied) print NR ": " $0 " (an applet the image must not build)"
      else if (sym ~ /^CONFIG_(SH|BASH)_IS_/ && sym != "CONFIG_SH_IS_NONE" && sym != "CONFIG_BASH_IS_NONE")
        print NR ": " $0 " (a shell selected)"
    }
    END { for (i = 1; i <= nr; i++) if (!(("CONFIG_" r[i]) in have)) print "1: CONFIG_" r[i] "=y is missing" }
  ' "$1") || exit 2
  lines_as_hits BusyBox "$2" "$bout"
}

# --- OS configuration mode -----------------------------------------------------------------------

# os_config OS_DIR: the text-only checks of pi/os (see "OS configuration mode" in the header).
os_config() {
  os=${1%/}
  [ -d "$os" ] || { printf 'banned-api-check: --os-config: %s is not a directory\n' "$1" >&2; exit 2; }
  board=$os/board/pizero
  exp=$os/expected
  [ -d "$exp" ] || {
    printf 'banned-api-check: --os-config: %s has no expected/ directory (tasks/todo.md, M4 commit 16: the lists, linux.config, kconfig-required and kconfig-forbidden of the reviewed image)\n' "$os" >&2
    exit 2
  }
  for f in "$board/rootfs-overlay/etc/inittab" "$board/rootfs-overlay/etc/fstab" "$board/cmdline.txt" \
    "$board/config.txt" "$board/busybox.config" "$board/linux.fragment" "$exp/linux.config" \
    "$exp/kconfig-required" "$exp/kconfig-forbidden"; do
    readable "$f" --os-config
  done
  otmp=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-os-config.XXXXXX") || exit 2
  trap 'rm -rf "$otmp"' EXIT
  trap 'exit 2' HUP INT TERM
  hits=0
  inittab_check "$board/rootfs-overlay/etc/inittab" "$board/rootfs-overlay/etc/inittab"
  fstab_check "$board/rootfs-overlay/etc/fstab" "$board/rootfs-overlay/etc/fstab"
  cmdline_check "$board/cmdline.txt" "$board/cmdline.txt"
  config_txt_check "$board/config.txt" "$board/config.txt"
  lists_match "$exp" "$board/linux.fragment" "$otmp" --os-config
  kconfig_check "$exp/linux.config" "$exp/linux.config" "$otmp/required" "$otmp/forbidden"
  busybox_check "$board/busybox.config" "$board/busybox.config"
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check --os-config $os: $hits hit(s)"
    exit 1
  fi
  echo "banned-api-check --os-config $os: clean: Q35's inittab, the fstab's options, cmdline.txt and config.txt as the plan says, expected/linux.config with the fragment's required and forbidden lists (which expected/kconfig-required and kconfig-forbidden equal) and one hwrng driver, and BusyBox with init and mount and no denied applet or shell"
  exit 0
}

# --- Image scan mode -----------------------------------------------------------------------------

# deny_check LIST: the deny list over the root list LIST (tasks/todo.md, M4 group 14, step 5), as
# Deny hits by path: a shell or login program as a path's or a link target's base name
# ($denied_programs), anything under /lib/modules, /usr/lib/modules or /etc/init.d, a setuid,
# setgid or sticky mode (any s or t in the mode string's nine permission letters) other than /tmp's
# own drwxrwxrwt, and a name that ends .age or holds seed, backup or mnemonic.
deny_check() {
  dout=$(awk -v denied="^($denied_programs)\$" '
    function base(p) { sub(/\/$/, "", p); sub(/.*\//, "", p); return p }
    {
      line = $0
      target = ""
      at = index(line, " -> ")
      if (at) { target = substr(line, at + 4); line = substr(line, 1, at - 1) }
      if (!match(line, / [^ ]+$/)) { print "\tcannot read the root list line: " $0; exit 1 }
      mode = substr(line, RSTART + 1)
      path = substr(line, 1, RSTART - 1)
      b = base(path)
      if (b ~ denied) print path "\ta shell or login program, " b
      else if (target != "" && base(target) ~ denied) print path "\ta link to a shell or login program, " target
      if (path ~ /^\/(usr\/)?lib\/modules(\/|$)/) print path "\tkernel modules"
      if (path ~ /^\/etc\/init\.d(\/|$)/) print path "\tstart-up scripts"
      if (substr(mode, 2) ~ /[sStT]/ && !(path == "/tmp" && mode == "drwxrwxrwt")) print path "\tsetuid, setgid or sticky mode " mode
      lb = tolower(b)
      if (lb ~ /\.age$/ || lb ~ /seed|backup|mnemonic/) print path "\tlooks like a seed or backup file"
    }
  ' "$1") || ifail "${dout#?}"
  [ -n "$dout" ] || return 0
  tab=$(printf '\t')
  while IFS= read -r line; do
    ahit Deny "${line%%"$tab"*}" "${line#*"$tab"}"
  done <<EOF
$dout
EOF
}

# boot_check: partition 1 holds exactly one start/fixup pair, start.elf and fixup.dat (no other
# start*.elf or fixup*.dat), and its cmdline.txt and config.txt equal the board files byte for
# byte ($board, the repo's pi/os/board/pizero).
boot_check() {
  bout=$(awk '
    /^\/start[^\/]*\.elf file$/ { starts = starts (starts == "" ? "" : ", ") substr($0, 2, length($0) - 6) }
    /^\/fixup[^\/]*\.dat file$/ { fixups = fixups (fixups == "" ? "" : ", ") substr($0, 2, length($0) - 6) }
    END {
      if (starts != "start.elf") print "holds " (starts == "" ? "no start*.elf" : starts) ", not exactly start.elf"
      if (fixups != "fixup.dat") print "holds " (fixups == "" ? "no fixup*.dat" : fixups) ", not exactly fixup.dat"
    }
  ' "$iw/boot.list") || exit 2
  if [ -n "$bout" ]; then
    while IFS= read -r line; do
      ahit Boot partition-1 "$line"
    done <<EOF
$bout
EOF
  fi
  for f in cmdline.txt config.txt; do
    if [ ! -f "$iw/boot/$f" ]; then
      ahit Boot "partition-1:/$f" 'is missing'
    elif ! cmp -s "$iw/boot/$f" "$board/$f"; then
      ahit Boot "partition-1:/$f" "differs from pi/os/board/pizero/$f (the diff is on stderr)"
      show_diff "$board/$f" "$iw/boot/$f"
    fi
  done
}

# elf_check FILE NAME: the rules for an ELF file of the root other than keepcrypt-pi (tasks/todo.md,
# M4 group 14, step 3; Buildroot strips them, so their dynamic symbols are read, llvm-nm -D): it
# must list dynamic symbols at all (a stripped static file lists none, and nothing could check
# it), and import no banned RNG symbol and define no rand-crate or getrandom-fallback symbol.
# glibc's libc.so.6 and ld-linux define rand, random, srand and the rest rather than import them,
# so only the undefined symbols meet the import rule.
elf_check() {
  symbols "$1" "$iw/dyn" -D
  if [ ! -s "$iw/dyn" ]; then
    ahit Format "$2" 'an ELF with no dynamic symbol table (a stripped static file), whose imports cannot be checked'
    return
  fi
  symbols "$1" "$iw/dynu" -D -u
  grep -E -e "$undefined_rng" "$iw/dynu" >"$iw/hits"
  [ $? -le 1 ] || exit 2
  from_list Symbol "$2" 'undefined ' "$iw/hits"
  symbols "$1" "$iw/dync" -D -C
  grep -E -e "$rng_crates" "$iw/dync" >"$iw/hits"
  [ $? -le 1 ] || exit 2
  from_list Symbol "$2" 'rand-family symbol ' "$iw/hits"
  grep -E -e "$fallback" "$iw/dync" >"$iw/hits"
  [ $? -le 1 ] || exit 2
  from_list Symbol "$2" "getrandom's fallback " "$iw/hits"
}

# image_scan IMG EXPECTED_DIR KCONFIG BIN_SHA256: the image scan (see "Image scan mode" in the
# header). Every input is checked before the image is unpacked: the four arguments, the six
# files of EXPECTED_DIR (readable and non-empty) and the repo's board files this scan compares
# against (pi/os/board/pizero's cmdline.txt, config.txt and linux.fragment, found from this
# script's path).
image_scan() {
  imode=--image
  img=$1
  exp=${2%/}
  kconfig=$3
  want_sha=$4
  printf '%s\n' "$want_sha" | grep -q -x -E '[0-9a-f]{64}' ||
    { printf 'banned-api-check: --image: BIN_SHA256 is not 64 lowercase hex digits: %s\n' "$want_sha" >&2; exit 2; }
  [ -d "$exp" ] || { printf 'banned-api-check: --image: EXPECTED_DIR %s is not a directory\n' "$2" >&2; exit 2; }
  for f in boot.list root.list linux.config kconfig-required kconfig-forbidden keepcrypt-pi.imports; do
    readable "$exp/$f" --image
  done
  readable "$kconfig" --image
  board=$(cd "$here/../pi/os/board/pizero" 2>/dev/null && pwd -P) ||
    { echo 'banned-api-check: --image: no pi/os/board/pizero beside this script' >&2; exit 2; }
  for f in cmdline.txt config.txt linux.fragment; do
    readable "$board/$f" --image
  done
  image_unpack "$img"
  image_boot_list
  image_root_list
  image_imports
  atmp=$iw
  artifact_rules arm-unknown-linux-gnueabihf
  hits=0
  linked=0
  archives=0
  # 1. The lists equal expected/.
  if ! cmp -s "$iw/boot.list" "$exp/boot.list"; then
    ahit List "$exp/boot.list" "differs from the image's boot file list (the diff is on stderr)"
    show_diff "$exp/boot.list" "$iw/boot.list"
  fi
  if ! cmp -s "$iw/root.list" "$exp/root.list"; then
    ahit List "$exp/root.list" "differs from the image's root file list (the diff is on stderr)"
    show_diff "$exp/root.list" "$iw/root.list"
  fi
  if ! cmp -s "$iw/imports.list" "$exp/keepcrypt-pi.imports"; then
    ahit Binary /usr/bin/keepcrypt-pi "imports differ from $exp/keepcrypt-pi.imports (the diff is on stderr)"
    show_diff "$exp/keepcrypt-pi.imports" "$iw/imports.list"
  fi
  # 2. The deny list and partition 1's files, whether or not the lists matched.
  deny_check "$iw/root.list"
  boot_check
  # 3. The inittab.
  inittab_check "$iw/root/etc/inittab" /etc/inittab
  # 4. The kernel config: KCONFIG equals expected/linux.config, expected/kconfig-required and
  # kconfig-forbidden equal the fragment's lists, and KCONFIG keeps those lists and one hwrng
  # driver.
  if ! cmp -s "$kconfig" "$exp/linux.config"; then
    ahit Kconfig "$kconfig" "differs from $exp/linux.config (the diff is on stderr)"
    show_diff "$exp/linux.config" "$kconfig"
  fi
  lists_match "$exp" "$board/linux.fragment" "$iw" --image
  kconfig_check "$kconfig" "$kconfig" "$iw/required" "$iw/forbidden"
  # 5. Bytes: the raw image (SquashFS is compressed, so this alone would miss a marker inside
  # the root), every file of partition 1 (the VideoCore start.elf and zImage among them) and
  # every file of the root but keepcrypt-pi, which artifact_file searches below. Every ELF file
  # of the root other than keepcrypt-pi gets elf_check; a symlink is listed, not read.
  byte_scan "$img" "$img"
  (cd "$iw/boot" && find . -type f -print) | sort >"$iw/boot.files" || exit 2
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    byte_scan "$iw/boot/${p#./}" "partition-1:/${p#./}"
  done <"$iw/boot.files"
  (cd "$iw/root" && find . -type f -print) | sort >"$iw/root.files" || exit 2
  elfs=0
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    rel=/${p#./}
    [ "$rel" = /usr/bin/keepcrypt-pi ] && continue
    byte_scan "$iw/root$rel" "$rel"
    magic=$(od -An -N4 -tx1 "$iw/root$rel" | tr -d ' \n')
    if [ "$magic" = 7f454c46 ]; then
      elfs=$((elfs + 1))
      elf_check "$iw/root$rel" "$rel"
    fi
  done <"$iw/root.files"
  # 6. /usr/bin/keepcrypt-pi: the artifact rules for the Pi target (the OS import, a .symtab,
  # no RNG symbol, std's random-key path absent, with Q52's passengers allowed), no simulator
  # crate as a symbol or as bytes (one hit), and the SHA-256 given.
  sim=
  if artifact_file "$kp" /usr/bin/keepcrypt-pi; then
    sim=$(grep -E -e 'keepcrypt_pi_sim' "$iw/all" | head -n 1)
  fi
  if [ -n "$sim" ]; then
    ahit Binary /usr/bin/keepcrypt-pi "names the simulator crate: symbol $sim"
  elif grep -q -F -e "$(hexbytes keepcrypt_pi_sim)" "$iw/dump"; then
    ahit Binary /usr/bin/keepcrypt-pi 'names the simulator crate: byte string keepcrypt_pi_sim'
  fi
  got_sha=$(sha256 "$kp") || exit 2
  [ "$got_sha" = "$want_sha" ] || ahit Binary /usr/bin/keepcrypt-pi "SHA-256 $got_sha, not BIN_SHA256 $want_sha"
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check --image $img: $hits hit(s)"
    exit 1
  fi
  echo "banned-api-check --image $img: clean: the boot and root lists and keepcrypt-pi's imports equal $exp, no denied file, start.elf and fixup.dat alone, the board's cmdline.txt and config.txt, Q35's inittab, the kernel config equals $exp/linux.config and keeps the fragment's lists with one hwrng driver, no marker or test key in the image or any file, $elfs other ELF file(s) with dynamic symbols and no RNG import, and /usr/bin/keepcrypt-pi passes the artifact rules with no simulator name and SHA-256 $want_sha"
  exit 0
}

# --- Image selftest mode -------------------------------------------------------------------------

# The hit categories of the image scan, for its selftests.
icats='^(Marker|TestKey|Format|Symbol|StdRandom|OSImport|Binary|List|Deny|Boot|Inittab|Kconfig): '

# sifail MESSAGE: a control cannot be built (exit 2).
sifail() {
  printf 'banned-api-check: --selftest-image: %s\n' "$1" >&2
  exit 2
}

# write_testkey FILE: the test registry key's 32 bytes, inside other bytes, into FILE.
write_testkey() {
  octal=
  rest=$testkey
  while [ -n "$rest" ]; do
    octal=$octal$(printf '\\%03o' "0x${rest%"${rest#??}"}")
    rest=${rest#??}
  done
  printf "x$octal\n" >"$1" || exit 2
}

# build_elf_controls DIR: ELF files for the Pi target, built with the pinned toolchain alone (rustc
# --emit obj, rust-lld, llvm-objcopy; no cross compiler) from scripts/testdata/image/controls.rs:
# DIR/getrandom.so, a shared object that imports getrandom and keeps its .symtab (a stand-in for
# keepcrypt-pi and the root's libraries); DIR/sim.so, the same with a keepcrypt_pi_sim_hwrng
# symbol; DIR/rand-stripped.so, a stripped shared object that imports rand (dynamic symbols
# only); DIR/static-stripped, a stripped static executable with no symbols at all. Exit 2 if one
# cannot be built.
build_elf_controls() {
  cdir=$1
  mkdir -p "$cdir" || exit 2
  csrc=$here/testdata/image/controls.rs
  [ -f "$csrc" ] || sifail "no $csrc"
  for c in getrandom:kc_getrandom sim:kc_sim rand:kc_rand static:kc_static; do
    if ! (cd "$repo" && rustc --edition 2024 --crate-type lib --crate-name kc_control --emit obj \
      -C panic=abort -C opt-level=1 --target arm-unknown-linux-gnueabihf --cfg "${c#*:}" \
      -o "$cdir/${c%%:*}.o" "$csrc") >"$cdir/rustc.log" 2>&1; then
      sed 's/^/    /' "$cdir/rustc.log" >&2
      sifail "rustc could not build the ${c%%:*} control"
    fi
  done
  for c in getrandom sim rand; do
    "$bin/rust-lld" -flavor gnu -shared -o "$cdir/$c.so" "$cdir/$c.o" >"$cdir/lld.log" 2>&1 ||
      { sed 's/^/    /' "$cdir/lld.log" >&2; sifail "rust-lld could not link the $c control"; }
  done
  "$bin/rust-lld" -flavor gnu -e _start -o "$cdir/static" "$cdir/static.o" >"$cdir/lld.log" 2>&1 ||
    { sed 's/^/    /' "$cdir/lld.log" >&2; sifail 'rust-lld could not link the static control'; }
  mv "$cdir/rand.so" "$cdir/rand-stripped.so" && mv "$cdir/static" "$cdir/static-stripped" || exit 2
  "$bin/llvm-objcopy" --strip-all "$cdir/rand-stripped.so" && "$bin/llvm-objcopy" --strip-all "$cdir/static-stripped" ||
    sifail 'llvm-objcopy could not strip a control'
}

# si_lists IMG DIR KCONFIG: a stand-in EXPECTED_DIR at DIR from --image-lists' own output on IMG
# (its boot and root lists and import list, under their headings), KCONFIG as linux.config and the
# fragment's two lists ($fraglists/required and forbidden). Prints the binary's SHA-256 from the
# listing.
si_lists() {
  lout=$(sh "$self" --image-lists "$1" "$3" 2>&1) || { printf '%s\n' "$lout" >&2; sifail "--image-lists failed on $1"; }
  mkdir -p "$2" || exit 2
  printf '%s\n' "$lout" | awk -v dir="$2" '
    /^== / {
      out = ""
      if (index($0, "== boot files") == 1) out = dir "/boot.list"
      else if (index($0, "== root files") == 1) out = dir "/root.list"
      else if (index($0, "== keepcrypt-pi imports") == 1) out = dir "/keepcrypt-pi.imports"
      next
    }
    /^banned-api-check / { out = "" }
    out != "" { print > out }
  ' || exit 2
  cp "$3" "$2/linux.config" && cp "$fraglists/required" "$2/kconfig-required" &&
    cp "$fraglists/forbidden" "$2/kconfig-forbidden" || exit 2
  printf '%s\n' "$lout" | sed -n 's/^sha256 keepcrypt-pi \([0-9a-f]\{64\}\)$/\1/p'
}

# sicase NAME WANT-HIT IMG EXPECTED_DIR KCONFIG BIN_SHA256: --image on the four arguments, in a
# new process, must exit 1 with exactly one hit, which starts with WANT-HIT; with WANT-HIT empty
# (a control), exit 0 with no hit.
sicase() {
  sout=$(sh "$self" --image "$3" "$4" "$5" "$6" 2>&1)
  rc=$?
  got=$(printf '%s\n' "$sout" | grep -E "$icats")
  count=$(printf '%s\n' "$sout" | grep -c -E "$icats")
  ok=no
  if [ -z "$2" ]; then
    [ "$rc" -eq 0 ] && [ "$count" -eq 0 ] && ok=yes
  elif [ "$rc" -eq 1 ] && [ "$count" -eq 1 ]; then
    case $got in "$2"*) ok=yes ;; esac
  fi
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> exit %s: %s\n' "$1" "$rc" "${got:-clean}"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted exit %s with %s, got exit %s:\n' "$1" "${2:+1}${2:-0}" "${2:-no hit}" "$rc"
    printf '%s\n' "$sout" | sed 's/^/    /'
  fi
}

# si_root NAME: a fresh unpack of the image's root into $sw/NAME/root, for a mutation.
si_root() {
  mkdir -p "$sw/$1" || exit 2
  unsquashfs -no-progress -d "$sw/$1/root" "$iw/p2.img" >"$sw/$1/log" 2>&1 ||
    { sed 's/^/    /' "$sw/$1/log" >&2; sifail "unsquashfs could not unpack the root for $1"; }
}

# si_image NAME P1 [ROOT]: $sw/NAME.img from the partition-1 image P1 (the image's own, or an
# edited copy) and either ROOT, repacked with mksquashfs -no-xattrs, or the image's own partition
# 2; a fresh MBR sized to the two (image_mbr), partition 1 at the image's first sector and
# partition 2 right after it.
si_image() {
  n=$1
  p1=$2
  mkdir -p "$sw/$n" || exit 2
  if [ -n "${3-}" ]; then
    mksquashfs "$3" "$sw/$n/p2.img" -no-xattrs -noappend -all-root -no-progress >"$sw/$n/mksquashfs.log" 2>&1 ||
      { sed 's/^/    /' "$sw/$n/mksquashfs.log" >&2; sifail "mksquashfs could not repack the root for $n"; }
    p2=$sw/$n/p2.img
  else
    p2=$iw/p2.img
  fi
  c1=$(($(wc -c <"$p1") / 512))
  c2=$((($(wc -c <"$p2") + 511) / 512))
  image_mbr "$sw/$n.img" $((s1 + c1 + c2)) 55aa "0c:$s1:$c1" "83:$((s1 + c1)):$c2" -
  dd if="$p1" of="$sw/$n.img" bs=512 seek="$s1" conv=notrunc 2>/dev/null || exit 2
  dd if="$p2" of="$sw/$n.img" bs=512 seek=$((s1 + c1)) conv=notrunc 2>/dev/null || exit 2
}

# si_boot NAME FILE TEXT: $sw/NAME/p1.img, a copy of partition 1 with its FILE replaced by TEXT
# (mcopy -o into the copy).
si_boot() {
  mkdir -p "$sw/$1" || exit 2
  cp "$iw/p1.img" "$sw/$1/p1.img" && printf '%s\n' "$3" >"$sw/$1/$2" || exit 2
  MTOOLS_SKIP_CHECK=1 mcopy -o -i "$sw/$1/p1.img" "$sw/$1/$2" "::$2" >"$sw/$1/mcopy.log" 2>&1 ||
    { sed 's/^/    /' "$sw/$1/mcopy.log" >&2; sifail "mcopy could not replace $2 for $1"; }
}

# si_kconfig NAME SED-EXPRESSION: $sw/NAME/linux.config, KCONFIG with SED-EXPRESSION applied.
si_kconfig() {
  mkdir -p "$sw/$1" || exit 2
  sed -e "$2" "$kconfig" >"$sw/$1/linux.config" || exit 2
}

# selftest_image IMG KCONFIG: the image scan's positive controls on the built image (see "Image
# selftest mode" in the header).
selftest_image() {
  imode=--selftest-image
  img=$1
  kconfig=$2
  readable "$kconfig" --selftest-image
  for tool in mcopy mdir unsquashfs mksquashfs; do
    command -v "$tool" >/dev/null 2>&1 ||
      sifail "no $tool on PATH (the build's host tools are in KC_WORK/out/host/bin)"
  done
  toolchain_bin
  for t in llvm-objcopy rust-lld; do
    [ -x "$bin/$t" ] || sifail "no $t in $bin (rust-toolchain.toml lists llvm-tools-preview)"
  done
  sw=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-selftest-image.XXXXXX") || exit 2
  trap 'rm -rf "$sw"' EXIT
  trap 'exit 2' HUP INT TERM
  image_unpack "$img"
  trap 'rm -rf "$iw" "$sw"' EXIT
  image_imports
  fraglists=$sw
  fragment_lists "$here/../pi/os/board/pizero/linux.fragment" "$sw/required" "$sw/forbidden" --selftest-image
  build_elf_controls "$sw/elf"
  pass=0
  fail=0
  # The control: the image passes against its own lists.
  sha=$(si_lists "$img" "$sw/clean" "$kconfig")
  sicase 'selftest-image-clean-image' '' "$img" "$sw/clean" "$kconfig" "$sha"
  # Mutations of the root (its lists stand in for expected/, so only the named rule can fail).
  si_root marker
  printf 'KC_TEST_SOURCE_DO_NOT_SHIP\n' >"$sw/marker/root/etc/kc-canary.txt" || exit 2
  si_image marker "$iw/p1.img" "$sw/marker/root"
  sha=$(si_lists "$sw/marker.img" "$sw/marker/expected" "$kconfig")
  sicase 'selftest-image-marker-in-a-text-file' 'Marker: /etc/kc-canary.txt: KC_TEST_SOURCE_DO_NOT_SHIP' \
    "$sw/marker.img" "$sw/marker/expected" "$kconfig" "$sha"
  si_root testkey
  write_testkey "$sw/testkey/root/etc/kc-canary.bin"
  si_image testkey "$iw/p1.img" "$sw/testkey/root"
  sha=$(si_lists "$sw/testkey.img" "$sw/testkey/expected" "$kconfig")
  sicase 'selftest-image-test-key-file' "TestKey: /etc/kc-canary.bin: the test registry public key $testkey" \
    "$sw/testkey.img" "$sw/testkey/expected" "$kconfig" "$sha"
  si_root rand
  cp "$sw/elf/rand-stripped.so" "$sw/rand/root/lib/libkc-canary.so.1" || exit 2
  si_image rand "$iw/p1.img" "$sw/rand/root"
  sha=$(si_lists "$sw/rand.img" "$sw/rand/expected" "$kconfig")
  sicase 'selftest-image-stripped-elf-importing-rand' 'Symbol: /lib/libkc-canary.so.1: undefined rand' \
    "$sw/rand.img" "$sw/rand/expected" "$kconfig" "$sha"
  si_root static
  cp "$sw/elf/static-stripped" "$sw/static/root/usr/bin/kc-canary" || exit 2
  si_image static "$iw/p1.img" "$sw/static/root"
  sha=$(si_lists "$sw/static.img" "$sw/static/expected" "$kconfig")
  sicase 'selftest-image-stripped-static-elf' 'Format: /usr/bin/kc-canary: an ELF with no dynamic symbol table' \
    "$sw/static.img" "$sw/static/expected" "$kconfig" "$sha"
  si_root sh
  ln -s busybox "$sw/sh/root/bin/sh" || exit 2
  si_image sh "$iw/p1.img" "$sw/sh/root"
  sha=$(si_lists "$sw/sh.img" "$sw/sh/expected" "$kconfig")
  sicase 'selftest-image-bin-sh' 'Deny: /bin/sh: a shell or login program, sh' \
    "$sw/sh.img" "$sw/sh/expected" "$kconfig" "$sha"
  si_root stripped
  "$bin/llvm-objcopy" --strip-all "$sw/stripped/root/usr/bin/keepcrypt-pi" || sifail 'llvm-objcopy could not strip keepcrypt-pi'
  si_image stripped "$iw/p1.img" "$sw/stripped/root"
  sha=$(si_lists "$sw/stripped.img" "$sw/stripped/expected" "$kconfig")
  sicase 'selftest-image-stripped-keepcrypt-pi' 'Format: /usr/bin/keepcrypt-pi: a stripped file with no symbol table (.symtab)' \
    "$sw/stripped.img" "$sw/stripped/expected" "$kconfig" "$sha"
  si_root urandom
  printf '/dev/urandom' >>"$sw/urandom/root/usr/bin/keepcrypt-pi" || exit 2
  si_image urandom "$iw/p1.img" "$sw/urandom/root"
  sha=$(si_lists "$sw/urandom.img" "$sw/urandom/expected" "$kconfig")
  sicase 'selftest-image-urandom-in-keepcrypt-pi' 'StdRandom: /usr/bin/keepcrypt-pi: byte string /dev/urandom' \
    "$sw/urandom.img" "$sw/urandom/expected" "$kconfig" "$sha"
  # The binary's hash.
  sha=$(si_lists "$img" "$sw/hash" "$kconfig")
  sicase 'selftest-image-wrong-binary-hash' 'Binary: /usr/bin/keepcrypt-pi: SHA-256 ' \
    "$img" "$sw/hash" "$kconfig" "$(printf '%064d' 0)"
  # Partition 1: cmdline.txt and config.txt differ from the board files.
  si_boot console cmdline.txt "$(cat "$iw/boot/cmdline.txt") console=ttyAMA0,115200"
  si_image console "$sw/console/p1.img"
  sha=$(si_lists "$sw/console.img" "$sw/console/expected" "$kconfig")
  sicase 'selftest-image-console-in-cmdline' 'Boot: partition-1:/cmdline.txt: differs from pi/os/board/pizero/cmdline.txt' \
    "$sw/console.img" "$sw/console/expected" "$kconfig" "$sha"
  si_boot gpumem config.txt "$(cat "$iw/boot/config.txt")
gpu_mem=16"
  si_image gpumem "$sw/gpumem/p1.img"
  sha=$(si_lists "$sw/gpumem.img" "$sw/gpumem/expected" "$kconfig")
  sicase 'selftest-image-gpu-mem-16-config-with-start-elf' 'Boot: partition-1:/config.txt: differs from pi/os/board/pizero/config.txt' \
    "$sw/gpumem.img" "$sw/gpumem/expected" "$kconfig" "$sha"
  # The kernel config: one line off expected/linux.config (which stays the build's), then three
  # mutations that expected/linux.config follows, so the forbidden, hwrng and required rules are
  # what fire.
  si_kconfig offline '$a\
# one line off (selftest-image)'
  sha=$(si_lists "$img" "$sw/offline/expected" "$kconfig")
  sicase 'selftest-image-kconfig-one-line-off' "Kconfig: $sw/offline/linux.config: differs from $sw/offline/expected/linux.config" \
    "$img" "$sw/offline/expected" "$sw/offline/linux.config" "$sha"
  si_kconfig net '/^# CONFIG_NET is not set$/d
$a\
CONFIG_NET=y'
  sha=$(si_lists "$img" "$sw/net/expected" "$sw/net/linux.config")
  sicase 'selftest-image-kconfig-net' "Kconfig: $sw/net/linux.config: forbidden option CONFIG_NET is set (=y)" \
    "$img" "$sw/net/expected" "$sw/net/linux.config" "$sha"
  si_kconfig hwrng '$a\
CONFIG_HW_RANDOM_CANARY=y'
  sha=$(si_lists "$img" "$sw/hwrng/expected" "$sw/hwrng/linux.config")
  sicase 'selftest-image-kconfig-two-hwrng-drivers' \
    "Kconfig: $sw/hwrng/linux.config: a hwrng driver other than BCM2835 is set: CONFIG_HW_RANDOM_CANARY=y" \
    "$img" "$sw/hwrng/expected" "$sw/hwrng/linux.config" "$sha"
  si_kconfig missing 's/^CONFIG_LEDS_TRIGGER_ACTPWR=y$/# CONFIG_LEDS_TRIGGER_ACTPWR is not set/'
  sha=$(si_lists "$img" "$sw/missing/expected" "$sw/missing/linux.config")
  sicase 'selftest-image-kconfig-missing-required-option' \
    "Kconfig: $sw/missing/linux.config: required option CONFIG_LEDS_TRIGGER_ACTPWR is not =y" \
    "$img" "$sw/missing/expected" "$sw/missing/linux.config" "$sha"
  echo "selftest-image: $pass passed, $fail failed"
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

# --- Workflow selftest ---------------------------------------------------------------------------

# wexpect NAME DIR WANT: run the workflow check on DIR in a new process. WANT=clean needs exit 0
# and no hit; WANT=error needs exit 2; any other WANT is the one file the hit must name (as
# DIR/<file>): exit 1 and exactly one "Workflow: DIR/<file>:<line>: <text>" line, where <text> is
# line <line> of the file as it stands, or a "missing ..." message.
wexpect() {
  out=$(sh "$self" --workflows "$2" 2>&1)
  rc=$?
  hit=$(printf '%s\n' "$out" | grep -E '^Workflow: ')
  count=$(printf '%s\n' "$out" | grep -c -E '^Workflow: ')
  ok=no
  if [ "$3" = clean ]; then
    [ "$rc" -eq 0 ] && [ "$count" -eq 0 ] && ok=yes
  elif [ "$3" = error ]; then
    [ "$rc" -eq 2 ] && ok=yes && hit="exit 2: ${out##*$nl}"
  elif [ "$rc" -eq 1 ] && [ "$count" -eq 1 ]; then
    case $hit in
      "Workflow: $2/$3:"[0-9]*)
        at=${hit#"Workflow: $2/$3:"}
        case ${at#*: } in
          'missing '*) ok=yes ;;
          *) [ "${at#*: }" = "$(sed -n "${at%%:*}p" "$2/$3")" ] && ok=yes ;;
        esac
        ;;
    esac
  fi
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> %s\n' "$1" "${hit:-clean}"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted %s, got exit %s:\n' "$1" "$3" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

# Every directory of scripts/testdata/workflows/: a workflow-* case holds one entropy-*.yml or
# entropy-*.yaml that must give exactly one hit, a clean-* case any number that must all pass.
# Then the errors: a directory with no entropy-*.yml or .yaml, and a missing directory.
workflows_selftest() {
  wseen=
  for fx in "$here/testdata/workflows"/*/; do
    [ -d "$fx" ] || continue
    fx=${fx%/}
    name=${fx##*/}
    case $name in
      workflow-*) want=hit ;;
      clean-*) want=clean ;;
      *) fail=$((fail + 1)); printf 'FAIL %s: unknown prefix\n' "$name"; continue ;;
    esac
    wseen="$wseen $want"
    if [ "$want" = hit ]; then
      file=$(cd "$fx" && find . -type f ! -name .DS_Store) || exit 2
      case $file in
        ./entropy-*.yml | ./entropy-*.yaml) ;;
        *) fail=$((fail + 1)); printf 'FAIL %s: a fixture holds exactly one entropy-*.yml or .yaml\n' "$name"; continue ;;
      esac
      want=${file#./}
    fi
    wexpect "$name" "$fx" "$want"
  done
  for want in hit clean; do
    case "$wseen " in *" $want "*) ;; *) fail=$((fail + 1)); echo "FAIL no $want workflow fixture" ;; esac
  done
  i=$((i + 1))
  d=$tmp/$i
  mkdir -p "$d" || exit 2
  : >"$d/other.yml" || exit 2
  wexpect 'workflow-error-no-entropy-yml' "$d" error
  wexpect 'workflow-error-missing-dir' "$tmp/absent" error
}

# --- Image lists selftest ------------------------------------------------------------------------

# iexpect NAME TEXT ARG...: run --image-lists ARG... in a new process; it must exit 2 with TEXT in
# its output. ixexpect MODE NAME TEXT ARG... does the same for another image mode.
iexpect() {
  ixexpect --image-lists "$@"
}

ixexpect() {
  imd=$1
  iname=$2
  want=$3
  shift 3
  out=$(sh "$self" "$imd" "$@" 2>&1)
  rc=$?
  ok=no
  if [ "$rc" -eq 2 ]; then
    case $out in *"$want"*) ok=yes ;; esac
  fi
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> exit 2: %s\n' "$iname" "${out##*$nl}"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted exit 2 with "%s", got exit %s:\n' "$iname" "$want" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

# le32 N: N as four little-endian bytes.
le32() {
  printf "$(printf '\\%03o\\%03o\\%03o\\%03o' $(($1 & 255)) $(($1 >> 8 & 255)) $(($1 >> 16 & 255)) $(($1 >> 24 & 255)))"
}

# image_mbr FILE SECTORS SIG ENTRY1 ENTRY2 ENTRY3 [ENTRY4]: FILE, SECTORS zero sectors with an MBR
# in the first: each ENTRY is TYPE:FIRST:COUNT (TYPE in hex) or - for an empty entry, entry 4 is
# empty when not given, and SIG is the two bytes at 510 in hex.
image_mbr() {
  dd if=/dev/zero of="$1" bs=512 count="$2" 2>/dev/null || exit 2
  for e in "$4" "$5" "$6" "${7:--}"; do
    case $e in
      -) printf '\000\000\000\000\000\000\000\000' && printf '\000\000\000\000\000\000\000\000' ;;
      *)
        r=${e#*:}
        printf '\000\000\000\000' && printf "\\$(printf '%03o' $((0x${e%%:*})))" &&
          printf '\000\000\000' && le32 "${r%%:*}" && le32 "${r#*:}"
        ;;
    esac
  done >"$1.mbr" || exit 2
  printf "\\$(printf '%03o' $((0x${3%??})))\\$(printf '%03o' $((0x${3#??})))" >>"$1.mbr" || exit 2
  dd if="$1.mbr" of="$1" bs=1 seek=446 conv=notrunc 2>/dev/null || exit 2
}

# Every refusal that comes before the host tools, so these run on any machine: the image's
# layout (16 sectors: partition 1 FAT32 at sectors 1-4, partition 2 Linux at 5-12) is accepted
# up to its missing SquashFS magic, and each change to it is refused. A real image's lists come
# from the image workflow, which has the build's host tools.
image_lists_selftest() {
  a=$tmp/image
  mkdir -p "$a" || exit 2
  k=$a/linux.config
  echo 'CONFIG_HW_RANDOM_BCM2835=y' >"$k" || exit 2
  iexpect 'image-lists-error-usage' 'usage:' "$a/x.img"
  image_mbr "$a/layout.img" 16 55aa 0c:1:4 83:5:8 -
  iexpect 'image-lists-error-missing-kconfig' "cannot read $a/absent.config" "$a/layout.img" "$a/absent.config"
  iexpect 'image-lists-error-missing-image' "cannot read $a/absent.img" "$a/absent.img" "$k"
  iexpect 'image-lists-layout-without-squashfs-magic' \
    "$a/layout.img: partition 2 does not start with the SquashFS magic hsqs" "$a/layout.img" "$k"
  # Partition 2 may end on the image's last sector: the layout checks pass it to the magic.
  image_mbr "$a/to-the-end.img" 16 55aa 0c:1:4 83:5:11 -
  iexpect 'image-lists-partition-2-to-the-last-sector' \
    "$a/to-the-end.img: partition 2 does not start with the SquashFS magic hsqs" "$a/to-the-end.img" "$k"
  # The layout with the magic is accepted up to the host tools: here a PATH that holds only the
  # tools the checks before them use, and no mcopy.
  image_mbr "$a/tools.img" 16 55aa 0c:1:4 83:5:8 -
  printf hsqs | dd of="$a/tools.img" bs=512 seek=5 conv=notrunc 2>/dev/null || exit 2
  mkdir "$a/bin" || exit 2
  for t in basename dirname wc dd od awk tr mktemp rm; do
    ln -s "$(command -v "$t")" "$a/bin/$t" || exit 2
  done
  shell=$(command -v sh) || exit 2
  out=$(PATH=$a/bin "$shell" "$self" --image-lists "$a/tools.img" "$k" 2>&1)
  rc=$?
  want="$a/tools.img: no mcopy on PATH (the build's host tools are in KC_WORK/out/host/bin)"
  if [ "$rc" -eq 2 ] && [ "$out" = "banned-api-check: --image-lists: $want" ]; then
    pass=$((pass + 1))
    printf 'PASS image-lists-layout-with-magic-needs-the-host-tools -> exit 2: %s\n' "$out"
  else
    fail=$((fail + 1))
    printf 'FAIL image-lists-layout-with-magic-needs-the-host-tools: wanted exit 2 with "%s", got exit %s:\n' "$want" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
  dd if="$a/layout.img" of="$a/short.img" bs=100 count=1 2>/dev/null || exit 2
  iexpect 'image-lists-shorter-than-mbr' "$a/short.img: 100 bytes, shorter than an MBR (512)" "$a/short.img" "$k"
  # NAME|SIG ENTRY1 ENTRY2 ENTRY3 [ENTRY4]|REASON
  for case in 'no-boot-signature|0000 0c:1:4 83:5:8 -|no MBR boot signature (55 aa at byte 510)' \
    'boot-signature-55-only|5500 0c:1:4 83:5:8 -|no MBR boot signature (55 aa at byte 510)' \
    'partition-1-linux|55aa 83:1:4 83:5:8 -|partition 1 has type 0x83, not FAT32 with LBA (0x0c)' \
    'partition-2-fat|55aa 0c:1:4 0c:5:8 -|partition 2 has type 0x0c, not Linux (0x83)' \
    'third-partition|55aa 0c:1:4 83:5:8 83:13:2|partition entry 3 is not empty' \
    'fourth-partition|55aa 0c:1:4 83:5:8 - 83:13:2|partition entry 4 is not empty' \
    'partition-1-empty|55aa 0c:1:0 83:5:8 -|partition 1 is empty' \
    'partition-1-at-sector-0|55aa 0c:0:4 83:5:8 -|partition 1 starts at sector 0, the MBR' \
    'partition-2-past-the-end|55aa 0c:1:4 83:5:20 -|partition 2 ends at sector 25, past the image (16 sectors)' \
    'partition-2-one-past-the-end|55aa 0c:1:4 83:5:12 -|partition 2 ends at sector 17, past the image (16 sectors)' \
    'partition-2-inside-partition-1|55aa 0c:1:4 83:3:8 -|partition 2 (first sector 3) does not start after partition 1 (sectors 1-4)'; do
    name=${case%%|*}
    rest=${case#*|}
    # SIG and the three or four entries, split on purpose.
    set -- ${rest%%|*}
    image_mbr "$a/$name.img" 16 "$@"
    iexpect "image-lists-$name" "$a/$name.img: ${rest#*|}" "$a/$name.img" "$k"
  done
  image_lists_stub_selftest
}

# The listing itself, with stub host tools on PATH and a stub rustc whose sysroot holds a stub
# llvm-nm, on the image's layout with the magic: the stub mcopy extracts two files and a
# directory, mdir prints two lines, unsquashfs -lln prints a fixed transcript (a directory, a
# setuid file, a symlink, a device with its "major,  minor", a name with spaces and a date in it)
# and unpacks a stub keepcrypt-pi, and llvm-nm prints its imports out of order with a duplicate.
# The whole output must be exactly the expected one, SHA-256s included; then a transcript line
# with no date is refused.
image_lists_stub_selftest() {
  st=$a/stub
  mkdir -p "$st/bin" "$st/sysroot/lib/rustlib/stubhost/bin" || exit 2
  printf '#!/bin/sh\ncase $1 in --print) echo %s/sysroot ;; -vV) echo "host: stubhost" ;; esac\n' \
    "$st" >"$st/bin/rustc" || exit 2
  printf '%s\n' '#!/bin/sh' 'for d; do :; done' \
    'mkdir "${d}overlays" && echo a >"${d}config.txt" && echo b >"${d}start.elf"' >"$st/bin/mcopy" || exit 2
  printf '%s\n' '#!/bin/sh' 'echo " Volume in drive : has no label"' \
    'echo "config   txt         2 2026-09-04  15:16  config.txt"' >"$st/bin/mdir" || exit 2
  printf '%s\n' '#!/bin/sh' "case \$1 in -lln) cat '$st/lln' ;;" \
    '*) mkdir -p "$3/usr/bin" && echo stub >"$3/usr/bin/keepcrypt-pi" ;; esac' >"$st/bin/unsquashfs" || exit 2
  printf '%s\n' '#!/bin/sh' "printf '%s\\n' '         U getrandom@GLIBC_2.25' '         w __gmon_start__' \\" \
    "  '         U abort@GLIBC_2.4' '         U abort@GLIBC_2.4'" >"$st/sysroot/lib/rustlib/stubhost/bin/llvm-nm" ||
    exit 2
  chmod +x "$st/bin/rustc" "$st/bin/mcopy" "$st/bin/mdir" "$st/bin/unsquashfs" \
    "$st/sysroot/lib/rustlib/stubhost/bin/llvm-nm" || exit 2
  printf '%s\n' 'drwxr-xr-x 0/0                    81 2026-09-04 15:16 squashfs-root' \
    '-rwsr-xr-x 0/0                 81234 2026-09-04 15:16 squashfs-root/bin/busybox' \
    'lrwxrwxrwx 0/0                     7 2026-09-04 15:16 squashfs-root/bin/mount -> busybox' \
    'crw-r--r-- 0/0                 5,  1 2026-09-04 15:16 squashfs-root/dev/console' \
    '-rw-r--r-- 0/0                     5 2026-09-04 15:16 squashfs-root/etc/a file 2026-01-01 10:10 x' \
    '-rwxr-xr-x 0/0               1234567 2026-09-04 15:16 squashfs-root/usr/bin/keepcrypt-pi' >"$st/lln" ||
    exit 2
  img=$a/tools.img
  want="== banned-api-check --image-lists $img $k
== partition table (MBR)
disk signature 0x00000000
partition 1: type 0x0c, boot flag 0x00, first sector 1, 4 sectors
partition 2: type 0x83, boot flag 0x00, first sector 5, 8 sectors
== SHA-256
sha256 image 32ce8169e9d2f23385fbe44443f32409d3b75e809cda11c12b1b99ceddce52e8
sha256 partition-1 e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad
sha256 partition-2 719cbc3103ceb5bda7ee7837616e3a7a0fb531bcd07160aa8a6d0fd1e96d822d
sha256 keepcrypt-pi 25cf54c697a69632c5952486ec189be371ddddc422bca30910f17b2c3a0ba31d
== boot files (partition 1, FAT: path, type)
/ dir
/config.txt file
/overlays dir
/start.elf file
== boot mdir -a (partition 1)
 Volume in drive : has no label
config   txt         2 2026-09-04  15:16  config.txt
== root files (partition 2, SquashFS: path, mode, link target)
/ drwxr-xr-x
/bin/busybox -rwsr-xr-x
/bin/mount lrwxrwxrwx -> busybox
/dev/console crw-r--r--
/etc/a file 2026-01-01 10:10 x -rw-r--r--
/usr/bin/keepcrypt-pi -rwxr-xr-x
== keepcrypt-pi imports (/usr/bin/keepcrypt-pi, llvm-nm -D -u: type, symbol)
U abort@GLIBC_2.4
U getrandom@GLIBC_2.25
w __gmon_start__
== kernel config (KCONFIG)
CONFIG_HW_RANDOM_BCM2835=y
banned-api-check --image-lists $img: listed, not scanned"
  out=$(PATH="$st/bin:$PATH" sh "$self" --image-lists "$img" "$k" 2>&1)
  rc=$?
  if [ "$rc" -eq 0 ] && [ "$out" = "$want" ]; then
    pass=$((pass + 1))
    echo 'PASS image-lists-stub-tools-listing -> exit 0: the expected listing'
  else
    fail=$((fail + 1))
    printf 'FAIL image-lists-stub-tools-listing: wanted exit 0 and the expected listing, got exit %s:\n' "$rc"
    printf '%s\n' "$out" >"$st/got"
    printf '%s\n' "$want" >"$st/want"
    diff "$st/want" "$st/got" | sed 's/^/    /'
  fi
  echo '-rw-r--r-- 0/0 5 squashfs-root/etc/no-date' >>"$st/lln" || exit 2
  opath=$PATH
  PATH=$st/bin:$PATH
  iexpect 'image-lists-stub-tools-unreadable-root-line' \
    "$img: unsquashfs -lln printed a line this script cannot read: -rw-r--r-- 0/0 5 squashfs-root/etc/no-date" \
    "$img" "$k"
  PATH=$opath
}

# --- OS configuration selftest -------------------------------------------------------------------

# oexpect NAME DIR WANT [TEXT]: run --os-config DIR in a new process. WANT=clean needs exit 0 and
# no hit, WANT=error exit 2 with TEXT in the output, any other WANT exit 1 and exactly one hit, of
# category WANT.
oexpect() {
  out=$(sh "$self" --os-config "$2" 2>&1)
  rc=$?
  ocats='^(Inittab|Fstab|Cmdline|ConfigTxt|Kconfig|BusyBox): '
  hit=$(printf '%s\n' "$out" | grep -E "$ocats")
  count=$(printf '%s\n' "$out" | grep -c -E "$ocats")
  ok=no
  if [ "$3" = clean ]; then
    [ "$rc" -eq 0 ] && [ "$count" -eq 0 ] && ok=yes
  elif [ "$3" = error ]; then
    if [ "$rc" -eq 2 ]; then
      case $out in *"${4:-}"*) ok=yes; hit="exit 2: ${out##*$nl}" ;; esac
    fi
  elif [ "$rc" -eq 1 ] && [ "$count" -eq 1 ]; then
    case $hit in "$3: "*) ok=yes ;; esac
  fi
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> %s\n' "$1" "${hit:-clean}"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted %s %s, got exit %s:\n' "$1" "$3" "${4:-}" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

# Every directory of scripts/testdata/os-config/ is a pi/os-shaped tree (board/pizero/... and
# expected/...). clean-pizero is the whole tree, which must pass: the board's real inittab, fstab,
# cmdline.txt and config.txt, a BusyBox config of the lines the check reads, a short fragment of
# both kinds of line and an expected/ that matches it. Every osconfig-<category>-* holds the one
# file of that tree it changes, copied over a copy of clean-pizero, and must fail with exactly one
# hit of its category. Then the errors, built here: no expected/, a missing or an empty file, a
# fragment line of another kind, and a path that is not a directory.
os_config_selftest() {
  ofx=$here/testdata/os-config
  clean=$ofx/clean-pizero
  if [ ! -d "$clean" ]; then
    fail=$((fail + 1))
    echo 'FAIL no clean-pizero os-config fixture'
    return
  fi
  oseen=
  for fx in "$ofx"/*/; do
    [ -d "$fx" ] || continue
    fx=${fx%/}
    name=${fx##*/}
    case $name in
      clean-*) want=clean ;;
      osconfig-inittab-*) want=Inittab ;;
      osconfig-fstab-*) want=Fstab ;;
      osconfig-cmdline-*) want=Cmdline ;;
      osconfig-config-txt-*) want=ConfigTxt ;;
      osconfig-kconfig-*) want=Kconfig ;;
      osconfig-busybox-*) want=BusyBox ;;
      *) fail=$((fail + 1)); printf 'FAIL %s: unknown prefix\n' "$name"; continue ;;
    esac
    oseen="$oseen $want"
    d=$tmp/os-config/$name
    mkdir -p "$d" && cp -R "$clean/." "$d/" || exit 2
    if [ "$want" != clean ]; then
      file=$(cd "$fx" && find . -type f ! -name .DS_Store) || exit 2
      case $file in
        '' | *"$nl"*) fail=$((fail + 1)); printf 'FAIL %s: a fixture holds exactly one file\n' "$name"; continue ;;
      esac
    fi
    [ "$name" = clean-pizero ] || cp -R "$fx/." "$d/" || exit 2
    oexpect "$name" "$d" "$want"
  done
  for want in clean Inittab Fstab Cmdline ConfigTxt Kconfig BusyBox; do
    case "$oseen " in *" $want "*) ;; *) fail=$((fail + 1)); echo "FAIL no $want os-config fixture" ;; esac
  done
  d=$tmp/os-config/errors
  rm -rf "$d" && mkdir -p "$d" && cp -R "$clean/." "$d/" || exit 2
  mv "$d/expected" "$d/expected.away" || exit 2
  oexpect 'osconfig-error-no-expected' "$d" error 'has no expected/ directory'
  mv "$d/expected.away" "$d/expected" || exit 2
  mv "$d/board/pizero/rootfs-overlay/etc/fstab" "$d/fstab.away" || exit 2
  oexpect 'osconfig-error-missing-fstab' "$d" error "cannot read $d/board/pizero/rootfs-overlay/etc/fstab, or it is empty"
  mv "$d/fstab.away" "$d/board/pizero/rootfs-overlay/etc/fstab" || exit 2
  cp "$d/expected/kconfig-required" "$d/required.away" && : >"$d/expected/kconfig-required" || exit 2
  oexpect 'osconfig-error-empty-kconfig-required' "$d" error "cannot read $d/expected/kconfig-required, or it is empty"
  mv "$d/required.away" "$d/expected/kconfig-required" || exit 2
  cp "$d/board/pizero/linux.fragment" "$d/fragment.away" && echo 'CONFIG_I2C=m' >>"$d/board/pizero/linux.fragment" || exit 2
  oexpect 'osconfig-error-fragment-line-of-another-kind' "$d" error 'a fragment line of another kind at line'
  mv "$d/fragment.away" "$d/board/pizero/linux.fragment" || exit 2
  oexpect 'osconfig-error-not-a-directory' "$d/board/pizero/cmdline.txt" error 'is not a directory'
}

# --- Image scan selftest -------------------------------------------------------------------------

# The scan's refusals, which run on any machine, then the scan itself on a stub image: the image
# lists' layout with the SquashFS magic, stub host tools (mcopy extracts $KC_STUB/boot, unsquashfs
# lists $KC_STUB/root as the real tool does and unpacks it), the real toolchain, and ELF files
# built for the Pi target with it (build_elf_controls) standing in for keepcrypt-pi, BusyBox and
# the libraries. The stub tree passes against lists made from it (the control); then each rule
# gets a mutation of a fresh copy of the tree, of the kernel config or of the expected lists,
# which must fail with exactly that one hit (the lists are remade from the mutated tree where the
# mutation changes them, so only the named rule can fail).
image_selftest() {
  a=$tmp/image-scan
  mkdir -p "$a/expected" || exit 2
  for f in boot.list root.list linux.config kconfig-required kconfig-forbidden keepcrypt-pi.imports; do
    echo x >"$a/expected/$f" || exit 2
  done
  k=$a/linux.config
  echo 'CONFIG_HW_RANDOM_BCM2835=y' >"$k" || exit 2
  zero=$(printf '%064d' 0)
  image_mbr "$a/layout.img" 16 55aa 0c:1:4 83:5:8 -
  ixexpect --image 'image-error-usage' 'usage:' "$a/layout.img" "$a/expected" "$k"
  ixexpect --image 'image-error-bad-sha256' 'BIN_SHA256 is not 64 lowercase hex digits: abc' "$a/layout.img" "$a/expected" "$k" abc
  ixexpect --image 'image-error-missing-expected-dir' "EXPECTED_DIR $a/absent is not a directory" "$a/layout.img" "$a/absent" "$k" "$zero"
  rm "$a/expected/root.list" || exit 2
  ixexpect --image 'image-error-missing-expected-file' "cannot read $a/expected/root.list, or it is empty" "$a/layout.img" "$a/expected" "$k" "$zero"
  : >"$a/expected/root.list" || exit 2
  ixexpect --image 'image-error-empty-expected-list' "cannot read $a/expected/root.list, or it is empty" "$a/layout.img" "$a/expected" "$k" "$zero"
  echo x >"$a/expected/root.list" || exit 2
  ixexpect --image 'image-error-missing-kconfig' "cannot read $a/absent.config, or it is empty" "$a/layout.img" "$a/expected" "$a/absent.config" "$zero"
  ixexpect --image 'image-error-missing-image' "--image: cannot read $a/absent.img" "$a/absent.img" "$a/expected" "$k" "$zero"
  ixexpect --image 'image-layout-without-squashfs-magic' \
    "--image: $a/layout.img: partition 2 does not start with the SquashFS magic hsqs" "$a/layout.img" "$a/expected" "$k" "$zero"
  ixexpect --selftest-image 'selftest-image-error-usage' 'usage:' "$a/layout.img"
  ixexpect --selftest-image 'selftest-image-error-missing-kconfig' "cannot read $a/absent.config, or it is empty" "$a/layout.img" "$a/absent.config"
  # The layout with the magic is accepted up to the host tools, as in --image-lists.
  image_mbr "$a/tools.img" 16 55aa 0c:1:4 83:5:8 -
  printf hsqs | dd of="$a/tools.img" bs=512 seek=5 conv=notrunc 2>/dev/null || exit 2
  mkdir "$a/bin" || exit 2
  for t in basename dirname wc dd od awk tr mktemp rm grep cat cd; do
    p=$(command -v "$t") || continue
    [ -x "$p" ] && ln -s "$p" "$a/bin/$t"
  done
  shell=$(command -v sh) || exit 2
  for m in --image --selftest-image; do
    case $m in
      --image) out=$(PATH=$a/bin "$shell" "$self" --image "$a/tools.img" "$a/expected" "$k" "$zero" 2>&1) ;;
      *) out=$(PATH=$a/bin "$shell" "$self" --selftest-image "$a/tools.img" "$k" 2>&1) ;;
    esac
    rc=$?
    want="banned-api-check: $m: no mcopy on PATH (the build's host tools are in KC_WORK/out/host/bin)"
    case $m in --image) want="banned-api-check: --image: $a/tools.img: no mcopy on PATH (the build's host tools are in KC_WORK/out/host/bin)" ;; esac
    if [ "$rc" -eq 2 ] && [ "$out" = "$want" ]; then
      pass=$((pass + 1))
      printf 'PASS %s-layout-with-magic-needs-the-host-tools -> exit 2: %s\n' "${m#--}" "$out"
    else
      fail=$((fail + 1))
      printf 'FAIL %s-layout-with-magic-needs-the-host-tools: wanted exit 2 with "%s", got exit %s:\n' "${m#--}" "$want" "$rc"
      printf '%s\n' "$out" | sed 's/^/    /'
    fi
  done
  image_stub_scan_selftest
}

# stub_tree NAME: $tree, a fresh copy of the pristine stub tree ($st/tree), which the stub tools
# read through KC_STUB, and $kc, the pristine kernel config.
stub_tree() {
  tree=$st/cases/$1
  mkdir -p "$st/cases" && cp -RPp "$st/tree" "$tree" || exit 2
  KC_STUB=$tree
  export KC_STUB
  kc=$st/linux.config
}

# stub_case NAME WANT-HIT [SHA]: lists remade from $tree as it stands (and $kc as the kernel
# config), then the scan, which must give the one hit WANT-HIT (empty: clean), with the binary's
# SHA-256 from the listing unless SHA is given.
stub_case() {
  sha=$(si_lists "$img" "$tree/expected" "$kc")
  [ -n "${3-}" ] && sha=$3
  sicase "image-stub-$1" "$2" "$img" "$tree/expected" "$kc" "$sha"
}

image_stub_scan_selftest() {
  st=$a/stub
  mkdir -p "$st/bin" "$st/tree/boot" || exit 2
  toolchain_bin
  build_elf_controls "$st/elf"
  # The stub tools, driven by KC_STUB. mcopy: the directory given last gets $KC_STUB/boot's files.
  # unsquashfs -lln: $KC_STUB/root listed as the real tool lists an image (mode, owner, size, date,
  # time, squashfs-root path, a link's target); otherwise the tree copied to the -d directory.
  cat >"$st/bin/mcopy" <<'EOF'
#!/bin/sh
for d; do :; done
cp -R "$KC_STUB/boot/." "$d"
EOF
  cat >"$st/bin/mdir" <<'EOF'
#!/bin/sh
echo " Volume in drive : has no label"
EOF
  cat >"$st/bin/unsquashfs" <<'EOF'
#!/bin/sh
case $1 in
  -lln)
    cd "$KC_STUB/root" || exit 1
    find . | LC_ALL=C sort | while IFS= read -r p; do
      m=$(ls -ld "$p" | cut -c1-10)
      case $p in .) n=squashfs-root ;; *) n=squashfs-root/${p#./} ;; esac
      if [ -h "$p" ]; then
        printf '%s 0/0 7 2026-09-04 15:16 %s -> %s\n' "$m" "$n" "$(readlink "$p")"
      else
        printf '%s 0/0 1 2026-09-04 15:16 %s\n' "$m" "$n"
      fi
    done
    ;;
  *) cp -RP "$KC_STUB/root" "$3" ;;
esac
EOF
  chmod +x "$st/bin/mcopy" "$st/bin/mdir" "$st/bin/unsquashfs" || exit 2
  # The pristine tree: the root the image has (BusyBox, keepcrypt-pi, the loader and libraries as
  # the getrandom control, the overlay's inittab and fstab, os-release, the mount points, /tmp
  # sticky) and partition 1's seven files (the board's cmdline.txt and config.txt, the rest text).
  r=$st/tree/root
  mkdir -p "$r/bin" "$r/dev" "$r/etc" "$r/lib" "$r/mnt/usb" "$r/proc" "$r/run" "$r/sys" "$r/tmp" "$r/usr/bin" "$r/usr/lib" || exit 2
  chmod 1777 "$r/tmp" || exit 2
  cp "$st/elf/getrandom.so" "$r/bin/busybox" && ln -s busybox "$r/bin/mount" || exit 2
  printf '%s\n' "$inittab_lines" >"$r/etc/inittab" && cp "$here/../pi/os/board/pizero/rootfs-overlay/etc/fstab" "$r/etc/fstab" || exit 2
  cp "$st/elf/getrandom.so" "$r/lib/ld-linux-armhf.so.3" && cp "$st/elf/getrandom.so" "$r/lib/libc.so.6" || exit 2
  cp "$st/elf/getrandom.so" "$r/usr/bin/keepcrypt-pi" || exit 2
  echo 'NAME=Buildroot' >"$r/usr/lib/os-release" && ln -s ../usr/lib/os-release "$r/etc/os-release" || exit 2
  b=$st/tree/boot
  for f in bootcode.bin start.elf fixup.dat zImage bcm2708-rpi-zero.dtb; do echo "$f" >"$b/$f" || exit 2; done
  cp "$here/../pi/os/board/pizero/cmdline.txt" "$here/../pi/os/board/pizero/config.txt" "$b/" || exit 2
  # The kernel config: the fragment's required options alone, so it passes the fragment's rules.
  sed -n 's/^\(CONFIG_[A-Za-z0-9_]*=y\)$/\1/p' "$here/../pi/os/board/pizero/linux.fragment" >"$st/linux.config" || exit 2
  fraglists=$st
  fragment_lists "$here/../pi/os/board/pizero/linux.fragment" "$st/required" "$st/forbidden" --selftest
  img=$a/tools.img
  opath=$PATH
  PATH=$st/bin:$PATH
  stub_tree clean
  stub_case clean ''
  # The lists.
  stub_tree boot-list
  sha=$(si_lists "$img" "$tree/expected" "$kc")
  grep -v '^/zImage ' "$tree/expected/boot.list" >"$tree/boot.list" && mv "$tree/boot.list" "$tree/expected/boot.list" || exit 2
  sicase image-stub-boot-list-differs "List: $tree/expected/boot.list: differs from the image's boot file list" "$img" "$tree/expected" "$kc" "$sha"
  stub_tree root-list
  sha=$(si_lists "$img" "$tree/expected" "$kc")
  echo '/etc/kc-canary -rw-r--r--' >>"$tree/expected/root.list" || exit 2
  sicase image-stub-root-list-differs "List: $tree/expected/root.list: differs from the image's root file list" "$img" "$tree/expected" "$kc" "$sha"
  stub_tree imports
  sha=$(si_lists "$img" "$tree/expected" "$kc")
  echo 'U rand' >>"$tree/expected/keepcrypt-pi.imports" || exit 2
  sicase image-stub-imports-differ "Binary: /usr/bin/keepcrypt-pi: imports differ from $tree/expected/keepcrypt-pi.imports" "$img" "$tree/expected" "$kc" "$sha"
  # The deny list, with the lists remade from the mutated tree.
  stub_tree sh
  ln -s busybox "$tree/root/bin/sh" || exit 2
  stub_case bin-sh 'Deny: /bin/sh: a shell or login program, sh'
  stub_tree link-to-ash
  ln -s /bin/ash "$tree/root/usr/bin/kc-canary" || exit 2
  stub_case link-to-a-shell 'Deny: /usr/bin/kc-canary: a link to a shell or login program, /bin/ash'
  stub_tree setuid
  chmod u+s "$tree/root/bin/busybox" || exit 2
  stub_case setuid-busybox 'Deny: /bin/busybox: setuid, setgid or sticky mode -rwsr-xr-x'
  stub_tree sticky
  chmod 1755 "$tree/root/run" || exit 2
  stub_case sticky-run 'Deny: /run: setuid, setgid or sticky mode drwxr-xr-t'
  stub_tree modules
  mkdir "$tree/root/lib/modules" || exit 2
  stub_case lib-modules 'Deny: /lib/modules: kernel modules'
  stub_tree init-d
  mkdir "$tree/root/etc/init.d" || exit 2
  stub_case etc-init-d 'Deny: /etc/init.d: start-up scripts'
  stub_tree age
  echo x >"$tree/root/etc/kc-canary.age" || exit 2
  stub_case age-file 'Deny: /etc/kc-canary.age: looks like a seed or backup file'
  stub_tree backup
  echo x >"$tree/root/usr/lib/Backup-words.txt" || exit 2
  stub_case backup-file 'Deny: /usr/lib/Backup-words.txt: looks like a seed or backup file'
  # Partition 1.
  stub_tree start-cd
  echo s >"$tree/boot/start_cd.elf" || exit 2
  stub_case start-cd-elf 'Boot: partition-1: holds start.elf, start_cd.elf, not exactly start.elf'
  stub_tree no-fixup
  rm "$tree/boot/fixup.dat" || exit 2
  stub_case no-fixup-dat 'Boot: partition-1: holds no fixup*.dat, not exactly fixup.dat'
  stub_tree console
  echo 'root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait panic=0 init_on_free=1 quiet loglevel=0 console=ttyAMA0,115200' >"$tree/boot/cmdline.txt" || exit 2
  stub_case console-in-cmdline 'Boot: partition-1:/cmdline.txt: differs from pi/os/board/pizero/cmdline.txt'
  stub_tree gpu-mem
  echo 'gpu_mem=16' >>"$tree/boot/config.txt" || exit 2
  stub_case gpu-mem-16-config 'Boot: partition-1:/config.txt: differs from pi/os/board/pizero/config.txt'
  # The inittab.
  stub_tree inittab
  printf '%s\n' '::sysinit:/bin/mount -a' '::respawn:/usr/bin/keepcrypt-pi' >"$tree/root/etc/inittab" || exit 2
  stub_case inittab-respawn 'Inittab: /etc/inittab: is not exactly the three lines'
  stub_tree inittab-link
  rm "$tree/root/etc/inittab" && ln -s ../usr/lib/os-release "$tree/root/etc/inittab" || exit 2
  stub_case inittab-symlink 'Inittab: /etc/inittab: is a symlink, not a file'
  # The kernel config: one line off expected/linux.config (which stays the pristine one), then
  # mutations that expected/linux.config follows.
  stub_tree kconfig-off
  { cat "$st/linux.config"; echo '# one line off (selftest)'; } >"$tree/linux.config" || exit 2
  sha=$(si_lists "$img" "$tree/expected" "$kc")
  sicase image-stub-kconfig-one-line-off "Kconfig: $tree/linux.config: differs from $tree/expected/linux.config" "$img" "$tree/expected" "$tree/linux.config" "$sha"
  stub_tree kconfig-net
  { cat "$st/linux.config"; echo 'CONFIG_NET=y'; } >"$tree/linux.config" && kc=$tree/linux.config || exit 2
  stub_case kconfig-net "Kconfig: $tree/linux.config: forbidden option CONFIG_NET is set (=y)"
  stub_tree kconfig-module
  { cat "$st/linux.config"; echo 'CONFIG_USB_SERIAL=m'; } >"$tree/linux.config" && kc=$tree/linux.config || exit 2
  stub_case kconfig-forbidden-module "Kconfig: $tree/linux.config: forbidden option CONFIG_USB_SERIAL is set (=m)"
  stub_tree kconfig-required
  grep -v '^CONFIG_SPI_SPIDEV=y$' "$st/linux.config" >"$tree/linux.config" && kc=$tree/linux.config || exit 2
  stub_case kconfig-missing-required "Kconfig: $tree/linux.config: required option CONFIG_SPI_SPIDEV is not =y"
  stub_tree kconfig-hwrng
  { cat "$st/linux.config"; echo 'CONFIG_HW_RANDOM_CANARY=y'; } >"$tree/linux.config" && kc=$tree/linux.config || exit 2
  stub_case kconfig-second-hwrng "Kconfig: $tree/linux.config: a hwrng driver other than BCM2835 is set: CONFIG_HW_RANDOM_CANARY=y"
  stub_tree required-drift
  sha=$(si_lists "$img" "$tree/expected" "$kc")
  grep -v '^CONFIG_TTY$' "$st/required" >"$tree/expected/kconfig-required" || exit 2
  sicase image-stub-kconfig-required-list-drift "Kconfig: $tree/expected/kconfig-required: does not equal the CONFIG_X=y lines" "$img" "$tree/expected" "$kc" "$sha"
  stub_tree forbidden-drift
  sha=$(si_lists "$img" "$tree/expected" "$kc")
  echo CONFIG_KC_CANARY >>"$tree/expected/kconfig-forbidden" || exit 2
  sicase image-stub-kconfig-forbidden-list-drift "Kconfig: $tree/expected/kconfig-forbidden: does not equal the \"# CONFIG_X is not set\" lines" "$img" "$tree/expected" "$kc" "$sha"
  # Bytes: a marker in a boot file, in a root file and in the raw image; the test key in a file.
  stub_tree marker-boot
  echo KC_SIMULATOR_DO_NOT_SHIP >>"$tree/boot/zImage" || exit 2
  stub_case marker-in-boot-file 'Marker: partition-1:/zImage: KC_SIMULATOR_DO_NOT_SHIP'
  stub_tree marker-root
  echo KC_TEST_REGISTRY_DO_NOT_SHIP >>"$tree/root/usr/lib/os-release" || exit 2
  stub_case marker-in-root-file 'Marker: /usr/lib/os-release: KC_TEST_REGISTRY_DO_NOT_SHIP'
  stub_tree marker-raw
  cp "$img" "$tree/raw.img" && printf KC_TEST_SOURCE_DO_NOT_SHIP | dd of="$tree/raw.img" bs=512 seek=7 conv=notrunc 2>/dev/null || exit 2
  sha=$(si_lists "$tree/raw.img" "$tree/expected" "$kc")
  sicase image-stub-marker-in-raw-image "Marker: $tree/raw.img: KC_TEST_SOURCE_DO_NOT_SHIP" "$tree/raw.img" "$tree/expected" "$kc" "$sha"
  stub_tree testkey
  write_testkey "$tree/root/etc/kc-canary.bin"
  stub_case test-key-file "TestKey: /etc/kc-canary.bin: the test registry public key $testkey"
  # keepcrypt-pi: the hash, a stripped file, the fallback's device path, the simulator's name;
  # the other ELF files: a stripped import of rand, a stripped static file.
  stub_tree hash
  stub_case wrong-binary-hash 'Binary: /usr/bin/keepcrypt-pi: SHA-256 ' "$zero"
  stub_tree stripped
  "$bin/llvm-objcopy" --strip-all "$tree/root/usr/bin/keepcrypt-pi" || exit 2
  stub_case stripped-keepcrypt-pi 'Format: /usr/bin/keepcrypt-pi: a stripped file with no symbol table (.symtab)'
  stub_tree urandom
  printf '/dev/urandom' >>"$tree/root/usr/bin/keepcrypt-pi" || exit 2
  stub_case urandom-in-keepcrypt-pi 'StdRandom: /usr/bin/keepcrypt-pi: byte string /dev/urandom'
  stub_tree sim
  cp "$st/elf/sim.so" "$tree/root/usr/bin/keepcrypt-pi" || exit 2
  stub_case simulator-symbol-in-keepcrypt-pi 'Binary: /usr/bin/keepcrypt-pi: names the simulator crate: symbol keepcrypt_pi_sim_hwrng'
  stub_tree rand
  cp "$st/elf/rand-stripped.so" "$tree/root/lib/libkc-canary.so.1" || exit 2
  stub_case stripped-elf-importing-rand 'Symbol: /lib/libkc-canary.so.1: undefined rand'
  stub_tree static
  cp "$st/elf/static-stripped" "$tree/root/usr/bin/kc-canary" || exit 2
  stub_case stripped-static-elf 'Format: /usr/bin/kc-canary: an ELF with no dynamic symbol table'
  PATH=$opath
  unset KC_STUB
}

# --- Artifact selftest -------------------------------------------------------------------------

# aexpect NAME WANT-EXIT WANT-HITS TARGET FILE...: run the artifact scan in a new process. The exit
# code must be WANT-EXIT, and the hit lines, sorted, exactly WANT-HITS (newline-separated, sorted;
# empty for none). For WANT-EXIT 2, WANT-HITS is a text the output must contain instead.
aexpect() {
  aname=$1
  want_rc=$2
  want=$3
  shift 3
  out=$(sh "$self" --artifact "$@" 2>&1)
  rc=$?
  got=$(printf '%s\n' "$out" | grep -E '^(Marker|TestKey|Format|Symbol|StdRandom|OSImport): ' | sort)
  ok=no
  if [ "$rc" -eq "$want_rc" ]; then
    if [ "$want_rc" -eq 2 ]; then
      case $out in *"$want"*) ok=yes ;; esac
    elif [ "$got" = "$(printf '%s\n' "$want" | sed '/^$/d' | sort)" ]; then
      ok=yes
    fi
  fi
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> exit %s%s\n' "$aname" "$rc" "$(printf '%s\n' "$got" | sed '/^$/d; s/^/; /' | tr -d '\n')"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted exit %s with:\n%s\ngot exit %s:\n' "$aname" "$want_rc" "$want" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

artifact_selftest() {
  toolchain_bin
  fixture=$here/testdata/artifact
  a=$tmp/artifact
  mkdir -p "$a" || exit 2
  # The pinned key is kcr.json's test registry key.
  if sed -n '/"test_registry": {/,/}/p' "$here/../vectors/kcr.json" | grep -q -F -e "\"public_key_hex\": \"$testkey\""; then
    pass=$((pass + 1))
    echo 'PASS artifact-test-key-is-kcr-json-test-registry-key'
  else
    fail=$((fail + 1))
    echo "FAIL artifact-test-key-is-kcr-json-test-registry-key: $testkey is not vectors/kcr.json's test_registry public_key_hex"
  fi
  # The scan's RNG crates are deny.toml's rule-1 block, name for name (scripts/canaries.sh pins
  # that block). A block this cannot read gives an empty list, which fails.
  deny_rng=$(sed -n '/^ *# Rule 1:/,/^ *#/p' "$repo/deny.toml" | sed -n 's/^ *"\([A-Za-z0-9_-]*\)",$/\1/p' | sort | tr '\n' ' ')
  scan_rng=$(printf '%s\n' $rng_crate_names | sort | tr '\n' ' ')
  if [ -n "$deny_rng" ] && [ "$deny_rng" = "$scan_rng" ]; then
    pass=$((pass + 1))
    echo "PASS artifact-rng-crates-are-deny-toml-rule-1 ($(printf '%s\n' $rng_crate_names | wc -l | tr -d ' ') names)"
  else
    fail=$((fail + 1))
    printf 'FAIL artifact-rng-crates-are-deny-toml-rule-1:\n    deny.toml: %s\n    scan:      %s\n' "$deny_rng" "$scan_rng"
  fi
  # One object per case and target, from the one fixture source (see its header).
  for t in aarch64-linux-android aarch64-apple-ios; do
    case $t in *-apple-*) p=_ import=_CCRandomGenerateBytes ;; *) p= import=getrandom ;; esac
    for c in clean:kc_fixture: arc4random:kc_fixture:kc_arc4random no-os-import:kc_fixture:kc_no_os_import \
      getentropy:kc_fixture:kc_getentropy libc-r:kc_fixture:kc_libc_r rand-crate:rand: \
      getrandom-fallback:getrandom: random-state:kc_fixture:kc_random_state; do
      case_name=${c%%:*}
      rest=${c#*:}
      crate=${rest%%:*}
      cfg=${rest#*:}
      if ! (cd "$repo" && rustc --edition 2024 --crate-type lib --crate-name "$crate" --emit obj \
        -C panic=abort -C opt-level=1 --target "$t" ${cfg:+--cfg "$cfg"} \
        -o "$a/$t-$case_name.o" "$fixture/fixture.rs") >"$a/rustc.log" 2>&1; then
        fail=$((fail + 1))
        printf 'FAIL artifact %s %s: rustc could not build the fixture:\n' "$t" "$case_name"
        sed 's/^/    /' "$a/rustc.log"
      fi
    done
    o=$a/$t
    aexpect "artifact-$t-clean-object" 0 '' "$t" "$o-clean.o"
    aexpect "artifact-$t-arc4random-import" 1 "Symbol: $o-arc4random.o: undefined ${p}arc4random" "$t" "$o-arc4random.o"
    aexpect "artifact-$t-missing-os-import" 1 \
      "OSImport: $o-no-os-import.o: no undefined $import, the OS import on $t" "$t" "$o-no-os-import.o"
    case $t in
      *-apple-*) aexpect "artifact-$t-getentropy-allowed" 0 '' "$t" "$o-getentropy.o" ;;
      *) aexpect "artifact-$t-getentropy-import" 1 "Symbol: $o-getentropy.o: undefined getentropy" "$t" "$o-getentropy.o" ;;
    esac
    # glibc's reentrant draws and a rand48 seeder (the old pattern let all three through).
    aexpect "artifact-$t-libc-reentrant-draws" 1 "Symbol: $o-libc-r.o: undefined ${p}lrand48_r
Symbol: $o-libc-r.o: undefined ${p}random_r
Symbol: $o-libc-r.o: undefined ${p}seed48" "$t" "$o-libc-r.o"
    # Every symbol of the rand crate is a hit; in the getrandom crate only the fallback is.
    aexpect "artifact-$t-rand-crate-symbols" 1 \
      "Symbol: $o-rand-crate.o: rand-family symbol rand::backends::use_file::fill_inner
Symbol: $o-rand-crate.o: rand-family symbol rand::rngs::next_u32" "$t" "$o-rand-crate.o"
    aexpect "artifact-$t-getrandom-fallback-symbol" 1 \
      "Symbol: $o-getrandom-fallback.o: getrandom's fallback getrandom::backends::use_file::fill_inner" \
      "$t" "$o-getrandom-fallback.o"
    # An archive (as an rlib is) needs no OS import, but its members meet every other rule.
    rm -f "$o-no-import.rlib" "$o-arc4random.rlib"
    "$bin/llvm-ar" rcs "$o-no-import.rlib" "$o-no-os-import.o" || exit 2
    "$bin/llvm-ar" rcs "$o-arc4random.rlib" "$o-no-os-import.o" "$o-arc4random.o" || exit 2
    aexpect "artifact-$t-archive-needs-no-import" 0 '' "$t" "$o-no-import.rlib"
    aexpect "artifact-$t-archive-member-arc4random" 1 \
      "Symbol: $o-arc4random.rlib: undefined ${p}arc4random" "$t" "$o-arc4random.rlib"
    # A thin archive holds its members' paths, not their bytes, so it fails whatever it lists.
    rm -f "$o-thin.rlib"
    "$bin/llvm-ar" rcsT "$o-thin.rlib" "$o-clean.o" || exit 2
    aexpect "artifact-$t-thin-archive" 1 \
      "Format: $o-thin.rlib: a thin archive, which holds its members' paths, not their bytes" "$t" "$o-thin.rlib"
    # A stripped object (tasks/todo.md, M4 group 12): llvm-strip takes the symbol table off the
    # object with no imports (one with relocations keeps the symbols they name), and the scan
    # must refuse the file rather than find no RNG symbol in it; the missing OS import is not
    # reached.
    cp "$o-no-os-import.o" "$o-stripped.o" && "$bin/llvm-strip" --strip-all "$o-stripped.o" || exit 2
    aexpect "artifact-$t-stripped-object" 1 \
      "Format: $o-stripped.o: a stripped file with no symbol table (.symtab), so its symbols cannot be checked" \
      "$t" "$o-stripped.o"
    # std's random keys (M4 group 12): RandomState::new() inlines into the fixture, leaving the
    # thread-local KEYS and the hashmap_random_keys import, every one of them a hit; the OS import
    # is present. The names are std 1.98.1's and move with the toolchain.
    case $t in
      *-apple-*) std_hits="StdRandom: $o-random-state.o: symbol <std::hash::random::RandomState>::new::KEYS::{K#0}::{closure#1}::__RUST_STD_INTERNAL_VAL
StdRandom: $o-random-state.o: symbol <std::sys::thread_local::native::lazy::Storage<core::cell::Cell<(u64, u64)>, !>>::get_or_init_slow::<<std::hash::random::RandomState>::new::KEYS::__rust_std_internal_init_fn>
StdRandom: $o-random-state.o: symbol <std::thread::local::LocalKey<core::cell::Cell<(u64, u64)>>>::with::<<std::hash::random::RandomState>::new::{closure#0}, std::hash::random::RandomState>
StdRandom: $o-random-state.o: symbol std::sys::random::hashmap_random_keys" ;;
      *) std_hits="StdRandom: $o-random-state.o: symbol <std::hash::random::RandomState>::new::KEYS::{closure#0}::__RUST_STD_INTERNAL_VAL
StdRandom: $o-random-state.o: symbol <std::sys::thread_local::os::Storage<core::cell::Cell<(u64, u64)>, 8>>::try_initialize::<<std::hash::random::RandomState>::new::KEYS::__rust_std_internal_init_fn>
StdRandom: $o-random-state.o: symbol <std::thread::local::LocalKey<core::cell::Cell<(u64, u64)>>>::with::<<std::hash::random::RandomState>::new::{closure#0}, std::hash::random::RandomState>
StdRandom: $o-random-state.o: symbol std::sys::random::linux::hashmap_random_keys" ;;
    esac
    aexpect "artifact-$t-std-random-state" 1 "$std_hits" "$t" "$o-random-state.o"
  done
  # std's passengers on the Pi target (tasks/todo.md, M4 group 12, Q52): an object built as std
  # whose getrandom inlines away leaves its three statics as local data (type d), which pass on
  # arm-unknown-linux-gnueabihf and nowhere else, and never inside an archive; the reader object
  # keeps the function (type t), which is a hit beside the passing statics; and a DEVICE in .bss
  # (type b) is a hit, since only type d passes.
  t=arm-unknown-linux-gnueabihf
  for c in std-passengers:kc_std_passengers std-reader:kc_std_reader std-bss:kc_std_bss; do
    if ! (cd "$repo" && rustc --edition 2024 --crate-type lib --crate-name std --emit obj \
      -C panic=abort -C opt-level=1 --target "$t" --cfg "${c#*:}" \
      -o "$a/$t-${c%%:*}.o" "$fixture/fixture.rs") >"$a/rustc.log" 2>&1; then
      fail=$((fail + 1))
      printf 'FAIL artifact %s %s: rustc could not build the fixture:\n' "$t" "${c%%:*}"
      sed 's/^/    /' "$a/rustc.log"
    fi
  done
  o=$a/$t
  sp=std::sys::random::linux::getrandom
  aexpect "artifact-$t-std-passengers-allowed" 0 '' "$t" "$o-std-passengers.o"
  aexpect 'artifact-aarch64-linux-android-std-passengers' 1 "StdRandom: $o-std-passengers.o: symbol $sp::DEVICE
StdRandom: $o-std-passengers.o: symbol $sp::GETRANDOM_AVAILABLE (.0)
StdRandom: $o-std-passengers.o: symbol $sp::GRND_INSECURE_AVAILABLE (.0)" aarch64-linux-android "$o-std-passengers.o"
  aexpect "artifact-$t-std-reader" 1 "StdRandom: $o-std-reader.o: symbol $sp" "$t" "$o-std-reader.o"
  aexpect "artifact-$t-std-passenger-in-bss" 1 "StdRandom: $o-std-bss.o: symbol $sp::DEVICE" "$t" "$o-std-bss.o"
  rm -f "$o-std-passengers.rlib"
  "$bin/llvm-ar" rcs "$o-std-passengers.rlib" "$o-std-passengers.o" || exit 2
  aexpect "artifact-$t-std-passengers-archive" 1 "StdRandom: $o-std-passengers.rlib: symbol $sp::DEVICE
StdRandom: $o-std-passengers.rlib: symbol $sp::GETRANDOM_AVAILABLE (.0)
StdRandom: $o-std-passengers.rlib: symbol $sp::GRND_INSECURE_AVAILABLE (.0)" "$t" "$o-std-passengers.rlib"
  # Each other crate of the list, on one target: every symbol in it is a hit, as in rand.
  t=aarch64-linux-android
  for crate in $rng_crate_names; do
    [ "$crate" = rand ] && continue
    o=$a/$t-crate-$crate
    if ! (cd "$repo" && rustc --edition 2024 --crate-type lib --crate-name "$crate" --emit obj \
      -C panic=abort -C opt-level=1 --target "$t" -o "$o.o" "$fixture/fixture.rs") >"$a/rustc.log" 2>&1; then
      fail=$((fail + 1))
      printf 'FAIL artifact %s crate %s: rustc could not build the fixture:\n' "$t" "$crate"
      sed 's/^/    /' "$a/rustc.log"
      continue
    fi
    aexpect "artifact-$t-$crate-crate-symbols" 1 \
      "Symbol: $o.o: rand-family symbol $crate::backends::use_file::fill_inner
Symbol: $o.o: rand-family symbol $crate::rngs::next_u32" "$t" "$o.o"
  done
  # Any file, whatever its format: each marker as text, and the key's 32 bytes inside other bytes.
  t=aarch64-linux-android
  for m in source:KC_TEST_SOURCE_DO_NOT_SHIP registry:KC_TEST_REGISTRY_DO_NOT_SHIP \
    simulator:KC_SIMULATOR_DO_NOT_SHIP; do
    mf=$fixture/marker-${m%%:*}.txt
    aexpect "artifact-marker-${m%%:*}-text" 1 "Marker: $mf: ${m#*:}
Format: $mf: not an ELF, Mach-O or ar file, so its symbols cannot be checked" "$t" "$mf"
  done
  write_testkey "$a/test-key.bin"
  aexpect 'artifact-test-key-bytes' 1 "TestKey: $a/test-key.bin: the test registry public key $testkey
Format: $a/test-key.bin: not an ELF, Mach-O or ar file, so its symbols cannot be checked" "$t" "$a/test-key.bin"
  # The device files std's fallback reads, as bytes in any file (M4 group 12).
  mf=$fixture/std-random-paths.txt
  aexpect 'artifact-std-random-byte-strings' 1 "StdRandom: $mf: byte string /dev/urandom
StdRandom: $mf: byte string /dev/random
Format: $mf: not an ELF, Mach-O or ar file, so its symbols cannot be checked" "$t" "$mf"
  # Each file is reported on its own: a clean object beside a marker file.
  mf=$fixture/marker-source.txt
  aexpect 'artifact-two-files' 1 "Marker: $mf: KC_TEST_SOURCE_DO_NOT_SHIP
Format: $mf: not an ELF, Mach-O or ar file, so its symbols cannot be checked" "$t" "$a/$t-clean.o" "$mf"
  # Errors: a TARGET with no rule, a missing file, no file at all.
  aexpect 'artifact-error-unknown-target' 2 'no OS-import rule for target x86_64-pc-windows-msvc' \
    x86_64-pc-windows-msvc "$a/$t-clean.o"
  aexpect 'artifact-error-missing-file' 2 "cannot read $a/absent.o" "$t" "$a/absent.o"
  aexpect 'artifact-error-no-file' 2 'usage:' "$t"
}

case ${1-} in
  --artifact) shift; [ $# -ge 1 ] || { usage >&2; exit 2; }; artifact "$@" ;;
  --workflows) shift; [ $# -eq 1 ] || { usage >&2; exit 2; }; workflows "$1" ;;
  --image-lists) shift; [ $# -eq 2 ] || { usage >&2; exit 2; }; image_lists "$1" "$2" ;;
  --image) shift; [ $# -eq 4 ] || { usage >&2; exit 2; }; image_scan "$1" "$2" "$3" "$4" ;;
  --selftest-image) shift; [ $# -eq 2 ] || { usage >&2; exit 2; }; selftest_image "$1" "$2" ;;
  --os-config) shift; [ $# -eq 1 ] || { usage >&2; exit 2; }; os_config "$1" ;;
esac

case $# in
  0) root=$(cd "$here/.." && pwd -P) || exit 2; scan "$root" ;;
  1)
    case $1 in
      --selftest) selftest ;;
      -h | --help) usage; exit 0 ;;
      -*) usage >&2; exit 2 ;;
      *) [ -d "$1" ] || { usage >&2; exit 2; }; scan "$1" ;;
    esac
    ;;
  *) usage >&2; exit 2 ;;
esac
