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
#   scripts/banned-api-check.sh --selftest  every fixture in scripts/testdata/banned-api/ must trip the
#                                           gate for its category; every clean-* fixture must pass; the
#                                           artifact fixtures in scripts/testdata/artifact/ must give
#                                           exactly their pinned hits (needs the pinned toolchain); the
#                                           workflow fixtures in scripts/testdata/workflows/ must trip
#                                           or pass the workflow check as their names say
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
#              byte string /dev/urandom or /dev/random, which std's fallback reads
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
#   - every "uses:" one of actions/checkout, actions/cache or actions/upload-artifact, pinned to a
#     40-hex commit SHA (a tag, a branch, a short SHA or any other action is a hit);
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
usage: scripts/banned-api-check.sh [--selftest | DIR | --artifact TARGET FILE... | --workflows DIR]
  (none)      scan the repo this script lives in
  DIR         scan DIR as if it were the repo root
  --artifact  scan release artifacts built for TARGET: test markers, the test registry key, RNG
              symbols other than TARGET's OS import, std's random-key path, a stripped file, and
              that import (see the script header)
  --workflows check every DIR/entropy-*.yml and .yaml workflow's hardening: read-only permissions, three
              SHA-pinned actions, no secrets, no fork-trusting trigger, no expression in a run step
  --selftest  run the fixtures in scripts/testdata/banned-api/, scripts/testdata/artifact/ and
              scripts/testdata/workflows/
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

artifact() {
  target=$1
  shift
  [ $# -ge 1 ] || { usage >&2; exit 2; }
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
  toolchain_bin
  atmp=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-artifact.XXXXXX") || exit 2
  trap 'rm -rf "$atmp"' EXIT
  trap 'exit 2' HUP INT TERM
  keybytes=$(printf '%s\n' "$testkey" | sed 's/../ &/g')
  hits=0
  n=0
  linked=0
  archives=0
  for f in "$@"; do
    n=$((n + 1))
    if [ ! -f "$f" ] || [ ! -r "$f" ]; then
      printf 'banned-api-check: cannot read %s\n' "$f" >&2
      exit 2
    fi
    dump "$f" >"$atmp/dump" || { printf 'banned-api-check: cannot read %s\n' "$f" >&2; exit 2; }
    for m in $markers; do
      if grep -q -F -e "$(printf '%s' "$m" | od -An -v -tx1 | tr -s ' \n' '  ' | sed 's/ $//')" "$atmp/dump"; then
        ahit Marker "$f" "$m"
      fi
    done
    if grep -q -F -e "$keybytes" "$atmp/dump"; then
      ahit TestKey "$f" "the test registry public key $testkey"
    fi
    # The device files std's random-key fallback reads, as bytes in any file (the symbol half of
    # the StdRandom rule follows the symbol rules below).
    for path in /dev/urandom /dev/random; do
      if grep -q -F -e "$(printf '%s' "$path" | od -An -v -tx1 | tr -s ' \n' '  ' | sed 's/ $//')" "$atmp/dump"; then
        ahit StdRandom "$f" "byte string $path"
      fi
    done
    magic=$(od -An -N8 -tx1 "$f" | tr -d ' \n')
    case $magic in
      213c617263683e0a) kind=archive ;;
      213c7468696e3e0a)
        ahit Format "$f" "a thin archive, which holds its members' paths, not their bytes"
        continue
        ;;
      7f454c46* | feedface* | feedfacf* | cefaedfe* | cffaedfe* | cafebabe*) kind=object ;;
      *)
        ahit Format "$f" 'not an ELF, Mach-O or ar file, so its symbols cannot be checked'
        continue
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
        ahit Format "$f" 'a stripped file with no symbol table (.symtab), so its symbols cannot be checked'
        continue
      fi
    fi
    grep -E -e "$undefined_rng" "$atmp/undefined" >"$atmp/hits"
    [ $? -le 1 ] || exit 2
    from_list Symbol "$f" 'undefined ' "$atmp/hits"
    grep -E -e "$rng_crates" "$atmp/all" >"$atmp/hits"
    [ $? -le 1 ] || exit 2
    from_list Symbol "$f" 'rand-family symbol ' "$atmp/hits"
    grep -E -e "$fallback" "$atmp/all" >"$atmp/hits"
    [ $? -le 1 ] || exit 2
    from_list Symbol "$f" "getrandom's fallback " "$atmp/hits"
    # std's random-key path: its symbols, demangled (a name llvm-nm cannot demangle stays mangled,
    # where 3std3sys6random is the module path); the byte strings were searched above.
    grep -E -e "$std_random" "$atmp/all" >"$atmp/hits"
    [ $? -le 1 ] || exit 2
    from_list StdRandom "$f" 'symbol ' "$atmp/hits"
    if [ "$kind" = archive ]; then
      archives=$((archives + 1))
    else
      linked=$((linked + 1))
      grep -q -x -F -e "$import" "$atmp/undefined" ||
        ahit OSImport "$f" "no undefined $import, the OS import on $target"
    fi
  done
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check --artifact $target: $hits hit(s) in $n file(s)"
    exit 1
  fi
  echo "banned-api-check --artifact $target: clean, $n file(s): no marker, no test key, no other RNG symbol, no std random-key path, no stripped file; $import imported by all $linked object or linked file(s) ($archives archive(s), which need no import)"
  exit 0
}

# --- Workflow mode -------------------------------------------------------------------------------

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
# not pinned to one of the three actions at a 40-hex SHA, the word secrets, github.token (also
# github['token']), pull_request_target, workflow_run.
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
    grep -v -E -e '^[0-9]+:[[:space:]]*(- )?uses:[[:space:]]*actions/(checkout|cache|upload-artifact)@[0-9a-f]{40}[[:space:]]*(#.*)?$')
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
  octal=
  rest=$testkey
  while [ -n "$rest" ]; do
    octal=$octal$(printf '\\%03o' "0x${rest%"${rest#??}"}")
    rest=${rest#??}
  done
  printf "x$octal\n" >"$a/test-key.bin" || exit 2
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
