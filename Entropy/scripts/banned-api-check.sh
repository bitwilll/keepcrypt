#!/bin/sh
# Banned-API grep gate: CLAUDE.md security rules 1, 3, 5 and 9 (plan: tasks/todo.md, M0), and the
# release-artifact scan for rules 1 and 10 (tasks/todo.md, M1 group 11).
#
#   scripts/banned-api-check.sh             scan the repo this script lives in
#   scripts/banned-api-check.sh DIR         scan DIR as if it were the repo root
#   scripts/banned-api-check.sh --artifact TARGET FILE...
#                                           scan built release artifacts for TARGET (see "Artifact
#                                           mode" below)
#   scripts/banned-api-check.sh --selftest  every fixture in scripts/testdata/banned-api/ must trip the
#                                           gate for its category; every clean-* fixture must pass; the
#                                           artifact fixtures in scripts/testdata/artifact/ must give
#                                           exactly their pinned hits (needs the pinned toolchain)
#
# Prints "<category>: <file>:<line>: <text>" per hit, then a summary. Exit 0 clean, 1 hits,
# 2 usage or read error: a file that cannot be read fails the gate, it is never skipped.
#
# Artifact mode (docs/build-plan.md "Security rules enforced in CI", rows "One RNG path in shipped
# binaries" and "Test stubs never ship"; tasks/todo.md, M1 Q3, Q8 and group 11). Prints
# "<category>: <file>: <detail>" per hit, then a summary; exit 0 clean, 1 hits, 2 error (an
# unreadable file, a file llvm-nm cannot read, no llvm-nm, a TARGET with no rule, bad usage).
#   Marker     any file holding KC_TEST_SOURCE_DO_NOT_SHIP or KC_TEST_REGISTRY_DO_NOT_SHIP (rule 10)
#   TestKey    any file holding the 32 bytes of the test registry public key (rule 10; pinned below
#              and checked against vectors/kcr.json by the selftest)
#   Format     a file that is not an ELF, Mach-O or ar file (an rlib is an ar file): its symbols
#              cannot be checked, so it fails. So does a thin ar file (!<thin>), which holds only its
#              members' paths: the marker and key searches would never see the members' bytes
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
#   OSImport   an object or linked file (not an archive: core's rlib calls the getrandom crate,
#              whose own rlib imports the OS call) without the OS import for TARGET: getrandom on
#              Linux and Android, _CCRandomGenerateBytes on iOS (Q8), and _getentropy on macOS,
#              which getrandom uses there (a host rule, for scripts/canaries.sh on a Mac)
# The byte searches run on an od dump, one "xx" per byte, so they match whole bytes of any value
# with plain fixed-string greps.
#
# Categories (main patterns; the full lists are in the check functions below; comments count
# everywhere):
#   RNG        rule 1: any PRNG, and any OS RNG outside core: Math.random, java.util.Random, a bare
#              Random( (Kotlin has no "new"), SecureRandom, SplittableRandom, SecRandomCopyBytes,
#              arc4random, GameplayKit GK*Random* and GK*Distribution, Python random (also as
#              "import (random, ..." and, in a .py file, a wrapped import line that holds only
#              names and random, such as "    random," or "    random \", and a line starting
#              "    random import" after "from \"), C rand(), rand_r(), random(), drand48, C++
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
#              2026-10-10), an import of socket, ssl (or their C modules _socket and _ssl),
#              socketserver, urllib, urllib3, http, ftplib, smtplib, smtpd, poplib, imaplib,
#              nntplib, telnetlib, xmlrpc, asyncio, asyncore, asynchat, wsgiref, webbrowser,
#              requests, httpx, aiohttp, multiprocessing.connection or logging.handlers (also by
#              their own names, as "from logging import handlers" brings one in), in the shapes
#              Python random has under RNG. Anchored on the import, so a URL string such as
#              "https://registry.invalid" passes.
#   Clipboard  rule 5 and docs/mobile-apps.md ("Never offered: share sheet, copy"): clipboard APIs,
#              plus UI that copies or shares: .textSelection( unless it is exactly
#              .textSelection(.disabled), which the docs require (spaces around .disabled are
#              fine; .enabled, a variable, a custom static such as .dragToCopy, or an argument on
#              the next line all hit), EnabledTextSelectability (the type such a static needs),
#              ShareLink, UIActivityViewController, SelectionContainer, Intent.ACTION_SEND (and
#              _MULTIPLE, SENDTO), and any line that names textIsSelectable, setTextIsSelectable
#              or isTextSelectable, unless each one's value is the literal false: ="false",
#              ">false<", (false) or "= false". In a .py file (Q23; completed by the stage-A review,
#              2026-10-10): an import of the clipboard module, in the shapes of the Python network
#              imports; anywhere a word starts with one, pyperclip, win32clipboard, tkinter's
#              clipboard_append, clipboard_get and selection_get, pandas' to_clipboard and
#              read_clipboard, and the tools pbcopy, pbpaste, xclip, xsel, wl-copy, wl-paste,
#              PowerShell's Get-Clipboard and Set-Clipboard, clip.exe (never a bare clip) and
#              osascript's "the clipboard" (these last three in any letter case); and any attribute
#              or dotted module named clipboard (QApplication.clipboard(), app.clipboard()).
#   Rule1      rule 1 path check: getrandom in any .rs file is a hit, except in the core module
#              core/src/source, in either file layout: source.rs or anything under source/. A
#              look-alike such as core/src/sourcex.rs is another module. The games are no
#              exception: they get their bytes from core's separate game-randomness call
#              (docs/pi-firmware.md, "Game randomness").
#              core/src/lib.rs must hold the exact line #![forbid(unsafe_code)] (a missing line is
#              reported at line 1).
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
#
# Fail-closed noise, not bypasses (rename or spell it out instead): a named format argument called
# path that rustfmt wraps onto its own line ("        path = \"seed.age\",") is an Include hit in
# any .rs file (name it file = ...), and a ": _ =" type placeholder ("let n: _ = f()?;") or an _name
# type alias ("type _Unused = u8;") is a FailOpen hit in core/, ffi/ and pi/app/ (write the type).
# A field or variable named include passed bare ("Filter { include, exclude }") is an Include hit.
# In a .py file, prose that says "the clipboard" (AppleScript's phrase) is a Clipboard hit (write
# "a clipboard"); an import of any module or name called connection or handlers (the names
# multiprocessing.connection and logging.handlers come in under) is a Network hit; and a wrapped
# line that holds only names, one of them a banned module's name or clipboard ("    requests," or
# "    clipboard," as a call's argument), is a hit like a wrapped import line (rename the variable).
#
# Portable on purpose: POSIX sh, POSIX ERE (no \b \s \< \>, no -P -w), POSIX sed (BRE, in
# selectable() and textselection()) and LC_ALL=C, so BSD grep and sed (macOS) and GNU grep and sed
# (ubuntu CI) agree.
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
usage: scripts/banned-api-check.sh [--selftest | DIR | --artifact TARGET FILE...]
  (none)      scan the repo this script lives in
  DIR         scan DIR as if it were the repo root
  --artifact  scan release artifacts built for TARGET: test markers, the test registry key, RNG
              symbols other than TARGET's OS import, and that import (see the script header)
  --selftest  run the fixtures in scripts/testdata/banned-api/ and scripts/testdata/artifact/
Hits: RNG APIs (and the OS RNG read outside core/src/source), network APIs, Python network imports
and hard-coded http URLs (outside registry/), clipboard, copy and share APIs and Python clipboard
modules, tools and calls, getrandom in a .rs file outside core/src/source, a core/src/lib.rs without
#![forbid(unsafe_code)], in Rust under core/, ffi/ or pi/app/ a discarded result (_ =, an _name
binding, drop or forget of a call), clippy as a cfg predicate and /dev/stdout, /dev/stderr or
/dev/tty, include! (by any path or alias) or a path attribute in any .rs file, and a C #include of
a file with a binary extension.
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

# Each check runs grep -n on one file: prints "<line>:<text>", exits 0 hit, 1 none, 2 error.
# Rule 1 covers app code too: only core reads the OS RNG, so SecureRandom and SecRandomCopyBytes
# are banned like the PRNGs. A bare Random( is java.util.Random in Kotlin after import java.util.*;
# the word boundary keeps SecureRandom( and RandomAccessFile( out of it. Python imports: "import
# random", "import os, random" and "from numpy import(array, random)" (the comma pattern), and
# "from numpy import (random, array)" (random first inside the parenthesis).
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
    -e "${L}import[[:space:]]+random$R" \
    -e "${L}import[[:space:](][(A-Za-z0-9_.,[:space:]]*,[[:space:]]*random$R" \
    -e "${L}import[[:space:]]*[(][[:space:]]*random$R" \
    -e "${L}from[[:space:]]+random$R" \
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
# r,", "    array, random", "    random \" or a bare "    random". The other names must be
# comma-separated words, so a word list such as "ranch random range" passes; a word list one word
# per line belongs in a .txt file. After "from \" the next line starts with the module:
# "    random import choice".
pyrandom() {
  grep -n -a -E \
    -e '^[[:space:]]*random[[:space:]]+import([^A-Za-z0-9_]|$)' \
    -e '^[[:space:]]*([A-Za-z0-9_]+([[:space:]]+as[[:space:]]+[A-Za-z0-9_]+)?[[:space:]]*,[[:space:]]*)*random([[:space:]]+as[[:space:]]+[A-Za-z0-9_]+)?[[:space:]]*([,)#]|\\|$)' \
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
# line after "from \" ("    socket import create_connection"). Anchored on the import, so the
# names pass in a URL such as "https://registry.invalid", in other strings, as attributes and
# inside longer names.
pyimport() {
  grep -n -a -E \
    -e "${L}import[[:space:]]+$1$R" \
    -e "${L}import[[:space:](][(A-Za-z0-9_.,[:space:]]*,[[:space:]]*$1$R" \
    -e "${L}import[[:space:]]*[(][[:space:]]*$1$R" \
    -e "${L}from[[:space:]]+$1$R" \
    -e "^[[:space:]]*$1([.][A-Za-z0-9_]+)*[[:space:]]+import$R" \
    -e "^[[:space:]]*([A-Za-z0-9_.]+([[:space:]]+as[[:space:]]+[A-Za-z0-9_]+)?[[:space:]]*,[[:space:]]*)*$1([.][A-Za-z0-9_]+)*([[:space:]]+as[[:space:]]+[A-Za-z0-9_]+)?[[:space:]]*([,)#]|\\\\|\$)" \
    -- "$2"
}

# .py files only, outside registry/ like network() (tasks/todo.md M2 group 2, Q23; completed by the
# stage-A review, 2026-10-10): an import of a network module, in pyimport()'s shapes. _socket and
# _ssl are the C modules behind socket and ssl, with the same calls. multiprocessing and logging
# run offline, but multiprocessing.connection (Listener and Client over TCP) and logging.handlers
# (SocketHandler, SysLogHandler, SMTPHandler, HTTPHandler) do not. Each is listed by its full name
# and by its own name, which "from multiprocessing import connection" and "from logging import
# handlers" bring in, so any import of a module or name called connection or handlers is a hit.
# Grep cannot see __import__("socket") or importlib.import_module("socket"), an attribute path
# such as getpass.os.system, or a subprocess running a network tool. For verify.py, tasks/todo.md
# M2 group 3's check 12 (vectorgen.py --selftest) closes all four; vectorgen and scripts/ keep this
# gate only.
pynet='(socket|ssl|_socket|_ssl|socketserver|urllib|urllib3|http|ftplib|smtplib|smtpd|poplib|imaplib|nntplib|telnetlib|xmlrpc|asyncio|asyncore|asynchat|wsgiref|webbrowser|requests|httpx|aiohttp|multiprocessing[.]connection|connection|logging[.]handlers|handlers)'
pynetwork() {
  pyimport "$pynet" "$1"
}

# Clipboard APIs, and UI that hands the words to copy or share (docs/mobile-apps.md, "Never offered:
# share sheet, copy"). EnabledTextSelectability is the type a custom static such as .dragToCopy
# needs. ACTION_SEND also matches _MULTIPLE and SENDTO. .textSelection( and textIsSelectable have
# their own checks, textselection() and selectable() below.
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
    -- "$1"
}

# .py files only (Q23; completed by the stage-A review, 2026-10-10): pyperclip, win32clipboard,
# tkinter's clipboard_append, clipboard_get and selection_get, pandas' to_clipboard and
# read_clipboard, and the clipboard tools pbcopy, pbpaste, xclip, xsel, wl-copy, wl-paste,
# PowerShell's Get-Clipboard and Set-Clipboard, clip.exe and AppleScript's "the clipboard" (run by
# osascript), anywhere on a line, since a subprocess names its tool in a string. Each must start a
# word, so idxsel and maxclip pass, while a longer name such as pyperclip3 or xclipboard hits.
# PowerShell, Windows file names and AppleScript ignore letter case, so the last three match in
# any case. clip hits only as clip.exe, since clip is a common word; a bare clip passes.
# selection_get hits whatever its selection: CLIPBOARD may sit on the next line or in a variable,
# and the default, PRIMARY, is X11's other clipboard. The last pattern is any attribute or dotted
# module named clipboard: QApplication.clipboard() or QGuiApplication.clipboard(), app.clipboard()
# on a Qt application object, pandas.io.clipboard.
pyclipboard() {
  grep -n -a -E \
    -e "${L}pyperclip" \
    -e "${L}win32clipboard" \
    -e "${L}clipboard_(append|get)" \
    -e "${L}selection_get" \
    -e "${L}(to|read)_clipboard" \
    -e "${L}(pbcopy|pbpaste|xclip|xsel|wl-copy|wl-paste)" \
    -e "${L}[GgSs][Ee][Tt]-[Cc][Ll][Ii][Pp][Bb][Oo][Aa][Rr][Dd]" \
    -e "${L}[Cc][Ll][Ii][Pp][.][Ee][Xx][Ee]" \
    -e "${L}[Tt][Hh][Ee][[:space:]]+[Cc][Ll][Ii][Pp][Bb][Oo][Aa][Rr][Dd]" \
    -e "[.][[:space:]]*clipboard$R" \
    -- "$1"
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
    # Rule 1: only core/src/source may name getrandom ('*' in case also matches '/').
    case $rel in
      core/src/source.rs | core/src/source/*) ;;
      *.rs) report Rule1 getrandom_use "$rel" ;;
    esac
    case $rel in core/*.rs | ffi/*.rs | pi/app/*.rs) report FailOpen failopen "$rel" ;; esac
    case $rel in *.rs) report Include include_code "$rel" ;; esac
    report Include cinclude "$rel"
  done <<EOF
$files
EOF
  if ! { [ -f core/src/lib.rs ] && grep -q -a -x -F -e '#![forbid(unsafe_code)]' core/src/lib.rs; }; then
    echo 'Rule1: core/src/lib.rs:1: missing the line #![forbid(unsafe_code)]'
    hits=$((hits + 1))
  fi
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check: $hits hit(s) in $n files scanned ($skipped binary by extension, not scanned)"
    exit 1
  fi
  echo "banned-api-check: clean, $n files scanned ($skipped binary by extension, not scanned)"
  exit 0
}

# fresh: new repo-like dir $d holding only a valid core/src/lib.rs.
fresh() {
  i=$((i + 1))
  d=$tmp/$i
  mkdir -p "$d/core/src" || exit 2
  echo '#![forbid(unsafe_code)]' >"$d/core/src/lib.rs" || exit 2
}

# expect NAME DIR WANT [FILE]: scan DIR in a new process. WANT=clean needs exit 0 and no hit,
# WANT=error needs exit 2 and output containing FILE (if given, the expected message), any other
# WANT needs exit 1 and exactly one hit "<WANT>: <FILE>:<line>: <text>", where <text> is line
# <line> of FILE as it stands (Rule1's missing-line message is the one exception).
expect() {
  out=$(sh "$self" "$2" 2>&1)
  rc=$?
  cats='^(RNG|Network|Clipboard|Rule1|FailOpen|Include): '
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
          'missing the line '*) ok=yes ;;
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
    # FailOpen covers core/, ffi/ and pi/app/ only: the same file in pi/sim/src/ passes.
    if [ "$want" = FailOpen ]; then
      fresh
      mkdir -p "$d/pi/sim/src" && cp "$fx/$file" "$d/pi/sim/src/" || exit 2
      expect "$name in pi/sim/" "$d" clean
    fi
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
  for want in RNG Network Clipboard Rule1 FailOpen Include clean; do
    case "$seen " in *" $want "*) ;; *) fail=$((fail + 1)); echo "FAIL no $want fixture" ;; esac
  done
  artifact_selftest
  echo "selftest: $pass passed, $fail failed"
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

# --- Artifact mode -----------------------------------------------------------------------------

# The test registry public key: core/src/seal/registry_key.rs, vectors/kcr.json "keys"
# "test_registry" (the selftest checks it against kcr.json; the positive controls in
# scripts/canaries.sh check it against a real test-registry build).
testkey=42e9fa0e206d4bdf410f987ac7ded54fb02fb49ef277cc425d5fdfdb72c3b94b
markers='KC_TEST_SOURCE_DO_NOT_SHIP KC_TEST_REGISTRY_DO_NOT_SHIP'
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
    grep -E -e "$undefined_rng" "$atmp/undefined" >"$atmp/hits"
    [ $? -le 1 ] || exit 2
    from_list Symbol "$f" 'undefined ' "$atmp/hits"
    grep -E -e "$rng_crates" "$atmp/all" >"$atmp/hits"
    [ $? -le 1 ] || exit 2
    from_list Symbol "$f" 'rand-family symbol ' "$atmp/hits"
    grep -E -e "$fallback" "$atmp/all" >"$atmp/hits"
    [ $? -le 1 ] || exit 2
    from_list Symbol "$f" "getrandom's fallback " "$atmp/hits"
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
  echo "banned-api-check --artifact $target: clean, $n file(s): no marker, no test key, no other RNG symbol; $import imported by all $linked object or linked file(s) ($archives archive(s), which need no import)"
  exit 0
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
  got=$(printf '%s\n' "$out" | grep -E '^(Marker|TestKey|Format|Symbol|OSImport): ' | sort)
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
      getrandom-fallback:getrandom:; do
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
  for m in source:KC_TEST_SOURCE_DO_NOT_SHIP registry:KC_TEST_REGISTRY_DO_NOT_SHIP; do
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
