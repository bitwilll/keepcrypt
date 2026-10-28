#!/bin/sh
# Banned-API grep gate: CLAUDE.md security rules 1, 3, 5 and 9 (plan: tasks/todo.md, M0; the Shell
# category and the hash ban: M3 group 13; the Kotlin, Android and FFI categories: M5 group 3; the
# Kotlin Multiplatform, iPhone and bridge rules: M5's re-plan for Compose Multiplatform, "Gate
# changes"), and the release-artifact scan for rules 1 and 10 (tasks/todo.md, M1 group 11).
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
#   scripts/banned-api-check.sh --apk VARIANT APK EXPECTED_DIR MERGER_REPORT CERT_SHA256 JNILIBS_DIR
#                                           check and scan a signed Android APK against the reviewed
#                                           files in EXPECTED_DIR (mobile/android/expected), its
#                                           manifest-merger report, the run's signing certificate and
#                                           the libraries scripts/android-rust.sh built and scanned
#                                           into JNILIBS_DIR (see "APK mode" below)
#   scripts/banned-api-check.sh --selftest-apk
#                                           the APK check's refusals and rules on stub tools and stub
#                                           APKs, with no Android SDK (see "APK selftest mode" below)
#   scripts/banned-api-check.sh --selftest  every fixture in scripts/testdata/banned-api/ must trip the
#                                           gate for its category; every clean-* fixture must pass; the
#                                           Kotlin hit fixtures whose rule a scope skips must pass
#                                           when copied into that scope (the KMP test sets
#                                           included); the Build, KtBinary and KtRoot rules'
#                                           cases, scratch git repositories built here, and the FFI
#                                           cases that need two crates must trip or pass as their
#                                           names say; the
#                                           artifact fixtures in scripts/testdata/artifact/ must give
#                                           exactly their pinned hits (needs the pinned toolchain); the
#                                           workflow fixtures in scripts/testdata/workflows/ must trip
#                                           or pass the workflow check as their names say, and so
#                                           must the bootstrap exception's cases, on copies of this
#                                           script with a stand-in list; the
#                                           image lists' built-in cases must be refused before any
#                                           host tool runs; the OS configuration fixtures in
#                                           scripts/testdata/os-config/ must pass or fail as their
#                                           names say; the shard option's malformed and
#                                           out-of-range values must be refused; and the image
#                                           scan's built-in cases must be refused, or, on a stub
#                                           image, give exactly their one hit
#   scripts/banned-api-check.sh --selftest --shard K/N
#                                           the same cases, those of shard K of N alone (see
#                                           "Selftest shards" below)
#
# Prints "<category>: <file>:<line>: <text>" per hit, then a summary. Exit 0 clean, 1 hits,
# 2 usage or read error: a file that cannot be read fails the gate, it is never skipped, and so
# does a tool the scan, --workflows or --artifact runs that cannot start, fails or is killed,
# naming itself (see "The tools the gate runs fail closed" below).
#
# Selftest shards (tasks/todo.md, M5-63: CI's gates job runs the selftest as two shards side by
# side). --selftest --shard K/N walks the whole case list in its fixed order and runs case c
# (counted from 1) only when (c - 1) mod N is K - 1, so neighbouring cases go to different
# shards and every kind of case falls into every shard: the fixtures, the scope trees' scans, the
# cases built here and the other modes' cases. A case is skipped only at its judged run, so what
# comes before that is still made in every shard: each case's scratch tree (and an image stub
# case's lists), the scope trees' copies, the artifact objects and the image stub, which the
# shard's own cases need too. Before its summary a sharded run prints "selftest: shard K/N: OWN
# of WHOLE cases", OWN the cases it judged (passed and failed) and WHOLE the cases in the list;
# the shards of one tree split one list when each prints the same WHOLE and their OWN add up to
# it. K and N are decimal numbers from 1 to 9999 with no leading zero, K at most N; any other
# value, a missing one or a further argument is exit 2 before any case runs. Without the option
# every case runs, and the output is as before.
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
#     hit too;
#   - no way back to the Android build's bootstrap (KtSdk's kt_bootstrap, tasks/todo.md, M5 group
#     4): kc.bootstrap, --write-locks, --update-locks, --write-verification-metadata or its -M,
#     LockMode.DEFAULT or LENIENT, dependency verification (or -F) set to anything but strict, or
#     the build-script calls that turn locking or verification off, comments included, but on the
#     one line that the reviewed, temporary exception names (kt_bootstrap_exception:
#     entropy-android.yml only, its line once; empty but during the re-plan's second bootstrap,
#     M5-13, Q67 and Q73; a list of any other shape is exit 2);
#   - none of KtSdk's Kotlin/Native refusals (kt_kmp_refused, any letter case, comments included:
#     CocoaPods, Swift packages, xcodeCompatibility.nowarn, the device-test builder,
#     downloadFromMaven with any value, any kotlin.native., kotlin.apple. or kotlin.mpp. name and
#     any name holding konan, KONAN_DATA_DIR among them, as a -P or -D option, an environment
#     variable or anything else), so no workflow sets a Kotlin/Native or Kotlin Multiplatform
#     property (M5 builds no Kotlin/Native, Q73);
#   - the canary property kc.canary (any letter case, comments included) only as the canary
#     step's one Gradle command line, whole: sh scripts/android-gradle.sh
#     --dependency-verification strict --offline -Pkc.canary=true :app:assembleShippingRelease
#     (kt_canary_workflow; tasks/todo.md, M5 group 5), and that line once.
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
# (the control). Then each of group 14's 16 positive controls is a mutation of the image (the
# root unpacked afresh, edited and repacked with mksquashfs -no-xattrs; partition 1 copied and a
# file replaced with mcopy -o; the pieces reassembled under a fresh MBR sized to them), of KCONFIG
# or of BIN_SHA256, isolated so that the named rule alone fires: a mutated root's lists stand in
# for expected/ (so only the deny-list, marker, key or ELF rule can fail it), and a mutated
# KCONFIG is also the stand-in linux.config except in the one-line-off case. The ELF controls (a
# stripped shared object importing rand, one carrying a rand-crate symbol, one carrying a
# getrandom-fallback symbol, a stripped static executable) are built from
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
#              nosuid, nodev, noexec and a size=; no line carries rw, exec, suid, dev or remount
#              (mount applies options in order, so a later one clears the flag before it); no
#              line of another filesystem type; at least one line.
#   Cmdline    no console= and no init= word, and no double quote (the kernel strips a word's quotes
#              before it reads param=value); the words ro, panic=0 and init_on_free=1.
#   ConfigTxt  no enable_uart=1, dtoverlay, start_file, fixup_file, start_x=1, start_debug=1 or
#              plain gpu_mem= line (each of the last five selects other firmware files); the
#              gpu_mem_* lines are gpu_mem_256=100, gpu_mem_512=100 and gpu_mem_1024=100, each
#              once (comments skipped).
#   Kconfig    expected/kconfig-required and kconfig-forbidden equal the fragment's =y and
#              "is not set" lines, and expected/linux.config keeps them with exactly one
#              CONFIG_HW_RANDOM_* driver, BCM2835, as in the image scan.
#   BusyBox    only init and mount, as an allow-list: CONFIG_INIT, FEATURE_USE_INITTAB, MOUNT,
#              FEATURE_MOUNT_FSTAB, FEATURE_MOUNT_FLAGS, SH_IS_NONE and BASH_IS_NONE at =y, and no
#              CONFIG_X=y line but those and the build settings pi/os/board/pizero/busybox.config
#              keeps (busybox_allowed below), so no applet or shell can be added to it.
#
# APK mode (tasks/todo.md, M5 group 5; rule 9, rule 10, and rule 1 as Q59 (b) reads it): the Android
# workflow runs it on the shipping and test-registry APKs once signed, and on the canary APK, which
# it must refuse. VARIANT is one of :app's flavours, shipping or withTestRegistry; APK the signed
# APK; EXPECTED_DIR mobile/android/expected; MERGER_REPORT the Android Gradle plugin's
# manifest-merger report of that variant's release build; CERT_SHA256 the SHA-256 of the run's
# throwaway signing certificate (64 lowercase hex digits); JNILIBS_DIR the variant's
# mobile/android/app/src/VARIANT/jniLibs, where scripts/android-rust.sh copied the libkeepcrypt.so
# it built and scanned for each ABI (M5 commit 14, lead decision M5-9). aapt2, dexdump, zipalign and
# apksigner (the build-tools) and llvm-nm and llvm-readobj (the NDK's) come from PATH, and python3 -I
# reads the APK with its zipfile module (the Python half, apk_py below). Prints the APK's SHA-256
# and its manifest summary, then "<Category>: <name>: <detail>" per hit and a one-line count; exit
# 0 clean, 1 hits, 2 anything that cannot be read or run. Nothing passes vacuously: a bad argument,
# a missing or empty expected file or report, a missing JNILIBS_DIR or scanned copy, a tool missing
# from PATH or failing, a dump or report line the parsers cannot read, a malformed native-libs.txt
# line or one that does not list libkeepcrypt.so for each ABI, and dex files in which dexdump lists
# no com.keepcrypt class are each exit 2.
# The manifest summary, defined here once, one fact per line: from aapt2 dump badging, package
# NAME, versionName V, minSdk N and targetSdk N; from dump permissions, permission NAME (declared)
# and uses-permission NAME (used; with maxSdkVersion=N when set), sorted, and any line of another
# shape as permissions-dump LINE; from dump xmltree AndroidManifest.xml, application ATTR=V for
# every attribute of <application> (its class name, appComponentFactory, process and the rest),
# sorted, with allowBackup=, dataExtractionRules=, debuggable= (also true when badging prints
# application-debuggable), extractNativeLibs=, fullBackupContent= and usesCleartextTraffic= always
# there (unset when absent), a resource reference reading set wherever it is a value (its id
# changes from build to build); manifest sharedUserId= when present; every activity, activity-alias,
# provider, receiver and service as KIND NAME exported=V (an absent exported reads as the
# platform's default: true with an intent filter, false without), then KIND NAME ATTR=V for each of
# its other attributes, sorted, then its intent filters as KIND NAME intent-filter action:A
# category:C data:K=V,..., sorted by component; uses-library and uses-native-library NAME
# required=V, sorted; then, sorted, uses-feature NAME required=V, queries TAG NAME (one line per
# child of <queries>, or queries alone), and every other element of the application or the manifest
# as application-element or manifest-element TAG NAME; and from the merger report, removed KEY
# [ATTRIBUTE] for every node (a line at column 0) or attribute (indented one tab) with a record
# whose verb is not ADDED, MERGED, INJECTED, IMPLIED or CONVERTED (tools:node="remove" records
# REJECTED), sorted. The rules:
#   Manifest   the summary equals EXPECTED_DIR/manifest-VARIANT.txt byte for byte (the diff on
#              stderr). Whatever that file says, hard rules on the summary: a line (but a removed
#              one) naming android.permission.INTERNET, ACCESS_NETWORK_STATE or ACCESS_WIFI_STATE;
#              any provider, receiver or service; any queries line; allowBackup,
#              fullBackupContent, usesCleartextTraffic or debuggable other than false, and
#              dataExtractionRules unset; more than one exported activity or activity-alias (one
#              hit naming them). And every line of MERGER_REPORT that names INTERNET: no network
#              permission is ever stripped.
#   NativeLib  every entry under lib/ is lib/<abi>/<name>.so for one of MA:23's three ABIs
#              (arm64-v8a, armeabi-v7a, x86_64; lead decision M5-10), an ELF, listed in
#              EXPECTED_DIR/native-libs.txt, of its ABI's ELF class and machine, and, when 64-bit,
#              with every LOAD segment aligned to a multiple of 0x4000 (16 KB pages); every listed
#              one is in the APK; and no ELF anywhere else in it. native-libs.txt lists a third
#              party's library by "<abi> <name> <sha256>" (graphics-path's), whose SHA-256 the
#              entry must have, and ours by "<abi> libkeepcrypt.so android-rust.sh", for each of
#              the three ABIs: that entry must be stored (extractNativeLibs=false) and hold exactly
#              the bytes of JNILIBS_DIR/<abi>/libkeepcrypt.so, so the library the APK ships is the
#              one android-rust.sh's release-artifact scan passed. Each libkeepcrypt.so also
#              exports, by llvm-nm -D --defined-only, exactly JNI_OnLoad and
#              Java_com_keepcrypt_entropy_ffi_Native_call beside secp256k1-sys 0.10.1's own four
#              (lead decisions M5-21 and M5-40, as entropy-ci.yml's cross legs check them), and
#              needs libc.so, with at most libm.so and libdl.so beside it (DT_NEEDED, llvm-readobj
#              --needed-libs). In the test-registry APK each must hold its registry marker and the
#              test key (a NativeLib hit for each one missing: the library is not that build's).
#   Format, Symbol, StdRandom, OSImport
#              every libkeepcrypt.so goes through the whole release-artifact scan for its ABI's
#              target, as the cross legs scan the cargo output (artifact_file: a .symtab, no RNG
#              symbol, no std random-key path, the getrandom import), and every other native
#              library that passed NativeLib through the image scan's elf_check (llvm-nm -D:
#              dynamic symbols listed, no banned RNG import, no rand-crate or getrandom-fallback
#              symbol).
#   Marker, TestKey
#              the three markers and the test key in the APK's own bytes (its stored entries, the
#              zip comment) and in every entry, decompressed: dex files, resources, libraries.
#              libkeepcrypt.so is searched once, as the library, under the artifact scan (its
#              stored bytes are blanked in the APK's own), where the test-registry APK's must hold
#              exactly its registry marker and the test key, which are then no hit, and the
#              shipping APK's neither.
#   DexRef     dexdump -d of every .dex entry: in each class whose descriptor starts
#              Lcom/keepcrypt/, any line naming java.util.Random, the kotlin.random or
#              java.util.random package, ThreadLocalRandom, SplittableRandom,
#              java.security.SecureRandom, Math.random, StrictMath.random, UUID.randomUUID,
#              Collections.shuffle, or shuffle, shuffled, random or randomOrNull of a
#              kotlin.collections, kotlin.ranges or kotlin.text class (dex_banned below), one hit
#              per class and name. Library classes are not judged (Q59 (b)): R8 is off, so the
#              APK carries Kotlin's own Random.
#   Zipalign   zipalign -c -P 16 -v 4 fails (4-byte entries, 16 KB-aligned native libraries).
#   Signature  apksigner verify --print-certs fails, or lists any signer but exactly one, whose
#              certificate SHA-256 is CERT_SHA256.
#
# APK selftest mode (tasks/todo.md, M5 group 5): CI's gates job runs it with no Android SDK, only
# sh, python3's standard library and stub aapt2, dexdump, zipalign, apksigner, llvm-nm and
# llvm-readobj, which print canned output (a stub dex file holds the text dexdump would print for
# it; a stub library is an ELF header with its LOAD segments and the NM:<name> (undefined),
# DEF:<name> (defined) and NEEDED:<library> words the stub llvm-nm and llvm-readobj list, and
# NOSYMTAB when it has no .symtab). The base
# case is aapt2's three dumps of the shipping APK (scripts/testdata/apk/, from the Android run
# 39062895784; the xmltree dump has since gained the application's class, KeepCryptApp, M5 commit
# 15, and all three CAMERA, the xmltree dump with the camera feature not required, M5 commit 18), a
# stand-in merger report that removes the androidx.startup provider, the run's
# signer and a stub APK laid out as the real one; it must pass against the committed
# mobile/android/expected/manifest-shipping.txt (the control). Each case changes one thing and must
# give exactly that one hit: INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, a provider, a
# receiver, a service, allowBackup true, debuggable, fullBackupContent true, usesCleartextTraffic
# true, dataExtractionRules unset, an extra exported activity, an exported activity-alias and a
# <queries> element (each against its own summary, so that only the hard rule can fail it), a
# summary that differs from the expected one, a changed appComponentFactory, another Application
# class and an added activity attribute (each against the committed summary), INTERNET in the
# merger report; an unlisted .so, a 4 KB-aligned and a 0x6000-aligned 64-bit .so, a 64-bit .so with
# no LOAD segment, another SHA-256, a listed .so missing, an x86 .so, a .so for another machine, a
# .so that is not an ELF, a truncated one, one in a subdirectory of lib/<abi>/, an ELF outside lib/,
# a .so importing rand; a libkeepcrypt.so (the base case has one per ABI, with its scanned copy in
# the case's jnilibs/) that is not the scanned copy's bytes, missing for an ABI, compressed, 4 KB
# aligned on 64-bit, stripped, importing rand, without the getrandom import, with an extra export,
# without JNI_OnLoad, with another secp256k1-sys export, needing liblog.so, not needing libc.so,
# and in the shipping APK holding the registry marker or the test key; in the test-registry APK,
# whose clean control has both in each library, a library without its marker, without the test
# key or with the stub marker, the marker in the zip comment and the test key in resources.arsc; a
# marker in a dex file, the test key in resources.arsc, a marker in the zip comment, a reference
# from a com.keepcrypt class to each name of dex_banned (a library class's passes in the base case);
# zipalign failing, another signer, a second signer beside the run's and apksigner failing (the stub
# dexdump, zipalign and apksigner refuse to run without --apk's exact arguments). Its refusals must
# exit 2: bad usage, a bad VARIANT or CERT_SHA256, a missing expected directory, JNILIBS_DIR,
# expected file, report or APK, no aapt2 on PATH, a malformed native-libs.txt line, one listing
# libkeepcrypt.so by a SHA-256 or not for every ABI, a missing scanned copy and no com.keepcrypt
# class. Prints PASS or FAIL per case and a count; exit 0 all passed, 1 not.
#
# Categories (main patterns; the full lists are in the check functions below; comments count
# everywhere but where a rule says otherwise):
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
#              Kotlin/Swift .random( and .shuffled(, randomUUID (UUID.randomUUID; tasks/todo.md,
#              M5 group 3), and Kotlin's kotlin.uuid package and Uuid.random or Uuid::random (the M5
#              re-plan: they read the OS outside the pool, on Android and iPhone alike). Rule 1
#              allows one source of OS randomness, so
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
#              TcpListener, UdpSocket, and (tasks/todo.md, M5 group 3) android.webkit, WebView,
#              javax.net, Socket(, DatagramSocket, java.net.http, ConnectivityManager, Cronet and
#              DownloadManager. Not banned: "import Network" and NWPathMonitor (the offline
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
#              core/src, ffi/src, ffi/guard/src, ffi/jni/src, ffi/capi/src or pi/app/src (the
#              shipped crates; their tests use BTreeSet and BTreeMap). The artifact scan cannot see
#              it: std reads the OS for the hash keys.
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
#   Build      no tracked file under mobile/**/build/, mobile/**/.gradle/ or mobile/**/.konan/
#              (tasks/todo.md, M5 group 2; the re-plan's lead decision M5-28): Gradle's output, its
#              per-project cache and Kotlin/Native's project-local data directory never enter git,
#              so a committed one is a hit, "Build: <file>: <detail>" with no line. The tracked
#              files come from git ls-files, never from the scan list, so in a git work tree the
#              scan can leave out the ignored output Q76's local builds leave, and does (lead
#              decision M5-62 (a); gradle_out): mobile/android/.gradle/, mobile/android/build/ and
#              each module's build/ (app, capture-control, core-ffi, screens and secure-ui, the
#              modules mobile/android/settings.gradle.kts includes), exactly those directories; any
#              other build/ (gradle/'s, expected/'s, one deeper down) is scanned, and so is a
#              file or a link of one of those names (a link to a directory refused, as anywhere).
#              In a working tree that has built, their generated reports held 1,874 hits (M5-62),
#              and CI's fresh checkout has none of them. The skip hides nothing tracked: this rule
#              refuses every tracked file there, so only an untracked one goes unread, and no
#              untracked file is in CI's tree. A tree that is no git work tree (an export, a copy,
#              the selftest's scratch trees) has no index, so this rule is silent there and the
#              scan leaves nothing out: every file is read, those directories' too, as nothing
#              there tells a committed file from an ignored one. git missing from PATH is exit 2.
#              Gradle's own build.gradle.kts files, buildSrc/ and gradle/ (the version catalog and
#              the wrapper) are not output directories and pass.
#              The index is read with ls-files -s -z: -z names a file whole where plain ls-files
#              would quote it (a non-ASCII byte, a double quote, a backslash), which would defeat
#              the match, and -s shows the mode, so a gitlink (mode 160000, a submodule) anywhere
#              under mobile/ is a hit of its own: ls-files cannot list a submodule's files, so
#              this rule could not clear them.
#   Kotlin and Android (tasks/todo.md, M5 group 3; Q55; the re-plan's "Gate changes"; the re-cut
#              after Q73), on every scanned file under mobile/android (Kotlin, Java, XML, Gradle
#              files, lockfiles, a cinterop .def), by scope: the test source sets right under a
#              module's directory (mobile/android/<module>/), src/test, src/androidTest,
#              src/commonTest and src/androidHostTest (exactly those: src/withTestRegistry/ is a
#              flavour's and ships, and a src/test/ or src/commonTest/ directory deeper down, under
#              src/main/kotlin/ or src/commonMain/kotlin/ say, is compiled into the app and is
#              shipping code) skip KtIntent, KtStorage, KtDevice, KtFailOpen's catch list and
#              KtInput's Activity rule; mobile/android/capture-control (the CI-only positive
#              control, never shipped) skips only the FLAG_SECURE rules (KtWindow's securePolicy
#              and flag checks) and the Activity rule; every other file (commonMain, androidMain,
#              and iosMain and iosTest, which KtSourceSet refuses in M5, included) gets every rule.
#              Each named file below is one path, the app's
#              (mobile/android/app/src/main/kotlin/com/keepcrypt/entropy/NAME) unless secure-ui's
#              (.../secure-ui/src/main/kotlin/com/keepcrypt/entropy/secure/NAME) or :screens'
#              (.../screens/src/commonMain/kotlin/com/keepcrypt/entropy/screens/NAME) is named; a
#              file of the same name anywhere else gets every rule.
#   KtLog      Log (android.util.Log, Log.v/d/i/w/e/wtf( ), println( and print(, System.out,
#              System.err, printStackTrace, Timber, java.util.logging, slf4j, and a $ template in a
#              string on a line that calls error(, check(, require(, checkNotNull( or
#              requireNotNull( or builds an Exception, Error, Throwable or KcHalt (rules 3 and 5;
#              no message in app code is built from runtime values); not in
#              mobile/android/gradle/verification-metadata.xml, a list of the build's own
#              artifacts (the Android Gradle plugin's slf4j among them), never code.
#   KtFailOpen runCatching, getOrNull, getOrElse, getOrDefault, onFailure, exceptionOrNull (and
#              getCompletionExceptionOrNull), CoroutineExceptionHandler, SupervisorJob and
#              supervisorScope as words, and recover, recoverCatching and fold as calls, in every
#              scope;
#              and, outside the test source sets, the catch list: every catch (and Flow's
#              .catch { }) is a hit but catch (x: KcHalt) in :screens' commonMain CeremonyModel.kt
#              (mobile/android/screens/src/commonMain/.../CeremonyModel.kt; the re-plan's shared
#              model replaced the app's CeremonyViewModel.kt), catch (x: IOException) in
#              files/Documents.kt, and catch (x: CameraAccessException) and catch (x:
#              ReaderException) (ZXing's "no code in this frame", M5-53) in
#              camera/GoAheadScanner.kt, so Throwable, Exception, RuntimeException and Error,
#              ReaderException's subclasses (NotFoundException), any catch in :core-ffi
#              (androidMain and iosMain included) and a KcHalt caught elsewhere all hit; a file
#              with an allowed catch must hold its type's own import line, exactly (import
#              com.keepcrypt.entropy.ffi.KcHalt, import java.io.IOException, import
#              android.hardware.camera2.CameraAccessException, import
#              com.google.zxing.ReaderException), in its import header (its leading blank, //
#              comment, package and import lines, so never inside a block comment), or the catch
#              hits, "missing ..."; and an alias or cast to one of those four names ("as KcHalt",
#              an import alias included), an "as" followed by a comment, a typealias of one, a
#              typealias with a comment or a line break after it and an import that ends in "as"
#              all hit, so no other type (Throwable, say) stands behind an allowed catch's bare
#              name. The catch list also covers the uncaught-exception handlers, a catch-all no
#              catch shows (M5-58): setUncaughtExceptionHandler, setDefaultUncaughtExceptionHandler
#              and UncaughtExceptionHandler as words, and uncaughtExceptionHandler (Kotlin's
#              property for a thread's getter and setter), and the other ways a thread's failure
#              stops short of the default handler, ThreadGroup (a thread with no handler of its
#              own hands its failures to its group), getUncaughtExceptionHandler (the getter a
#              Thread subclass can override) and uncaughtException (the method every handler
#              implements) as words, so a call, a method reference, a property assignment, an
#              override, an import, an alias and a typealias of one all hit, but for two places,
#              once each and each exactly, its indentation aside: the line
#              Thread.setDefaultUncaughtExceptionHandler( in the app's KeepCryptApp.kt, with the
#              line after it CrashHandler(wipe = { Core.wipeAll() }, end = {
#              Process.killProcess(Process.myPid()) }), (the call that installs CrashHandler; any
#              other line there is a hit, "missing ..." at the file's end), and CrashHandler's
#              one-line class header, with Thread.UncaughtExceptionHandler its only supertype, with
#              the line after it override fun uncaughtException(thread: Thread, exception:
#              Throwable) {, in the app's CrashHandler.kt; any other mention in either file hits.
#              It also covers the other catch-alls no catch shows (M5-60): a task whose failure
#              waits where nobody need read it, ExecutorService, Executors, CompletableFuture,
#              FutureTask, ForkJoinPool and coroutines' async and Deferred as words, and Executor
#              but in the app's camera/GoAheadScanner.kt, whose import header must then hold the
#              exact line import java.util.concurrent.Executor ("missing ..."); any mention of
#              java.util.concurrent or kotlinx.coroutines but the import lines the shipping code
#              has today, each a whole line, exactly: import kotlinx.coroutines.X for X each of
#              CoroutineDispatcher, CoroutineScope, Dispatchers, Job, cancel, delay,
#              flow.MutableStateFlow, flow.StateFlow, launch and withContext in any file, and
#              import java.util.concurrent.Executor in the scanner alone, so another import, a star
#              import, an alias, two imports on one line, a qualified name in code (with blanks,
#              backticks or line breaks around its dots, or a comment among its parts, a hit
#              too) and a package line all hit, a mention in a comment or a string too (M5-60
#              (b)); any mention of the standard library's kotlin.coroutines or a subpackage of it
#              (intrinsics, cancellation or any other), read the same way, with no allowed line,
#              as its startCoroutine and createCoroutine take a completion that can ignore the
#              failure it is handed (M5-65); and a return, break or continue inside a finally
#              block, which drops the exception in flight, read fail closed without a parser: a
#              quote (" or '), a backtick or a comment in the block, or a comment between finally
#              and its {, where a brace could be text, hits at its line, and a file that ends
#              inside the block hits at its finally ("missing ...").
#   KtWindow   Toast, Snackbar, Notification, Dialog(, AlertDialog, DialogFragment, Popup(,
#              PopupWindow, ListPopupWindow, PopupMenu, DropdownMenu, ModalBottomSheet, Spinner,
#              AutoCompleteTextView, tooltips, WindowManager's addView and
#              TYPE_APPLICATION_OVERLAY; and, outside :capture-control, DialogProperties( or
#              PopupProperties( without securePolicy = SecureFlagPolicy.SecureOn as a named
#              argument closed on the same line (fail closed, like .textSelection()), and
#              anything that can turn FLAG_SECURE off: clearFlags, setFlags but
#              setFlags(WindowManager.LayoutParams.FLAG_SECURE,
#              WindowManager.LayoutParams.FLAG_SECURE), attributes = ..., setAttributes and
#              updateViewLayout.
#   KtInput    TextField (Basic, Outlined, Secure), EditText, InputMethodManager and
#              SoftwareKeyboardController; and, in shipping sources but secure-ui's
#              SecureActivity.kt, an Activity subclass: a constructor call of a capitalized name
#              ending in Activity (": ComponentActivity()"), a class header with no primary
#              constructor whose supertypes name one (class X : ComponentActivity {, built through
#              a secondary constructor), or Java's extends ...Activity, but SecureActivity (the
#              app's activity derives from it). A typealias of an Activity is not seen.
#   KtStorage  outside the test source sets (rule 8): SharedPreferences, DataStore,
#              openFileOutput/openFileInput, FileOutputStream/FileInputStream, File(,
#              filesDir, cacheDir, getExternal, MediaStore, Room, SQLite, createTempFile,
#              rememberSaveable, SavedStateHandle and takePersistableUriPermission; getDir(,
#              dataDir, getDatabasePath, openOrCreateDatabase, RandomAccessFile, FileWriter,
#              FileReader, java.nio.file, Files., Paths., Path.of, writeBytes(, writeText(,
#              appendBytes(, appendText( and createDeviceProtectedStorageContext; and
#              openOutputStream, openInputStream and openFileDescriptor outside files/Documents.kt.
#   KtIntent   outside the test source sets and files/Documents.kt: Intent( and its factory
#              calls (Intent.parseUri), startActivity (and ForResult, startActivities,
#              startIntentSender), start...Service, bind...Service, send...Broadcast,
#              PendingIntent, registerReceiver, ShareCompat, createChooser, ACTION_VIEW,
#              LocalUriHandler, openUri, LinkAnnotation, and the activity-result API
#              (ActivityResultContract(s), registerForActivityResult,
#              rememberLauncherForActivityResult) but a launcher of
#              ActivityResultContracts.RequestPermission() on one line and the line import
#              androidx.activity.result.contract.ActivityResultContracts; in AirplaneSettingsIntent.kt
#              (the Android end of the airplane-settings seam, lead decision M5-20) also
#              startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS)), whole on one line.
#   KtDevice   outside the test source sets: the camera (Camera, Camera* classes, camera2,
#              androidx.camera) only in camera/GoAheadScanner.kt, sensors (Sensor*) only in
#              SensorMotionSource.kt (the Android end of the motion-source seam, M5-20), and
#              Settings.Global (and Settings.Secure and Settings.System) only in secure-ui's
#              OfflineMonitor.kt.
#   KtSdk      in build files and lockfiles (*.gradle.kts, *.gradle, gradle.properties,
#              *.versions.toml, *.lockfile), any letter case: firebase, crashlytics,
#              com.google.android.gms, play-services, mlkit, sentry, bugsnag, acra, appcenter,
#              datadog, newrelic, segment, mixpanel, amplitude, flurry, admob, facebook,
#              instabug and onesignal anywhere on a line; a repository but google() and
#              mavenCentral() (maven, ivy, exclusiveContent, gradlePluginPortal, jcenter,
#              mavenLocal, flatDir, includeBuild, a url or uri); files(, fileTree(,
#              fileCollection, zipTree, tarTree, apply(from, apply from:, buildscript {,
#              classpath(; a repositories block in any build file but
#              mobile/android/settings.gradle.kts; and any srcDir, srcDirs, setSrcDirs,
#              directories, srcFile or setSrcFile but srcDir("src/...") or srcDirs("src/...")
#              with one plain path under the module's src/ (no .., no $, no build path) that is
#              not a test source set's (src/test, src/androidTest, src/commonTest or
#              src/androidHostTest, which skip the shipping rules). In build
#              files but lockfiles (whose generated header names --write-locks), in
#              scripts/android-gradle.sh and in every workflow (Workflow mode), the bootstrap
#              (group 4): kc.bootstrap, --write-locks, --update-locks,
#              --write-verification-metadata and its short -M, LockMode.DEFAULT or LENIENT,
#              dependency verification (--dependency-verification, its short -F,
#              org.gradle.dependency.verification) set to anything but strict, startParameter's
#              verification and lock-writing settings, deactivateDependencyLocking,
#              unlockAllConfigurations, ignoredDependencies, disableDependencyVerification (one
#              configuration's verification off), and lockMode or lockFile but the line
#              lockMode.set(LockMode.STRICT). In the same files, the canary (group 5): kc.canary,
#              projectDir, setProjectDir, includeFlat, buildFileName and setBuildFileName, any
#              letter case, but the guard line if (providers.gradleProperty("kc.canary").orNull
#              == "true") { in mobile/android/settings.gradle.kts and app/build.gradle.kts, and the
#              canary library's projectDir line in the settings file as the guard block's third
#              line, after include(":canary-lib") (kt_canary). Whenever mobile/android exists,
#              mobile/android/build.gradle.kts must hold the lines lockAllConfigurations() and
#              lockMode.set(LockMode.STRICT) (a missing one is reported at line 1). In build
#              files but lockfiles, the Kotlin Multiplatform DSL by allow-list (kt_kmp; the
#              re-plan's "New file types and build lines", for the Android target alone after Q73):
#              a line naming a word of kt_kmp_ere (a kotlin { block, a Kotlin target or per-target
#              source set, the cinterop, binary, linker, compiler, test-run and device settings,
#              osVersionMin, the Android target's builders, CocoaPods, Swift packages,
#              XCFrameworks, Xcode settings) or a kotlin.mpp. property in any letter case, comments
#              included, passes only as one of kt_kmp_lines exactly (indentation and trailing
#              blanks aside): kotlin {, withHostTestBuilder {} and withHostTestBuilder {, so an
#              iPhone target, an iosMain or iosTest block, a cinterop block, a framework, a linker
#              or compiler option, a simulator device and osVersionMin are each a hit in M5; and,
#              in any letter case, CocoaPods, Swift packages, xcodeCompatibility.nowarn,
#              withDeviceTestBuilder, downloadFromMaven with any value, any kotlin.native. or
#              kotlin.apple. name and any name holding konan (konan.data.dir, KONAN_DATA_DIR) hit
#              whatever the list says, there and in scripts/android-gradle.sh (and Workflow, in the
#              workflows), where a kotlin.mpp. name hits too (kt_kmp_refused).
#   KtBinary   a tracked file (or link) under mobile/ with the extension jar, aar, so, dex, class,
#              apk, aab, jks or keystore, or any other code or archive extension the scan list
#              skips (zip, gz, xz, bz2, zst, tar, ipa, dylib, a, rlib, o, car), or a Kotlin/Native
#              klib, any letter case, or under a directory named *.framework or *.xcframework, read
#              from git ls-files as the Build rule reads it, "KtBinary: <file>: <detail>": the scan
#              never reads those files, so none may be tracked where a build could use it. Images,
#              fonts, sound and PDF stay allowed. And any tracked regular file under mobile/ whose
#              first four bytes (from the index's blob) are the magic number of a Mach-O file (thin
#              or fat, either byte order), an ELF file, an ar archive (a static library or an rlib),
#              a zip archive (a jar, aar, apk, aab, ipa or klib), a dex file, a JKS or JCEKS
#              keystore, or a gzip, xz, zstd or bzip2 stream, whatever its name: a library,
#              executable, object, package, bytecode, key store or archive named .png is still one.
#   KtManifest in every AndroidManifest.xml under mobile/android: android.permission.INTERNET,
#              ACCESS_NETWORK_STATE and ACCESS_WIFI_STATE (a tools:node="remove" on them hits too:
#              no network permission is ever stripped), allowBackup="true",
#              usesCleartextTraffic="true", debuggable with any value, a <provider, <receiver or
#              <service unless tools:node="remove" is on its line, and, fail closed, an
#              <application start tag (read over lines to its first >) without
#              allowBackup="false", fullBackupContent="false" and dataExtractionRules.
#   KtTestChannel
#              in any file: the instrumentation status key kc_ci_throwaway_passphrase (the CI
#              throwaway seed's backup passphrase, tasks/todo.md M5 group 18) outside
#              mobile/android/app/src/androidTest/ and scripts/android-age-check.py.
#   KtSourceSet
#              (the re-plan's lead decisions M5-19 and M5-20; "KtSourceSet: <file>: <detail>", a
#              path rule): in the KMP modules (kt_kmp_modules: core-ffi and screens) only
#              commonMain, commonTest, androidMain and androidHostTest right under src/ (M5 builds
#              the Android target alone, Q73), so iosMain, iosTest, nativeInterop, appleMain,
#              nativeMain, the per-target sets (iosArm64Main, iosSimulatorArm64Main),
#              androidDeviceTest, Android's main and test, and a file right under src/ are
#              refused; in every other module no KMP source-set name (one that ends in Main or
#              Test but androidTest, or nativeInterop); and no src/ below mobile/android/ that is
#              not a module's own (each module is one directory under mobile/android/, so a nested
#              module's sources, include(":ui:words") at mobile/android/ui/words/, and the root
#              project's, mobile/android/src/, are refused); and no Java source anywhere under
#              mobile/android, a .java file in any letter case, in every scope (lead decision M5-60
#              (c): Java reads backslash-u escapes as the characters they name, so a .java file's
#              text can hide every rule's word, and the app has no Java).
#   KtIos      (rules 1, 5, 8 and 9 in Kotlin/Native) in iosMain and iosTest right under any
#              module's src/, on top of every Kt rule: Apple's storage (NSUserDefaults,
#              NSFileManager, NSFileHandle, writeToFile, NSKeyedArchiver, SecItemAdd, CoreData,
#              NSUbiquitousKeyValueStore, CloudKit), posix files and logging (fopen, fwrite, a call
#              of open, the printf family, syslog), other apps (openURL,
#              UIDocumentInteractionController), windows (UIAlertController, a UIWindow
#              constructor, UIMenu), input (UITextView, becomeFirstResponder), logging (NSLog,
#              os_log, AccessibilityDebugLogger), randomness and identifiers (platform.posix.rand,
#              the words random and srand, NSUUID) and the network's C names (nw_connection,
#              nw_listener, nw_browser, nw_endpoint, nw_parameters, CFStream, CFSocket,
#              getaddrinfo, a call of socket); and in every file under mobile/android:
#              staticCFunction, setUnhandledExceptionHook and nw_path_*, and usePinned and
#              addressOf (only an iPhone actual over a C bridge would pin memory, and M5 has none,
#              Q73). UIActivityViewController, UIPasteboard, UNUserNotificationCenter, UITextField,
#              drand48, arc4random, SecRandomCopyBytes, URLSession, NWConnection and CFNetwork are
#              other categories' everywhere. KtSourceSet refuses iosMain and iosTest themselves in
#              M5, so a KtIos hit there comes with one of its.
#   KtRoot     (lead decisions M5-19 and M5-25; "KtRoot: <file>: <detail>"): a .kt or .kts file
#              under mobile/ outside mobile/android/, and any tracked file under mobile/ios/ (read
#              from git ls-files as the Build rule reads it), which stays empty until M6 brings the
#              Swift and Xcode rules.
#   KtCinterop (the re-plan's C bridge): mobile/android/core-ffi/src/nativeInterop/cinterop/
#              keepcrypt.def holds exactly the lines headers = keepcrypt.h, headerFilter =
#              keepcrypt.h and package = com.keepcrypt.native, each once, and no other (no ---
#              section, second header, staticLibraries, libraryPaths, linkerOpts or compilerOpts;
#              a missing line is reported at line 1); any other .def under mobile/android is a hit
#              of its own. KtSourceSet refuses nativeInterop itself in M5 (Q73), so even that one
#              definition is a hit there.
#   FFI        in .rs files under ffi/ (tasks/todo.md, M5 groups 3 and 7; Q53; Q66's split into
#              keepcrypt-guard and keepcrypt-jni, M5-32; keepcrypt-capi is M6's after Q73):
#              catch_unwind outside every comment and string or char literal (so ffi/clippy.toml's
#              ban, a doc line and a string are no call site) anywhere but ffi/guard/src/lib.rs,
#              and there every one but the path call std::panic::catch_unwind( in the body of the
#              crate root's fn guarded, once (so a use line naming it, a rename, a re-export, a
#              wrapper, a fn guarded in a mod, an impl or another fn, a macro_rules definition and a
#              second call are hits); an export (no_mangle, export_name, or the word extern, which
#              an extern fn with any ABI string or none starts, outside comments and literals)
#              anywhere but ffi/jni/src/lib.rs, and there an export whose own body does not call
#              keepcrypt_guard::guarded( (the crate root's no_mangle JNI_OnLoad aside) or that has
#              no body, an extern that $ or ) follows (a macro's ABI), and macro_rules; the JNI
#              names (a Java_ function, JNI_OnLoad, JNIEnv, jni_sys) outside comments and literals
#              anywhere but ffi/jni/, and in ffi/jni/src/lib.rs an extern fn whose ABI is not
#              "system", its words read over lines and comments; macro_rules and macro_export
#              outside comments and literals in any file under ffi/src/, ffi/guard/src/ and
#              ffi/jni/src/ (lead decision M5-35; lib.rs's through the export scan), so no macro
#              writes an export out of the export scan's sight; pub outside comments and literals
#              in any file under ffi/guard/src/ but the crate root's one line
#              "pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {" (M5-35), so
#              keepcrypt-guard re-exports nothing of keepcrypt-ffi and keepcrypt-jni reaches the
#              safe layer through guarded alone, and any line after it there but exactly
#              "    let input = Zeroizing::new(input);", so guarded wipes the input it takes (a
#              missing one is reported at the pinned line); and once ffi/jni/src/lib.rs exports a
#              function,
#              the one catch_unwind call in fn guarded is required (a missing one is reported at
#              ffi/jni/src/lib.rs:1).
#              Session::new (the Shell rule's shapes, comments counting) anywhere under ffi/ but
#              ffi/src/ceremony.rs, each one after its first there, and none there once the file
#              exists (reported at line 1). The identifiers thread and JoinHandle anywhere but in
#              keepcrypt-ffi's integration tests (ffi/tests/, lead decision M5-8), comments included:
#              a joined thread would turn a panic into a value, and the shared clippy.toml cannot ban
#              thread spawning (core/tests/panic_wipe.rs joins one). A test thread turns no shipped
#              panic into a value, and ffi_discard_during_call needs one.
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
# use std::thread; passes (write those). Under ffi/, a comment that says thread is an FFI hit
# (write "the caller's own call"), and so is one that names Session::new outside ceremony.rs.
# Under mobile/android, UI text in XML is scanned like code: write camera, sensor, room and
# notification in lower case there ("Camera", "Sensor", "Room" and "Notification" hit), and a word
# such as Toast or Spinner hits in any text. A collection's fold( is a KtFailOpen hit like Result's
# (write the loop), and a local named attributes (val attributes = ...) is a KtWindow hit (rename
# it). In a build file, a comment that names a Kotlin target, framework(, binaries, a name holding
# konan or another word of the KMP DSL is a KtSdk hit (write "the two iPhone targets"); in
# iosMain and iosTest the word random (a comment's too) and any name holding printf are KtIos hits;
# and anywhere, prose that names Kotlin's uuid package by its dotted name is an RNG hit (write
# "Kotlin's uuid package"). A catch of a qualified type (java.io.IOException) in Documents.kt is a
# hit (import it), and so is a DialogProperties(securePolicy = ...) wrapped over lines (keep the
# call on one line); a removal of a manifest component is written on one line, tools:node="remove"
# with the tag.
#
# Portable on purpose: POSIX sh, POSIX ERE (no \b \s \< \>, no -P -w), POSIX sed (BRE, in
# selectable() and textselection(); ERE with -E, which BSD and GNU sed share, in threads_by_path())
# and LC_ALL=C, so BSD grep and sed (macOS) and GNU grep and sed (ubuntu CI) agree.
# Not scanned: .git/ target/ docs/ tasks/ CLAUDE.md scripts/testdata/, this script, files with a
# binary extension (the list at $binext below), and, in a git work tree, the ignored Gradle output a
# local build leaves, mobile/android/.gradle/, mobile/android/build/ and each module's build/ (see
# Build).
#
# Symlinks: a file symlink is scanned under its link name. A directory symlink fails the gate
# (exit 2, naming the link): its target may be outside the repo or under an excluded path, where
# nothing would ever scan it.
#
# Every other file is read as text (grep -a), whatever bytes it holds. grep -I used to skip any file
# with a NUL byte near its start, so one NUL in a comment hid a whole source file, and BSD and GNU
# grep differ on how far they look for one. Skipping goes by file extension instead, matched in any
# case (grep -i: under LC_ALL=C both greps fold ASCII letters only). The rules that read lines with
# awk instead (KtFailOpen's package mentions and finally blocks) read each file with its NUL bytes
# dropped (kt_text): the Mac's awk ends a line at a NUL, so a NUL in a comment or a string would
# hide the rest of its line from them.
#
# The patterns match API shapes (rand::, rand_core::, rand(), Math.random), not crate names:
# "rand_core" in a string or comment passes, because cargo-deny bans the crate itself.

set -u
unset CDPATH
LC_ALL=C # bytes, not characters: any byte is text, and the same [A-Za-z] ranges in both greps
export LC_ALL
nl='
'

# --- The tools the gate runs fail closed (tasks/todo.md, lead decision M5-66) --------------------
#
# A tool that cannot start (exit 126 or 127), exits with an error or is killed stops the gate with
# exit 2 and names itself, how it failed and what the gate was reading ($on), never "clean" and
# never a hit with no line. sh has no pipefail, so the scan, and each mode that calls fail_closed
# (below), runs no pipeline with two tools in it: each tool's output is a command substitution's,
# its status read there, and fed on with printf, a builtin, so a pipeline's status is its one
# tool's, and a command substitution's is its last command's. scripts/banned-api-faults.sh makes
# each tool fail at each place that runs it, in each of those ways, in each of those modes.
#
# And the scan's own shell starts no tool as a command of its own, only in a command substitution
# (report(), found()), which banned-api-faults.sh also checks in the text. That was the M5-66 hit
# with no line: macOS's /bin/sh, bash 3.2, keeps the finished job of a command its shell ran itself
# until that shell runs another one of its own. The scan ran git rev-parse so once, before its loop,
# and then only command substitutions, so git's finished job stayed in its job table for the whole
# scan. Each command substitution's shell starts with a copy of that table, and when the first tool
# it starts itself gets git's pid again (under load the pid space wraps in seconds, and a scan of a
# large tree takes far longer), that shell takes the old entry for its tool: it does not wait for
# the tool and reads exit 0, whatever the tool and git exited. A check's grep that matched nothing
# (exit 1) so gave report() exit 0 and no line, which it printed as the hit "Shell:
# ...MainActivity.kt:: ". No tool failed; the shell misread one. Every other shell of the scan
# lives far less than a wrap of the pid space, so no tool it starts can get the pid of a command it
# or its parent ran before. dash, CI's sh, does not do this. report() also refuses what the
# misreading gave: a check's exit 0 with no hit, and a hit without its line number.
#
# tool_status TOOL STATUS [NONE]: STATUS is TOOL's nonzero exit status. It is returned when it is
# NONE (grep's and the gate's awk programs' 1, "no line"); otherwise TOOL's failure is named, with
# $on, and the shell exits 2.
tool_status() {
  [ "$2" != "${3-}" ] || return "$2"
  case $2 in
    126 | 127) how='could not start' ;;
    129 | 1[3-8][0-9] | 19[0-2]) how="was killed by signal $(($2 - 128))" ;;
    *) how='failed' ;;
  esac
  printf 'banned-api-check: %s %s (exit %s)%s\n' "$1" "$how" "$2" "${on:+ on $on}" >&2
  exit 2
}

# fail_closed: from here on, each tool the gate runs is a function of its name that runs the tool
# (command bypasses the function) and passes its status through tool_status. The scan,
# --workflows and --artifact call it first; the other modes read their tools' statuses as they
# always have.
fail_closed() {
  awk() { command awk "$@" || tool_status awk "$?" 1; }
  find() { command find "$@" || tool_status find "$?"; }
  git() { command git "$@" || tool_status git "$?"; }
  grep() { command grep "$@" || tool_status grep "$?" 1; }
  mktemp() { command mktemp "$@" || tool_status mktemp "$?"; }
  od() { command od "$@" || tool_status od "$?"; }
  rm() { command rm "$@" || tool_status rm "$?"; }
  rustc() { command rustc "$@" || tool_status rustc "$?"; }
  sed() { command sed "$@" || tool_status sed "$?"; }
  sort() { command sort "$@" || tool_status sort "$?"; }
  tr() { command tr "$@" || tool_status tr "$?"; }
}

# found CHECK ARG...: true when CHECK ARG... exits 0, false when it exits 1 (a check of the gate's
# or grep -q), run in a command substitution so the scan's shell starts no tool itself. Any other
# status stops the gate with exit 2.
found() {
  r=$("$@" >/dev/null; echo "$?")
  case $r in
    0) return 0 ;;
    1) return 1 ;;
  esac
  printf 'banned-api-check: %s exited %s%s\n' "$1" "${r:-before its status was read}" "${on:+ on $on}" >&2
  exit 2
}

on=$0
dir=$(dirname "$0") || tool_status dirname "$?"
here=$(cd "$dir" && pwd -P) || exit 2
base=$(basename "$0") || tool_status basename "$?"
self=$here/$base

usage() {
  cat <<'EOF'
usage: scripts/banned-api-check.sh [--selftest [--shard K/N] | DIR | --artifact TARGET FILE... | --workflows DIR |
                                   --image-lists IMG KCONFIG | --image IMG EXPECTED_DIR KCONFIG BIN_SHA256 |
                                   --selftest-image IMG KCONFIG | --os-config OS_DIR |
                                   --apk VARIANT APK EXPECTED_DIR MERGER_REPORT CERT_SHA256 JNILIBS_DIR |
                                   --selftest-apk]
  (none)      scan the repo this script lives in
  DIR         scan DIR as if it were the repo root
  --artifact  scan release artifacts built for TARGET: test markers, the test registry key, RNG
              symbols other than TARGET's OS import, std's random-key path, a stripped file, and
              that import (see the script header)
  --workflows check every DIR/entropy-*.yml and .yaml workflow's hardening: read-only permissions, three
              actions at their approved SHAs, no secrets, no fork-trusting trigger, no expression
              in a run step, no Android bootstrap switch but the line a reviewed exception names
              (the clean line says whether kt_bootstrap_exception holds one, and which), the
              canary property only in the canary step's Gradle command, no Kotlin/Native or
              Kotlin Multiplatform setting
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
  --apk       check and scan a signed APK of VARIANT (shipping or withTestRegistry): its manifest
              summary equals EXPECTED_DIR's manifest-VARIANT.txt (mobile/android/expected) with no
              network permission, provider, receiver, service or <queries>, backup and debugging off
              and one exported activity; MERGER_REPORT names no INTERNET; its native libraries are
              native-libs.txt's, 64-bit ones 16 KB aligned, libkeepcrypt.so the bytes android-rust.sh
              scanned into JNILIBS_DIR, under the artifact rules, exporting our two symbols and
              needing libc, libm and libdl alone, the others through elf_check; no other ELF; no
              marker or test key but the test-registry library's own; no banned RNG reference from
              a com.keepcrypt class; zipalign; and CERT_SHA256 the one signer (build-tools and the
              NDK's llvm-nm and llvm-readobj on PATH)
  --selftest-apk
              the APK check's refusals and rules on stub tools and stub APKs (sh and python3 only)
  --selftest  run the fixtures in scripts/testdata/banned-api/, scripts/testdata/artifact/,
              scripts/testdata/workflows/ and scripts/testdata/os-config/, the image lists' built-in
              cases and the image scan's, on a stub image; with --shard K/N (K and N from 1 to 9999,
              K at most N), only case c of the list where (c - 1) mod N is K - 1, and a line
              counting them beside the whole list
Hits: RNG APIs (and the OS RNG read outside core/src/source), network APIs, Python network imports
and hard-coded http URLs (outside registry/), clipboard, copy and share APIs and Python clipboard
modules, tools and calls, getrandom in a .rs file outside core/src/source, std's OS-seeded hashing
in core/src, ffi/src, ffi/guard/src, ffi/jni/src, ffi/capi/src or pi/app/src, a core/src/lib.rs
(and pi/app's lib.rs and main.rs) without #![forbid(unsafe_code)], in Rust under core/, ffi/ or
pi/app/ a discarded result (_ =, an _name binding, drop or forget of a call), clippy as a cfg
predicate and /dev/stdout, /dev/stderr or /dev/tty, include! (by any path or alias) or a path
attribute in any .rs file, a C #include of a file with a binary extension, the shells' paths to
core: a session, pool input or clock named in the games, game_random named outside core and the
games, a second Session::new in pi/app, and a release probe that does not call game_random; and in
pi/app the firmware's device rules: a path literal outside device/paths.rs or off its list, a file
API outside device/, a file created outside device/usb.rs or any truncating, appending, renaming or
directory API, rppal or nix outside device/, MNT_FORCE, MNT_DETACH outside device/usb.rs, a
process, a thread or BufReader; and a tracked file (git ls-files) under mobile/**/build/,
mobile/**/.gradle/ or mobile/**/.konan/, or a submodule under mobile/. Under mobile/android, by
scope (the test source sets, :capture-control, the rest): logging and runtime-built messages,
fail-open Kotlin and catches outside the four allowed, dialogs, popups and other windows, text
fields and activities but SecureActivity, storage, intents, the camera, sensors and system settings
outside their files, SDKs, other repositories, local build inputs and the bootstrap's switches in
build files (and android-gradle.sh), strict locking missing from the root build file, and the
manifest's network permissions, backup, debug and components; a Kotlin Multiplatform source set
outside the allow list (no iPhone set in M5), a Java source, the iOS names in iosMain and iosTest,
C callbacks, pinned memory, Kotlin Multiplatform DSL lines outside the allow list (no iPhone target
in M5) and Kotlin/Native settings, and a cinterop definition other than the one exact .def; Kotlin outside
mobile/android and a tracked file under mobile/ios; a tracked binary (a klib, a framework, any
Mach-O, ELF, ar, zip, dex, keystore or compressed file among them) under mobile/; the CI passphrase
key outside its two files; and under ffi/ a catch_unwind but the one std::panic::catch_unwind call
in the crate root's fn guarded in ffi/guard/src/lib.rs, an export outside ffi/jni/src/lib.rs or one
there that does not call keepcrypt_guard::guarded, macro_rules there or macro_rules and
macro_export in ffi/src, ffi/guard/src and ffi/jni/src, a pub in ffi/guard/src but fn guarded's
one line, a first statement of guarded other than the input's Zeroizing wrap, a JNI name outside ffi/jni/ or a C-ABI export in its lib.rs, a second Session::new or one
outside ffi/src/ceremony.rs, and thread or JoinHandle outside ffi/tests/. A directory symlink is
refused. Exit 0 clean, 1 hits, 2 usage or read error.
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
# the import, so randomize, randomart and a random word in a string pass. Kotlin's kotlin.uuid
# package (no default import reaches it) and Uuid.random or Uuid::random draw from the OS outside
# the pool, on Android and in Kotlin/Native alike (tasks/todo.md, M5 re-plan, "Gate changes").
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
    -e 'randomUUID' \
    -e 'kotlin[.]uuid' \
    -e "${L}Uuid[[:space:]]*(::|[.])[[:space:]]*random" \
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
# The plan's java.net.http (tasks/todo.md, M5 group 3) is under java.net. already.
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
    -e 'android[.]webkit' \
    -e 'WebView' \
    -e 'javax[.]net' \
    -e 'Socket[[:space:]]*[(]' \
    -e 'DatagramSocket' \
    -e 'ConnectivityManager' \
    -e 'Cronet' \
    -e 'DownloadManager' \
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

# Rule 1, for .rs files under core/src, ffi/src (and the boundary crates' ffi/guard/src, ffi/jni/src
# and ffi/capi/src) and pi/app/src (tasks/todo.md, M3 group 13): std's
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

# rust_lex: awk functions, run with -v sq="'". lex() sets code to the line $0 with every comment
# removed and the contents of every string and char literal emptied, as rust_code_match below
# describes; depth (a block comment's nesting) and instr, israw and raw (an open string) carry over
# lines. It also keeps each string's text as written (escapes unread, a line break as \n) in
# lits[1..nlits], in the order the strings close on the line, and lit holds an open one's text
# over lines; only ffi_jni_abi reads them. rust_tokens' tokens() then feeds code to the program's
# own tok(t), one token at a time and in order over lines: a word, ::, "" (a string, emptied; the
# k-th "" of a line is lits[k]) or any other character but a blank.
rust_lex='
    # charlen(line, i): the length of the char or byte literal whose opening quote is at i, or 0
    # for a lifetime or a label: an escape runs to the next quote after the escaped character; a
    # double quote, or one to four bytes holding no quote, backslash or double quote, is closed by
    # the quote right after it.
    function charlen(line, i,    k, ch) {
      if (substr(line, i + 1, 1) == "\\") {
        k = index(substr(line, i + 3), sq)
        return k > 0 ? k + 2 : 0
      }
      if (substr(line, i + 1, 2) == "\"" sq) return 3
      for (k = 1; k <= 5; k++) {
        ch = substr(line, i + k, 1)
        if (ch == sq) return k > 1 ? k + 1 : 0
        if (ch == "" || ch == "\\" || ch == "\"") return 0
      }
      return 0
    }
    function lex(    line, n, i, c, two, rest, prev, len) {
      code = ""
      nlits = 0
      line = $0
      n = length(line)
      i = 1
      while (i <= n) {
        c = substr(line, i, 1)
        if (depth > 0) {
          two = substr(line, i, 2)
          if (two == "/*") {
            depth++
            i += 2
          } else if (two == "*/") {
            depth--
            i += 2
            if (depth == 0) code = code " "
          } else {
            i++
          }
        } else if (instr) {
          if (!israw && c == "\\") {
            lit = lit substr(line, i, 2)
            i += 2
          } else if (c == "\"" && substr(line, i + 1, length(raw)) == raw) {
            instr = 0
            code = code "\"\""
            lits[++nlits] = lit
            i += 1 + length(raw)
          } else {
            lit = lit c
            i++
          }
        } else {
          two = substr(line, i, 2)
          rest = substr(line, i)
          prev = i > 1 ? substr(line, i - 1, 1) : " "
          if (two == "//") {
            break
          } else if (two == "/*") {
            depth = 1
            i += 2
          } else if (c == "\"") {
            instr = 1
            israw = 0
            raw = ""
            lit = ""
            i++
          } else if (prev !~ /[A-Za-z0-9_]/ && match(rest, /^[bc]?r#*"/)) {
            instr = 1
            israw = 1
            lit = ""
            raw = substr(rest, 1, RLENGTH - 1)
            sub(/^[bc]?r/, "", raw)
            i += RLENGTH
          } else if (c == sq && (len = charlen(line, i)) > 0) {
            code = code sq sq
            i += len
          } else {
            code = code c
            i++
          }
        }
      }
      if (instr) lit = lit "\n"
    }'
rust_tokens='
    function tokens(    s, t) {
      s = code
      while (s != "") {
        if (match(s, /^[[:space:]]+/)) {
          s = substr(s, RLENGTH + 1)
          continue
        }
        if (match(s, /^[A-Za-z_][A-Za-z0-9_]*/) || match(s, /^::/) || match(s, /^""/)) {
          t = substr(s, 1, RLENGTH)
        } else {
          t = substr(s, 1, 1)
        }
        s = substr(s, length(t) + 1)
        tok(t)
      }
    }'

# rust_code_match ERE FILE: prints "<line>:<text>" for each line of the Rust file FILE whose code,
# with every comment and the contents of every string and char literal removed, matches ERE, and
# exits 0 hit, 1 none, 2 unreadable (the grep checks' codes). The awk pass reads the file byte by
# byte, as Rust's lexer does, so a doc line, a commented-out call, a call after // or inside a
# block comment (nested and over lines as Rust's are), and a name inside a string do not count,
# and a // or /* inside a literal starts no comment: reading one as a comment would drop the
# code after it, and with it a banned call (a "/*" before a catch_unwind hid it). A string
# literal ("..." with backslash escapes, also b"..." and c"...", and raw r"...", r#"..."# and
# br#"..."#, over as many lines as it takes) is left as "" at its close, so extern "system"
# reads extern "". A ' starts a char or byte literal only when one is there ('x', a character
# of up to four bytes, '"', or an escape such as '\'' or '\u{1F600}'), and is a lifetime or a
# label otherwise. The code is matched with a space before and after it, so ERE names a word
# boundary as [^A-Za-z0-9_] on both sides, with no ^ or $ inside a group (awk dialects differ
# there); the line printed is the line as it stands, comments included. The lexer is rust_lex,
# which the FFI rules' scans (ffi_guard_scan, ffi_export_scan) share.
rust_code_match() {
  [ -f "$2" ] && [ -r "$2" ] || return 2
  awk -v ere="$1" -v sq="'" "$rust_lex"'
    {
      lex()
      if ((" " code " ") ~ ere) {
        print NR ":" $0
        found = 1
      }
    }
    END { exit !found }' "$2"
}

# probe_calls_game_random: core/examples/release_probe.rs calls game_random outside every comment
# (rust_code_match), so a doc line, a commented-out call and a call after // or inside a block
# comment do not count. A file that cannot be read counts as no call, so it fails closed.
probe_calls_game_random() {
  [ -f core/examples/release_probe.rs ] || return 1
  rust_code_match '[^A-Za-z0-9_]game_random[[:space:]]*[(]' core/examples/release_probe.rs >/dev/null
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
# "mod tests;", so the file is compiled for cargo test alone. A missing parent, or a blank line or
# another attribute between the two, means no exception (fail closed); an unreadable one stops the
# gate (awk's failure, M5-66).
tests_rs_declared() {
  x=${1%/tests.rs}
  for parent in "$x.rs" "$x/mod.rs"; do
    [ -f "$parent" ] || continue
    on=$parent
    if awk '
      prev ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ && $0 ~ /^[[:space:]]*mod tests;[[:space:]]*$/ { found = 1 }
      { prev = $0 }
      END { exit !found }' "$parent"; then
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

# --- Kotlin and Android (tasks/todo.md, M5 group 3; Q55) ------------------------------------------

# The named files' directories: each named file (camera/GoAheadScanner.kt, files/Documents.kt,
# AirplaneSettingsIntent.kt, SensorMotionSource.kt, KeepCryptApp.kt and CrashHandler.kt in the app,
# SecureActivity.kt and OfflineMonitor.kt in secure-ui, CeremonyModel.kt in :screens) is one path,
# its module's package directory and its name, so a file of the same name anywhere else, deeper
# under src/main/ (a src/test/ there included) or in another package, gets every rule.
kt_app=mobile/android/app/src/main/kotlin/com/keepcrypt/entropy
kt_secure_ui=mobile/android/secure-ui/src/main/kotlin/com/keepcrypt/entropy/secure
kt_screens=mobile/android/screens/src/commonMain/kotlin/com/keepcrypt/entropy/screens

# kept_hits ERE SED-ARGUMENT...: the lines of $t (grep -n output) that still match ERE (which holds
# no %) after sed's deletions, given as the remaining arguments, each line printed as it was (sed's
# h/x shape, as selectable()). Exits 0 when a line is left, 1 when none is, 2 when sed fails.
kept_hits() {
  kere=$1
  shift
  t=$(printf '%s\n' "$t" | sed -E -e h "$@" -e "\\%$kere%!d" -e x) || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

# KtLog (rules 3 and 5: nothing is logged or printed, and no message is built from runtime values):
# Android's Log and its calls, println( and print(, System.out and System.err, printStackTrace,
# Timber, java.util.logging and slf4j, and a $ template inside a string on a line that calls
# error(, check(, require(, checkNotNull( or requireNotNull( (the message may be the lambda,
# check(ok) { "stage $s" }) or builds an exception, error or KcHalt ("...Exception(", "...Error(",
# "...Throwable(", "KcHalt("). A message written on a line of its own, under the call, is not seen.
ktlog() {
  grep -n -a -E \
    -e 'android[.]util[.]Log' \
    -e "${L}Log[[:space:]]*[.][[:space:]]*(v|d|i|w|e|wtf)[[:space:]]*[(]" \
    -e "${L}print(ln)?[[:space:]]*[(]" \
    -e 'System[[:space:]]*[.][[:space:]]*(out|err)' \
    -e 'printStackTrace' \
    -e "${L}[Tt]imber$R" \
    -e 'java[.]util[.]logging' \
    -e '[Ss]lf4j' \
    -e "(${L}(error|check|require|checkNotNull|requireNotNull)[[:space:]]*[({]|(Exception|Error|Throwable|KcHalt)[[:space:]]*[(]).*\"[^\"]*[$]" \
    -- "$1"
}

# KtFailOpen (rule 3), every scope: Kotlin's ways to turn a failure into a value, runCatching and
# Result's (and collections') getOrNull, getOrElse, getOrDefault and onFailure, Result's and a
# Deferred's exceptionOrNull and getCompletionExceptionOrNull, and the coroutine handlers that
# keep a failure from reaching the uncaught-exception handler (CoroutineExceptionHandler, and
# SupervisorJob and supervisorScope, under which a failed async child is dropped unless
# awaited), as words; and Result's recover, recoverCatching and fold as calls (as words they
# would hit UI text such as "recover a wallet"), so a collection's fold( is a hit too.
ktfailopen() {
  grep -n -a -E \
    -e "${L}(runCatching|getOrNull|getOrElse|getOrDefault|onFailure)$R" \
    -e "${L}([A-Za-z]*[Ee]xceptionOrNull|CoroutineExceptionHandler|SupervisorJob|supervisorScope)$R" \
    -e "${L}(recover|recoverCatching|fold)[[:space:]]*[({]" \
    -- "$1"
}

# KtFailOpen's catch list, outside the test source sets: every catch is a hit, Flow's .catch { }
# operator too, except the four the plan names, each in one named file: catch (x: KcHalt) in :screens'
# commonMain CeremonyModel.kt (the re-plan's shared model, which replaced the app's
# CeremonyViewModel.kt), catch (x: IOException) in the app's files/Documents.kt and catch (x:
# CameraAccessException) in the app's camera/GoAheadScanner.kt, each mapped to a refusal on its
# screen, and catch (x: ReaderException) in the same scanner file, ZXing's "no code in this frame",
# which drops the frame and reads the next (M5-53). So a catch of Throwable, Exception,
# RuntimeException, Error or a ReaderException subclass (NotFoundException), any catch in
# :core-ffi (androidMain and iosMain included) and a KcHalt caught anywhere else are hits. The
# allowed shape is the bare type name alone in the parentheses, on the catch's own line: a qualified
# name (java.io.IOException), two catches on one line with one of another type, and Java's catch
# (IOException e) hit. The bare name must be the real type: kt_catch_allowing FILE TYPE IMPORT
# [TYPE IMPORT]... also needs FILE's import header (kt_header) to hold the line "import IMPORT"
# exactly when FILE has an allowed catch of TYPE, or its first one hits ("missing import ..."), and
# kt_alias keeps every other way to bind the name out of the tree.
kt_catch() {
  grep -n -a -E -e "${L}catch[[:space:]]*[({]" -- "$1"
}
# A Kotlin file's import header: its leading lines that are blank, a // comment, a package line or
# an import line of a plain dotted name (with .* or an alias, or neither), up to its first other
# line. A block comment or a string opens on none of them, so an import line here is an import, and
# one inside /* */ (or a raw string) further down is not. A file annotation or a block comment
# before the imports ends the header there, and the allowed catch then fails closed, "missing ...".
kt_header='^[[:space:]]*($|//)|^(package|import)[[:space:]]+[A-Za-z_][A-Za-z0-9_.]*([.][*]|[[:space:]]+as[[:space:]]+[A-Za-z_][A-Za-z0-9_]*)?[[:space:]]*$'
kt_catch_allowing() {
  f=$1
  shift
  t=$(grep -n -a -E -e "${L}catch[[:space:]]*[({]" -- "$f")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  header=$(sed -n -E -e "\\%$kt_header%!q" -e p <"$f") || return 2
  allowed="(^|[^A-Za-z0-9_])catch[[:space:]]*[(][[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:[[:space:]]*"
  names=
  missing=
  while [ "$#" -ge 2 ]; do
    # The first allowed catch's line, and the header's import line, read in the shell.
    first=$(printf '%s\n' "$t" | grep -a -E -e "$allowed$1[[:space:]]*[)]")
    [ $? -le 1 ] || return 2
    first=${first%%:*}
    case $nl$header$nl in
      *"${nl}import $2$nl"*) ;;
      *) [ -z "$first" ] || missing="$missing${missing:+$nl}$first:missing import $2 for its catch of $1" ;;
    esac
    names="$names${names:+|}$1"
    shift 2
  done
  kept=$(kept_hits "(^|[^A-Za-z0-9_])catch[[:space:]]*[({]" -e "s/$allowed($names)[[:space:]]*[)]/\\1/g")
  case $? in 0 | 1) ;; *) return 2 ;; esac
  [ -n "$kept$missing" ] || return 1
  [ -z "$kept" ] || printf '%s\n' "$kept"
  [ -z "$missing" ] || printf '%s\n' "$missing"
}
kt_catch_kchalt() {
  kt_catch_allowing "$1" KcHalt com.keepcrypt.entropy.ffi.KcHalt
}
kt_catch_ioexception() {
  kt_catch_allowing "$1" IOException java.io.IOException
}
kt_catch_camera() {
  kt_catch_allowing "$1" CameraAccessException android.hardware.camera2.CameraAccessException \
    ReaderException com.google.zxing.ReaderException
}

# KtFailOpen's names, where the catch list applies (outside the test source sets): it allows KcHalt,
# IOException, CameraAccessException and ReaderException by their bare names, so nothing may bind
# one of those names to another type: an alias or cast to one ("as KcHalt", which an import alias on
# one line or with "as" at the start of the next line has), an "as" followed by a comment (its name
# comes after it), a typealias of one, a typealias with anything but a plain name after it (a
# comment, or a line break: Kotlin allows either there), and an import that ends in "as", whose
# alias is on the next line. A name in backticks is the same name, and needs no space before it.
kt_alias() {
  grep -n -a -E \
    -e "${L}as(([[:space:]]*\`|[[:space:]]+)(KcHalt|IOException|CameraAccessException|ReaderException)$R|[[:space:]]*/[*/])" \
    -e "${L}typealias(([[:space:]]*\`|[[:space:]]+)(KcHalt|IOException|CameraAccessException|ReaderException)$R|[[:space:]]*$|[[:space:]]*[^[:space:]A-Za-z0-9_\`])" \
    -e "${L}import[[:space:]].*[[:space:]]as[[:space:]]*$" \
    -- "$1"
}

# KtFailOpen's handlers (M5-58), with the catch list (outside the test source sets): an
# uncaught-exception handler is a catch-all no catch shows, so a handler on a thread of the app's
# own (the scanner's HandlerThread) or a second default handler would keep a failure from
# CrashHandler, which wipes the slot and ends the process. setUncaughtExceptionHandler,
# setDefaultUncaughtExceptionHandler and UncaughtExceptionHandler hit as words, with or without
# Thread. (a call, a method reference, an import, an alias or a typealias of one), and so does
# uncaughtExceptionHandler, the property Kotlin makes of a thread's getter and setter (its
# assignment is the setter's call; a read hits too). So do the other ways a thread's failure stops
# short of the default handler, as words: ThreadGroup, the JDK's other handler (a thread with no
# handler of its own hands its failures to its group, a subclass of which can drop them),
# getUncaughtExceptionHandler (a Thread subclass can override the getter the JVM asks for its
# handler) and uncaughtException (the method every handler implements, so an override of it hits
# whatever its class's supertype is called). Two places are allowed, once each, each in its named
# file and each exactly as written there, its indentation aside (as ffi_guard_pub pins guarded's
# line): KeepCryptApp.kt's Thread.setDefaultUncaughtExceptionHandler( alone on its line, with its
# argument pinned on the line after it, so the handler it installs is CrashHandler with the app's
# own wipe and end (a wrapper that passes any handler on, null and a wipe that does nothing all
# hit), and CrashHandler.kt's one-line class header, with Thread.UncaughtExceptionHandler its only
# supertype, with its override of uncaughtException pinned on the line after it.
# kt_handler_allowing FILE LINE...: FILE's hit lines, but the first line that is the first LINE
# passes, and each line after it must be the next LINE in turn or it is a hit, its own text (a file
# that ends first is one at its last line, "missing ..."). A second such line, or one with anything
# more on it, hits.
kt_handler_names="${L}(set(Default)?UncaughtExceptionHandler|getUncaughtExceptionHandler|[Uu]ncaughtExceptionHandler|uncaughtException|ThreadGroup)$R"
kt_handler() {
  grep -n -a -E -e "$kt_handler_names" -- "$1"
}
kt_handler_allowing() {
  f=$1
  shift
  t=$(kt_handler "$f")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  # The hits come in on the standard input, the file after them; k counts the LINEs matched so far
  # while the lines after the first are pinned.
  printf '%s\n' "$t" | KC_HANDLER_LINES=$(printf '%s\n' "$@") awk '
    function out(l, text) {
      print l ":" text
      found = 1
    }
    BEGIN { n = split(ENVIRON["KC_HANDLER_LINES"], want, "\n") }
    NR == FNR {
      l = $0
      sub(/:.*/, "", l)
      hit[l] = 1
      next
    }
    {
      line = $0
      sub(/^[ \t]+/, "", line)
    }
    k {
      k++
      if (line != want[k]) out(FNR, $0)
      if (k == n) k = 0
      next
    }
    !seen && line == want[1] {
      seen = 1
      if (n > 1) k = 1
      next
    }
    FNR in hit { out(FNR, $0) }
    END {
      if (k) out(FNR, "missing the line after it, " want[k + 1])
      exit !found
    }' - "$f"
}
kt_handler_app() {
  kt_handler_allowing "$1" 'Thread.setDefaultUncaughtExceptionHandler(' \
    'CrashHandler(wipe = { Core.wipeAll() }, end = { Process.killProcess(Process.myPid()) }),'
}
kt_handler_crash() {
  kt_handler_allowing "$1" \
    'internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {' \
    'override fun uncaughtException(thread: Thread, exception: Throwable) {'
}

# KtFailOpen's tasks (M5-60), with the catch list (outside the test source sets): a task handed to
# an executor service or a fork-join pool, or run as a future, keeps its failure in a future nobody
# need read, and a coroutine's async keeps its failure in its Deferred until awaited (SupervisorJob
# and supervisorScope hit for the same reason), so none of them reaches CrashHandler.
# ExecutorService, Executors, CompletableFuture, FutureTask, ForkJoinPool, async and Deferred hit as
# words, and so does Executor, but in the app's camera/GoAheadScanner.kt, which hands Camera2 an
# Executor that posts each callback to the scanner's own HandlerThread, whose failures reach
# CrashHandler. There the bare name must be the JDK's interface: the file's import header
# (kt_header) must hold the line import java.util.concurrent.Executor exactly, or its first
# Executor hits ("missing import ..."), as an allowed catch's type must.
# A word list cannot be complete (ThreadPoolExecutor, ScheduledThreadPoolExecutor,
# ScheduledExecutorService, ForkJoinTask's fork, kotlinx.coroutines.future's future and Flow's
# retry and retryWhen all passed it), so the two packages that hold such tasks, java.util.concurrent
# and kotlinx.coroutines, are allowed only by the import lines the shipping code has today, each a
# whole line, exactly (M5-60 (b)): kt_coroutines_lines in any file, and import
# java.util.concurrent.Executor in the scanner alone (elsewhere its Executor is a hit too). Any
# other mention of either package is a hit (kt_packages): another import, a star import, an alias,
# two imports on one line (the second after a ";"), a qualified name in code, a package line. The
# standard library's kotlin.coroutines, always on the compile classpath, is read the same way with
# no allowed line, every subpackage with it (intrinsics, cancellation and any other) (M5-65): its
# startCoroutine and createCoroutine take a completion whose resumeWith can ignore the failure it
# is handed, a catch-all with no catch, and the shipping code names nothing from it. A new name
# from any of the three packages needs a lead decision that says why it cannot hold a failure. A
# line that both the words and the packages find is reported once.
kt_task_names='ExecutorService|Executors|CompletableFuture|FutureTask|ForkJoinPool|async|Deferred'
kt_coroutines_lines='import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext'
kt_tasks() {
  t=$(grep -n -a -E -e "${L}(Executor|$kt_task_names)$R" -- "$1")
  case $? in 0 | 1) ;; *) return 2 ;; esac
  kt_tasks_and_packages "$1" "$kt_coroutines_lines"
}
kt_tasks_scanner() {
  t=$(grep -n -a -E -e "${L}($kt_task_names)$R" -- "$1")
  case $? in 0 | 1) ;; *) return 2 ;; esac
  first=$(grep -n -a -E -e "${L}Executor$R" -- "$1")
  [ $? -le 1 ] || return 2
  first=${first%%:*}
  if [ -n "$first" ]; then
    header=$(sed -n -E -e "\\%$kt_header%!q" -e p <"$1") || return 2
    case $nl$header$nl in
      *"${nl}import java.util.concurrent.Executor$nl"*) ;;
      *) t="$t${t:+$nl}$first:missing import java.util.concurrent.Executor for its Executor" ;;
    esac
  fi
  kt_tasks_and_packages "$1" "$kt_coroutines_lines${nl}import java.util.concurrent.Executor"
}
# kt_tasks_and_packages FILE LINES: $t (FILE's task hits, as grep -n prints them), then each line
# kt_packages FILE LINES finds that $t does not hold.
kt_tasks_and_packages() {
  p=$(kt_packages "$1" "$2")
  case $? in 0 | 1) ;; *) return 2 ;; esac
  if [ -n "$t" ] && [ -n "$p" ]; then
    p=$(printf '%s\n' "$p" | KC_TASK_HITS=$t awk '
      BEGIN {
        n = split(ENVIRON["KC_TASK_HITS"], h, "\n")
        for (k = 1; k <= n; k++) {
          sub(/:.*/, "", h[k])
          seen[h[k]] = 1
        }
      }
      {
        l = $0
        sub(/:.*/, "", l)
        if (!(l in seen)) print
      }') || return 2
  fi
  [ -n "$t$p" ] || return 1
  [ -z "$t" ] || printf '%s\n' "$t"
  [ -z "$p" ] || printf '%s\n' "$p"
}

# kt_packages FILE LINES: the lines of FILE where a mention of java.util.concurrent,
# kotlinx.coroutines or the standard library's kotlin.coroutines starts, but a line that is one of
# LINES (one per line) exactly (none names kotlin.coroutines: M5-65 allows no line of it). A
# mention is read as Kotlin reads a qualified name, and fail closed: from the word java, kotlinx or
# kotlin (a whole word, so javax, a name such as kotlinCoroutinesNote and the standard library's
# other packages, kotlin.concurrent and kotlin.collections among them, are other names), past
# blanks (a space, a tab, a form feed or a carriage return), backticks (`kotlinx`.coroutines is the
# same name) and line breaks, each dot and then each part in turn, so a name spaced out or split
# over lines (Kotlin takes a line break before a dot) is still one, at the line of its first word;
# a subpackage (kotlin.coroutines.intrinsics) is a mention of its package. A comment (// or /*)
# after any part or dot of a name not yet complete is a hit there too, as Kotlin skips it and the
# rest of the name could follow: so the word java, kotlinx or kotlin right before a comment is a
# hit (Foo::class.java and, after blank lines, a // comment). Comments and strings are otherwise
# read as text, as the other word rules read Kotlin (ktfailopen, kt_tasks), so a mention in either
# hits. FILE is read through kt_text.
kt_packages() {
  grep -q -a -E -e "${L}(java|kotlinx|kotlin)$R" -- "$1"
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  ktext=$(kt_text "$1") || return 2
  printf '%s\n' "$ktext" | KC_PACKAGE_LINES=$2 awk '
    function out(l) {
      if (!(l in done)) print l ":" src[l]
      done[l] = 1
      found = 1
    }
    BEGIN {
      n = split(ENVIRON["KC_PACKAGE_LINES"], a, "\n")
      for (k = 1; k <= n; k++) if (a[k] != "") allowed[a[k]] = 1
    }
    # state: 0 outside a name, 1 after a part of one (the next is part[k] of parts; sl, the line
    # of its first word), 2 after the dot that follows a part.
    {
      src[NR] = $0
      if ($0 in allowed) {
        state = 0
        next
      }
      line = $0
      len = length(line)
      i = 1
      while (i <= len) {
        c = substr(line, i, 1)
        if (c ~ /[A-Za-z0-9_]/) {
          match(substr(line, i), /^[A-Za-z0-9_]+/)
          w = substr(line, i, RLENGTH)
          i += RLENGTH
          if (state == 2 && w == part[k]) {
            if (k == parts) {
              out(sl)
              state = 0
            } else {
              k++
              state = 1
            }
          } else if (w == "java" || w == "kotlinx" || w == "kotlin") {
            if (w == "java") parts = split("util concurrent", part, " ")
            else parts = split("coroutines", part, " ")
            k = 1
            state = 1
            sl = NR
          } else {
            state = 0
          }
        } else if (c == " " || c == "\t" || c == "\f" || c == "\r" || c == "`") {
          i++
        } else if (state == 1 && c == ".") {
          state = 2
          i++
        } else if (state && c == "/" && (substr(line, i + 1, 1) == "/" || substr(line, i + 1, 1) == "*")) {
          out(sl)
          state = 0
          i += 2
        } else {
          state = 0
          i++
        }
      }
    }
    END { exit !found }'
}

# kt_text FILE: FILE's text with its NUL bytes dropped, for the rules that read its lines with awk
# (kt_packages, kt_finally). The Mac's awk (BWK, version 20200816) ends a line at a NUL, so a NUL in
# a comment or a string would hide the rest of its line from them; dropped, every awk reads each
# line whole, and the line is the one every other rule's hit prints (sh and dash drop a NUL from a
# command's output).
kt_text() {
  tr -d '\0' <"$1"
}

# KtFailOpen's finally blocks (M5-60), with the catch list (outside the test source sets): a return,
# break or continue inside a finally block leaves it with the exception in flight dropped. Each
# block is read without a parser, fail closed: from the word finally, past blanks (a space, a tab, a
# form feed, which Kotlin's lexer also skips, and a carriage return) and line breaks, to its { and on
# to the } that brings the count of braces back, a return, break or continue as a word hits (a
# labelled one too, and one that leaves only a loop or a lambda inside the block), and so does a
# quote (" or '), a backtick or a comment (// or /*) in the block, or a comment between finally and
# its {, where a brace could be text the count must not see: the block is read no further. A file
# that ends inside a block hits at its finally ("missing ..."). A finally followed by anything else
# is no block (a word in prose, or a name: finally is a soft keyword). FILE is read through kt_text.
kt_finally() {
  grep -q -a -E -e "${L}finally$R" -- "$1"
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  ktext=$(kt_text "$1") || return 2
  printf '%s\n' "$ktext" | awk -v sq="'" '
    function out(l) {
      if (!(l in done)) print l ":" src[l]
      done[l] = 1
      found = 1
    }
    # state: 0 outside a block, 1 after a finally (fl, its line), 2 in its block, depth braces deep.
    {
      src[NR] = $0
      line = $0
      n = length(line)
      i = 1
      while (i <= n) {
        c = substr(line, i, 1)
        if (state == 0) {
          # the next finally, as a word (the characters on either side of it read in the line)
          k = index(substr(line, i), "finally")
          if (!k) break
          j = i + k - 1
          i = j + 7
          if ((j == 1 || substr(line, j - 1, 1) !~ /[A-Za-z0-9_]/) && substr(line, i, 1) !~ /[A-Za-z0-9_]/) {
            state = 1
            fl = NR
          }
        } else if (state == 1) {
          if (c == " " || c == "\t" || c == "\f" || c == "\r") {
            i++
          } else if (c == "{") {
            state = 2
            depth = 1
            i++
          } else if (c == "/" && (substr(line, i + 1, 1) == "/" || substr(line, i + 1, 1) == "*")) {
            out(NR)
            state = 0
            break
          } else {
            state = 0
          }
        } else if (c == "\"" || c == sq || c == "`" || (c == "/" && (substr(line, i + 1, 1) == "/" || substr(line, i + 1, 1) == "*"))) {
          out(NR)
          state = 0
          break
        } else if (c ~ /[A-Za-z0-9_]/) {
          match(substr(line, i), /^[A-Za-z0-9_]+/)
          w = substr(line, i, RLENGTH)
          if (w == "return" || w == "break" || w == "continue") out(NR)
          i += RLENGTH
        } else {
          if (c == "{") depth++
          if (c == "}" && --depth == 0) state = 0
          i++
        }
      }
    }
    END {
      if (state == 2) {
        print fl ":missing the } that ends its finally block"
        found = 1
      }
      exit !found
    }'
}

# KtWindow (Q57: no dialogs, popups, menus, sheets, toasts, notifications or tooltips, so the app
# has one window), every scope: those APIs by name (Dialog( and Popup( as constructor names, so
# DialogProperties( is left to the next check), Spinner and AutoCompleteTextView (their lists are
# popups), WindowManager's addView and the overlay window type. Dialog and Popup also hit before a
# trailing lambda (Popup { }), which Kotlin allows when every parameter has a default.
ktwindow() {
  grep -n -a -E \
    -e 'Toast' \
    -e 'Snackbar' \
    -e 'Notification' \
    -e 'Dialog[[:space:]]*[({]' \
    -e 'AlertDialog' \
    -e 'DialogFragment' \
    -e 'Popup[[:space:]]*[({]' \
    -e 'PopupWindow' \
    -e 'PopupMenu' \
    -e 'DropdownMenu' \
    -e 'ModalBottomSheet' \
    -e 'Spinner' \
    -e 'AutoCompleteTextView' \
    -e '[Tt]ooltip' \
    -e '[Ww]indow[Mm]anager.*addView' \
    -e 'TYPE_APPLICATION_OVERLAY' \
    -- "$1"
}

# KtWindow's FLAG_SECURE rule (MA:70), outside :capture-control: DialogProperties( or
# PopupProperties( is a hit unless every one of them on the line carries
# securePolicy = SecureFlagPolicy.SecureOn as a named argument and closes on that line, parsed
# fail closed like textselection(): an argument on the next line, a positional policy, SecureOff,
# Inherit, a variable or a nested call among the arguments all hit.
kt_secure_policy() {
  t=$(grep -n -a -E -e '(Dialog|Popup)Properties[[:space:]]*[(]' -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  kept_hits '(Dialog|Popup)Properties[[:space:]]*[(]' \
    -e 's/(Dialog|Popup)Properties[[:space:]]*[(][^()]*securePolicy[[:space:]]*=[[:space:]]*SecureFlagPolicy[[:space:]]*[.][[:space:]]*SecureOn([^A-Za-z0-9_()][^()]*)?[)]//g'
}

# KtWindow's FLAG_SECURE rule (rule 9, MA:41), outside :capture-control: nothing turns FLAG_SECURE
# off once SecureActivity has set it. clearFlags, any setFlags but SecureActivity's own
# setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) (a
# setFlags(0, FLAG_SECURE) clears it), and a new window layout (attributes = ..., setAttributes,
# updateViewLayout), which can drop the flag, are hits; reading window.attributes.flags passes.
kt_flag_secure() {
  t=$(grep -n -a -E -e "clearFlags|setFlags|${L}(attributes[[:space:]]*=([^=]|\$)|setAttributes|updateViewLayout)" -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  kept_hits "clearFlags|setFlags|(^|[^A-Za-z0-9_])(attributes[[:space:]]*=([^=]|\$)|setAttributes|updateViewLayout)" \
    -e 's/setFlags[[:space:]]*[(][[:space:]]*WindowManager[[:space:]]*[.][[:space:]]*LayoutParams[[:space:]]*[.][[:space:]]*FLAG_SECURE[[:space:]]*,[[:space:]]*WindowManager[[:space:]]*[.][[:space:]]*LayoutParams[[:space:]]*[.][[:space:]]*FLAG_SECURE[[:space:]]*[)]//g'
}

# KtInput (Q57: the system keyboard never opens), every scope: text fields of any kind
# (TextField, BasicTextField, OutlinedTextField, SecureTextField), EditText, InputMethodManager
# and SoftwareKeyboardController.
ktinput() {
  grep -n -a -E -e 'TextField' -e 'EditText' -e 'InputMethodManager' -e 'SoftwareKeyboardController' -- "$1"
}

# KtInput's Activity rule, in shipping sources but secure-ui's SecureActivity.kt: a constructor
# call of Activity or of a capitalized name that ends in it (": ComponentActivity()", "object :
# AppCompatActivity()", ", FragmentActivity()" after another supertype), which in app code is
# only ever a superclass call, since the system makes activities, and Java's "extends ...Activity".
# A class with no primary constructor names its superclass without parentheses and calls it
# from a secondary constructor ("class X : ComponentActivity {" then "constructor() : super()"),
# so a class header whose supertypes, before any { or =, name a ...Activity not followed by ( is
# a hit too (a class with a primary constructor must call its superclass there, which the first
# shape sees). SecureActivity passes in each shape, so the app's activity can derive from
# SecureActivity and keep its FLAG_SECURE; startActivity( starts with a small letter and is
# KtIntent's. A typealias of an Activity is not seen.
kt_activity_ere="(^|[^A-Za-z0-9_])([A-Z][A-Za-z0-9_]*)?Activity[[:space:]]*[(]|(^|[^A-Za-z0-9_])extends[[:space:]]+([A-Za-z0-9_]+[.])*[A-Za-z0-9_]*Activity([^A-Za-z0-9_]|$)|(^|[^A-Za-z0-9_])class[[:space:]]+[A-Za-z0-9_]+[[:space:]]*(<[^>]*>[[:space:]]*)?:[^{=]*Activity([^A-Za-z0-9_(]|$)"
kt_activity() {
  t=$(grep -n -a -E -e "$kt_activity_ere" -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  kept_hits "$kt_activity_ere" -e 's/(^|[^A-Za-z0-9_])SecureActivity([^A-Za-z0-9_]|$)/\1\2/g'
}

# KtStorage (rule 8: nothing is persisted), outside the test source sets: preferences,
# DataStore (also androidx.datastore in a build file), app-private files and their directories,
# java.io.File's constructor, external storage, MediaStore, Room, SQLite, temp files, saved state
# (rememberSaveable, SavedStateHandle) and persisted URI grants; and the other ways to an app
# directory or file (getDir(, dataDir, getDatabasePath, openOrCreateDatabase,
# createDeviceProtectedStorageContext), java.io's RandomAccessFile, FileWriter and FileReader,
# java.nio.file (Files., Paths., Path.of) and Kotlin's File writers (writeBytes(, writeText(,
# appendBytes(, appendText().
ktstorage() {
  grep -n -a -E \
    -e 'SharedPreferences' \
    -e '[Dd]ata[Ss]tore' \
    -e 'openFile(Output|Input)' \
    -e 'File(Output|Input)Stream' \
    -e "${L}File[[:space:]]*[(]" \
    -e '[Ff]ilesDir' \
    -e '[Cc]acheDir' \
    -e 'getExternal' \
    -e 'MediaStore' \
    -e "${L}Room$R" \
    -e 'androidx[.]room' \
    -e 'SQLite' \
    -e 'androidx[.]sqlite' \
    -e 'createTempFile' \
    -e 'rememberSaveable' \
    -e 'SavedStateHandle' \
    -e 'takePersistableUriPermission' \
    -e "${L}getDir[[:space:]]*[(]" \
    -e '[Dd]ataDir' \
    -e 'getDatabasePath|openOrCreateDatabase|createDeviceProtectedStorageContext' \
    -e 'RandomAccessFile|File(Writer|Reader)' \
    -e 'java[.]nio[.]file' \
    -e "${L}(Files|Paths)[[:space:]]*[.]" \
    -e "${L}Path[[:space:]]*[.][[:space:]]*of$R" \
    -e "${L}(write|append)(Bytes|Text)[[:space:]]*[(]" \
    -- "$1"
}

# KtStorage, outside the test source sets and app's files/Documents.kt: the document streams
# (the backup's one "rwt" write and the picked .age and .kcr reads live in Documents.kt alone).
kt_open_stream() {
  grep -n -a -E -e 'open(Output|Input)Stream|openFileDescriptor' -- "$1"
}

# KtIntent (no share sheet, no link, no other app), outside the test source sets and app's
# files/Documents.kt: Intent( and Intent's factory calls (Intent.parseUri, Intent.makeMainActivity:
# a lower-case name after "Intent."; an upper-case constant only ever goes into an Intent(, which
# hits), every start of an activity (startActivity, startActivityForResult, startActivities,
# startIntentSender), service (start...Service, bind...Service) or broadcast (send...Broadcast,
# registerReceiver), PendingIntent, ShareCompat, createChooser, ACTION_VIEW, LocalUriHandler,
# openUri and LinkAnnotation, and the activity-result API (ActivityResultContracts and custom
# ActivityResultContract classes, registerForActivityResult, rememberLauncherForActivityResult),
# whose document, content and camera contracts reach other apps with no Intent( in our code. One
# launcher shape passes everywhere, on one line: (remember|register)...ForActivityResult(
# ActivityResultContracts.RequestPermission()), the scan screen's CAMERA prompt, which the system's
# permission controller answers, and so does its class's own import line, exactly "import
# androidx.activity.result.contract.ActivityResultContracts" (an alias, or a nested class's import,
# hits), which lets no other contract in: each still has to be named. In app's
# AirplaneSettingsIntent.kt (the Android end of the airplane-settings seam, M5-20; the Go offline
# screen itself is shared code in :screens) the one call
# startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS)) passes too, written whole on one
# line, so no other intent can be started there (kt_intent_airplane).
ktintent_ere="(^|[^A-Za-z0-9_])Intent[[:space:]]*([(]|[.][[:space:]]*[a-z])|startActivit|startIntentSender|start[A-Za-z]*Service|bind[A-Za-z]*Service|send[A-Za-z]*Broadcast|PendingIntent|registerReceiver|ShareCompat|createChooser|ACTION_VIEW|LocalUriHandler|openUri|LinkAnnotation|ActivityResultContract|(register|rememberLauncher)ForActivityResult"
kt_permission_launcher='s/(register|rememberLauncher)ForActivityResult[[:space:]]*[(][[:space:]]*ActivityResultContracts[[:space:]]*[.][[:space:]]*RequestPermission[[:space:]]*[(][[:space:]]*[)][[:space:]]*[)]//g'
kt_permission_import='s/^([0-9]+:)import androidx[.]activity[.]result[.]contract[.]ActivityResultContracts$/\1/'
ktintent() {
  t=$(grep -n -a -E -e "$ktintent_ere" -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  kept_hits "$ktintent_ere" -e "$kt_permission_launcher" -e "$kt_permission_import"
}
kt_intent_airplane() {
  t=$(grep -n -a -E -e "$ktintent_ere" -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  kept_hits "$ktintent_ere" -e "$kt_permission_launcher" -e "$kt_permission_import" \
    -e 's/(^|[^A-Za-z0-9_])startActivity[[:space:]]*[(][[:space:]]*Intent[[:space:]]*[(][[:space:]]*(android[.]provider[.])?Settings[[:space:]]*[.][[:space:]]*ACTION_AIRPLANE_MODE_SETTINGS[[:space:]]*[)][[:space:]]*[)]/\1/g'
}

# KtDevice, outside the test source sets: the camera (Camera, Camera* classes such as CameraManager
# and CameraAccessException, camera2, CameraX) only in app's camera/GoAheadScanner.kt; sensors
# (Sensor, SensorManager, SensorEvent...) only in app's SensorMotionSource.kt (the Android end of
# the motion-source seam, M5-20; the device-entropy screen is shared code in :screens); and the
# system settings tables (Settings.Global, and Settings.Secure and Settings.System, which hold the
# same device state) only in secure-ui's OfflineMonitor.kt. Manifest.permission.CAMERA is upper case
# and passes.
kt_camera() {
  grep -n -a -E -e "${L}Camera([A-Z][A-Za-z0-9_]*)?$R" -e '[.]camera2' -e 'androidx[.]camera' -- "$1"
}
kt_sensor() {
  grep -n -a -E -e "${L}Sensor[A-Za-z0-9_]*" -- "$1"
}
kt_settings() {
  grep -n -a -E -e "${L}Settings[[:space:]]*[.][[:space:]]*(Global|Secure|System)$R" -- "$1"
}

# KtSdk (rule 9 and Q54: no analytics, crash, ad or Play services SDK, two repositories, no local
# or remote build input outside them), in build files and lockfiles (*.gradle.kts, *.gradle,
# gradle.properties, *.versions.toml, *.lockfile under mobile/android), any letter case: the SDK
# names anywhere on a line (datadoghq and io.sentry included); a repository other than google()
# and mavenCentral() (maven, ivy, exclusiveContent, gradlePluginPortal, jcenter, mavenLocal,
# flatDir, includeBuild, and a url or uri, which only a repository or a remote input takes);
# files(, fileTree(, fileCollection, zipTree and tarTree (a local file or archive fed into the
# build: objects.fileCollection().from("libs/x.zip") passes a dependency without files( ),
# apply(from, apply from:, buildscript { and classpath(. Source sets are kt_source_sets'.
kt_sdk() {
  grep -n -a -i -E \
    -e 'firebase|crashlytics|com[.]google[.]android[.]gms|play-services|mlkit|sentry|bugsnag|acra|appcenter|datadog' \
    -e 'newrelic|segment|mixpanel|amplitude|flurry|admob|facebook|instabug|onesignal' \
    -e "${L}(maven|ivy)[[:space:]]*[({]" \
    -e "${L}(exclusiveContent|gradlePluginPortal|jcenter|mavenLocal|flatDir|includeBuild)$R" \
    -e "${L}(url|uri|setUrl)[[:space:]]*[(=]" \
    -e "${L}(files|fileTree|classpath)[[:space:]]*[(]" \
    -e "${L}(fileCollection|zipTree|tarTree)$R" \
    -e "${L}apply[[:space:]]*[(][[:space:]]*from" \
    -e "${L}apply[[:space:]]+from[[:space:]]*:" \
    -e "${L}buildscript[[:space:]]*[{]" \
    -- "$1"
}

# KtSdk, in build files: a source set pointed anywhere but a plain path under the module's own
# src/. Every srcDir, srcDirs, setSrcDirs, directories (AGP's newer source-set API), srcFile and
# setSrcFile is a hit but srcDir("src/...") or srcDirs("src/...") with one literal path of
# letters, digits, _, - and / (so no .., no $ and no build output) whose first directory is not
# a test source set's (test, androidTest, commonTest or androidHostTest): their files
# skip KtFailOpen's catch list, KtStorage, KtIntent, KtDevice and the Activity rule, so
# commonMain { kotlin.srcDir("src/commonTest/kotlin") } would ship them unchecked. A build path
# (build/rust, layout.buildDirectory) would compile or package what a script left there, another
# manifest (manifest.srcFile) would escape KtManifest, and ../capture-control's sources would be
# built into :app with that module's exemptions; the plan builds none of these (tasks/todo.md, M5
# group 3: "srcDir( or srcDirs( naming a build path", here by allow-list so that no spelling
# passes). libkeepcrypt.so reaches the APK through Gradle's default native-library source set,
# src/<flavour>/jniLibs, which scripts/android-rust.sh fills (lead decision M5-9), so no srcDir line
# is needed for it.
kt_source_sets() {
  t=$(grep -n -a -E -e "${L}(srcDirs?|setSrcDirs|directories|srcFile|setSrcFile)$R" -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  kept_hits "(^|[^A-Za-z0-9_])(srcDirs?|setSrcDirs|directories|srcFile|setSrcFile)([^A-Za-z0-9_]|$)" \
    -e 's#(srcDirs?[[:space:]]*[(][[:space:]]*")(src/(test|androidTest|commonTest|androidHostTest)[/"])#\1!\2#g' \
    -e 's#(^|[^A-Za-z0-9_])srcDirs?[[:space:]]*[(][[:space:]]*"src/[A-Za-z0-9_/-]*"[[:space:]]*[)]#\1#g'
}

# KtSdk, in build files but mobile/android/settings.gradle.kts: a repositories block, which only
# the settings file's dependencyResolutionManagement and pluginManagement hold (with
# FAIL_ON_PROJECT_REPOS).
kt_repositories() {
  grep -n -a -E -e "${L}repositories[[:space:]]*[{(]" -- "$1"
}

# KtSdk, in build files but lockfiles, and in scripts/android-gradle.sh (and Workflow, in the
# workflows; tasks/todo.md, M5 group 4): no way back to the bootstrap at the final head. Any letter
# case: the bootstrap property kc.bootstrap, Gradle's switches that write lock state or
# verification metadata (--write-locks, --update-locks, --write-verification-metadata), a lock mode
# other than strict (LockMode.DEFAULT, LockMode.LENIENT), dependency verification set to lenient or
# off (--dependency-verification, org.gradle.dependency.verification), and the build-script calls
# that do the same or turn locking off (startParameter's DependencyVerificationMode,
# WriteDependencyLocks, WriteDependencyVerifications and LockedDependenciesToUpdate;
# deactivateDependencyLocking, unlockAllConfigurations, ignoredDependencies; and ResolutionStrategy's
# disableDependencyVerification, which skips verification-metadata.xml for one configuration, so a
# tampered artifact of the locked version would pass). As written, by
# allow-list: Gradle's short options -M (--write-verification-metadata, any value) and -F
# (--dependency-verification), alone or after its flags that take no value (-qM), but -F strict
# (and a -F with a digit, mkfs.vfat's); dependency verification set to anything but strict (a
# variable included); and lockMode or lockFile but the line lockMode.set(LockMode.STRICT) (so
# neither a star-imported LENIENT nor a lockfile moved elsewhere passes). A -M or -F of another
# program in a workflow is a hit too: spell its long option. M5 expects no dependency change after
# commit 6 (lead decision M5-13): one stops the work for the lead's re-plan, because regenerating the
# lockfiles and metadata needs a reviewed, temporary exception to this rule, kt_bootstrap_exception
# below (the Compose Multiplatform re-plan's second bootstrap, Q67).
kt_bootstrap() {
  a=$(grep -n -a -i -E \
    -e 'kc[.]bootstrap' \
    -e '--(write-locks|update-locks|write-verification-metadata)' \
    -e "${L}LockMode[[:space:]]*[.][[:space:]]*(DEFAULT|LENIENT)$R" \
    -e "dependency[-.]verification[[:space:]=:\"']+(lenient|off)$R" \
    -e 'DependencyVerificationMode|WriteDependencyLocks|WriteDependencyVerifications|LockedDependenciesToUpdate' \
    -e 'deactivateDependencyLocking|unlockAllConfigurations|ignoredDependencies|disableDependencyVerification' \
    -- "$1")
  [ $? -le 1 ] || return 2
  kbere="(^[0-9]+:|[[:space:]\"'=\\\\])-[adimqsStwvh]*[FM]|dependency[-.]verification[[:space:]=:\"']+|${L}(lockMode|lockFile|setLockMode|setLockFile)$R"
  t=$(grep -n -a -E -e "(^|[[:space:]\"'=\\\\])-[adimqsStwvh]*[FM]" -e "dependency[-.]verification[[:space:]=:\"']+" \
    -e "${L}(lockMode|lockFile|setLockMode|setLockFile)$R" -- "$1")
  case $? in
    0)
      b=$(kept_hits "$kbere" \
        -e 's/(^[0-9]+:|[[:space:]])-F[[:space:]]*([0-9]|strict([^A-Za-z0-9_]|$))/\1 /g' \
        -e "s/dependency[-.]verification[[:space:]=:\"']+strict([^A-Za-z0-9_]|\$)/ /g" \
        -e 's/(^|[^A-Za-z0-9_])lockMode[[:space:]]*[.][[:space:]]*set[[:space:]]*[(][[:space:]]*LockMode[[:space:]]*[.][[:space:]]*STRICT[[:space:]]*[)]/\1 /g')
      [ $? -le 1 ] || return 2
      ;;
    1) b= ;;
    *) return 2 ;;
  esac
  [ -n "$a$b" ] || return 1
  t=$(printf '%s\n' "$a${a:+${b:+$nl}}$b" | sort -t : -k 1,1n -u) || return 2
  printf '%s\n' "$t"
}

# The reviewed, temporary exception to kt_bootstrap that lead decision M5-13 reserved, for the
# Compose Multiplatform re-plan's second bootstrap (tasks/todo.md, M5 re-plan, "Dependency
# bootstrap"; Q67; the re-cut after Q73), in Workflow mode only: build files, lockfiles and
# scripts/android-gradle.sh never get one. The list holds at most one line: it names the Android
# workflow, entropy-android.yml, and after one space the one line of that workflow (any
# indentation, then exactly this text) whose kt_bootstrap hits pass, the first time it occurs: a
# second copy of the line, any other line and any other workflow still hit. Any other shape of the
# list is exit 2 (kt_bootstrap_exception_check). Empty: no exception.
#
# Filled at commit 8q (2026-10-20; the re-plan's 8o), under the owner's answer to Q67 of
# 2026-10-20 ("approve all as recommended": the one reviewed, temporary exception), with the
# bootstrap Gradle lines of entropy-android.yml and of the iPhone workflow. The owner's answer to
# Q73 of 2026-10-20 ("Drop iPhone from M5") removed the iPhone workflow, so commit 8w keeps the
# Android line alone, and the Android job writes the lock state and metadata once more without the
# iPhone's configurations. Emptied at commit 8x, which commits that run's files (their review
# against Google's Maven and Maven Central needs a fetch, a later commit's), so M5-13's stop
# holds again: scripts/canaries.sh pins the list empty (workflow-bootstrap-exception-empty: its one
# assignment, and the value a --workflows run holds, which the clean line states) and plants that
# former line in the real workflow, where it must hit, so a list filled again turns CI red until a
# re-plan changes those checks too.
kt_bootstrap_exception=''

kt_bootstrap_exception_check() {
  printf '%s\n' "$kt_bootstrap_exception" | awk '
    $0 == "" { next }
    {
      f = $0
      sub(/ .*/, "", f)
      rest = substr($0, length(f) + 2)
      if (f != "entropy-android.yml" || !index($0, " ") || rest == "" || rest ~ /^[[:space:]]/ ||
        seen[f]++) bad = 1
    }
    END { exit bad }'
}

# kt_bootstrap_allowed WORKFLOW: kt_bootstrap's hits in WORKFLOW ($b, "<line>:<text>" lines) but
# the first whose text, its indentation dropped, is the exception's line for that workflow (none
# passes when the list names no line for it). The line goes through the environment, so no awk
# escape processing touches a backslash in it. Both awks run whatever the list holds, each with its
# status read, so the fault check (scripts/banned-api-faults.sh) reaches both.
kt_bootstrap_allowed() {
  bx=$(printf '%s\n' "$kt_bootstrap_exception" | awk -v f="${1##*/}" 'index($0, f " ") == 1 { print substr($0, length(f) + 2) }') ||
    return 2
  printf '%s\n' "$b" | KC_BOOTSTRAP_LINE=$bx awk '
    { t = $0; sub(/^[0-9]+:[ ]*/, "", t) }
    ENVIRON["KC_BOOTSTRAP_LINE"] != "" && !seen && t == ENVIRON["KC_BOOTSTRAP_LINE"] { seen = 1; next }
    { print }'
}

# KtSdk (tasks/todo.md, M5 re-plan, "New file types and build lines"; lead decisions M5-22 and
# M5-31; the re-cut after Q73), in build files but lockfiles (whose configuration names spell every
# target): the Kotlin Multiplatform DSL by allow-list, for the Android target alone. A line that
# names any word of kt_kmp_ere (a kotlin { block; any Kotlin target or per-target source set; the
# cinterop definition, header, include, compiler, linker and extra options; the binary kinds,
# framework export and binary options; free compiler arguments; test runs and devices;
# osVersionMin; the Android target's builders; CocoaPods, Swift packages, Swift export,
# XCFrameworks and Xcode settings) or a kotlin.mpp. property in any letter case
# (kt_kmp_mpp_ere), comments included, passes only when the line, its indentation and trailing
# blanks dropped, is one of kt_kmp_lines exactly. The Android build needs three: kotlin {,
# withHostTestBuilder {} and its block form. Commit 8q's iPhone lines are gone with Q73 (the two
# targets and their blocks, the iosMain and iosTest dependency blocks, the cinterop block and its
# include path, the framework and isStatic, the test executables' linker lines, the simulator's
# device line and the data directory's property), so each of them, and any other target, is a hit
# in M5, and no kotlin.mpp. property is allowed. The names of kt_kmp_refused_ere hit whatever
# kt_kmp_lines says, in any letter case and with any value: CocoaPods, Swift packages,
# xcodeCompatibility.nowarn, the device-test builder, downloadFromMaven, any kotlin.native. or
# kotlin.apple. name and any name holding konan (konan.data.dir, KONAN_DATA_DIR,
# override-konan-properties): M5 builds no Kotlin/Native, so no setting of it has a place.
# scripts/android-gradle.sh and every workflow (kt_kmp_refused) have no allow-list, so there a
# kotlin.mpp. name hits too: a -P or -D option, an environment variable and a comment alike.
kt_kmp_ere='[^A-Za-z0-9_](kotlin[[:space:]]*[{]|(ios|macos|watchos|tvos|linux|mingw|androidNative|wasm)[A-Z0-9][A-Za-z0-9_]*|(jvm|js|headers?|export|framework|executable|staticLib|sharedLib)[[:space:]]*[({])'
kt_kmp_ere="$kt_kmp_ere|[^A-Za-z0-9_](cinterops?|definitionFile|defFile|compilerOpts|linkerOpts|includeDirs|extraOpts|packageName|binaries|isStatic|transitiveExport|embedBitcode|binaryOptions?|freeCompilerArgs|testRuns|deviceId|osVersionMin|minVersion|withHostTestBuilder|withDeviceTestBuilder|withJava|androidTarget|androidLibrary)[^A-Za-z0-9_]"
kt_kmp_ere="$kt_kmp_ere|cocoapods|swiftPM|swiftExport|[Xx][Cc][Ff]ramework|xcodeCompatibility"
# Matched in lower case, so any letter case.
kt_kmp_mpp_ere='kotlin[.]mpp[.]'
kt_kmp_refused_ere='cocoapods|swiftpmdependencies|xcodecompatibility[.]nowarn|withdevicetestbuilder|downloadfrommaven|kotlin[.](native|apple)[.]|konan'
kt_kmp_lines='kotlin {
withHostTestBuilder {}
withHostTestBuilder {'
kt_kmp() {
  [ -f "$1" ] && [ -r "$1" ] || return 2
  t=$(KC_KMP_LINES=$kt_kmp_lines awk -v ere="$kt_kmp_ere" -v mpp="$kt_kmp_mpp_ere" -v refused="$kt_kmp_refused_ere" '
    BEGIN {
      n = split(ENVIRON["KC_KMP_LINES"], a, "\n")
      for (k = 1; k <= n; k++) if (a[k] != "") ok[a[k]] = 1
    }
    {
      l = " " $0 " "
      lo = tolower(l)
      if (l !~ ere && lo !~ mpp && lo !~ refused) next
      t = $0
      sub(/^[[:space:]]+/, "", t)
      sub(/[[:space:]]+$/, "", t)
      if (lo !~ refused && (t in ok)) next
      print NR ":" $0
    }' "$1") || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}
kt_kmp_refused() {
  grep -n -a -i -E -e "$kt_kmp_refused_ere|$kt_kmp_mpp_ere" -- "$1"
}

# KtSdk, in build files but lockfiles and in scripts/android-gradle.sh (and Workflow, in the
# workflows: kt_canary_workflow): the canary build (tasks/todo.md, M5 group 5) is the one way a
# project from outside mobile/android joins the build, and only with the canary property set. Any
# letter case: the property's name kc.canary, and Gradle's ways to place a project or its build file
# elsewhere (projectDir, setProjectDir, includeFlat, buildFileName, setBuildFileName; includeBuild is
# kt_sdk's), comments included. Two lines pass, each whole and exact (MODE settings or app, the file
# it is): the guard if (providers.gradleProperty("kc.canary").orNull == "true") { in
# mobile/android/settings.gradle.kts and mobile/android/app/build.gradle.kts, and in the settings
# file the canary library's projectDir line, only as the third line of the guard's block, after
# include(":canary-lib") and before the closing }. So no real build includes the canary library,
# whose build file and sources lie outside this scan, and no other project or build file comes from
# outside mobile/android; the property cannot be set in gradle.properties or android-gradle.sh.
kt_canary() {
  [ -f "$1" ] && [ -r "$1" ] || return 2
  t=$(awk -v mode="$2" '
    { line[NR] = $0 }
    END {
      guard = "if (providers.gradleProperty(\"kc.canary\").orNull == \"true\") {"
      inc = "    include(\":canary-lib\")"
      dir = "    project(\":canary-lib\").projectDir = file(\"../../scripts/testdata/android-canary-lib\")"
      for (i = 1; i <= NR; i++) {
        l = " " tolower(line[i]) " "
        if (!index(l, "kc.canary") &&
          l !~ /[^a-z0-9_](projectdir|setprojectdir|includeflat|buildfilename|setbuildfilename)[^a-z0-9_]/) continue
        if ((mode == "settings" || mode == "app") && line[i] == guard) continue
        if (mode == "settings" && line[i] == dir && i > 2 && line[i - 2] == guard && line[i - 1] == inc &&
          i < NR && line[i + 1] == "}") continue
        print i ":" line[i]
      }
    }
  ' "$1") || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}
kt_canary_settings() { kt_canary "$1" settings; }
kt_canary_app() { kt_canary "$1" app; }
kt_canary_other() { kt_canary "$1" other; }

# Workflow (tasks/todo.md, M5 group 5): the canary property only in the Android workflow's canary
# step, as its one Gradle command line, whole and exact: sh scripts/android-gradle.sh
# --dependency-verification strict --offline -Pkc.canary=true :app:assembleShippingRelease (any
# indentation). Any other line naming kc.canary, any letter case and comments included, and each
# such command line after the first, is a hit, so no other build of the workflow is a canary build.
kt_canary_workflow() {
  [ -f "$1" ] && [ -r "$1" ] || return 2
  t=$(awk '
    {
      if (!index(tolower($0), "kc.canary")) next
      if (!seen && $0 ~ /^[ ]*sh scripts\/android-gradle[.]sh --dependency-verification strict --offline -Pkc[.]canary=true :app:assembleShippingRelease$/) {
        seen = 1
        next
      }
      print NR ":" $0
    }
  ' "$1") || return 2
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

# KtManifest (gate item 2; rule 9), in every AndroidManifest.xml under mobile/android: the network
# permissions, even with tools:node="remove" (no network permission is ever stripped: a library
# that asks for one is rejected), backup or cleartext switched on, and debuggable with any value.
kt_manifest() {
  grep -n -a -E \
    -e 'android[.]permission[.]INTERNET' \
    -e 'ACCESS_NETWORK_STATE' \
    -e 'ACCESS_WIFI_STATE' \
    -e "allowBackup[[:space:]]*=[[:space:]]*[\"']true" \
    -e "usesCleartextTraffic[[:space:]]*=[[:space:]]*[\"']true" \
    -e 'debuggable' \
    -- "$1"
}

# KtManifest: a <provider, <receiver or <service, unless tools:node="remove" is on the same line (so
# a removal is written on one line).
kt_manifest_components() {
  t=$(grep -n -a -E -e '<(provider|receiver|service)([[:space:]/>]|$)' -- "$1")
  case $? in 0) ;; 1) return 1 ;; *) return 2 ;; esac
  kept_hits '<(provider|receiver|service)([[:space:]/>]|$)' \
    -e 's/.*tools:node[[:space:]]*=[[:space:]]*"remove".*//'
}

# KtManifest, fail closed: each <application start tag, read from <application to the first > over
# as many lines as it takes, must hold allowBackup="false", fullBackupContent="false" and a
# dataExtractionRules attribute (double quotes; a > inside a value ends the tag early, so an
# attribute after it counts as missing). A hit names the tag's first line. The line is matched with
# a space after it, so the tag name may end the line without a $ inside a group (awk dialects
# differ there, as in rust_code_match).
kt_manifest_application() {
  [ -f "$1" ] && [ -r "$1" ] || return 2
  awk '
    function judge() {
      intag = 0
      if (tag !~ /allowBackup[[:space:]]*=[[:space:]]*"false"/ || tag !~ /fullBackupContent[[:space:]]*=[[:space:]]*"false"/ || tag !~ /dataExtractionRules[[:space:]]*=/) {
        print at ":" first
        found = 1
      }
    }
    intag {
      cut = index($0, ">")
      tag = tag " " (cut ? substr($0, 1, cut) : $0)
      if (cut) judge()
      next
    }
    (" " $0 " ") ~ /<application[[:space:]>\/]/ {
      first = $0
      at = NR
      tag = substr($0, index($0, "<application"))
      cut = index(tag, ">")
      if (cut) { tag = substr(tag, 1, cut); judge() } else intag = 1
    }
    END {
      if (intag) judge()
      exit !found
    }' "$1"
}

# KtTestChannel (group 18): the instrumentation status key that carries the CI throwaway seed's
# backup passphrase appears only under mobile/android/app/src/androidTest/ and in
# scripts/android-age-check.py, in any file anywhere else.
kt_test_channel() {
  grep -n -a -E -e 'kc_ci_throwaway_passphrase' -- "$1"
}

# --- Kotlin Multiplatform and the iPhone target (tasks/todo.md, M5 re-plan, "Gate changes", "The
# iOS C-ABI bridge"; Q64-Q72; the re-cut after Q73) --------------------------------------------

# KtSourceSet (lead decisions M5-19, M5-20 and M5-31): the KMP modules, the only ones whose src/
# holds Kotlin Multiplatform source sets, and the source sets allowed there: the Android target's
# and the common ones, since M5 builds no iPhone target (Q73). Any other directory or file right
# under such a module's src/ is refused: iosMain and iosTest (iPhone code, with KtIos's names on
# top), nativeInterop (a C bridge's cinterop definition, with KtCinterop's lines on top), appleMain,
# nativeMain and the per-target sets (iosArm64Main, iosSimulatorArm64Main), androidDeviceTest (a
# device test outside :app's androidTest), and Android's main and test sets, which have no place
# in a KMP module. Every other module is Android-only, and a KMP source-set name under its src/
# (any name that ends in Main or Test but androidTest, and nativeInterop) is refused, so no Kotlin
# escapes these rules by its directory name.
kt_kmp_modules='core-ffi screens'
kt_kmp_sets='commonMain commonTest androidMain androidHostTest'
kt_kmp_module() {
  case " $kt_kmp_modules " in *" $1 "*) return 0 ;; esac
  return 1
}
# kt_source_set_refused MODULE SET: exit 0 when SET (the first path segment under MODULE's src/) is
# refused there.
kt_source_set_refused() {
  if kt_kmp_module "$1"; then
    case " $kt_kmp_sets " in *" $2 "*) return 1 ;; esac
    return 0
  fi
  case $2 in
    androidTest) return 1 ;;
    *Main | *Test | nativeInterop) return 0 ;;
  esac
  return 1
}
# KtSourceSet also refuses any Java source under mobile/android, a .java file in any letter case,
# test source sets, :capture-control and paths outside src/ included (M5-60 (c)): Java turns each
# backslash-u escape into its character before it reads the code, so a .java file can spell every
# word of the text rules in escapes the gate cannot see, and the app has no Java. Its hit is the
# path's, as for a refused source set, so a hit fixture of another rule in a .java file gives this
# line too (the selftest's also line).
kt_java_refused="a Java source (Java reads backslash-u escapes as the characters they name, so its text can hide any rule's word; the app has no Java, lead decision M5-60)"

# KtIos (rules 1, 5, 8 and 9 in Kotlin/Native), in iosMain and iosTest right under any module's
# src/, on top of every Kt rule: Apple's storage (NSUserDefaults, NSFileManager, NSFileHandle,
# writeToFile, NSKeyedArchiver, SecItemAdd, CoreData, NSUbiquitousKeyValueStore, CloudKit); posix
# files and logging (fopen, fwrite, a call of open, the printf family, syslog); other apps (openURL,
# UIDocumentInteractionController); windows (UIAlertController, a UIWindow constructor, UIMenu);
# input (UITextView, becomeFirstResponder); logging (NSLog, os_log, AccessibilityDebugLogger);
# randomness and identifiers (platform.posix.rand, the words random and srand, NSUUID); and the
# network's C names (nw_connection, nw_listener, nw_browser, nw_endpoint, nw_parameters, CFStream,
# CFSocket, getaddrinfo, a call of socket). Other categories already refuse, everywhere,
# UIActivityViewController and UIPasteboard (Clipboard), UNUserNotificationCenter (KtWindow's
# Notification), UITextField (KtInput), drand48, arc4random and SecRandomCopyBytes (RNG), and
# URLSession, NWConnection and CFNetwork (Network).
kt_ios() {
  grep -n -a -E \
    -e 'NSUserDefaults|NSFileManager|NSFileHandle|writeToFile|NSKeyedArchiver|SecItemAdd|CoreData' \
    -e 'NSUbiquitousKeyValueStore|CloudKit' \
    -e "fopen|fwrite|printf|syslog|${L}open[[:space:]]*[(]" \
    -e 'openURL|UIDocumentInteractionController' \
    -e "UIAlertController|${L}UIWindow[[:space:]]*[(]|UIMenu|UITextView|becomeFirstResponder" \
    -e "NSLog|${L}os_log|AccessibilityDebugLogger" \
    -e "platform[.]posix[.]rand|${L}(random|srand)$R|NSUUID" \
    -e "nw_(connection|listener|browser|endpoint|parameters)|CFStream|CFSocket|getaddrinfo" \
    -e "${L}socket[[:space:]]*[(]" \
    -- "$1"
}

# KtIos, in every file under mobile/android, any source set: no callback from C into Kotlin
# (staticCFunction), no process-wide exception hook in M5 (setUnhandledExceptionHook), no network
# path monitor (nw_path_*); and no pinned memory (usePinned, addressOf: kt_pinned), which only an
# iPhone actual over a C bridge would need, and M5 has none (Q73).
kt_native() {
  grep -n -a -E -e 'staticCFunction|setUnhandledExceptionHook|nw_path_' -- "$1"
}
kt_pinned() {
  grep -n -a -E -e "${L}(usePinned|addressOf)$R" -- "$1"
}

# KtCinterop (the bridge's cinterop rule): the one definition file,
# mobile/android/core-ffi/src/nativeInterop/cinterop/keepcrypt.def, holds the lines
# headers = keepcrypt.h, headerFilter = keepcrypt.h and package = com.keepcrypt.native, each once,
# and no other line, a blank one included: no --- section of C code, no second header, no
# staticLibraries, libraryPaths, linkerOpts or compilerOpts. So no Rust library is packed into a
# klib or the framework, and the header's include path comes from the Gradle block alone
# (kt_kmp_lines). A missing line is reported at line 1. Any other .def file under mobile/android is
# a hit of its own (in scan()).
kt_def() {
  [ -f "$1" ] && [ -r "$1" ] || return 2
  awk '
    BEGIN {
      want[1] = "headers = keepcrypt.h"
      want[2] = "headerFilter = keepcrypt.h"
      want[3] = "package = com.keepcrypt.native"
    }
    {
      for (k = 1; k <= 3; k++) if ($0 == want[k] && !seen[k]) { seen[k] = 1; next }
      print NR ":" $0
      found = 1
    }
    END {
      for (k = 1; k <= 3; k++) if (!seen[k]) { print "1:missing the line " want[k]; found = 1 }
      exit !found
    }' "$1"
}

# --- FFI (tasks/todo.md, M5 groups 3 and 7; Q53; Q66's keepcrypt-guard and, after Q73, M5-32: the
# guard and the JNI boundary, keepcrypt-capi being M6's), .rs files under ffi/ ----------------------

# One catch, one place, tied to every export: catch_unwind outside every comment and literal
# (rust_code_match, so a doc line, a string and ffi/clippy.toml's ban entry are no site) anywhere
# under ffi/ but ffi/guard/src/lib.rs. There every catch_unwind but one is a hit (ffi_guard_catch):
# the one is the path call std::panic::catch_unwind( written in the body of the crate root's fn
# guarded, the function every export calls as keepcrypt_guard::guarded (ffi_export_scan). So a use
# line naming it (pub or not, alone or in a group), a rename with as, a shorter path
# (panic::catch_unwind), a leading ::, a turbofish, the function taken as a value, a second call,
# and a call in any other function, in a macro_rules definition (inside fn guarded too) or in a fn
# guarded that is not the crate root's (one in a mod or an impl, or nested in another fn) are each
# a hit: an alias or wrapper exported by keepcrypt-guard would let the boundary catch and continue
# (rule 3) with no catch_unwind of its own. Once ffi/jni/src/lib.rs declares an export
# (ffi_export_ere), that one call is required (ffi_guard_site, checked after the scan and reported
# at ffi/jni/src/lib.rs:1).
ffi_catch_unwind() {
  rust_code_match '[^A-Za-z0-9_]catch_unwind[^A-Za-z0-9_]' "$1"
}
# ffi_guard_scan MODE FILE: MODE bad prints each line of FILE that holds a catch_unwind other than
# the one call above, each line once; MODE site prints the one call's line. A fn's body is found by
# its braces from rust_tokens' tokens; a { or ; inside the signature's parentheses or a type's
# brackets neither opens nor ends it, and a body that a const generic's braces in the signature
# cut short leaves the call outside fn guarded, which fails closed. The crate root's fn guarded is
# the one whose body opens at brace depth 0 with no fn body open (a mod, impl, trait or block
# around it adds a brace); a macro_rules definition runs from macro_rules to the close of its first
# bracket, whichever kind.
ffi_guard_scan() {
  [ -f "$2" ] && [ -r "$2" ] || return 2
  awk -v mode="$1" -v sq="'" "$rust_lex$rust_tokens"'
    function out(l) {
      if (mode == "bad" && !(l in done)) print l ":" src[l]
      done[l] = 1
      found = 1
    }
    # tok(t): a catch_unwind is settled by the token after it; a fn name followed by its { opens a
    # body named after it on the stack, closed by the } that brings the depth back; mrd is the
    # bracket depth inside a macro_rules definition, 0 outside one.
    function tok(t) {
      if (cu) {
        cu = 0
        if (path && t == "(" && top == 1 && at[1] == 0 && name[1] == "guarded" && !mrd && !site) site = cl
        else out(cl)
      }
      if (t == "macro_rules") {
        mr = 1
      } else if (mr && (t == "{" || t == "(" || t == "[")) {
        mr = 0
        if (!mrd) mrd = pd + bd + 1
      }
      if (t == "catch_unwind") {
        cu = 1
        cl = NR
        path = p1 == "::" && p2 == "panic" && p3 == "::" && p4 == "std" && p5 != "::"
      } else if (p1 == "fn" && t ~ /^[A-Za-z_]/) {
        pend = 1
        pname = t
      } else if (t == "(" || t == "[") {
        pd++
      } else if (t == ")" || t == "]") {
        pd--
      } else if (t == "{") {
        if (pend && pd == 0) {
          top++
          name[top] = pname
          at[top] = bd
          pend = 0
        }
        bd++
      } else if (t == "}") {
        bd--
        if (top > 0 && bd == at[top]) top--
      } else if (t == ";" && pd == 0) {
        pend = 0
      }
      if (mrd && pd + bd < mrd) mrd = 0
      p5 = p4
      p4 = p3
      p3 = p2
      p2 = p1
      p1 = t
    }
    {
      src[NR] = $0
      lex()
      tokens()
    }
    END {
      if (cu) out(cl)
      if (mode == "site") {
        if (site) print site ":" src[site]
        exit !site
      }
      exit !found
    }' "$2"
}
ffi_guard_catch() {
  ffi_guard_scan bad "$1"
}
ffi_guard_site() {
  ffi_guard_scan site "$1"
}

# Every export sits in ffi/jni/src/lib.rs and calls guarded(): outside every comment and literal,
# no_mangle and export_name (bare or inside unsafe(...)) and the word extern, which starts an extern
# fn with an ABI string ("system", "C", "C-unwind", any: rust_code_match leaves it as "") or without
# one (which is "C"), are hits under ffi/ anywhere but ffi/jni/src/lib.rs (ffi_export). The word
# alone, whatever follows it, so an extern fn split from its fn over lines, one whose ABI a macro
# takes as $abi, and an extern passed to a macro as tokens are hits too. An extern "C" and an extern
# "system" function share an ABI on Android, and RegisterNatives can bind a native method to a
# function that is not exported by name, so each form is one: in another file it would run outside
# the reviewed boundary. keepcrypt-capi is M6's (Q73, M5-32), so ffi/capi/src/lib.rs is no boundary
# in M5. In ffi/jni/src/lib.rs (ffi_export_scan) each export's own body calls
# keepcrypt_guard::guarded(, written as that path (a leading :: or a longer path does not count), so
# a panic under it halts and wipes instead of aborting the process before any destructor runs; a
# helper that calls it does not count for the export. JNI_OnLoad alone is exempt: it runs at
# System.loadLibrary, before any session exists, and returns the JNI version. The exemption is for
# the real one only, the crate root's fn JNI_OnLoad marked no_mangle and not export_name, so a fn
# of that name in a mod, an impl or another fn, one exported under another name (a Java_ symbol)
# and an extern fn of that name that RegisterNatives could bind are each held to the tie. A hit is
# reported at the function's fn line, and an export with no body (a no_mangle static, an extern fn
# type) at its own line, so it is a hit too; an extern fn type in a helper's signature makes the
# helper one, which fails closed. macro_rules is a hit of its own there: an export a macro writes
# has its name and body only at the macro's call sites, out of the scan's sight, so every export
# is written out in the file. So is an extern that $ or ) follows, with its ABI string or not: the
# ABI a macro takes ($abi) or a macro call passes as tokens (call!(pub extern "system")), which a
# macro from elsewhere would turn into an export.
ffi_export_ere='[^A-Za-z0-9_](no_mangle|export_name|extern)[^A-Za-z0-9_]'
ffi_export() {
  rust_code_match "$ffi_export_ere" "$1"
}
ffi_export_scan() {
  [ -f "$1" ] && [ -r "$1" ] || return 2
  awk -v sq="'" "$rust_lex$rust_tokens"'
    function out(l) {
      if (!(l in done)) print l ":" src[l]
      done[l] = 1
      found = 1
    }
    # tok(t): an export marker waits for its fn name and its { (or a ;), which opens the export
    # body on the stack; a keepcrypt_guard::guarded( marks the innermost open export body. nm and
    # ex record a no_mangle and an export_name among the markers of the pending export.
    function tok(t) {
      if (t == "(" && p1 == "guarded" && p2 == "::" && p3 == "keepcrypt_guard" && p4 != "::" && top > 0) ok[top] = 1
      if (t == "macro_rules") out(NR)
      if ((t == "$" || t == ")") && (p1 == "extern" || (p1 == "\"\"" && p2 == "extern"))) out(NR)
      if (t == "no_mangle" || t == "export_name" || (t == "fn" && (p1 == "extern" || (p1 == "\"\"" && p2 == "extern")))) {
        if (!want) wl = NR
        want = 1
        if (t == "no_mangle") nm = 1
        if (t == "export_name") ex = 1
      } else if (want && p1 == "fn" && t ~ /^[A-Za-z_]/) {
        wl = NR
        wname = t
      } else if (t == "(" || t == "[") {
        pd++
      } else if (t == ")" || t == "]") {
        pd--
      } else if (t == "{") {
        if (want && pd == 0) {
          top++
          at[top] = bd
          ln[top] = wl
          ok[top] = wname == "JNI_OnLoad" && nm && !ex && bd == 0
          want = 0
          wname = ""
          nm = ex = 0
        }
        bd++
      } else if (t == "}") {
        bd--
        if (top > 0 && bd == at[top]) {
          if (!ok[top]) out(ln[top])
          top--
        }
      } else if (t == ";" && want && pd == 0) {
        out(wl)
        want = 0
        wname = ""
        nm = ex = 0
      }
      p4 = p3
      p3 = p2
      p2 = p1
      p1 = t
    }
    {
      src[NR] = $0
      lex()
      tokens()
    }
    END {
      if (want) out(wl)
      for (; top > 0; top--) if (!ok[top]) out(ln[top])
      exit !found
    }' "$1"
}

# The JNI surface only in keepcrypt-jni: the JNI names (a Java_ function, JNI_OnLoad, JNIEnv, the
# jni_sys crate), outside every comment and literal, are hits under ffi/ anywhere but ffi/jni/
# (ffi_jni_names). In ffi/jni/src/lib.rs every extern fn names JNI's "system" ABI (ffi_jni_abi): the
# file is read as tokens over lines (rust_tokens), as the compiler reads a signature, so an extern
# followed by fn, or by one string and then fn, is an extern fn wherever its lines break and
# whatever comments sit between its words, and it is a hit at the extern's line unless that
# string's text is exactly system. So an extern "C" fn, an extern fn with no ABI string (which is
# "C"), and either one split over lines (pub extern "C" on one line, fn Java_... on the next) are
# hits; an escape in the string fails closed. An extern block or extern crate is no extern fn.
ffi_jni_names() {
  rust_code_match '[^A-Za-z0-9_](Java_[A-Za-z0-9_]*|JNI_OnLoad|JNIEnv|jni_sys)[^A-Za-z0-9_]' "$1"
}
ffi_jni_abi() {
  [ -f "$1" ] && [ -r "$1" ] || return 2
  awk -v sq="'" "$rust_lex$rust_tokens"'
    # tok(t): st is 1 right after an extern, whose line is el, and 2 after its string, whose text
    # is abi; the next token settles it, fn making an extern fn. si counts the strings of the
    # line, so lits[si] is the text of the "" token just read.
    function tok(t) {
      if (t == "\"\"") si++
      if (st == 1 && t == "\"\"") {
        st = 2
        abi = lits[si]
        return
      }
      if (st && t == "fn" && (st == 1 || abi != "system")) {
        if (!(el in done)) print el ":" src[el]
        done[el] = 1
        found = 1
      }
      st = 0
      if (t == "extern") {
        st = 1
        el = NR
      }
    }
    {
      src[NR] = $0
      si = 0
      lex()
      tokens()
    }
    END { exit !found }' "$1"
}

# No export written by a macro (lead decision M5-35): macro_rules and macro_export, outside every
# comment and literal, are hits in any .rs file under ffi/src/, ffi/guard/src/ and ffi/jni/src/
# but ffi/jni/src/lib.rs (ffi_macros), whose macro_rules is the export scan's hit (ffi_export_scan).
# A macro that keepcrypt-ffi or keepcrypt-guard exported and keepcrypt-jni called, or one in
# another of keepcrypt-jni's files, would split an export's tokens between two files, which the
# export scan, reading ffi/jni/src/lib.rs alone, cannot see whole (an extern fn whose ABI comes in
# as $abi, bound by RegisterNatives from JNI_OnLoad, ran outside the catch); so every export stays
# written out in that file. The crates' tests may define macros.
ffi_macros() {
  rust_code_match '[^A-Za-z0-9_](macro_rules|macro_export)[^A-Za-z0-9_]' "$1"
}

# keepcrypt-guard's surface is fn guarded alone (lead decision M5-35): keepcrypt-jni depends on
# keepcrypt-guard and jni-sys only, so what keepcrypt-guard makes public is all of the safe layer the
# boundary can reach, and a re-export (pub use keepcrypt_ffi as ffi;), a pub mod or a second pub fn
# would let an export run it outside the catch, where a panic aborts before any destructor wipes
# the session. So every pub (pub(crate) and the other restricted forms too), outside every comment
# and literal, in any .rs file under ffi/guard/src/ is a hit (ffi_guard_pub), but the crate root's
# one line ffi_guard_pub_line, exactly as written there and once: its signature is pinned with it,
# so no other return type hands the boundary a way in. A pub split over lines is a hit at its pub.
# The line after it is guarded's first statement, which must be exactly ffi_guard_wrap_line, or it
# is a hit (and a file that ends at the pinned line is one there, "missing ..."): the input the
# boundary hands over can be secret (dice faces, extra entropy, the backup passphrase's words), and
# no test can see whether it is wiped. With it first, every later use of input is the wrapped one,
# so a deleted wrap, one moved after the hook or the catch, or a body that dispatches on the raw Vec
# (which still compiles, a Vec deref-ing to a slice) is a hit.
ffi_guard_pub_line='pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {'
ffi_guard_wrap_line='    let input = Zeroizing::new(input);'
ffi_guard_pub() {
  [ -f "$1" ] && [ -r "$1" ] || return 2
  case $1 in ffi/guard/src/lib.rs) groot=1 ;; *) groot=0 ;; esac
  GUARD_PUB_LINE=$ffi_guard_pub_line GUARD_WRAP_LINE=$ffi_guard_wrap_line \
    awk -v ere='[^A-Za-z0-9_]pub[^A-Za-z0-9_]' -v sq="'" -v groot="$groot" "$rust_lex"'
    function out(l, text) {
      if (!(l in done)) print l ":" text
      done[l] = 1
      found = 1
    }
    # wrap: the number of the pinned line, until the line after it is read.
    {
      lex()
      if (wrap) {
        if ($0 != ENVIRON["GUARD_WRAP_LINE"]) out(NR, $0)
        wrap = 0
      }
      if ((" " code " ") ~ ere) {
        if (groot && !seen && $0 == ENVIRON["GUARD_PUB_LINE"]) {
          seen = 1
          wrap = NR
        } else {
          out(NR, $0)
        }
      }
    }
    END {
      if (wrap) {
        w = ENVIRON["GUARD_WRAP_LINE"]
        sub(/^ +/, "", w)
        out(wrap, "missing the first statement of guarded on the next line, " w)
      }
      exit !found
    }' "$1"
}

# The other way to turn a panic into a value, a joined thread, cannot be banned in the shared
# clippy.toml (core/tests/panic_wipe.rs joins one), so the identifiers thread and JoinHandle are
# refused anywhere under ffi/ (ffi/guard, ffi/jni and ffi/capi included), comments included
# (threads and thread_local are other words), but in keepcrypt-ffi's integration tests, ffi/tests/
# (lead decision M5-8): a test thread turns no shipped panic into a value, and
# ffi_discard_during_call holds a long call at a barrier from one. Every other place stays refused,
# the other crates' tests/, a build script, examples and a tests/ directory under src/ among them.
ffi_threads() {
  grep -n -a -E -e "${L}(thread|JoinHandle)$R" -- "$1"
}

# report CATEGORY CHECK FILE: print and count each hit of CHECK in FILE. CHECK exits 0 with its hits,
# each "<line>:<text>", or 1 with nothing; anything else (a tool of it that failed, or a check that
# exits 0 with no hit, a line without its number, or 1 with output, the M5-66 hit with no line)
# stops the gate with exit 2, naming CHECK and FILE.
report() {
  on=$3
  out=$("$2" "$3")
  rc=$?
  case $rc:$out in
    1:) return ;;
    0:?*) ;;
    *)
      case $rc:$out in
        0:) rc='0 and no hit' ;;
        1:*) rc='1 and output' ;;
      esac
      printf 'banned-api-check: %s exited %s on %s\n' "$2" "$rc" "$3" >&2
      exit 2
      ;;
  esac
  while IFS= read -r line; do
    case $line in
      *:*) num=${line%%:*} ;;
      *) num= ;;
    esac
    case $num in
      '' | *[!0-9]*)
        printf 'banned-api-check: %s exited 0 on %s with a line that is not "<line>:<text>": %s\n' "$2" "$3" "$line" >&2
        exit 2
        ;;
    esac
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

# gradle_out: the ignored output a local Gradle build leaves (the header's Build; lead decision
# M5-62 (a)), as an ERE over list()'s paths: a path inside mobile/android/.gradle/,
# mobile/android/build/ or a module's build/. Only a path inside a directory matches (find descends
# into no link), so a file or a link of one of those names is no match, and neither is any other
# build/. A new module in mobile/android/settings.gradle.kts joins the list here and in
# scripts/canaries.sh's copy_tree (until it does, a local build's output there is read, so the gate
# fails loud, never quiet).
gradle_out='^[.]/mobile/android/([.]gradle|build|(app|capture-control|core-ffi|screens|secure-ui)/build)/'

# build_rule_cleanup: the Build rule's temporary files, removed by the scan's EXIT trap. A function
# rather than the trap's own text, since bash 5 numbers a trap's text from line 1 and bash 3.2 does
# not, while a function's lines are its lines in this file under both, so banned-api-faults.sh's
# traced run finds this rm where the text holds it (lead decision M5-66).
build_rule_cleanup() {
  rm -f "$index" ${blob:+"$blob"}
}

scan() {
  cd "$1" || exit 2
  fail_closed
  on='the scanned tree'
  # A newline in a name would split it in the list and leave it unscanned: refuse instead.
  odd=$(list -name "*$nl*") || exit 2
  if [ -n "$odd" ]; then
    echo 'banned-api-check: a file name contains a newline; rename it' >&2
    exit 2
  fi
  all=$(list) || exit 2
  # In a git work tree the Build rule refuses every tracked file in the ignored Gradle output, so the
  # scan leaves that output out; outside one (no index) every file is scanned (the header's Build).
  # git exits 128 outside a work tree; any other failure is the gate's (tool_status). Without git
  # the Build rule's tracked files cannot be listed. git runs in a command substitution: run here
  # as a command of its own, its finished job was what bash 3.2 later took for a check's grep
  # (see "The tools the gate runs fail closed").
  command -v git >/dev/null 2>&1 || {
    echo 'banned-api-check: git is not on PATH, so the tracked files under mobile/ cannot be listed' >&2
    exit 2
  }
  wt=$(command git rev-parse --is-inside-work-tree 2>/dev/null)
  rc=$?
  case $rc in
    0) work_tree=yes ;;
    128) work_tree=no ;;
    *) tool_status git "$rc" ;;
  esac
  if [ "$work_tree" = yes ]; then
    all=$(printf '%s\n' "$all" | grep -v -E -e "$gradle_out")
    [ $? -le 1 ] || exit 2
  fi
  all=$(printf '%s\n' "$all" | sort) || exit 2
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
    case $rel in
      core/src/*.rs | ffi/src/*.rs | ffi/guard/src/*.rs | ffi/jni/src/*.rs | ffi/capi/src/*.rs | pi/app/src/*.rs)
        report Rule1 hashing "$rel"
        ;;
    esac
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
            if found tests_rs_declared "$rel"; then
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
    # Kotlin and Android: every file under mobile/android, by scope. The test source sets right
    # under a module's directory, src/test, src/androidTest, src/commonTest and src/androidHostTest
    # (exactly those: src/withTestRegistry/ ships), skip KtIntent, KtStorage, KtDevice,
    # KtFailOpen's catch list and KtInput's Activity rule; :capture-control skips only the
    # FLAG_SECURE and Activity rules; every other file, build files included, gets every rule. The
    # module is the one path segment after mobile/android/, matched as a literal: a pattern's *
    # would also match /, so .../src/main/kotlin/x/src/test/ or .../src/commonMain/kotlin/x/src/
    # commonTest/ would pass as a test source set although Gradle compiles it into the app. A
    # module one level deeper (include(":ui:words"), mobile/android/ui/words/) would have no rule
    # here that reads its source sets by module, iosMain's names included, so KtSourceSet refuses
    # any src/ below mobile/android/ but a module's own, and the root project's src/.
    case $rel in
      mobile/android/*)
        ktmod=${rel#mobile/android/}
        ktmod=${ktmod%%/*}
        case $rel in
          "mobile/android/$ktmod/src/test/"* | "mobile/android/$ktmod/src/androidTest/"* | \
            "mobile/android/$ktmod/src/commonTest/"* | "mobile/android/$ktmod/src/androidHostTest/"*) ktscope=test ;;
          mobile/android/capture-control/*) ktscope=capture ;;
          *) ktscope=main ;;
        esac
        # KtSourceSet: the source sets a module may hold (kt_source_set_refused), and no src/
        # but a module's own, a path rule reported without a line.
        case $rel in
          "mobile/android/$ktmod/src/"*)
            ktset=${rel#"mobile/android/$ktmod/src/"}
            ktset=${ktset%%/*}
            if kt_source_set_refused "$ktmod" "$ktset"; then
              if kt_kmp_module "$ktmod"; then
                echo "KtSourceSet: $rel: src/$ktset in a KMP module (allowed: $kt_kmp_sets)"
              else
                echo "KtSourceSet: $rel: the KMP source set src/$ktset in an Android-only module"
              fi
              hits=$((hits + 1))
            fi
            ;;
          mobile/android/src/* | mobile/android/*/src/*)
            echo "KtSourceSet: $rel: a src/ that is not a module's own (each module is one directory under mobile/android/, and the root project holds no sources)"
            hits=$((hits + 1))
            ;;
        esac
        # KtSourceSet: no Java source, in any scope (kt_java_refused).
        case $rel in
          *.[Jj][Aa][Vv][Aa])
            echo "KtSourceSet: $rel: $kt_java_refused"
            hits=$((hits + 1))
            ;;
        esac
        # KtIos: the iOS names in iosMain and iosTest; the C-boundary and M6-only names, and pinned
        # memory, everywhere.
        case $rel in
          "mobile/android/$ktmod/src/iosMain/"* | "mobile/android/$ktmod/src/iosTest/"*) report KtIos kt_ios "$rel" ;;
        esac
        report KtIos kt_native "$rel"
        report KtIos kt_pinned "$rel"
        # KtCinterop: the one cinterop definition, exact; no other .def file.
        case $rel in
          mobile/android/core-ffi/src/nativeInterop/cinterop/keepcrypt.def) report KtCinterop kt_def "$rel" ;;
          *.[Dd][Ee][Ff])
            echo "KtCinterop: $rel: a cinterop definition other than mobile/android/core-ffi/src/nativeInterop/cinterop/keepcrypt.def"
            hits=$((hits + 1))
            ;;
        esac
        # The verification metadata lists the build's own artifacts (the Android Gradle plugin's
        # slf4j among them), never code; the shipped classpath is the lockfiles' and the expected list's.
        case $rel in
          mobile/android/gradle/verification-metadata.xml) ;;
          *) report KtLog ktlog "$rel" ;;
        esac
        report KtFailOpen ktfailopen "$rel"
        report KtWindow ktwindow "$rel"
        [ "$ktscope" = capture ] || report KtWindow kt_secure_policy "$rel"
        [ "$ktscope" = capture ] || report KtWindow kt_flag_secure "$rel"
        report KtInput ktinput "$rel"
        if [ "$ktscope" = main ]; then
          case $rel in
            "$kt_secure_ui/SecureActivity.kt") ;;
            *) report KtInput kt_activity "$rel" ;;
          esac
        fi
        if [ "$ktscope" != test ]; then
          case $rel in
            "$kt_screens/CeremonyModel.kt") report KtFailOpen kt_catch_kchalt "$rel" ;;
            "$kt_app/files/Documents.kt") report KtFailOpen kt_catch_ioexception "$rel" ;;
            "$kt_app/camera/GoAheadScanner.kt") report KtFailOpen kt_catch_camera "$rel" ;;
            *) report KtFailOpen kt_catch "$rel" ;;
          esac
          report KtFailOpen kt_alias "$rel"
          case $rel in
            "$kt_app/KeepCryptApp.kt") report KtFailOpen kt_handler_app "$rel" ;;
            "$kt_app/CrashHandler.kt") report KtFailOpen kt_handler_crash "$rel" ;;
            *) report KtFailOpen kt_handler "$rel" ;;
          esac
          case $rel in
            "$kt_app/camera/GoAheadScanner.kt") report KtFailOpen kt_tasks_scanner "$rel" ;;
            *) report KtFailOpen kt_tasks "$rel" ;;
          esac
          report KtFailOpen kt_finally "$rel"
          report KtStorage ktstorage "$rel"
          case $rel in
            "$kt_app/files/Documents.kt") ;;
            *) report KtStorage kt_open_stream "$rel" ;;
          esac
          case $rel in
            "$kt_app/files/Documents.kt") ;;
            "$kt_app/AirplaneSettingsIntent.kt") report KtIntent kt_intent_airplane "$rel" ;;
            *) report KtIntent ktintent "$rel" ;;
          esac
          case $rel in
            "$kt_app/camera/GoAheadScanner.kt") ;;
            *) report KtDevice kt_camera "$rel" ;;
          esac
          case $rel in
            "$kt_app/SensorMotionSource.kt") ;;
            *) report KtDevice kt_sensor "$rel" ;;
          esac
          case $rel in
            "$kt_secure_ui/OfflineMonitor.kt") ;;
            *) report KtDevice kt_settings "$rel" ;;
          esac
        fi
        case $rel in
          *.gradle.kts | *.gradle | */gradle.properties | *.versions.toml | *.lockfile)
            report KtSdk kt_sdk "$rel"
            report KtSdk kt_source_sets "$rel"
            # Not in lockfiles, whose generated header names Gradle's own --write-locks and whose
            # configuration names spell every Kotlin target.
            case $rel in *.lockfile) ;; *) report KtSdk kt_bootstrap "$rel"; report KtSdk kt_kmp "$rel" ;; esac
            case $rel in
              *.lockfile) ;;
              mobile/android/settings.gradle.kts) report KtSdk kt_canary_settings "$rel" ;;
              mobile/android/app/build.gradle.kts) report KtSdk kt_canary_app "$rel" ;;
              *) report KtSdk kt_canary_other "$rel" ;;
            esac
            case $rel in
              mobile/android/settings.gradle.kts) ;;
              *) report KtSdk kt_repositories "$rel" ;;
            esac
            ;;
        esac
        case $rel in
          */AndroidManifest.xml)
            report KtManifest kt_manifest "$rel"
            report KtManifest kt_manifest_components "$rel"
            report KtManifest kt_manifest_application "$rel"
            ;;
        esac
        ;;
    esac
    case $rel in
      scripts/android-gradle.sh)
        report KtSdk kt_bootstrap "$rel"
        report KtSdk kt_canary_other "$rel"
        report KtSdk kt_kmp_refused "$rel"
        ;;
    esac
    # KtRoot (lead decisions M5-19 and M5-25): Kotlin lives under mobile/android, the one Gradle
    # root, and nowhere else under mobile/.
    case $rel in
      mobile/android/*) ;;
      mobile/*.[Kk][Tt] | mobile/*.[Kk][Tt][Ss])
        echo "KtRoot: $rel: Kotlin outside mobile/android/, the one Gradle root (lead decision M5-19)"
        hits=$((hits + 1))
        ;;
    esac
    case $rel in
      mobile/android/app/src/androidTest/* | scripts/android-age-check.py) ;;
      *) report KtTestChannel kt_test_channel "$rel" ;;
    esac
    # FFI: one catch_unwind, the path call in fn guarded in ffi/guard/src/lib.rs; exports only in
    # ffi/jni/src/lib.rs, each calling keepcrypt_guard::guarded, JNI names only under ffi/jni/ and
    # only the JNI ABI in its lib.rs; no macro_rules or macro_export in ffi/src, ffi/guard/src or
    # ffi/jni/src; no pub in ffi/guard/src but fn guarded's line; one Session::new, in
    # ffi/src/ceremony.rs (comments count, as under pi/app/src); no thread or JoinHandle outside
    # ffi/tests/ (M5-8).
    case $rel in
      ffi/*.rs)
        case $rel in
          ffi/guard/src/lib.rs) report FFI ffi_guard_catch "$rel"; report FFI ffi_export "$rel" ;;
          ffi/jni/src/lib.rs) report FFI ffi_catch_unwind "$rel"; report FFI ffi_export_scan "$rel" ;;
          *) report FFI ffi_catch_unwind "$rel"; report FFI ffi_export "$rel" ;;
        esac
        case $rel in ffi/jni/src/lib.rs) report FFI ffi_jni_abi "$rel" ;; esac
        case $rel in ffi/jni/*) ;; *) report FFI ffi_jni_names "$rel" ;; esac
        case $rel in
          ffi/jni/src/lib.rs) ;;
          ffi/src/*.rs | ffi/guard/src/*.rs | ffi/jni/src/*.rs) report FFI ffi_macros "$rel" ;;
        esac
        case $rel in ffi/guard/src/*.rs) report FFI ffi_guard_pub "$rel" ;; esac
        case $rel in
          ffi/src/ceremony.rs) report FFI session_new_again "$rel" ;;
          *) report FFI session_new "$rel" ;;
        esac
        case $rel in ffi/tests/*) ;; *) report FFI ffi_threads "$rel" ;; esac
        ;;
    esac
  done <<EOF
$files
EOF
  # The unsafe-code ban in core's lib.rs, and in pi/app's lib.rs and main.rs once pi/app exists.
  # These checks and the Build rule's run each tool through found() or in a command substitution,
  # so the scan's shell starts none itself (see "The tools the gate runs fail closed").
  forbid=core/src/lib.rs
  [ -e pi/app ] && forbid="$forbid pi/app/src/lib.rs pi/app/src/main.rs"
  for f in $forbid; do
    on=$f
    if ! { [ -f "$f" ] && found grep -q -a -x -F -e '#![forbid(unsafe_code)]' "$f"; }; then
      echo "Rule1: $f:1: missing the line #![forbid(unsafe_code)]"
      hits=$((hits + 1))
    fi
  done
  on=core/examples/release_probe.rs
  if [ -e core ] && ! found probe_calls_game_random; then
    echo 'Shell: core/examples/release_probe.rs:1: missing a call to game_random outside a comment'
    hits=$((hits + 1))
  fi
  # FFI: the one Session::new is required once ffi/src/ceremony.rs exists, and the one catch_unwind,
  # the path call in fn guarded in ffi/guard/src/lib.rs, once ffi/jni/src/lib.rs exports a function
  # (an export without the catch aborts on a panic before any destructor runs, so the session would
  # not be wiped). An unreadable file was already exit 2 in the loop.
  on=ffi/src/ceremony.rs
  if [ -f ffi/src/ceremony.rs ] && ! found session_new ffi/src/ceremony.rs; then
    echo 'FFI: ffi/src/ceremony.rs:1: missing the one Session::new under ffi/'
    hits=$((hits + 1))
  fi
  on=ffi/jni/src/lib.rs
  if [ -f ffi/jni/src/lib.rs ] && found ffi_export ffi/jni/src/lib.rs &&
    ! { [ -f ffi/guard/src/lib.rs ] && on=ffi/guard/src/lib.rs && found ffi_guard_site ffi/guard/src/lib.rs; }; then
    echo 'FFI: ffi/jni/src/lib.rs:1: missing the one catch_unwind call site, std::panic::catch_unwind( in fn guarded in ffi/guard/src/lib.rs, which every export needs'
    hits=$((hits + 1))
  fi
  # KtSdk: once mobile/android exists, its root build file locks every configuration strictly
  # (group 4), each of the two lines whole on a line of its own, so a commented-out one is not
  # one. Without them Gradle resolves with no lock state, and the classpath allow-list, which reads
  # the lockfile, would no longer be what the build resolves.
  kroot=mobile/android/build.gradle.kts
  on=$kroot
  if [ -e mobile/android ] && ! { [ -f "$kroot" ] &&
    found grep -q -a -x -E -e '[[:space:]]*lockAllConfigurations[(][)][[:space:]]*' "$kroot" &&
    found grep -q -a -x -E -e '[[:space:]]*lockMode[.]set[(]LockMode[.]STRICT[)][[:space:]]*' "$kroot"; }; then
    echo "KtSdk: $kroot:1: missing the lines lockAllConfigurations() and lockMode.set(LockMode.STRICT)"
    hits=$((hits + 1))
  fi
  # Build: no tracked file under mobile/**/build/, mobile/**/.gradle/ or mobile/**/.konan/, read
  # from git's index (see the header). Outside a work tree nothing is tracked; without git nothing
  # can be listed (checked before the scan). The test is the scan's own ($work_tree), so the scan
  # left the Gradle output out exactly where this rule reads the index.
  if [ "$work_tree" = yes ]; then
    # One entry per line, "<mode> <object> <stage><tab><path>": -z keeps a name whole that plain
    # ls-files would print quoted, and the newline check above already refused a newline in a
    # name. The listing goes through a file so that ls-files' own exit status is read, which a
    # pipeline into tr would hide; ls-files and cat-file write their files from a command
    # substitution, which prints nothing.
    tab=$(printf '\t')
    on="git's index of mobile/"
    index=$(mktemp "${TMPDIR:-/tmp}/banned-api-index.XXXXXX") || exit 2
    blob=
    trap 'build_rule_cleanup' EXIT
    trap 'exit 2' HUP INT TERM
    blob=$(mktemp "${TMPDIR:-/tmp}/banned-api-blob.XXXXXX") || exit 2
    listed=$(git ls-files -s -z -- mobile >"$index") || exit 2
    tracked=$(tr '\0' '\n' <"$index") || exit 2
    built=$(printf '%s\n' "$tracked" | grep -E "^160000 |${tab}mobile/(.*/)?(build|[.]gradle|[.]konan)/")
    [ $? -le 1 ] || exit 2
    while IFS= read -r e; do
      [ -n "$e" ] || continue
      f=${e#*"$tab"}
      case $e in
        160000\ *) echo "Build: $f: a submodule under mobile/ (git ls-files cannot list its files, so this rule cannot clear them)" ;;
        *) echo "Build: $f: a tracked file under mobile/**/build/, mobile/**/.gradle/ or mobile/**/.konan/ (build output and toolchains never enter git)" ;;
      esac
      hits=$((hits + 1))
    done <<EOF
$built
EOF
    # KtRoot (lead decision M5-25): mobile/ios/ stays empty in M5, so any tracked file under it is a
    # hit, until M6's first gate commit brings the Swift and Xcode rules.
    ios=$(printf '%s\n' "$tracked" | grep -E "${tab}mobile/ios/")
    [ $? -le 1 ] || exit 2
    while IFS= read -r e; do
      [ -n "$e" ] || continue
      echo "KtRoot: ${e#*"$tab"}: a tracked file under mobile/ios/, which stays empty in M5 (lead decision M5-25)"
      hits=$((hits + 1))
    done <<EOF
$ios
EOF
    # KtBinary: a tracked file (or link; not a submodule, the Build rule's) under mobile/ with a
    # binary extension, in any letter case: the plan's nine, every other code or archive extension
    # of $binext (whose files the scan never reads) and a Kotlin/Native klib, or under a directory
    # named *.framework or *.xcframework (an iPhone bundle). The scan list skips such files by
    # extension, so they are read from the index too.
    binaries=$(printf '%s\n' "$tracked" | grep -i -E "^1[02][0-7]{4} [^$tab]*${tab}mobile/(.*[.](jar|aar|so|dex|class|apk|aab|jks|keystore|zip|gz|xz|bz2|zst|tar|ipa|dylib|a|rlib|o|car|klib)\$|(.*/)?[^/]*[.](framework|xcframework)/)")
    [ $? -le 1 ] || exit 2
    while IFS= read -r e; do
      [ -n "$e" ] || continue
      echo "KtBinary: ${e#*"$tab"}: a tracked binary under mobile/ (no code, archive, package or key file enters git)"
      hits=$((hits + 1))
    done <<EOF
$binaries
EOF
    # KtBinary: a compiled or packed file whatever its name, by its first four bytes: a Mach-O
    # file, thin or fat, either byte order (an iPhone library, executable or object); an ELF file
    # (an Android .so, executable or object); an ar archive, !<arch> (a static library or an
    # rlib); a zip archive, PK\003\004 (a jar, aar, apk, aab, ipa or klib); a dex file, dex\n
    # (Android bytecode, packed into an APK unchanged from src/main/assets or res/raw); a JKS or
    # JCEKS keystore, feedfeed or cececece (a signing key); or a gzip (1f8b08), xz (fd377a58),
    # zstd (28b52ffd) or bzip2 (BZh and its block-size digit) stream. So each format of the
    # extension list above that opens with a fixed magic is refused under any name; a tar archive
    # (its ustar mark is at byte 257) and a PKCS#12 keystore (a plain DER sequence, as any
    # certificate is) open with none, and are refused by their extension only. The bytes come
    # from the index's blob, what a commit holds, for every tracked regular file under mobile/
    # (links and submodules are paths, not files). A fat file's cafebabe is also a Java class
    # file's magic, refused either way.
    while IFS= read -r e; do
      case $e in 100644\ * | 100755\ *) ;; *) continue ;; esac
      obj=${e#* }
      obj=${obj%% *}
      on="${e#*"$tab"} (blob $obj)"
      listed=$(git cat-file blob "$obj" >"$blob") || exit 2
      magic=$(od -A n -t x1 -N 4 "$blob") || exit 2
      magic=$(printf '%s' "$magic" | tr -d ' \t\n') || exit 2
      case $magic in
        feedface | feedfacf | cefaedfe | cffaedfe | cafebabe | bebafeca | cafebabf | bfbafeca) kind='a Mach-O file' ;;
        7f454c46) kind='an ELF file' ;;
        213c6172) kind='an ar archive' ;;
        504b0304) kind='a zip archive' ;;
        6465780a) kind='a dex file' ;;
        feedfeed | cececece) kind='a Java keystore' ;;
        1f8b08*) kind='a gzip stream' ;;
        fd377a58) kind='an xz stream' ;;
        28b52ffd) kind='a zstd stream' ;;
        425a683[1-9]) kind='a bzip2 stream' ;;
        *) continue ;;
      esac
      echo "KtBinary: ${e#*"$tab"}: $kind under mobile/ (magic $magic), whatever its name"
      hits=$((hits + 1))
    done <<EOF
$tracked
EOF
  fi
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check: $hits hit(s) in $n files scanned ($skipped binary by extension, not scanned)"
    exit 1
  fi
  echo "banned-api-check: clean, $n files scanned ($skipped binary by extension, not scanned)"
  exit 0
}

# fresh: new repo-like dir $d holding only what the tree-wide checks need: core/src/lib.rs,
# pi/app/src/lib.rs and pi/app/src/main.rs with the unsafe-code ban, a release probe that calls
# game_random, and mobile/android/build.gradle.kts with the two strict-locking lines. A fixture's
# file at one of these paths replaces it.
fresh() {
  i=$((i + 1))
  d=$tmp/$i
  mkdir -p "$d/core/src" "$d/core/examples" "$d/pi/app/src" || exit 2
  for f in core/src/lib.rs pi/app/src/lib.rs pi/app/src/main.rs; do
    echo '#![forbid(unsafe_code)]' >"$d/$f" || exit 2
  done
  echo 'fn main() -> Result<(), u8> { game_random(&mut [0; 32]).map_err(|_| 20) }' \
    >"$d/core/examples/release_probe.rs" || exit 2
  mkdir -p "$d/mobile/android" || exit 2
  printf '%s\n' 'dependencyLocking {' '    lockAllConfigurations()' '    lockMode.set(LockMode.STRICT)' '}' \
    >"$d/mobile/android/build.gradle.kts" || exit 2
}

# The selftest's shard, K of N (--selftest --shard K/N; without the option, one shard of one,
# which runs every case), and the cases counted so far in the list's fixed order (see "Selftest
# shards" above).
sharded=no
shard_k=1
shard_n=1
ordinal=0

# shard K/N: this run's shard, or exit 2 for anything but K/N with K and N decimal numbers from 1 to
# 9999 with no leading zero and K at most N.
shard() {
  shard_k=${1%%/*}
  shard_n=${1#*/}
  ok=no
  if [ "$shard_k/$shard_n" = "$1" ]; then
    ok=yes
    for x in "$shard_k" "$shard_n"; do
      case $x in [1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9]) ;; *) ok=no ;; esac
    done
  fi
  if [ "$ok" = no ]; then
    printf 'banned-api-check: --selftest --shard: %s is not K/N, two numbers from 1 to 9999 with no leading zero\n' "$1" >&2
    exit 2
  fi
  if [ "$shard_k" -gt "$shard_n" ]; then
    printf 'banned-api-check: --selftest --shard: %s names shard %s of %s, past the last\n' "$1" "$shard_k" "$shard_n" >&2
    exit 2
  fi
  sharded=yes
}

# mine: counts the selftest's next case and is true when the case is this shard's to run: case c
# (from 1) is shard ((c - 1) mod N) + 1's, so without the option every case is. Each case helper
# (expect, wexpect, aexpect, ixexpect, oexpect, sicase) and each case judged inline asks it first
# and does nothing more when it is false.
mine() {
  ordinal=$((ordinal + 1))
  [ $(((ordinal - 1) % shard_n + 1)) -eq "$shard_k" ]
}

# expect NAME DIR WANT [FILE]: scan DIR in a new process. WANT=clean needs exit 0 and no hit,
# WANT=error needs exit 2 and output containing FILE (if given, the expected message), any other
# WANT needs exit 1 and exactly one hit "<WANT>: <FILE>:<line>: <text>", where <text> is line
# <line> of FILE as it stands (the messages for a missing line or call, "missing ...", are the
# exception), or a whole-file hit "<WANT>: <FILE>: <detail>" with no line (the Build, KtSourceSet
# and KtRoot rules). The gate run is $gate, this script unless a case sets another copy. When $also
# is set (one whole output line), the output must hold that line too, which is not counted (once:
# a line two rules report is in the output twice): a fixture in an iPhone source set hits its own
# rule and KtSourceSet, which refuses the set in M5 (Q73), and so does one in a .java file under
# mobile/android, which KtSourceSet refuses too (M5-60 (c)). When $atline is set, the one hit must
# be at that line of FILE (a case with more than one candidate line, such as the second of two
# exports).
expect() {
  mine || return 0
  out=$(sh "${gate:-$self}" "$2" 2>&1)
  rc=$?
  alsook=yes
  if [ -n "${also:-}" ]; then
    if printf '%s\n' "$out" | grep -q -x -F -e "$also"; then
      out=$(printf '%s\n' "$out" | ALSO=$also awk '!gone && $0 == ENVIRON["ALSO"] { gone = 1; next } { print }')
    else
      alsook=no
    fi
  fi
  cats='^(RNG|Network|Clipboard|Rule1|FailOpen|Include|Shell|Device|Build|KtLog|KtFailOpen|KtWindow|KtInput|KtStorage|KtIntent|KtDevice|KtSdk|KtBinary|KtManifest|KtTestChannel|KtSourceSet|KtIos|KtRoot|KtCinterop|FFI): '
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
        [ -z "${atline:-}" ] || [ "${at%%:*}" = "$atline" ] || ok=no
        ;;
      "$3: $4: "*) ok=yes ;;
    esac
  fi
  [ "$alsook" = yes ] || ok=no
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> %s\n' "$1" "${hit:-clean}${also:+ (and $also)}"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted %s %s%s%s, got exit %s:\n' "$1" "$3" "${4:-}" "${atline:+:$atline}" "${also:+ and the line $also}" "$rc"
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
  gate=
  also=
  atline=
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
      ktlog-*) want=KtLog ;;
      ktfailopen-*) want=KtFailOpen ;;
      ktwindow-*) want=KtWindow ;;
      ktinput-*) want=KtInput ;;
      ktstorage-*) want=KtStorage ;;
      ktintent-*) want=KtIntent ;;
      ktdevice-*) want=KtDevice ;;
      ktsdk-*) want=KtSdk ;;
      ktmanifest-*) want=KtManifest ;;
      kttestchannel-*) want=KtTestChannel ;;
      ktsourceset-*) want=KtSourceSet ;;
      ktios-*) want=KtIos ;;
      ktroot-*) want=KtRoot ;;
      ktcinterop-*) want=KtCinterop ;;
      ffi-*) want=FFI ;;
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
    # A hit fixture of another rule in an iPhone source set of a KMP module (iosMain, iosTest,
    # nativeInterop) also gives KtSourceSet's hit for its file: M5 refuses those sets (Q73), and
    # the rules for what they hold (KtIos, KtCinterop and the rest) still fire. So does one in a
    # .java file under mobile/android, which KtSourceSet refuses in every scope (M5-60 (c)), so the
    # Java forms of the other rules stay tested (no fixture is both).
    case $want:$file in
      KtSourceSet:*) ;;
      *:mobile/android/*.[Jj][Aa][Vv][Aa]) also="KtSourceSet: $file: $kt_java_refused" ;;
      *:mobile/android/*/src/*)
        kmod=${file#mobile/android/}
        kmod=${kmod%%/*}
        kset=${file#mobile/android/"$kmod"/src/}
        kset=${kset%%/*}
        case $kset in
          iosMain | iosTest | nativeInterop)
            if kt_kmp_module "$kmod"; then
              also="KtSourceSet: $file: src/$kset in a KMP module (allowed: $kt_kmp_sets)"
            fi
            ;;
        esac
        ;;
    esac
    fresh
    cp -R "$fx/." "$d/" || exit 2
    expect "$name" "$d" "$want" "$file"
    also=
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
    # The Kotlin scopes: a hit fixture in a shipping source set (src/main of a module, or
    # commonMain, androidMain or iosMain) whose rule the test source sets skip (KtIntent, KtStorage,
    # KtDevice, the catch list, the Activity rule) is copied into its module's test source sets
    # (src/test and src/androidTest of an Android-only module, commonTest and androidHostTest of a
    # KMP module) and, from an Android-only module, into :screens' two as well; one that
    # :capture-control skips (the FLAG_SECURE and Activity rules) is copied there. Each copy sits
    # under its own directory, and the five trees are scanned once each after this loop. A .java
    # fixture is not copied: KtSourceSet refuses Java in every scope, and each rule's exemption
    # there is tested by its Kotlin fixtures.
    case $file in
      *.[Jj][Aa][Vv][Aa]) ;;
      mobile/android/*/src/*)
        kmod=${file#mobile/android/}
        kmod=${kmod%%/*}
        ksrc=${file#mobile/android/"$kmod"/src/}
        kset=${ksrc%%/*}
        krest=${ksrc#*/}
        case $kset in main | commonMain | androidMain | iosMain) ;; *) kset= ;; esac
        if [ -n "$kset" ]; then
          case $want:$name in
            KtIntent:* | KtStorage:* | KtDevice:* | KtFailOpen:ktfailopen-catch-* | KtInput:ktinput-activity-*)
              if kt_kmp_module "$kmod"; then
                ktests="$kmod:commonTest $kmod:androidHostTest"
              else
                ktests="$kmod:test $kmod:androidTest screens:commonTest screens:androidHostTest"
              fi
              for kt in $ktests; do
                kto=$tmp/scope-${kt#*:}/mobile/android/${kt%%:*}/src/${kt#*:}/$name/$krest
                mkdir -p "${kto%/*}" && cp "$fx/$file" "$kto" || exit 2
              done
              ;;
          esac
          case $want:$name in
            KtWindow:ktwindow-secure-* | KtInput:ktinput-activity-*)
              kto=$tmp/scope-capture/mobile/android/capture-control/src/main/$name/$krest
              mkdir -p "${kto%/*}" && cp "$fx/$file" "$kto" || exit 2
              ;;
          esac
        fi
        ;;
    esac
  done
  # CrashHandler.kt's header (kt_handler_crash) is allowed once and exactly, with its override
  # pinned on the line after it, and that override is itself a hit wherever no allowed header comes
  # before it. So a header the allowance must refuse, written with its override, is two hits, and a
  # gate that took the header gives none; a fixture of one file and one hit cannot tell such a gate
  # from this one, since there the refused header alone still gives one hit ("missing ..." at its
  # line, or the next line's), which is how 18g's pinned override left the header-with-body and
  # header-twice fixtures. These trees are built here, each a refused header and its override: the
  # one hit counted is the header's (atline), the override's the extra line (also). The class named
  # otherwise, a second supertype, the header over two lines, the header with a body after its {
  # (a second mention on the allowed line, which a header matched by its start took), a second class
  # after ";" on its line (18e's pattern took that line, the override then the second class's), a
  # second class before it on its line with no ";" (which a header matched by its end took), and the
  # header again after the allowed one (once only). Each also goes in the test scopes' trees below,
  # clean there.
  kt_hdr='internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {'
  kt_ovr='    override fun uncaughtException(thread: Thread, exception: Throwable) {'
  for case in other-class:1 second-supertype:1 over-two-lines:2 body-on-its-line:1 second-class-after-semicolon:1 \
    second-class-before-it:1 twice:6; do
    name=ktfailopen-catch-handler-crash-header-${case%%:*}
    case ${case%%:*} in
      other-class)
        kt_body='internal class QuietHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {'
        ;;
      second-supertype)
        kt_body='internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler, Runnable {'
        ;;
      over-two-lines)
        kt_body=$(printf '%s\n' 'internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) :' \
          '    Thread.UncaughtExceptionHandler {')
        ;;
      body-on-its-line)
        kt_body="$kt_hdr override fun uncaughtException(thread: Thread, exception: Throwable) {} }"
        ;;
      second-class-after-semicolon)
        kt_body='internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Runnable by Runnable(wipe); private class QuietHandler() : Thread.UncaughtExceptionHandler {'
        ;;
      second-class-before-it)
        kt_body="private class QuietHandler : Thread.UncaughtExceptionHandler { override fun uncaughtException(thread: Thread, exception: Throwable) {} } $kt_hdr"
        ;;
      twice)
        kt_body=$(printf '%s\n' "$kt_hdr" "$kt_ovr" '        wipe()' '    }' '}' "$kt_hdr")
        ;;
    esac
    fresh
    mkdir -p "$d/$kt_app" || exit 2
    printf '%s\n' "$kt_body" "$kt_ovr" >"$d/$kt_app/CrashHandler.kt" || exit 2
    atline=${case#*:}
    also="KtFailOpen: $kt_app/CrashHandler.kt:$((atline + 1)): $kt_ovr"
    expect "$name" "$d" KtFailOpen "$kt_app/CrashHandler.kt"
    also=
    atline=
    for kt in app:test app:androidTest screens:commonTest screens:androidHostTest; do
      kto=$tmp/scope-${kt#*:}/mobile/android/${kt%%:*}/src/${kt#*:}/$name/kotlin/com/keepcrypt/entropy/CrashHandler.kt
      mkdir -p "${kto%/*}" && cp "$d/$kt_app/CrashHandler.kt" "$kto" || exit 2
    done
  done
  # A NUL byte earlier on a line ended it for the Mac's awk, so KtFailOpen's package arm and finally
  # rule read no further (kt_text): a NUL in a block comment before a qualified name of
  # kotlinx.coroutines, and one in a string before a finally block's return, each on one line of the
  # app's CeremonyHolder.kt, are a hit at that line. Each was clean on the Mac before kt_text; they
  # are built here, as a fixture in git would hold the byte where no diff shows it. Each also goes in
  # the test scopes' trees below, clean there.
  for case in package:'/* \000 */ kotlinx.coroutines.GlobalScope.launch { model.finish() }' \
    finally:'internal fun drop(work: () -> Unit) { val gap = "\000"; try { work() } finally { return } }'; do
    name=ktfailopen-catch-${case%%:*}-after-a-nul
    fresh
    mkdir -p "$d/$kt_app" || exit 2
    { echo '// The line below holds a NUL byte, at which the Mac'"'"'s awk ended it.' && printf "${case#*:}\\n"; } \
      >"$d/$kt_app/CeremonyHolder.kt" || exit 2
    atline=2
    expect "$name" "$d" KtFailOpen "$kt_app/CeremonyHolder.kt"
    atline=
    for kt in app:test app:androidTest screens:commonTest screens:androidHostTest; do
      kto=$tmp/scope-${kt#*:}/mobile/android/${kt%%:*}/src/${kt#*:}/$name/kotlin/com/keepcrypt/entropy/CeremonyHolder.kt
      mkdir -p "${kto%/*}" && cp "$d/$kt_app/CeremonyHolder.kt" "$kto" || exit 2
    done
  done
  # A package mention is a hit at the line of its first word (kt_packages), so a name split over
  # lines is reported where java or kotlinx stands, not where the name completes; and the task words'
  # hits and the packages' on other lines of one file are both reported (kt_tasks_and_packages drops
  # only a line both find). No fixture pins either, as expect() takes a hit at any line whose text it
  # shows, so these are built here: :screens' Timers.kt with kotlinx at line 2 and .coroutines on line
  # 3 is a hit at line 2 (atline), and the app's CeremonyHolder.kt with an ExecutorService at line 2
  # and a qualified name of kotlinx.coroutines at line 3 is the word's hit (also) and the package's
  # (atline). Each also goes in the test scopes' trees below, clean there.
  for case in line-break-before-dot beside-a-task-word; do
    name=ktfailopen-catch-package-$case
    case $case in
      line-break-before-dot)
        kt_dir=$kt_screens
        kt_file=Timers.kt
        kt_body=$(printf '%s\n' '// A qualified name over two lines: Kotlin takes a line break before a dot.' 'kotlinx' \
          '.coroutines.GlobalScope.launch { model.finish() }')
        atline=2
        ktests='screens:commonTest screens:androidHostTest'
        ;;
      beside-a-task-word)
        kt_dir=$kt_app
        kt_file=CeremonyHolder.kt
        kt_body=$(printf '%s\n' '// A task word and a package mention on two lines of one file: each is its own hit.' \
          'private val pool: ExecutorService = pool()' 'private val done = kotlinx.coroutines.GlobalScope.launch { model.finish() }')
        atline=3
        also="KtFailOpen: $kt_app/CeremonyHolder.kt:2: private val pool: ExecutorService = pool()"
        ktests='app:test app:androidTest screens:commonTest screens:androidHostTest'
        ;;
    esac
    fresh
    mkdir -p "$d/$kt_dir" || exit 2
    printf '%s\n' "$kt_body" >"$d/$kt_dir/$kt_file" || exit 2
    expect "$name" "$d" KtFailOpen "$kt_dir/$kt_file"
    also=
    atline=
    for kt in $ktests; do
      kto=$tmp/scope-${kt#*:}/mobile/android/${kt%%:*}/src/${kt#*:}/$name/${kt_dir#mobile/android/*/src/*/}/$kt_file
      mkdir -p "${kto%/*}" && cp "$d/$kt_dir/$kt_file" "$kto" || exit 2
    done
  done
  # The copies above, one tree per scope: each must be clean, so no copied hit fires there. Each
  # tree must hold copies, or a rename of the fixtures would leave the exemptions untested.
  for kset in test androidTest commonTest androidHostTest capture; do
    kn=0
    if [ -d "$tmp/scope-$kset" ]; then
      kn=$(find "$tmp/scope-$kset" -type f | wc -l | tr -d ' ') || exit 2
    fi
    if [ "$kn" -eq 0 ]; then
      fail=$((fail + 1))
      echo "FAIL no fixture copied to the $kset scope"
      continue
    fi
    fresh
    cp -R "$tmp/scope-$kset/." "$d/" || exit 2
    expect "clean-kt-$kset-scope-copies ($kn fixtures)" "$d" clean
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
  # The strict-locking lines are required whenever mobile/android exists, so a tree without the
  # root build file is a hit and a tree without mobile/android is clean.
  fresh
  rm "$d/mobile/android/build.gradle.kts" || exit 2
  expect 'ktsdk-root-build-file-absent' "$d" KtSdk mobile/android/build.gradle.kts
  fresh
  rm -r "$d/mobile" || exit 2
  expect 'clean-no-mobile-android' "$d" clean
  # The iPhone lines commit 8q's kt_kmp allowed (kt_kmp_lines' and the simulator's device line),
  # and an osVersionMin switch, which its plan would have added later, are refused in M5 (Q73):
  # each, alone in :core-ffi's build file, is one KtSdk hit, and so is the data directory's
  # property alone in gradle.properties.
  for case in 'ios-arm64-target:iosArm64()' 'ios-simulator-arm64-target:iosSimulatorArm64()' \
    'ios-arm64-block:iosArm64 {' 'ios-simulator-arm64-block:iosSimulatorArm64 {' \
    'ios-main-dependencies:iosMain.dependencies {' 'ios-test-dependencies:iosTest.dependencies {' \
    'cinterop-block:compilations.getByName("main").cinterops.create("keepcrypt") {' \
    'cinterop-include:compilerOpts("-I$rootDir/../../ffi/capi/include")' \
    'framework:binaries.framework {' 'framework-static:isStatic = true' \
    'test-linker-opts-device:binaries.getTest("DEBUG").linkerOpts("$rootDir/../../target/ios-test/aarch64-apple-ios/release/libkeepcrypt_capi.a")' \
    'test-linker-opts-simulator:binaries.getTest("DEBUG").linkerOpts("$rootDir/../../target/ios-test/aarch64-apple-ios-sim/release/libkeepcrypt_capi.a")' \
    'simulator-device:testRuns["test"].deviceId = "iPhone 16 Pro"' 'os-version-min:binaryOption("osVersionMin", "17.0")'; do
    fresh
    mkdir -p "$d/mobile/android/core-ffi" || exit 2
    printf '    %s\n' "${case#*:}" >"$d/mobile/android/core-ffi/build.gradle.kts" || exit 2
    expect "ktsdk-kmp-8q-line-${case%%:*}" "$d" KtSdk mobile/android/core-ffi/build.gradle.kts
  done
  fresh
  echo 'konan.data.dir=.konan' >"$d/mobile/android/gradle.properties" || exit 2
  expect 'ktsdk-kmp-8q-line-konan-data-dir' "$d" KtSdk mobile/android/gradle.properties
  # The Build rule reads git's index, so its cases are scratch repositories made here (a fixture
  # directory is none): a tracked file under mobile/**/build/, mobile/**/.gradle/ or
  # mobile/**/.konan/ (Kotlin/Native's data directory, M5-28) is a hit (git
  # add -f, so a global excludes file cannot keep it out), also under a name that plain ls-files
  # would print quoted (a non-ASCII byte, written in octal to keep this file ASCII, and a double
  # quote); the same file untracked is not; a submodule (a gitlink entry written with
  # update-index, whose commit need not exist) is a hit at a build/ path and anywhere else under
  # mobile/; and Gradle's build.gradle.kts files, buildSrc/ and gradle/ are not output
  # directories. The fixture trees above are no repositories at all, which is the rule's silence
  # outside a work tree. The presence check below needs Build recorded here, as no fixture
  # directory does it.
  for case in 'app-build:mobile/android/app/build/x.kt' 'dot-gradle:mobile/android/.gradle/config.properties' \
    'mobile-build:mobile/build/x.txt' "non-ascii-name:mobile/android/app/build/$(printf '\303\251').kt" \
    'double-quote-name:mobile/android/app/build/a"b.kt' \
    'dot-konan:mobile/android/.konan/dependencies/llvm-21-aarch64-macos-essentials-97/bin/clang'; do
    x=${case#*:}
    fresh
    git init -q "$d" || exit 2
    mkdir -p "$d/${x%/*}" && echo 'kc.gate.canary=true' >"$d/$x" || exit 2
    git -C "$d" add -f -- "$x" || exit 2
    expect "build-tracked-${case%%:*}" "$d" Build "$x"
  done
  seen="$seen Build"
  for case in 'submodule-at-build:mobile/android/app/build' 'submodule-elsewhere:mobile/android/vendor'; do
    x=${case#*:}
    fresh
    git init -q "$d" || exit 2
    git -C "$d" update-index --add --cacheinfo "160000,0123456789abcdef0123456789abcdef01234567,$x" || exit 2
    expect "build-tracked-${case%%:*}" "$d" Build "$x"
  done
  fresh
  git init -q "$d" || exit 2
  mkdir -p "$d/mobile/android/app/build" && echo 'kc.gate.canary=true' >"$d/mobile/android/app/build/x.kt" || exit 2
  expect 'clean-build-untracked' "$d" clean
  # The scan's skip of a local build's ignored output (M5-62 (a), gradle_out): in a git work tree, a
  # file that KtLog would hit, under mobile/android/.gradle/, mobile/android/build/ or a module's
  # build/, is the Build hit alone when tracked (the rule still sees it, and the scan did not read
  # it) and clean when untracked (not read), in each of the five modules; the same file under
  # another first-level directory's build/ (gradle/'s, expected/'s), a build/ deeper down or a
  # module's .gradle/ is read, and so is a tracked regular file named like one of those directories
  # (the Build rule's own match needs a / after the name); a link named build to a directory is
  # refused. Outside a work tree (no index, so no Build rule) the file under each of the three kinds
  # is read, so only those directories are skipped, and only where git's index holds what is tracked.
  for case in 'dot-gradle:mobile/android/.gradle/9.7.1/x.kt' 'root-build:mobile/android/build/x.kt' \
    'module-build:mobile/android/capture-control/build/x.kt'; do
    x=${case#*:}
    for tracked in yes no; do
      fresh
      git init -q "$d" || exit 2
      mkdir -p "$d/${x%/*}" && echo 'android.util.Log.d("kc", "gate canary")' >"$d/$x" || exit 2
      if [ "$tracked" = yes ]; then
        git -C "$d" add -f -- "$x" || exit 2
        expect "build-tracked-unread-${case%%:*}" "$d" Build "$x"
      else
        expect "clean-build-untracked-unread-${case%%:*}" "$d" clean
      fi
    done
    fresh
    mkdir -p "$d/${x%/*}" && echo 'android.util.Log.d("kc", "gate canary")' >"$d/$x" || exit 2
    expect "ktlog-build-skip-reads-${case%%:*}-outside-a-work-tree" "$d" KtLog "$x"
  done
  for m in app core-ffi screens secure-ui; do
    fresh
    git init -q "$d" || exit 2
    mkdir -p "$d/mobile/android/$m/build" && echo 'android.util.Log.d("kc", "gate canary")' >"$d/mobile/android/$m/build/x.kt" || exit 2
    expect "clean-build-untracked-unread-$m-build" "$d" clean
  done
  for case in 'deeper-build:mobile/android/app/src/main/kotlin/build/x.kt' 'module-dot-gradle:mobile/android/app/.gradle/x.kt' \
    'gradle-dir-build:mobile/android/gradle/build/x.kt' 'expected-dir-build:mobile/android/expected/build/x.kt'; do
    x=${case#*:}
    fresh
    git init -q "$d" || exit 2
    mkdir -p "$d/${x%/*}" && echo 'android.util.Log.d("kc", "gate canary")' >"$d/$x" || exit 2
    expect "ktlog-build-skip-reads-${case%%:*}" "$d" KtLog "$x"
  done
  for case in 'module-build-file:mobile/android/app/build' 'root-build-file:mobile/android/build' \
    'dot-gradle-file:mobile/android/.gradle'; do
    x=${case#*:}
    fresh
    git init -q "$d" || exit 2
    mkdir -p "$d/${x%/*}" && echo 'android.util.Log.d("kc", "gate canary")' >"$d/$x" || exit 2
    git -C "$d" add -f -- "$x" || exit 2
    expect "ktlog-build-skip-reads-tracked-${case%%:*}" "$d" KtLog "$x"
  done
  fresh
  git init -q "$d" || exit 2
  mkdir -p "$d/mobile/android/app/src" && ln -s src "$d/mobile/android/app/build" || exit 2
  expect 'error-build-skip-link-named-build' "$d" error 'mobile/android/app/build is a symlink to a directory'
  fresh
  git init -q "$d" || exit 2
  mkdir -p "$d/mobile/android/app" "$d/mobile/android/buildSrc" "$d/mobile/android/gradle/wrapper" || exit 2
  for x in mobile/android/app/build.gradle.kts mobile/android/buildSrc/build.gradle.kts \
    mobile/android/gradle/libs.versions.toml mobile/android/gradle/wrapper/gradle-wrapper.properties; do
    echo 'plugins {}' >"$d/$x" || exit 2
  done
  git -C "$d" add -f -- mobile || exit 2
  expect 'clean-build-gradle-files-tracked' "$d" clean
  # KtBinary reads the index too, so its cases are scratch repositories as well: a tracked file
  # under mobile/ with each code or archive extension (one in upper case, some outside
  # mobile/android, one a symlink) or under a *.framework or *.xcframework directory is a hit, and
  # so is a Mach-O, ELF, ar, zip, dex, keystore or compressed file by its magic whatever its name
  # (each magic below once, some named as an image); the same file untracked, a tracked image (a
  # real PNG's magic among them) and font, and a tracked jar outside mobile/ (which the scan skips
  # by extension) are not.
  for case in 'jar:mobile/android/app/libs/x.jar' 'aar:mobile/android/app/libs/x.aar' \
    'so:mobile/android/app/src/main/jniLibs/x86_64/libx.so' 'dex:mobile/android/app/classes.dex' \
    'class:mobile/android/core-ffi/Native.class' 'apk:mobile/android/app/app-shipping-release.apk' \
    'aab:mobile/android/app/app.aab' 'jks:mobile/android/release.jks' 'keystore:mobile/android/debug.keystore' \
    'upper-case-jar:mobile/android/app/libs/X.JAR' 'shared-so:mobile/shared/libx.so' \
    'zip:mobile/android/app/libs/evil.zip' 'gz:mobile/android/app/libs/x.tar.gz' 'xz:mobile/android/app/libs/x.xz' \
    'bz2:mobile/android/app/libs/x.bz2' 'zst:mobile/android/app/libs/x.zst' 'tar:mobile/android/app/libs/x.tar' \
    'ipa:mobile/shared/KeepCrypt.ipa' 'dylib:mobile/shared/libkc.dylib' 'a:mobile/android/app/libs/libkc.a' \
    'rlib:mobile/android/app/libs/libkc.rlib' 'o:mobile/android/app/libs/kc.o' 'car:mobile/shared/Assets.car' \
    'klib:mobile/android/core-ffi/libs/keepcrypt.klib' 'upper-case-klib:mobile/android/screens/libs/X.KLIB' \
    'framework:mobile/android/screens/Screens.framework/Info.plist' \
    'xcframework:mobile/shared/KeepCrypt.xcframework/ios-arm64/Info.plist'; do
    x=${case#*:}
    fresh
    git init -q "$d" || exit 2
    mkdir -p "$d/${x%/*}" && echo 'kc.gate.canary=true' >"$d/$x" || exit 2
    git -C "$d" add -f -- "$x" || exit 2
    expect "ktbinary-tracked-${case%%:*}" "$d" KtBinary "$x"
  done
  fresh
  git init -q "$d" || exit 2
  mkdir -p "$d/mobile/android/app/libs" && ln -s ../../../../core/x.jar "$d/mobile/android/app/libs/x.jar" || exit 2
  git -C "$d" add -f -- mobile || exit 2
  expect 'ktbinary-tracked-symlink' "$d" KtBinary mobile/android/app/libs/x.jar
  # The magic numbers in octal: Mach-O's cffaedfe (64-bit, little-endian), feedfacf (64-bit,
  # big-endian), cefaedfe (32-bit, little-endian), feedface (32-bit, big-endian), cafebabe and its
  # reverse bebafeca (fat), and cafebabf and its reverse bfbafeca (fat, 64-bit); ELF's 7f454c46; an
  # ar archive's !<arch> (a static library or an rlib); a zip archive's PK\003\004 (a klib, jar,
  # aar or apk); a dex file's dex\n035\0; a JKS keystore's feedfeed and a JCEKS one's cececece;
  # and the gzip (1f8b08), xz (fd377a58), zstd (28b52ffd) and bzip2 (BZh9) streams' first bytes.
  for case in 'macho-64-no-extension:\317\372\355\376:mobile/android/app/libs/libkc' \
    'macho-64-big-endian-as-text:\376\355\372\317:mobile/android/core-ffi/notes.txt' \
    'macho-32-outside-android:\316\372\355\376:mobile/shared/kc' \
    'macho-32-big-endian:\376\355\372\316:mobile/android/app/libs/kc32' \
    'macho-fat-as-png:\312\376\272\276:mobile/android/app/src/main/res/drawable/icon.png' \
    'macho-fat-reversed:\276\272\376\312:mobile/android/app/libs/kc-fat' \
    'macho-fat-64:\312\376\272\277:mobile/android/app/libs/kc-fat64' \
    'macho-fat-64-reversed:\277\272\376\312:mobile/shared/kc-fat64' \
    'elf-as-png:\177ELF:mobile/android/app/src/main/res/drawable/libkeepcrypt.png' \
    'ar-as-png:!<arch>\n:mobile/android/app/src/main/res/drawable/libkc-static.png' \
    'zip-as-png:PK\003\004:mobile/android/app/src/main/res/drawable/keepcrypt-klib.png' \
    'dex-as-png:dex\n035\000:mobile/android/app/src/main/res/drawable/classes.png' \
    'jks-as-png:\376\355\376\355:mobile/android/app/src/main/res/drawable/release-key.png' \
    'jceks-as-png:\316\316\316\316:mobile/android/app/src/main/res/drawable/upload-key.png' \
    'gz-as-png:\037\213\010:mobile/android/app/src/main/res/drawable/pack.png' \
    'xz-as-png:\3757zXZ\000:mobile/android/app/src/main/assets/pack.png' \
    'zstd-as-png:(\265/\375:mobile/android/app/src/main/res/raw/pack.png' \
    'bzip2-as-png:BZh9:mobile/android/app/src/main/res/drawable/pack-bz2.png'; do
    x=${case##*:}
    m=${case#*:}
    m=${m%%:*}
    fresh
    git init -q "$d" || exit 2
    mkdir -p "$d/${x%/*}" && printf "${m}kc.gate.canary\\n" >"$d/$x" || exit 2
    git -C "$d" add -f -- "$x" || exit 2
    expect "ktbinary-tracked-${case%%:*}" "$d" KtBinary "$x"
  done
  seen="$seen KtBinary"
  fresh
  git init -q "$d" || exit 2
  mkdir -p "$d/mobile/android/app/libs" "$d/mobile/android/app/src/main/res/drawable" \
    "$d/mobile/android/app/src/main/res/font" "$d/tools" || exit 2
  echo 'kc.gate.canary=true' >"$d/mobile/android/app/libs/x.jar" || exit 2
  echo 'kc.gate.canary=true' >"$d/mobile/android/app/src/main/res/drawable/icon.png" || exit 2
  printf '\211PNG\r\n\032\n' >"$d/mobile/android/app/src/main/res/drawable/seal.png" || exit 2
  echo 'kc.gate.canary=true' >"$d/mobile/android/app/src/main/res/font/braille.ttf" || exit 2
  echo 'kc.gate.canary=true' >"$d/tools/x.jar" || exit 2
  git -C "$d" add -f -- mobile/android/app/src tools || exit 2
  expect 'clean-ktbinary-untracked-image-outside-mobile' "$d" clean
  # KtRoot's mobile/ios rule reads the index too (lead decision M5-25): any tracked file under
  # mobile/ios/ is a hit, a Swift file, a plist and an Xcode project alike; the same file untracked
  # is not.
  for case in 'ios-swift:mobile/ios/KeepCrypt/SecureHostViewController.swift' \
    'ios-plist:mobile/ios/KeepCrypt/Info.plist' 'ios-xcode-project:mobile/ios/KeepCrypt.xcodeproj/project.pbxproj'; do
    x=${case#*:}
    fresh
    git init -q "$d" || exit 2
    mkdir -p "$d/${x%/*}" && echo 'kc.gate.canary=true' >"$d/$x" || exit 2
    git -C "$d" add -f -- "$x" || exit 2
    expect "ktroot-tracked-${case%%:*}" "$d" KtRoot "$x"
  done
  fresh
  git init -q "$d" || exit 2
  mkdir -p "$d/mobile/ios/KeepCrypt" && echo 'kc.gate.canary=true' >"$d/mobile/ios/KeepCrypt/App.swift" || exit 2
  expect 'clean-ktroot-untracked-under-mobile-ios' "$d" clean
  # The FFI cases that need keepcrypt-guard beside the JNI boundary (a fixture holds one file): with
  # the one catch in fn guarded in ffi/guard/src/lib.rs, an extern "C" fn or an extern fn with no
  # ABI string in ffi/jni/src/lib.rs is a hit of its own (JNI's ABI is "system"), and a guard file
  # without the catch leaves the boundary's export with none.
  guard='pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    match std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, &input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}'
  for case in 'jni-extern-c:pub extern "C" fn Java_com_keepcrypt_entropy_ffi_Native_call() -> u8 {' \
    'jni-extern-no-abi:pub extern fn JNI_OnLoad() -> i32 {'; do
    fresh
    mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
    printf '%s\n' "$guard" >"$d/ffi/guard/src/lib.rs" || exit 2
    printf '%s\n' '#[unsafe(no_mangle)]' "${case#*:}" '    keepcrypt_guard::guarded(0, Vec::new())[0]' '}' >"$d/ffi/jni/src/lib.rs" || exit 2
    expect "ffi-${case%%:*}-beside-the-guard" "$d" FFI ffi/jni/src/lib.rs
  done
  # The ABI is read as the compiler reads the signature (ffi_jni_abi), not line by line: an
  # extern "C" or a bare extern on one line and its fn on the next, or a comment between extern and
  # its ABI string, is a hit at the extern's line (a line-based check passed all three); the same
  # splits with "system", and extern "C" fn named in a comment or a string, are clean.
  for case in 'jni-extern-c-split-over-lines:pub extern "C":fn Java_com_keepcrypt_entropy_ffi_Native_call() -> u8 {' \
    'jni-extern-no-abi-split-over-lines:pub extern:fn Java_com_keepcrypt_entropy_ffi_Native_call() -> u8 {' \
    'jni-extern-c-after-a-comment:pub extern /* the VM calls it */ "C" fn Java_com_keepcrypt_entropy_ffi_Native_call():    -> u8 {'; do
    abi=${case#*:}
    fresh
    mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
    printf '%s\n' "$guard" >"$d/ffi/guard/src/lib.rs" || exit 2
    printf '%s\n' '#[unsafe(no_mangle)]' "${abi%%:*}" "${abi#*:}" '    keepcrypt_guard::guarded(0, Vec::new())[0]' '}' \
      >"$d/ffi/jni/src/lib.rs" || exit 2
    atline=2
    expect "ffi-${case%%:*}-beside-the-guard" "$d" FFI ffi/jni/src/lib.rs
    atline=
  done
  # A bare extern fn after an extern "system" one is a hit at its extern's line, on one line or
  # split over two, in the real lib.rs's order (JNI_OnLoad first): the first's ABI string does not
  # carry over, as each extern is settled by its own next token (a gate whose bare-extern branch
  # read the last string seen gave these trees no hit, and every other case passed).
  for split in no yes; do
    if [ "$split" = yes ]; then
      bare=$(printf '%s\n' 'pub extern' 'fn Java_com_keepcrypt_entropy_ffi_Native_call() -> u8 {')
      name=jni-extern-no-abi-split-over-lines-after-a-system-one
    else
      bare='pub extern fn Java_com_keepcrypt_entropy_ffi_Native_call() -> u8 {'
      name=jni-extern-no-abi-after-a-system-one
    fi
    fresh
    mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
    printf '%s\n' "$guard" >"$d/ffi/guard/src/lib.rs" || exit 2
    printf '%s\n' '#[unsafe(no_mangle)]' 'pub extern "system" fn JNI_OnLoad() -> i32 {' '    JNI_VERSION_1_6' '}' \
      '#[unsafe(no_mangle)]' "$bare" '    keepcrypt_guard::guarded(0, Vec::new())[0]' '}' >"$d/ffi/jni/src/lib.rs" || exit 2
    atline=6
    expect "ffi-$name-beside-the-guard" "$d" FFI ffi/jni/src/lib.rs
    atline=
  done
  fresh
  mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
  printf '%s\n' "$guard" >"$d/ffi/guard/src/lib.rs" || exit 2
  printf '%s\n' '#[unsafe(no_mangle)]' 'pub unsafe extern' '    "system"' '    fn Java_com_keepcrypt_entropy_ffi_Native_call() -> u8 {' \
    '    let note = "not extern \"C\" fn"; // nor an extern "C" fn' '    keepcrypt_guard::guarded(0, Vec::new())[0]' '}' \
    '#[unsafe(no_mangle)]' 'pub extern /* JNI'"'"'s ABI */ "system" fn JNI_OnLoad() -> i32 {' '    JNI_VERSION_1_6' '}' \
    >"$d/ffi/jni/src/lib.rs" || exit 2
  expect 'clean-ffi-jni-extern-system-split-over-lines' "$d" clean
  fresh
  mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
  printf '%s\n' 'pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {' '    let input = Zeroizing::new(input);' \
    '    keepcrypt_ffi::dispatch(op, &input)' '}' \
    >"$d/ffi/guard/src/lib.rs" || exit 2
  printf '%s\n' '#[unsafe(no_mangle)]' 'pub extern "system" fn Java_com_keepcrypt_entropy_ffi_Native_call(op: jint) -> u8 {' \
    '    keepcrypt_guard::guarded(op as u32, Vec::new())[0]' '}' >"$d/ffi/jni/src/lib.rs" || exit 2
  expect 'ffi-jni-export-beside-a-guard-without-catch-unwind' "$d" FFI ffi/jni/src/lib.rs
  # A fn guarded in a mod is not the crate root's, which every export calls: its catch is a hit of
  # its own, and the export beside it still finds no catch in the crate root's guarded.
  fresh
  mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
  printf '%s\n' 'pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {' '    let input = Zeroizing::new(input);' \
    '    keepcrypt_ffi::dispatch(op, &input)' '}' \
    'mod probe {' '    fn guarded() -> bool {' '        std::panic::catch_unwind(|| ()).is_ok()' '    }' '}' \
    >"$d/ffi/guard/src/lib.rs" || exit 2
  printf '%s\n' '#[unsafe(no_mangle)]' 'pub extern "system" fn Java_com_keepcrypt_entropy_ffi_Native_call(op: jint) -> u8 {' \
    '    keepcrypt_guard::guarded(op as u32, Vec::new())[0]' '}' >"$d/ffi/jni/src/lib.rs" || exit 2
  also='FFI: ffi/guard/src/lib.rs:7:         std::panic::catch_unwind(|| ()).is_ok()'
  expect 'ffi-jni-export-beside-a-guard-whose-catch-is-in-a-mod' "$d" FFI ffi/jni/src/lib.rs
  also=
  # The tie between each export and the catch (ffi_export_scan): beside that guard, an export in
  # ffi/jni/src/lib.rs whose own body does not call keepcrypt_guard::guarded( is a hit at its fn
  # line, at the line the case names: one that calls the safe layer directly, the second of two
  # exports when the first calls guarded, one that calls it through a use line or through a helper,
  # one that names it only in a comment and a string, one that calls a local mod keepcrypt_guard
  # through crate::, an export_name function and an extern "system" fn bound by RegisterNatives; a
  # no_mangle static, with no body, at its attribute line, alone or before an export that calls
  # guarded. A fn named JNI_OnLoad that is not the real one is held to the tie: exported as the
  # Java_ symbol (by export_name alone, or on Android through cfg_attr beside a no_mangle), in a mod
  # (bare, with no_mangle, or exported as the Java_ symbol beside the real one) or with no
  # no_mangle, which RegisterNatives could bind. macro_rules is a hit at its line, as an export a
  # macro writes is out of the scan's sight. Exports that each call it (in a block, with an array
  # in the signature), the crate root's no_mangle JNI_OnLoad and a helper that does not are clean.
  call='pub extern "system" fn Java_com_keepcrypt_entropy_ffi_Native_call(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {'
  direct='    to_java(env, keepcrypt_ffi::dispatch(op as u32, &from_java(env, input)))'
  for case in safe-layer-directly:2 second-export:6 imported-guarded:3 guarded-in-a-helper:2 \
    guarded-in-a-comment-and-a-string:2 guarded-of-a-local-mod:7 export-name:2 registered-native:1 \
    no-mangle-static:1 no-mangle-static-before-an-export:1 onload-exported-as-java:2 \
    onload-exported-as-java-on-android:3 onload-in-a-mod:2 onload-no-mangle-in-a-mod:3 \
    onload-in-a-mod-as-java-with-the-real-one:3 onload-without-no-mangle:1 macro-written-exports:1; do
    case ${case%%:*} in
      safe-layer-directly) jni=$(printf '%s\n' '#[unsafe(no_mangle)]' "$call" "$direct" '}') ;;
      second-export)
        jni=$(printf '%s\n' '#[unsafe(no_mangle)]' "$call" \
          '    to_java(env, keepcrypt_guard::guarded(op as u32, from_java(env, input)))' '}' '#[unsafe(no_mangle)]' \
          'pub extern "system" fn Java_com_keepcrypt_entropy_ffi_Native_wipe(env: *mut JNIEnv) -> jbyteArray {' \
          '    to_java(env, keepcrypt_ffi::dispatch(OP_WIPE, &[]))' '}')
        ;;
      imported-guarded)
        jni=$(printf '%s\n' 'use keepcrypt_guard::guarded;' '#[unsafe(no_mangle)]' "$call" \
          '    to_java(env, guarded(op as u32, from_java(env, input)))' '}')
        ;;
      guarded-in-a-helper)
        jni=$(printf '%s\n' '#[unsafe(no_mangle)]' "$call" '    to_java(env, run(op, from_java(env, input)))' '}' \
          'fn run(op: jint, input: Vec<u8>) -> Zeroizing<Vec<u8>> {' '    keepcrypt_guard::guarded(op as u32, input)' '}')
        ;;
      guarded-in-a-comment-and-a-string)
        jni=$(printf '%s\n' '#[unsafe(no_mangle)]' "$call" '    // keepcrypt_guard::guarded(op as u32, input) comes later.' \
          '    let note = "keepcrypt_guard::guarded(";' "$direct" '}')
        ;;
      export-name)
        jni=$(printf '%s\n' '#[unsafe(export_name = "Java_com_keepcrypt_entropy_ffi_Native_call")]' \
          'pub fn call(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {' "$direct" '}')
        ;;
      registered-native)
        jni=$(printf '%s\n' 'pub extern "system" fn native_call(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {' \
          "$direct" '}')
        ;;
      guarded-of-a-local-mod)
        jni=$(printf '%s\n' 'mod keepcrypt_guard {' '    pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {' \
          '        keepcrypt_ffi::dispatch(op, &input)' '    }' '}' '#[unsafe(no_mangle)]' "$call" \
          '    to_java(env, crate::keepcrypt_guard::guarded(op as u32, from_java(env, input)))' '}')
        ;;
      no-mangle-static) jni=$(printf '%s\n' '#[unsafe(no_mangle)]' 'pub static KC_ABI_VERSION: u32 = 1;') ;;
      no-mangle-static-before-an-export)
        jni=$(printf '%s\n' '#[unsafe(no_mangle)]' 'pub static KC_ABI_VERSION: u32 = 1;' '#[unsafe(no_mangle)]' "$call" \
          '    to_java(env, keepcrypt_guard::guarded(op as u32, from_java(env, input)))' '}')
        ;;
      onload-exported-as-java)
        jni=$(printf '%s\n' '#[unsafe(export_name = "Java_com_keepcrypt_entropy_ffi_Native_call")]' \
          'pub extern "system" fn JNI_OnLoad(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {' "$direct" '}')
        ;;
      onload-exported-as-java-on-android)
        jni=$(printf '%s\n' '#[cfg_attr(target_os = "android", unsafe(export_name = "Java_com_keepcrypt_entropy_ffi_Native_call"))]' \
          '#[cfg_attr(not(target_os = "android"), unsafe(no_mangle))]' \
          'pub extern "system" fn JNI_OnLoad(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {' "$direct" '}')
        ;;
      onload-in-a-mod)
        jni=$(printf '%s\n' 'mod natives {' \
          '    pub extern "system" fn JNI_OnLoad(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {' \
          "    $direct" '    }' '}')
        ;;
      onload-no-mangle-in-a-mod)
        jni=$(printf '%s\n' 'mod natives {' '    #[unsafe(no_mangle)]' \
          '    pub extern "system" fn JNI_OnLoad(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {' \
          "    $direct" '    }' '}')
        ;;
      onload-in-a-mod-as-java-with-the-real-one)
        jni=$(printf '%s\n' 'mod m {' '    #[unsafe(export_name = "Java_com_keepcrypt_entropy_ffi_Native_call")]' \
          '    pub extern "system" fn JNI_OnLoad(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {' \
          "    $direct" '    }' '}' '#[unsafe(no_mangle)]' \
          'pub unsafe extern "system" fn JNI_OnLoad(vm: *mut JavaVM, reserved: *mut c_void) -> jint {' '    JNI_VERSION_1_6' '}')
        ;;
      onload-without-no-mangle)
        jni=$(printf '%s\n' 'pub extern "system" fn JNI_OnLoad(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {' \
          "$direct" '}')
        ;;
      macro-written-exports)
        jni=$(printf '%s\n' 'macro_rules! export {' '    ($n:ident, $body:block) => {' '        #[unsafe(no_mangle)]' \
          '        pub extern "system" fn $n(env: *mut JNIEnv) -> u8 $body' '    }' '}' \
          'export! { Java_com_keepcrypt_entropy_ffi_Native_call, { keepcrypt_guard::guarded(0, Vec::new())[0] } }' \
          'export!(Java_com_keepcrypt_entropy_ffi_Native_wipe, { keepcrypt_ffi::dispatch(OP_WIPE, &[])[0] });')
        ;;
    esac
    fresh
    mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
    printf '%s\n' "$guard" >"$d/ffi/guard/src/lib.rs" || exit 2
    printf '%s\n' "$jni" >"$d/ffi/jni/src/lib.rs" || exit 2
    atline=${case#*:}
    expect "ffi-jni-${case%%:*}-beside-the-guard" "$d" FFI ffi/jni/src/lib.rs
    atline=
  done
  fresh
  mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
  printf '%s\n' "$guard" >"$d/ffi/guard/src/lib.rs" || exit 2
  printf '%s\n' '#[unsafe(no_mangle)]' "$call" '    let input = from_java(env, input);' \
    '    to_java(env, keepcrypt_guard::guarded(op as u32, input))' '}' '#[unsafe(no_mangle)]' \
    'pub extern "system" fn Java_com_keepcrypt_entropy_ffi_Native_probe(env: *mut JNIEnv, tag: [u8; 4]) -> jbyteArray {' \
    '    let out = { keepcrypt_guard::guarded(OP_PROBE, tag.to_vec()) };' '    to_java(env, out)' '}' '#[unsafe(no_mangle)]' \
    'pub unsafe extern "system" fn JNI_OnLoad(vm: *mut JavaVM, reserved: *mut c_void) -> jint {' '    JNI_VERSION_1_6' '}' \
    'fn from_java(env: *mut JNIEnv, input: jbyteArray) -> Vec<u8> {' '    read_capped(env, input, MAX_IN)' '}' \
    >"$d/ffi/jni/src/lib.rs" || exit 2
  expect 'clean-ffi-jni-exports-each-calling-guarded' "$d" clean
  # A macro in another of keepcrypt-jni's files (lead decision M5-35): beside that guard and lib.rs's
  # export that calls guarded, an extern fn the macro writes with the ABI it takes as $abi, or with
  # the extern and ABI a call passes as tokens, is bound by RegisterNatives in JNI_OnLoad and would
  # run outside the catch. The definition's line is a hit (ffi_macros), and so is the extern that $
  # follows there (ffi_export) or the extern that ) follows in lib.rs's call (ffi_export_scan).
  onload=$(printf '%s\n' '#[unsafe(no_mangle)]' \
    'pub unsafe extern "system" fn JNI_OnLoad(vm: *mut JavaVM, reserved: *mut c_void) -> jint {' \
    '    register(vm, &JNINativeMethod { name: NAME, signature: SIG, fnPtr: native_raw as *mut c_void });' \
    '    JNI_VERSION_1_6' '}')
  for mcase in abi-literal:glue.rs:1:3 abi-tokens:lib.rs:3:1; do
    case ${mcase%%:*} in
      abi-literal)
        glue=$(printf '%s\n' 'macro_rules! boundary {' '    ($abi:literal, $name:ident) => {' \
          '        pub extern $abi fn $name(env: *mut JNIEnv, op: jint) -> jbyte {' \
          '            keepcrypt_ffi::dispatch(op as u32, &[])[0]' '        }' '    };' '}')
        mcall='boundary!("system", native_raw);'
        ;;
      abi-tokens)
        glue=$(printf '%s\n' 'macro_rules! boundary {' '    ($($abi:tt)*) => {' \
          '        $($abi)* fn native_raw(env: *mut JNIEnv, op: jint) -> jbyte {' \
          '            keepcrypt_ffi::dispatch(op as u32, &[])[0]' '        }' '    };' '}')
        mcall='boundary!(pub extern "system");'
        ;;
    esac
    fresh
    mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
    printf '%s\n' "$guard" >"$d/ffi/guard/src/lib.rs" || exit 2
    printf '%s\n' "$glue" >"$d/ffi/jni/src/glue.rs" || exit 2
    printf '%s\n' '#[macro_use]' 'mod glue;' "$mcall" '#[unsafe(no_mangle)]' "$call" \
      '    to_java(env, keepcrypt_guard::guarded(op as u32, from_java(env, input)))' '}' "$onload" \
      >"$d/ffi/jni/src/lib.rs" || exit 2
    mat=${mcase#*:}
    mfile=ffi/jni/src/${mat%%:*}
    mat=${mat#*:}
    atline=${mat%%:*}
    malso=${mat#*:}
    case $mfile in */lib.rs) afile=ffi/jni/src/glue.rs ;; *) afile=$mfile ;; esac
    also="FFI: $afile:$malso: $(sed -n "${malso}p" "$d/$afile")"
    expect "ffi-jni-macro-in-another-file-${mcase%%:*}-registered-native" "$d" FFI "$mfile"
    also=
    atline=
  done
  # The alias crossing crates: a guard that re-exports catch_unwind under another name is a hit at
  # that line although the boundary beside it, whose export calls guarded, names no catch_unwind
  # when it catches and continues through the alias. The line is a pub in ffi/guard/src too
  # (ffi_guard_pub), so it is reported twice.
  fresh
  mkdir -p "$d/ffi/guard/src" "$d/ffi/jni/src" || exit 2
  printf '%s\n' 'pub use std::panic::catch_unwind as recover;' "$guard" >"$d/ffi/guard/src/lib.rs" || exit 2
  printf '%s\n' '#[unsafe(no_mangle)]' "$call" \
    '    match keepcrypt_guard::recover(|| keepcrypt_guard::guarded(op as u32, from_java(env, input))) {' \
    '        Ok(out) => to_java(env, out),' '        Err(payload) => empty(env, payload),' '    }' '}' \
    >"$d/ffi/jni/src/lib.rs" || exit 2
  atline=1
  also='FFI: ffi/guard/src/lib.rs:1: pub use std::panic::catch_unwind as recover;'
  expect 'ffi-catch-unwind-reexport-beside-a-jni-export' "$d" FFI ffi/guard/src/lib.rs
  also=
  atline=
  # A catch_unwind in a macro_rules definition in ffi/guard/src/lib.rs is a hit at its line, the
  # definition beside fn guarded or inside it, with its body in braces or in parentheses: the one
  # catch is the path call written in guarded's own body. The definition's line is a hit too
  # (ffi_macros, lead decision M5-35), so these trees are built here, each with that second line.
  for gcase in in-guard-macro:1:3 in-guard-macro-inside-guarded:4:6 in-guard-paren-macro-inside-guarded:3:4; do
    case ${gcase%%:*} in
      in-guard-macro)
        g=$(printf '%s\n' 'macro_rules! recover {' '    ($f:expr) => {' '        std::panic::catch_unwind($f)' '    };' '}' \
          'pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {' '    let input = Zeroizing::new(input);')
        ;;
      in-guard-macro-inside-guarded)
        g=$(printf '%s\n' '// A macro defined inside guarded would carry the catch out of it.' \
          'pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {' '    let input = Zeroizing::new(input);' \
          '    macro_rules! recover {' '        ($f:expr) => {' \
          '            std::panic::catch_unwind($f)' '        };' '    }')
        ;;
      in-guard-paren-macro-inside-guarded)
        g=$(printf '%s\n' 'pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {' '    let input = Zeroizing::new(input);' \
          '    macro_rules! recover (' \
          '        ($f:expr) => ( std::panic::catch_unwind($f) )' '    );')
        ;;
    esac
    g=$(printf '%s\n' "$g" '    match recover!(|| keepcrypt_ffi::dispatch(op, &input)) {' '        Ok(out) => out,' \
      '        Err(payload) => halt(payload),' '    }' '}')
    fresh
    mkdir -p "$d/ffi/guard/src" || exit 2
    printf '%s\n' "$g" >"$d/ffi/guard/src/lib.rs" || exit 2
    gm=${gcase#*:}
    also="FFI: ffi/guard/src/lib.rs:${gm%%:*}: $(sed -n "${gm%%:*}p" "$d/ffi/guard/src/lib.rs")"
    atline=${gm#*:}
    expect "ffi-catch-unwind-${gcase%%:*}" "$d" FFI ffi/guard/src/lib.rs
    also=
    atline=
  done
  for want in RNG Network Clipboard Rule1 FailOpen Include Shell Device Build KtLog KtFailOpen KtWindow KtInput KtStorage \
    KtIntent KtDevice KtSdk KtBinary KtManifest KtTestChannel KtSourceSet KtIos KtRoot KtCinterop FFI clean; do
    case "$seen " in *" $want "*) ;; *) fail=$((fail + 1)); echo "FAIL no $want fixture" ;; esac
  done
  # The shard option (M5-63): a shard past the last, a malformed value, a missing one, a further
  # argument and the option out of place are each exit 2 with their refusal. Each run's TMPDIR is
  # a file, so a gate that took one would stop at selftest's mktemp (exit 2, but without the
  # refusal) rather than run a selftest of its own.
  : >"$tmp/not-a-directory" || exit 2
  for case in 'past-the-last|--selftest --shard 3/2|3/2 names shard 3 of 2, past the last' \
    'two-of-one|--selftest --shard 2/1|2/1 names shard 2 of 1, past the last' \
    'no-slash|--selftest --shard 2|2 is not K/N' 'zero|--selftest --shard 0/2|0/2 is not K/N' \
    'leading-zero|--selftest --shard 1/02|1/02 is not K/N' 'letter|--selftest --shard a/2|a/2 is not K/N' \
    'three-numbers|--selftest --shard 1/2/2|1/2/2 is not K/N' 'slash-alone|--selftest --shard /|/ is not K/N' \
    'five-digits|--selftest --shard 1/10000|1/10000 is not K/N' 'no-value|--selftest --shard|usage:' \
    'further-argument|--selftest --shard 1/2 1/2|usage:' 'option-first|--shard 1/2 --selftest|usage:' \
    'equals-sign|--selftest --shard=1/2|usage:'; do
    mine || continue
    sname=selftest-shard-error-${case%%|*}
    rest=${case#*|}
    swant=${rest#*|}
    # The arguments, split on purpose.
    set -- ${rest%%|*}
    out=$(TMPDIR=$tmp/not-a-directory sh "$self" "$@" 2>&1)
    rc=$?
    ok=no
    if [ "$rc" -eq 2 ]; then
      case $out in *"$swant"*) ok=yes ;; esac
    fi
    if [ "$ok" = yes ]; then
      pass=$((pass + 1))
      printf 'PASS %s -> exit 2: %s\n' "$sname" "${out%%$nl*}"
    else
      fail=$((fail + 1))
      printf 'FAIL %s: wanted exit 2 with "%s", got exit %s:\n' "$sname" "$swant" "$rc"
      printf '%s\n' "$out" | sed 's/^/    /'
    fi
  done
  artifact_selftest
  workflows_selftest
  image_lists_selftest
  os_config_selftest
  image_selftest
  [ "$sharded" = no ] || echo "selftest: shard $shard_k/$shard_n: $((pass + fail)) of $ordinal cases"
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

# indented FILE: FILE's lines on stderr, each after four spaces (a tool's own error output), read
# in the shell, so an error path runs no tool of its own.
indented() {
  while IFS= read -r il || [ -n "$il" ]; do
    printf '    %s\n' "$il"
  done <"$1" >&2
}

# toolchain_bin: the bin/ of the pinned toolchain's llvm-tools-preview (rust-toolchain.toml), found
# through rustc run from the repo root, so rustup picks the pinned toolchain. The host is read from
# rustc -vV's "host: " line in the shell, so no pipeline hides rustc's status.
toolchain_bin() {
  on='the pinned toolchain'
  repo=$(cd "$here/.." && pwd -P) || exit 2
  sysroot=$(cd "$repo" && rustc --print sysroot) || {
    echo 'banned-api-check: rustc --print sysroot failed (is the pinned toolchain installed?)' >&2
    exit 2
  }
  vv=$(cd "$repo" && rustc -vV) || { echo 'banned-api-check: rustc -vV failed' >&2; exit 2; }
  vv=$nl$vv
  case $vv in
    *"${nl}host: "*)
      host=${vv#*"${nl}host: "}
      host=${host%%"$nl"*}
      ;;
    *) host= ;;
  esac
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
# suffixes ("getrandom@GLIBC_2.25"). llvm-nm failing on FILE is an error; sed and sort run one
# after the other, each with its status read.
symbols() {
  sf=$1
  sout=$2
  shift 2
  if ! "$bin/llvm-nm" -j "$@" "$sf" >"$atmp/nm" 2>"$atmp/nm-err"; then
    printf 'banned-api-check: llvm-nm cannot read %s:\n' "$sf" >&2
    indented "$atmp/nm-err"
    exit 2
  fi
  sed -e '/^$/d' -e '/:$/d' -e 's/@.*$//' "$atmp/nm" >"$atmp/nm-names" || exit 2
  sort -u "$atmp/nm-names" >"$sout" || exit 2
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
  # The crates' names as one alternation, and the key's bytes below, are built in the shell.
  alt=
  for c in $rng_crate_names; do alt=$alt${alt:+|}$c; done
  rng_crates="(^|[^A-Za-z0-9_])($alt)::"
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
  keybytes=
  kx=$testkey
  while [ -n "$kx" ]; do
    keybytes="$keybytes ${kx%"${kx#??}"}"
    kx=${kx#??}
  done
}

# hexbytes TEXT: TEXT's bytes as byte_scan lays a file's out, " 4b 43 ...", for a fixed-string
# search of its dump: printf gives each character's code (its argument after a quote), so no tool
# runs.
hexbytes() {
  hx=$1
  while [ -n "$hx" ]; do
    printf ' %02x' "'${hx%"${hx#?}"}"
    hx=${hx#?}
  done
}

# bytes_found HEX: true when $atmp/dump holds the bytes HEX lays out (as hexbytes does), false when
# not. grep's own failure stops the gate (tool_status) in every mode that runs this, whether or not
# the mode calls fail_closed.
bytes_found() {
  command grep -q -F -e "$1" "$atmp/dump"
  bf=$?
  [ "$bf" -le 1 ] || tool_status grep "$bf"
  return "$bf"
}

# byte_scan FILE NAME: FILE's bytes into $atmp/dump, then the Marker and TestKey rules on them,
# reported under NAME (the image scan names a file by its path inside the image). The dump is
# " xx xx ..." on one line: od -v writes every byte, then tr joins its lines and squeezes the
# spaces BSD and GNU od lay out differently, the two one after the other, each with its status
# read. Any byte value is two hex digits, so a fixed-string search for " 4b 43 ..." can only match
# whole bytes, in order.
byte_scan() {
  on=$2
  od -An -v -tx1 "$1" >"$atmp/od" || { printf 'banned-api-check: cannot read %s\n' "$2" >&2; exit 2; }
  tr -s ' \n' '  ' <"$atmp/od" >"$atmp/dump" || exit 2
  for m in $markers; do
    if bytes_found "$(hexbytes "$m")"; then
      ahit Marker "$2" "$m"
    fi
  done
  if bytes_found "$keybytes"; then
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
  on=$aname
  # The device files std's random-key fallback reads, as bytes in any file (the symbol half of
  # the StdRandom rule follows the symbol rules below).
  for path in /dev/urandom /dev/random; do
    if bytes_found "$(hexbytes "$path")"; then
      ahit StdRandom "$aname" "byte string $path"
    fi
  done
  # The first eight bytes as hex, joined in the shell.
  od8=$(od -An -N8 -tx1 "$f") || exit 2
  magic=
  for ob in $od8; do magic=$magic$ob; done
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
        "$bin/llvm-readobj" --section-headers "$f" >"$atmp/sections" 2>/dev/null || {
          printf 'banned-api-check: llvm-readobj cannot read %s\n' "$aname" >&2
          exit 2
        }
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
  # kept), is dropped. awk tells the files apart by name, so no pattern file is ever empty. The
  # hits left are $atmp/kept's, read in place.
  stdhits=$atmp/hits
  if [ -n "$std_passengers" ] && [ "$kind" = object ] && [ -s "$atmp/hits" ]; then
    if ! "$bin/llvm-nm" -C -P --defined-only "$f" >"$atmp/defined" 2>"$atmp/nm-err"; then
      printf 'banned-api-check: llvm-nm cannot read %s:\n' "$aname" >&2
      indented "$atmp/nm-err"
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
    stdhits=$atmp/kept
  fi
  from_list StdRandom "$aname" 'symbol ' "$stdhits"
  if [ "$kind" = archive ]; then
    archives=$((archives + 1))
  else
    linked=$((linked + 1))
    grep -q -x -F -e "$import" "$atmp/undefined" ||
      ahit OSImport "$aname" "no undefined $import, the OS import on $target"
  fi
  return 0
}

# artifact_cleanup: the artifact scan's temporary directory, removed by its EXIT trap: a function,
# as build_rule_cleanup is, so the rm is at its own line under every bash.
artifact_cleanup() {
  rm -rf "$atmp"
}

artifact() {
  fail_closed
  target=$1
  shift
  [ $# -ge 1 ] || { usage >&2; exit 2; }
  toolchain_bin
  on="the artifact scan's temporary directory"
  atmp=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-artifact.XXXXXX") || exit 2
  trap 'artifact_cleanup' EXIT
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
  # Each tool's output in a command substitution of its own (the uses: lines, then those but the
  # approved actions), as in the scan: see "The tools the gate runs fail closed".
  u=$(grep -n -a -E -e '^[[:space:]]*(- )?uses:' -- "$wf")
  [ $? -le 1 ] || return 2
  u=$(printf '%s\n' "$u" | grep -v -E -e "^[0-9]+:[[:space:]]*(- )?uses:[[:space:]]*($approved_actions)[[:space:]]*(#.*)?\$")
  [ $? -le 1 ] || return 2
  g=$(grep -n -a -E -e "${L}secrets$R" -e "${L}github[[:space:]]*[.[][[:space:]]*['\"]?token$R" \
    -e "${L}(pull_request_target|workflow_run)$R" -- "$wf")
  [ $? -le 1 ] || return 2
  b=$(kt_bootstrap "$wf")
  [ $? -le 1 ] || return 2
  b=$(kt_bootstrap_allowed "$wf") || return 2
  k=$(kt_canary_workflow "$wf")
  [ $? -le 1 ] || return 2
  r=$(kt_kmp_refused "$wf")
  [ $? -le 1 ] || return 2
  # The rules' hits joined in the shell, the empty ones left out, then sorted by line.
  all=
  for x in "$t" "$u" "$g" "$b" "$k" "$r"; do
    [ -z "$x" ] || all=$all${all:+$nl}$x
  done
  [ -n "$all" ] || return 1
  t=$(printf '%s\n' "$all" | sort -t : -k 1,1n -s) || return 2
  printf '%s\n' "$t"
}

workflows() {
  fail_closed
  dir=${1%/}
  [ -d "$dir" ] || { printf 'banned-api-check: --workflows: %s is not a directory\n' "$1" >&2; exit 2; }
  # The check's awk exits 1 for a list of another shape; any other failure tool_status has named.
  on='kt_bootstrap_exception'
  kt_bootstrap_exception_check
  case $? in
    0) ;;
    1)
      echo 'banned-api-check: --workflows: kt_bootstrap_exception holds a line that does not name entropy-android.yml (once) and, after one space, a workflow line' >&2
      exit 2
      ;;
    *) exit 2 ;;
  esac
  hits=0
  n=0
  for wf in "$dir"/entropy-*.yml "$dir"/entropy-*.yaml; do
    [ -e "$wf" ] || continue
    n=$((n + 1))
    on=$wf
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
  # The exception as this run holds it, whatever assigned it, so the line says what was granted: a
  # list with any character but a newline names a line.
  case $kt_bootstrap_exception in
    *[!"$nl"]*) bxstate="no bootstrap switch but the reviewed exception's line (kt_bootstrap_exception: $kt_bootstrap_exception)" ;;
    *) bxstate='no bootstrap switch and no bootstrap exception' ;;
  esac
  printf '%s\n' "banned-api-check --workflows $dir: clean, $n workflow(s): read-only permissions, pinned actions, no secrets, no fork-trusting trigger, no expression in a run step, $bxstate, the canary property only in the canary step's Gradle command, no Kotlin/Native or Kotlin Multiplatform setting"
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

# BusyBox (tasks/todo.md, M4 groups 11 and 13): "enables only init and mount" as an allow-list.
# busybox_required must be at =y: init reading /etc/inittab, mount reading /etc/fstab with the
# flags that give it nosuid, nodev and noexec, and no shell as sh or bash. busybox_allowed is every
# CONFIG_ symbol pi/os/board/pizero/busybox.config sets at =y: those seven and the build settings it
# keeps (its header names them), reviewed once with the file. Any other CONFIG_X=y line is a hit,
# so no applet, shell, login, network, module, power, swap or loop tool, seedrng or vi can be added
# without changing this list too.
busybox_required='INIT FEATURE_USE_INITTAB MOUNT FEATURE_MOUNT_FSTAB FEATURE_MOUNT_FLAGS SH_IS_NONE BASH_IS_NONE'
busybox_allowed="$busybox_required HAVE_DOT_CONFIG LONG_OPTS LFS TIME64 FEATURE_SYSLOG STATIC_LIBGCC
INSTALL_APPLET_SYMLINKS NO_DEBUG_LIB FEATURE_BUFFERS_USE_MALLOC MONOTONIC_SYSCALL TRY_LOOP_CONFIGURE"

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
# tmpfs line nosuid, nodev, noexec and a size=, no line carries rw, exec, suid, dev or remount
# (BusyBox's mount applies options in order, so a later rw, exec, suid or dev clears the flag
# before it: util-linux/mount.c's option table maps each to the flag's complement), and there is
# no line of another filesystem type (and at least one line; comments and blank lines are
# skipped).
fstab_check() {
  fout=$(awk '
    /^[[:space:]]*(#|$)/ { next }
    {
      n++
      opts = "," $4 ","
      split("rw exec suid dev remount", clears, " ")
      for (i = 1; i <= 5; i++) if (index(opts, "," clears[i] ",")) print NR ": " $3 " on " $2 " carries " clears[i] ", which clears the flag before it"
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

# cmdline_check FILE NAME: no console= or init= word, no double quote (the kernel's next_arg strips
# a word's quotes before it reads param=value, so "console=x" is console=x; the board file has
# none and needs none), and the words ro, panic=0 and init_on_free=1.
cmdline_check() {
  cout=$(awk '
    {
      if (index($0, "\"")) print NR ": a double quote (the kernel reads \"console=x\" as console=x)"
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

# config_txt_check FILE NAME: no enable_uart=1, dtoverlay, start_file, fixup_file, start_x=1,
# start_debug=1 or plain gpu_mem= line, and the gpu_mem_* lines exactly gpu_mem_256=100,
# gpu_mem_512=100 and gpu_mem_1024=100, each once (the default start.elf and fixup.dat pair boots
# them; start_x=1 selects start_x.elf and fixup_x.dat, start_debug=1 start_db.elf and
# fixup_db.dat, as start_file and a gpu_mem of 16 select other files; comments are skipped).
config_txt_check() {
  cout=$(awk '
    /^[[:space:]]*(#|$)/ { next }
    /^enable_uart=1[[:space:]]*$/ { print NR ": " $0 }
    /^dtoverlay/ { print NR ": " $0 }
    /^(start_file|fixup_file)/ { print NR ": " $0 }
    /^start_(x|debug)=1[[:space:]]*$/ { print NR ": " $0 " (selects other firmware files)" }
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

# busybox_check FILE NAME: every $busybox_required symbol at =y, and no CONFIG_X=y line whose
# symbol is outside $busybox_allowed.
busybox_check() {
  bout=$(awk -v req="$busybox_required" -v allow="$(printf '%s' "$busybox_allowed" | tr '\n' ' ')" '
    BEGIN {
      nr = split(req, r, " ")
      na = split(allow, a, " ")
      for (i = 1; i <= na; i++) allowed["CONFIG_" a[i]] = 1
    }
    /^CONFIG_[A-Za-z0-9_]+=y$/ {
      sym = $0
      sub(/=y$/, "", sym)
      have[sym] = 1
      if (!(sym in allowed)) print NR ": " $0 " (not a symbol the image sets: only init and mount build)"
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
  echo "banned-api-check --os-config $os: clean: Q35's inittab, the fstab's options, cmdline.txt and config.txt as the plan says, expected/linux.config with the fragment's required and forbidden lists (which expected/kconfig-required and kconfig-forbidden equal) and one hwrng driver, and BusyBox with init and mount and no other symbol set"
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
# only); DIR/rand-crate-stripped.so and DIR/fallback-stripped.so, stripped shared objects that
# define a symbol of the rand crate (rand::rngs::next_u32) and of getrandom's use_file fallback;
# DIR/static-stripped, a stripped static executable with no symbols at all. Exit 2 if one cannot
# be built.
build_elf_controls() {
  cdir=$1
  mkdir -p "$cdir" || exit 2
  csrc=$here/testdata/image/controls.rs
  [ -f "$csrc" ] || sifail "no $csrc"
  for c in getrandom:kc_getrandom sim:kc_sim rand:kc_rand rand-crate:kc_rand_crate fallback:kc_fallback static:kc_static; do
    if ! (cd "$repo" && rustc --edition 2024 --crate-type lib --crate-name kc_control --emit obj \
      -C panic=abort -C opt-level=1 --target arm-unknown-linux-gnueabihf --cfg "${c#*:}" \
      -o "$cdir/${c%%:*}.o" "$csrc") >"$cdir/rustc.log" 2>&1; then
      sed 's/^/    /' "$cdir/rustc.log" >&2
      sifail "rustc could not build the ${c%%:*} control"
    fi
  done
  for c in getrandom sim rand rand-crate fallback; do
    "$bin/rust-lld" -flavor gnu -shared -o "$cdir/$c.so" "$cdir/$c.o" >"$cdir/lld.log" 2>&1 ||
      { sed 's/^/    /' "$cdir/lld.log" >&2; sifail "rust-lld could not link the $c control"; }
  done
  "$bin/rust-lld" -flavor gnu -e _start -o "$cdir/static" "$cdir/static.o" >"$cdir/lld.log" 2>&1 ||
    { sed 's/^/    /' "$cdir/lld.log" >&2; sifail 'rust-lld could not link the static control'; }
  for c in rand-stripped.so:rand.so rand-crate-stripped.so:rand-crate.so fallback-stripped.so:fallback.so static-stripped:static; do
    mv "$cdir/${c#*:}" "$cdir/${c%%:*}" || exit 2
    "$bin/llvm-objcopy" --strip-all "$cdir/${c%%:*}" || sifail "llvm-objcopy could not strip the ${c#*:} control"
  done
}

# si_lists IMG DIR KCONFIG: a stand-in EXPECTED_DIR at DIR from --image-lists' own output on IMG
# (its boot and root lists and import list, under their headings), KCONFIG as linux.config and the
# fragment's two lists ($fraglists/required and forbidden). Prints the binary's SHA-256 from the
# listing. Every caller runs it as sha=$(si_lists ...) || exit 2: sifail's exit 2 ends the command
# substitution alone, and the assignment carries its status, so a control that cannot be listed
# is exit 2 rather than a FAIL of the scan on an empty hash.
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
  mine || return 0
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
    if [ -n "$2" ]; then want_rc=1; else want_rc=0; fi
    printf 'FAIL %s: wanted exit %s with %s, got exit %s:\n' "$1" "$want_rc" "${2:-no hit}" "$rc"
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
  sha=$(si_lists "$img" "$sw/clean" "$kconfig") || exit 2
  sicase 'selftest-image-clean-image' '' "$img" "$sw/clean" "$kconfig" "$sha"
  # Mutations of the root (its lists stand in for expected/, so only the named rule can fail).
  si_root marker
  printf 'KC_TEST_SOURCE_DO_NOT_SHIP\n' >"$sw/marker/root/etc/kc-canary.txt" || exit 2
  si_image marker "$iw/p1.img" "$sw/marker/root"
  sha=$(si_lists "$sw/marker.img" "$sw/marker/expected" "$kconfig") || exit 2
  sicase 'selftest-image-marker-in-a-text-file' 'Marker: /etc/kc-canary.txt: KC_TEST_SOURCE_DO_NOT_SHIP' \
    "$sw/marker.img" "$sw/marker/expected" "$kconfig" "$sha"
  si_root testkey
  write_testkey "$sw/testkey/root/etc/kc-canary.bin"
  si_image testkey "$iw/p1.img" "$sw/testkey/root"
  sha=$(si_lists "$sw/testkey.img" "$sw/testkey/expected" "$kconfig") || exit 2
  sicase 'selftest-image-test-key-file' "TestKey: /etc/kc-canary.bin: the test registry public key $testkey" \
    "$sw/testkey.img" "$sw/testkey/expected" "$kconfig" "$sha"
  si_root rand
  cp "$sw/elf/rand-stripped.so" "$sw/rand/root/lib/libkc-canary.so.1" || exit 2
  si_image rand "$iw/p1.img" "$sw/rand/root"
  sha=$(si_lists "$sw/rand.img" "$sw/rand/expected" "$kconfig") || exit 2
  sicase 'selftest-image-stripped-elf-importing-rand' 'Symbol: /lib/libkc-canary.so.1: undefined rand' \
    "$sw/rand.img" "$sw/rand/expected" "$kconfig" "$sha"
  si_root rand-crate
  cp "$sw/elf/rand-crate-stripped.so" "$sw/rand-crate/root/lib/libkc-canary.so.1" || exit 2
  si_image rand-crate "$iw/p1.img" "$sw/rand-crate/root"
  sha=$(si_lists "$sw/rand-crate.img" "$sw/rand-crate/expected" "$kconfig") || exit 2
  sicase 'selftest-image-stripped-elf-with-rand-crate-symbol' \
    'Symbol: /lib/libkc-canary.so.1: rand-family symbol rand::rngs::next_u32::h0000000000000000' \
    "$sw/rand-crate.img" "$sw/rand-crate/expected" "$kconfig" "$sha"
  si_root fallback
  cp "$sw/elf/fallback-stripped.so" "$sw/fallback/root/lib/libkc-canary.so.1" || exit 2
  si_image fallback "$iw/p1.img" "$sw/fallback/root"
  sha=$(si_lists "$sw/fallback.img" "$sw/fallback/expected" "$kconfig") || exit 2
  sicase 'selftest-image-stripped-elf-with-getrandom-fallback-symbol' \
    "Symbol: /lib/libkc-canary.so.1: getrandom's fallback getrandom::backends::use_file::fill_inner::h0000000000000000" \
    "$sw/fallback.img" "$sw/fallback/expected" "$kconfig" "$sha"
  si_root static
  cp "$sw/elf/static-stripped" "$sw/static/root/usr/bin/kc-canary" || exit 2
  si_image static "$iw/p1.img" "$sw/static/root"
  sha=$(si_lists "$sw/static.img" "$sw/static/expected" "$kconfig") || exit 2
  sicase 'selftest-image-stripped-static-elf' 'Format: /usr/bin/kc-canary: an ELF with no dynamic symbol table' \
    "$sw/static.img" "$sw/static/expected" "$kconfig" "$sha"
  si_root sh
  ln -s busybox "$sw/sh/root/bin/sh" || exit 2
  si_image sh "$iw/p1.img" "$sw/sh/root"
  sha=$(si_lists "$sw/sh.img" "$sw/sh/expected" "$kconfig") || exit 2
  sicase 'selftest-image-bin-sh' 'Deny: /bin/sh: a shell or login program, sh' \
    "$sw/sh.img" "$sw/sh/expected" "$kconfig" "$sha"
  si_root stripped
  "$bin/llvm-objcopy" --strip-all "$sw/stripped/root/usr/bin/keepcrypt-pi" || sifail 'llvm-objcopy could not strip keepcrypt-pi'
  si_image stripped "$iw/p1.img" "$sw/stripped/root"
  sha=$(si_lists "$sw/stripped.img" "$sw/stripped/expected" "$kconfig") || exit 2
  sicase 'selftest-image-stripped-keepcrypt-pi' 'Format: /usr/bin/keepcrypt-pi: a stripped file with no symbol table (.symtab)' \
    "$sw/stripped.img" "$sw/stripped/expected" "$kconfig" "$sha"
  si_root urandom
  printf '/dev/urandom' >>"$sw/urandom/root/usr/bin/keepcrypt-pi" || exit 2
  si_image urandom "$iw/p1.img" "$sw/urandom/root"
  sha=$(si_lists "$sw/urandom.img" "$sw/urandom/expected" "$kconfig") || exit 2
  sicase 'selftest-image-urandom-in-keepcrypt-pi' 'StdRandom: /usr/bin/keepcrypt-pi: byte string /dev/urandom' \
    "$sw/urandom.img" "$sw/urandom/expected" "$kconfig" "$sha"
  # The binary's hash.
  sha=$(si_lists "$img" "$sw/hash" "$kconfig") || exit 2
  sicase 'selftest-image-wrong-binary-hash' 'Binary: /usr/bin/keepcrypt-pi: SHA-256 ' \
    "$img" "$sw/hash" "$kconfig" "$(printf '%064d' 0)"
  # Partition 1: cmdline.txt and config.txt differ from the board files.
  si_boot console cmdline.txt "$(cat "$iw/boot/cmdline.txt") console=ttyAMA0,115200"
  si_image console "$sw/console/p1.img"
  sha=$(si_lists "$sw/console.img" "$sw/console/expected" "$kconfig") || exit 2
  sicase 'selftest-image-console-in-cmdline' 'Boot: partition-1:/cmdline.txt: differs from pi/os/board/pizero/cmdline.txt' \
    "$sw/console.img" "$sw/console/expected" "$kconfig" "$sha"
  si_boot gpumem config.txt "$(cat "$iw/boot/config.txt")
gpu_mem=16"
  si_image gpumem "$sw/gpumem/p1.img"
  sha=$(si_lists "$sw/gpumem.img" "$sw/gpumem/expected" "$kconfig") || exit 2
  sicase 'selftest-image-gpu-mem-16-config-with-start-elf' 'Boot: partition-1:/config.txt: differs from pi/os/board/pizero/config.txt' \
    "$sw/gpumem.img" "$sw/gpumem/expected" "$kconfig" "$sha"
  # The kernel config: one line off expected/linux.config (which stays the build's), then three
  # mutations that expected/linux.config follows, so the forbidden, hwrng and required rules are
  # what fire.
  si_kconfig offline '$a\
# one line off (selftest-image)'
  sha=$(si_lists "$img" "$sw/offline/expected" "$kconfig") || exit 2
  sicase 'selftest-image-kconfig-one-line-off' "Kconfig: $sw/offline/linux.config: differs from $sw/offline/expected/linux.config" \
    "$img" "$sw/offline/expected" "$sw/offline/linux.config" "$sha"
  si_kconfig net '/^# CONFIG_NET is not set$/d
$a\
CONFIG_NET=y'
  sha=$(si_lists "$img" "$sw/net/expected" "$sw/net/linux.config") || exit 2
  sicase 'selftest-image-kconfig-net' "Kconfig: $sw/net/linux.config: forbidden option CONFIG_NET is set (=y)" \
    "$img" "$sw/net/expected" "$sw/net/linux.config" "$sha"
  si_kconfig hwrng '$a\
CONFIG_HW_RANDOM_CANARY=y'
  sha=$(si_lists "$img" "$sw/hwrng/expected" "$sw/hwrng/linux.config") || exit 2
  sicase 'selftest-image-kconfig-two-hwrng-drivers' \
    "Kconfig: $sw/hwrng/linux.config: a hwrng driver other than BCM2835 is set: CONFIG_HW_RANDOM_CANARY=y" \
    "$img" "$sw/hwrng/expected" "$sw/hwrng/linux.config" "$sha"
  si_kconfig missing 's/^CONFIG_LEDS_TRIGGER_ACTPWR=y$/# CONFIG_LEDS_TRIGGER_ACTPWR is not set/'
  sha=$(si_lists "$img" "$sw/missing/expected" "$sw/missing/linux.config") || exit 2
  sicase 'selftest-image-kconfig-missing-required-option' \
    "Kconfig: $sw/missing/linux.config: required option CONFIG_LEDS_TRIGGER_ACTPWR is not =y" \
    "$img" "$sw/missing/expected" "$sw/missing/linux.config" "$sha"
  echo "selftest-image: $pass passed, $fail failed"
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

# --- Workflow selftest ---------------------------------------------------------------------------

# wexpect NAME DIR WANT [TEXT]: run the workflow check on DIR in a new process. WANT=clean needs
# exit 0, no hit and TEXT (when given) in the output; WANT=error needs exit 2; any other WANT is the
# one file the hit must name (as DIR/<file>): exit 1 and exactly one "Workflow: DIR/<file>:<line>:
# <text>" line, where <text> is line <line> of the file as it stands, or a "missing ..." message.
wexpect() {
  mine || return 0
  out=$(sh "${gate:-$self}" --workflows "$2" 2>&1)
  rc=$?
  hit=$(printf '%s\n' "$out" | grep -E '^Workflow: ')
  count=$(printf '%s\n' "$out" | grep -c -E '^Workflow: ')
  ok=no
  if [ "$3" = clean ]; then
    [ "$rc" -eq 0 ] && [ "$count" -eq 0 ] && ok=yes
    case $out in *"${4-}"*) ;; *) ok=no ;; esac
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
  # The bootstrap exception (kt_bootstrap_exception): copies of the script with a stand-in list
  # (bxcopy) must pass the named line in the Android workflow once, and refuse it anywhere else, a
  # second time, with anything added, and in a build script; a list of any other shape, one that
  # names the iPhone workflow (gone with Q73) among them, is exit 2; this script, whose list does
  # not name the line, refuses it. The clean line names the exception, or says there is none.
  bxline='sh scripts/android-gradle.sh --write-locks --write-verification-metadata sha256 :core-ffi:dependencies'
  wfhead='permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:'
  # bxdir NAME FILE LINE...: a directory holding FILE, a hardened workflow whose steps run each LINE.
  bxdir() {
    bxd=$tmp/bx-$1
    mkdir -p "$bxd" || exit 2
    bxf=$2
    shift 2
    { printf '%s\n' "$wfhead"; for l in "$@"; do printf '      - run: |\n          %s\n' "$l"; done; } >"$bxd/$bxf" || exit 2
  }
  # bxcopy LIST: $gate becomes a copy of this script whose kt_bootstrap_exception is LIST. The
  # assignment is the one line that starts kt_bootstrap_exception=, empty or with a single-quoted
  # value, and every line after it up to the one that ends the quote.
  bxcopy() {
    gate=$tmp/bootstrap-exception.sh
    KC_BOOTSTRAP_LIST=$1 awk -v q="'" '
      quoted { if (substr($0, length($0)) == q) quoted = 0; next }
      index($0, "kt_bootstrap_exception=") == 1 {
        print "kt_bootstrap_exception=" q ENVIRON["KC_BOOTSTRAP_LIST"] q
        n++
        v = substr($0, length("kt_bootstrap_exception=") + 1)
        if (substr(v, 1, 1) == q && (length(v) == 1 || substr(v, length(v)) != q)) quoted = 1
        next
      }
      { print }
      END { exit n != 1 || quoted }' "$self" >"$gate" || exit 2
  }
  bxdir allowed entropy-android.yml "$bxline"
  wexpect 'workflow-bootstrap-line-without-an-exception' "$bxd" entropy-android.yml
  bxcopy "entropy-android.yml $bxline"
  wexpect 'clean-bootstrap-exception-line' "$bxd" clean \
    "no bootstrap switch but the reviewed exception's line (kt_bootstrap_exception: entropy-android.yml $bxline),"
  bxcopy ''
  bxdir strict entropy-android.yml 'sh scripts/android-gradle.sh --dependency-verification strict help'
  wexpect 'clean-bootstrap-exception-empty' "$bxd" clean 'no bootstrap switch and no bootstrap exception,'
  bxcopy "entropy-android.yml $bxline"
  bxdir other-workflow entropy-ci.yml "$bxline"
  wexpect 'workflow-bootstrap-exception-line-in-another-workflow' "$bxd" entropy-ci.yml
  bxdir twice entropy-android.yml "$bxline" "$bxline"
  wexpect 'workflow-bootstrap-exception-line-twice' "$bxd" entropy-android.yml
  bxdir other-line entropy-android.yml "$bxline :app:dependencies"
  wexpect 'workflow-bootstrap-exception-line-with-more' "$bxd" entropy-android.yml
  bxdir update-locks entropy-android.yml 'sh scripts/android-gradle.sh --update-locks org.jetbrains.compose.ui:ui'
  wexpect 'workflow-bootstrap-exception-other-line' "$bxd" entropy-android.yml
  fresh
  mkdir -p "$d/scripts" && printf '%s\n' "$bxline" >"$d/scripts/android-gradle.sh" || exit 2
  expect 'ktsdk-bootstrap-exception-line-in-android-gradle-sh' "$d" KtSdk scripts/android-gradle.sh
  for case in "another-workflow:entropy-ci.yml $bxline" "ios-workflow:entropy-ios.yml $bxline" \
    'no-line:entropy-android.yml' "indented-line:entropy-android.yml   $bxline" "android-twice:entropy-android.yml $bxline
entropy-android.yml $bxline :app:dependencies" "android-and-ios:entropy-android.yml $bxline
entropy-ios.yml $bxline :screens:dependencies"; do
    bxcopy "${case#*:}"
    wexpect "workflow-error-bootstrap-exception-${case%%:*}" "$tmp/bx-allowed" error
  done
  gate=
}

# --- Image lists selftest ------------------------------------------------------------------------

# iexpect NAME TEXT ARG...: run --image-lists ARG... in a new process; it must exit 2 with TEXT in
# its output. ixexpect MODE NAME TEXT ARG... does the same for another image mode.
iexpect() {
  ixexpect --image-lists "$@"
}

ixexpect() {
  mine || return 0
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
  if mine; then
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
  if mine; then
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
  mine || return 0
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
# fragment line of another kind, a fragment with no "is not set" line, and a path that is not a
# directory.
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
  grep -v ' is not set$' "$d/fragment.away" >"$d/board/pizero/linux.fragment" || exit 2
  oexpect 'osconfig-error-fragment-without-is-not-set-lines' "$d" error 'has no CONFIG_X=y line, or no "# CONFIG_X is not set" line'
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
    mine || continue
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
  sha=$(si_lists "$img" "$tree/expected" "$kc") || exit 2
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
  sha=$(si_lists "$img" "$tree/expected" "$kc") || exit 2
  grep -v '^/zImage ' "$tree/expected/boot.list" >"$tree/boot.list" && mv "$tree/boot.list" "$tree/expected/boot.list" || exit 2
  sicase image-stub-boot-list-differs "List: $tree/expected/boot.list: differs from the image's boot file list" "$img" "$tree/expected" "$kc" "$sha"
  stub_tree root-list
  sha=$(si_lists "$img" "$tree/expected" "$kc") || exit 2
  echo '/etc/kc-canary -rw-r--r--' >>"$tree/expected/root.list" || exit 2
  sicase image-stub-root-list-differs "List: $tree/expected/root.list: differs from the image's root file list" "$img" "$tree/expected" "$kc" "$sha"
  stub_tree imports
  sha=$(si_lists "$img" "$tree/expected" "$kc") || exit 2
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
  stub_tree var-tmp
  mkdir -p "$tree/root/var/tmp" && chmod 1777 "$tree/root/var/tmp" || exit 2
  stub_case sticky-var-tmp 'Deny: /var/tmp: setuid, setgid or sticky mode drwxrwxrwt'
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
  sha=$(si_lists "$img" "$tree/expected" "$kc") || exit 2
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
  sha=$(si_lists "$img" "$tree/expected" "$kc") || exit 2
  grep -v '^CONFIG_TTY$' "$st/required" >"$tree/expected/kconfig-required" || exit 2
  sicase image-stub-kconfig-required-list-drift "Kconfig: $tree/expected/kconfig-required: does not equal the CONFIG_X=y lines" "$img" "$tree/expected" "$kc" "$sha"
  stub_tree forbidden-drift
  sha=$(si_lists "$img" "$tree/expected" "$kc") || exit 2
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
  sha=$(si_lists "$tree/raw.img" "$tree/expected" "$kc") || exit 2
  sicase image-stub-marker-in-raw-image "Marker: $tree/raw.img: KC_TEST_SOURCE_DO_NOT_SHIP" "$tree/raw.img" "$tree/expected" "$kc" "$sha"
  stub_tree testkey
  write_testkey "$tree/root/etc/kc-canary.bin"
  stub_case test-key-file "TestKey: /etc/kc-canary.bin: the test registry public key $testkey"
  # keepcrypt-pi: the hash, a stripped file, the fallback's device path, the simulator's name as
  # a symbol and as bytes;
  # the other ELF files: a stripped import of rand, a stripped file defining a rand-crate symbol
  # and one defining a getrandom-fallback symbol, a stripped static file.
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
  stub_tree sim-bytes
  printf keepcrypt_pi_sim >>"$tree/root/usr/bin/keepcrypt-pi" || exit 2
  stub_case simulator-bytes-in-keepcrypt-pi 'Binary: /usr/bin/keepcrypt-pi: names the simulator crate: byte string keepcrypt_pi_sim'
  stub_tree rand
  cp "$st/elf/rand-stripped.so" "$tree/root/lib/libkc-canary.so.1" || exit 2
  stub_case stripped-elf-importing-rand 'Symbol: /lib/libkc-canary.so.1: undefined rand'
  stub_tree rand-crate
  cp "$st/elf/rand-crate-stripped.so" "$tree/root/lib/libkc-canary.so.1" || exit 2
  stub_case stripped-elf-with-rand-crate-symbol 'Symbol: /lib/libkc-canary.so.1: rand-family symbol rand::rngs::next_u32::h0000000000000000'
  stub_tree fallback
  cp "$st/elf/fallback-stripped.so" "$tree/root/lib/libkc-canary.so.1" || exit 2
  stub_case stripped-elf-with-getrandom-fallback-symbol "Symbol: /lib/libkc-canary.so.1: getrandom's fallback getrandom::backends::use_file::fill_inner::h0000000000000000"
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
  mine || return 0
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
  if ! mine; then
    :
  elif sed -n '/"test_registry": {/,/}/p' "$here/../vectors/kcr.json" | grep -q -F -e "\"public_key_hex\": \"$testkey\""; then
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
  if ! mine; then
    :
  elif [ -n "$deny_rng" ] && [ "$deny_rng" = "$scan_rng" ]; then
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

# --- APK mode ------------------------------------------------------------------------------------

# apk_py COMMAND ARG...: the APK check's Python half (tasks/todo.md, M5 group 5: "unpacks the APK
# with Python's zipfile"), the program fed to python3 -I on its standard input, standard library
# only (a here-document inside $(...) would trip bash 3.2's parser, macOS's sh). manifest BADGING
# PERMISSIONS XMLTREE REPORT OUT APK writes the manifest summary to OUT (see "APK mode" in the
# header) and prints the manifest's hard-rule hits; scan APK NATIVE_LIST DIR TESTKEY JNILIBS_DIR
# MARKER... byte-searches the APK (but libkeepcrypt.so's stored bytes) and every entry (but
# libkeepcrypt.so, which the artifact rules search in the shell), judges every lib/ entry against
# NATIVE_LIST and each libkeepcrypt.so against JNILIBS_DIR's copy, writes each dex file and each
# native library that passed into DIR, and prints them; zip and elf build --selftest-apk's stub APKs
# and shared objects. Lines out: "HIT<tab>CATEGORY<tab>NAME<tab>DETAIL" per hit, and from scan
# "SO<tab>FILE<tab>ENTRY", "KC<tab>FILE<tab>ENTRY" (a libkeepcrypt.so), "DEX<tab>FILE<tab>ENTRY" and
# "COUNT<tab>ENTRIES<tab>LIBRARIES". Anything it cannot read or parse is exit 2, never a pass.
apk_py() {
  python3 -I - "$@" <<'APK_PY'
import hashlib
import re
import struct
import sys
import zipfile

ANDROID = "http://schemas.android.com/apk/res/android"
# MA:23's three ABIs (lead decision M5-10), with the ELF class (1: 32-bit, 2: 64-bit) and machine
# (EM_ARM 40, EM_X86_64 62, EM_AARCH64 183) of each; the 64-bit ones need 16 KB pages.
ABIS = {"arm64-v8a": (2, 183), "armeabi-v7a": (1, 40), "x86_64": (2, 62)}
PAGE = 0x4000
# Our library (M5 commit 14), which native-libs.txt lists for each ABI by this word, not a SHA-256:
# its bytes must be those of scripts/android-rust.sh's scanned copy in JNILIBS_DIR.
KEEPCRYPT = "libkeepcrypt.so"
OURS = "android-rust.sh"
NETWORK = ("android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE",
           "android.permission.ACCESS_WIFI_STATE")
# The application flags the summary always lists, each with the value the hard rules require
# (None: listed, judged only by the comparison); every other attribute it lists when present.
FLAGS = (("allowBackup", "false"), ("dataExtractionRules", "set"), ("debuggable", "false"),
         ("extractNativeLibs", None), ("fullBackupContent", "false"), ("usesCleartextTraffic", "false"))
COMPONENTS = ("activity", "activity-alias", "provider", "receiver", "service")
SKIPPED = ("uses-sdk", "uses-permission", "uses-permission-sdk-23", "permission", "application")
ATTR = re.compile(r"(?P<name>[^=(]+?)(?:\(0x[0-9a-fA-F]+\))?=(?P<value>.*)$")


def error(msg):
    sys.stderr.write("banned-api-check: --apk: %s\n" % msg)
    sys.exit(2)


def hit(category, name, detail):
    print("HIT\t%s\t%s\t%s" % (category, name, detail))


def text(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace")


class Element:
    def __init__(self, tag, indent):
        self.tag, self.indent, self.attrs, self.children = tag, indent, {}, []


def value(raw):
    if raw.startswith('"'):
        m = re.match(r'"((?:[^"\\]|\\.)*)"', raw)
        return m.group(1) if m else raw
    return raw.split(" ", 1)[0]


def xmltree(path):
    """aapt2 dump xmltree's tree: E lines are elements, A lines the attributes of the element above,
    nesting by indentation; N (namespace) and T (text) lines are skipped, anything else is exit 2."""
    root = Element("", -1)
    stack = [root]
    for n, line in enumerate(text(path).splitlines(), 1):
        body = line.lstrip(" ")
        indent = len(line) - len(body)
        if not body or body.startswith("N: ") or body.startswith("T: "):
            continue
        if not (body.startswith("E: ") or body.startswith("A: ")):
            error("%s line %d is not one aapt2 dump xmltree prints: %s" % (path, n, line))
        while stack[-1].indent >= indent:
            stack.pop()
        if body.startswith("E: "):
            el = Element(body[3:].split(" ", 1)[0], indent)
            stack[-1].children.append(el)
            stack.append(el)
            continue
        m = ATTR.match(body[3:])
        if not m or stack[-1] is root:
            error("%s line %d is not an attribute of an element: %s" % (path, n, line))
        ns, sep, local = m.group("name").rpartition(":")
        stack[-1].attrs[local if not sep or ns == ANDROID else m.group("name")] = value(m.group("value"))
    return root


def shown(v):
    if v is None:
        return "unset"
    return "set" if v.startswith("@") else v


def describe(el):
    parts = [] if el.tag == "intent-filter" else [el.tag]
    parts += [el.attrs[k] for k in ("name", "authorities") if k in el.attrs]
    for c in el.children:
        if c.tag in ("action", "category"):
            parts.append("%s:%s" % (c.tag, c.attrs.get("name", "")))
        else:
            parts.append("%s:%s" % (c.tag, ",".join("%s=%s" % kv for kv in sorted(c.attrs.items()))))
    return " ".join(parts)


def manifest(badging, permissions, tree, report, out, apk):
    b = text(badging)
    pkg = re.search(r"^package: name='([^']*)'.* versionName='([^']*)'", b, re.M)
    lo = re.search(r"^minSdkVersion:'([^']*)'$", b, re.M)
    hi = re.search(r"^targetSdkVersion:'([^']*)'$", b, re.M)
    if not (pkg and lo and hi):
        error("aapt2 dump badging printed no package line with versionName, or no SDK lines")
    head = ["package " + pkg.group(1), "versionName " + pkg.group(2), "minSdk " + lo.group(1),
            "targetSdk " + hi.group(1)]
    perms = []
    for line in text(permissions).splitlines():
        if not line.strip() or line.startswith("package: "):
            continue
        p = re.match(r"([a-z0-9-]+): name='([^']*)'(.*)$", line)
        d = re.match(r"permission: (\S+)$", line)
        if p:
            perms.append(" ".join([p.group(1), p.group(2)] + p.group(3).replace("'", "").split()))
        elif d:
            perms.append("permission " + d.group(1))
        else:
            perms.append("permissions-dump " + line.strip())
    tops = xmltree(tree).children
    if len(tops) != 1 or tops[0].tag != "manifest":
        error("aapt2 dump xmltree printed no single manifest element")
    man = tops[0]
    apps = [e for e in man.children if e.tag == "application"]
    app = apps[0] if apps else Element("application", 0)
    attrs = dict(app.attrs)
    for name, _ in FLAGS:
        v = app.attrs.get(name)
        if name == "debuggable":
            v = "true" if v == "true" or re.search(r"^application-debuggable$", b, re.M) else (v or "false")
        elif name == "dataExtractionRules":
            v = "unset" if v is None else "set"
        attrs[name] = v
    flags = ["application %s=%s" % (k, shown(attrs[k])) for k in sorted(attrs)]
    flags += ["manifest sharedUserId=" + man.attrs["sharedUserId"]] if "sharedUserId" in man.attrs else []
    comps, libs, extra = [], [], []
    for el in app.children:
        name = el.attrs.get("name", "")
        if el.tag in COMPONENTS:
            filters = [c for c in el.children if c.tag == "intent-filter"]
            exported = el.attrs.get("exported", "true" if filters else "false")
            comps.append(["%s %s exported=%s" % (el.tag, name, exported)] +
                         ["%s %s %s=%s" % (el.tag, name, k, shown(el.attrs[k]))
                          for k in sorted(el.attrs) if k not in ("name", "exported")] +
                         ["%s %s intent-filter %s" % (el.tag, name, describe(f)) for f in filters])
        elif el.tag in ("uses-library", "uses-native-library"):
            libs.append("%s %s required=%s" % (el.tag, name, el.attrs.get("required", "true")))
        else:
            extra.append(("application-element %s %s" % (el.tag, name)).rstrip())
    extra += ["manifest-element application"] * (len(apps) - 1 if apps else 0)
    for el in man.children:
        if el.tag in SKIPPED:
            continue
        if el.tag == "queries":
            extra += ["queries " + describe(c) for c in el.children] or ["queries"]
        elif el.tag == "uses-feature":
            extra.append("uses-feature %s required=%s" % (el.attrs.get("name", "glEsVersion=" + el.attrs.get("glEsVersion", "")),
                                                          el.attrs.get("required", "true")))
        else:
            extra.append(("manifest-element %s %s" % (el.tag, el.attrs.get("name", ""))).rstrip())
    # The merger report's removals: a node key starts a line, its attributes are indented one tab
    # and each record is "VERB from ..."; every verb but these five removes a node or attribute.
    removed, key, attr = set(), "", ""
    for line in text(report).splitlines():
        body = line.strip()
        if not body or body.startswith("--"):
            continue
        verb = re.match(r"([A-Z]+) from( |$)", body)
        if verb:
            if verb.group(1) not in ("ADDED", "MERGED", "INJECTED", "IMPLIED", "CONVERTED"):
                removed.add(("%s %s" % (key, attr)).strip())
        elif line.startswith("\t"):
            attr = body
        else:
            key, attr = body, ""
    lines = (head + sorted(perms) + flags + [x for c in sorted(comps) for x in c] + sorted(libs) + sorted(extra)
             + ["removed " + r for r in sorted(removed)])
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    # The hard rules, whatever the expected summary says.
    for x in lines:
        if not x.startswith("removed ") and any(p in x.split(" ") for p in NETWORK):
            hit("Manifest", apk, "a network permission (rule 9): " + x)
        if x.startswith("queries"):
            hit("Manifest", apk, "a <queries> element (package visibility): " + x)
    for c in comps:
        kind = c[0].split(" ")[0]
        if kind in ("provider", "receiver", "service"):
            hit("Manifest", apk, "a %s (the app has no provider, receiver or service): %s" % (kind, c[0]))
    for name, want in FLAGS:
        got = [x for x in flags if x.startswith("application %s=" % name)][0].split("=", 1)[1]
        if want is not None and got != want:
            hit("Manifest", apk, "application %s=%s, not %s" % (name, got, want))
    exported = sorted(c[0].split(" ")[1] for c in comps
                      if c[0].split(" ")[0] in ("activity", "activity-alias") and c[0].endswith(" exported=true"))
    if len(exported) > 1:
        hit("Manifest", apk, "%d exported activities, not the one launcher: %s" % (len(exported), ", ".join(exported)))


def elf_facts(data):
    """(class, machine, [p_align of every PT_LOAD]) of an ELF file, or None if it is truncated."""
    if len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    e = "<" if data[5] == 1 else ">"
    cls = data[4]
    machine = struct.unpack(e + "H", data[18:20])[0]
    if cls == 2:
        if len(data) < 64:
            return None
        phoff = struct.unpack(e + "Q", data[32:40])[0]
        phentsize, phnum = struct.unpack(e + "HH", data[54:58])
        size, at, fmt = 56, 48, "Q"
    else:
        phoff = struct.unpack(e + "I", data[28:32])[0]
        phentsize, phnum = struct.unpack(e + "HH", data[42:46])
        size, at, fmt = 32, 28, "I"
    if phentsize < size:
        return None
    aligns = []
    for i in range(phnum):
        ph = data[phoff + i * phentsize:phoff + i * phentsize + size]
        if len(ph) < size:
            return None
        if struct.unpack(e + "I", ph[0:4])[0] == 1:
            aligns.append(struct.unpack(e + fmt, ph[at:at + struct.calcsize(fmt)])[0])
    return cls, machine, aligns


def scan(apk, native_list, outdir, testkey, jnilibs, *markers):
    key = bytes.fromhex(testkey)
    want = {}
    for n, line in enumerate(text(native_list).splitlines(), 1):
        w = line.split(" ")
        if len(w) != 3 or w[0] not in ABIS or not re.match(r"lib[A-Za-z0-9_.+-]+[.]so$", w[1]) \
                or not re.match(r"[0-9a-f]{64}$|%s$" % OURS, w[2]) or (w[1] == KEEPCRYPT) != (w[2] == OURS) \
                or (w[0], w[1]) in want:
            error('%s line %d is not "<abi> <name>.so <sha256>", or "<abi> %s %s", for one of MA:23\'s three ABIs, '
                  'once: %s' % (native_list, n, KEEPCRYPT, OURS, line))
        want[(w[0], w[1])] = w[2]
    ours = sorted(abi for abi, so in want if so == KEEPCRYPT)
    if ours != sorted(ABIS):
        error("%s lists %s %s for %s, not for each of MA:23's three ABIs"
              % (native_list, KEEPCRYPT, OURS, ", ".join(ours) or "no ABI"))

    def bytescan(data, name):
        for m in markers:
            if m.encode() in data:
                hit("Marker", name, m)
        if key in data:
            hit("TestKey", name, "the test registry public key " + testkey)

    try:
        z = zipfile.ZipFile(apk)
        infos = z.infolist()
    except (zipfile.BadZipFile, OSError) as e:
        error("%s is not a zip file Python can read: %s" % (apk, e))
    # The APK's own bytes, with each stored libkeepcrypt.so's bytes blanked: the shell searches that
    # library under the artifact rules, where the test-registry one must hold its marker and key.
    with open(apk, "rb") as f:
        raw = bytearray(f.read())
    for info in infos:
        parts = info.filename.split("/")
        if len(parts) == 3 and parts[0] == "lib" and parts[2] == KEEPCRYPT and info.compress_type == zipfile.ZIP_STORED:
            head = raw[info.header_offset:info.header_offset + 30]
            if len(head) != 30 or head[:4] != b"PK\x03\x04":
                error("%s: no local file header for %s at offset %d" % (apk, info.filename, info.header_offset))
            name_len, extra_len = struct.unpack("<HH", bytes(head[26:30]))
            start = info.header_offset + 30 + name_len + extra_len
            raw[start:start + info.compress_size] = bytes(info.compress_size)
    bytescan(bytes(raw), apk)
    seen, entries, libs = set(), 0, 0
    for i, info in enumerate(infos):
        if info.filename.endswith("/"):
            continue
        name = info.filename
        entries += 1
        try:
            data = z.read(info)
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as e:
            error("cannot read %s from %s: %s" % (name, apk, e))
        parts = name.split("/")
        if not (len(parts) == 3 and parts[0] == "lib" and parts[2] == KEEPCRYPT):
            bytescan(data, name)
        elf = data[:4] == b"\x7fELF"
        if name.endswith(".dex"):
            path = "%s/dex-%d" % (outdir, i)
            with open(path, "wb") as f:
                f.write(data)
            print("DEX\t%s\t%s" % (path, name))
        parts = name.split("/")
        if parts[0] != "lib":
            if elf:
                hit("NativeLib", name, "an ELF outside lib/<abi>/*.so")
            continue
        if len(parts) != 3 or not parts[2].endswith(".so"):
            hit("NativeLib", name, "a file under lib/ that is not lib/<abi>/<name>.so")
            continue
        abi, so = parts[1], parts[2]
        sha = hashlib.sha256(data).hexdigest()
        if abi not in ABIS:
            hit("NativeLib", name, "an ABI outside MA:23's three (arm64-v8a, armeabi-v7a, x86_64)")
            continue
        if not elf:
            hit("NativeLib", name, "not an ELF file")
            continue
        seen.add((abi, so))
        libs += 1
        if (abi, so) not in want:
            hit("NativeLib", name, "not in native-libs.txt (SHA-256 %s)" % sha)
            continue
        if so == KEEPCRYPT:
            built = "%s/%s/%s" % (jnilibs, abi, KEEPCRYPT)
            try:
                with open(built, "rb") as f:
                    scanned = hashlib.sha256(f.read()).hexdigest()
            except OSError as e:
                error("cannot read %s, the scanned output of scripts/android-rust.sh: %s" % (built, e))
            if sha != scanned:
                hit("NativeLib", name, "SHA-256 %s, not that of %s (%s), the library scripts/android-rust.sh "
                    "built and scanned" % (sha, built, scanned))
                continue
            if info.compress_type != zipfile.ZIP_STORED:
                hit("NativeLib", name, "compressed in the APK, not stored as extractNativeLibs=false needs")
                continue
        elif sha != want[(abi, so)]:
            hit("NativeLib", name, "SHA-256 %s, not native-libs.txt's %s" % (sha, want[(abi, so)]))
            continue
        facts = elf_facts(data)
        if facts is None:
            hit("Format", name, "a truncated ELF header or program header table")
            continue
        cls, machine, aligns = facts
        if (cls, machine) != ABIS[abi]:
            hit("NativeLib", name, "an ELF of class %d for machine %d, not %s's (%d, %d)" % ((cls, machine, abi) + ABIS[abi]))
            continue
        if cls == 2 and (not aligns or any(a < PAGE or a % PAGE for a in aligns)):
            hit("NativeLib", name, "LOAD segments aligned to %s, not 0x4000 on every one (16 KB pages)"
                % (", ".join("0x%x" % a for a in aligns) or "nothing (no LOAD segment)"))
            continue
        path = "%s/so-%d" % (outdir, i)
        with open(path, "wb") as f:
            f.write(data)
        print("%s\t%s\t%s" % ("KC" if so == KEEPCRYPT else "SO", path, name))
    for abi, so in sorted(set(want) - seen):
        hit("NativeLib", "lib/%s/%s" % (abi, so), "in native-libs.txt but not in the APK")
    print("COUNT\t%d\t%d" % (entries, libs))


def stub_zip(out, comment, *entries):
    """The selftest's stub APKs: NAME=FILE entries, a .so stored as the real APK stores it (but from a
    FILE named *.deflate), the rest deflated (so a marker in an entry is not also in the zip's raw
    bytes)."""
    with zipfile.ZipFile(out, "w") as z:
        z.comment = comment.encode()
        for e in entries:
            name, path = e.split("=", 1)
            with open(path, "rb") as f:
                stored = name.endswith(".so") and not path.endswith(".deflate")
                z.writestr(name, f.read(), zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED)


def stub_elf(out, abi, align, *symbols):
    """The selftest's stub shared objects: an ELF header and two PT_LOAD segments aligned to ALIGN (hex)
    for ABI, or with ALIGN none two PT_PHDR segments and no LOAD one, then each symbol as "NM:<name>"
    (an undefined symbol), which the stub llvm-nm lists; a word that already holds a colon is written
    as it is: DEF:<name> (a defined symbol), NEEDED:<library> (a DT_NEEDED entry, which the stub
    llvm-readobj lists) and NOSYMTAB (no .symtab, for the stub llvm-readobj)."""
    cls, machine = ABIS[abi]
    ptype, align = (6, PAGE) if align == "none" else (1, int(align, 16))
    if cls == 2:
        head = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        phs = b"".join(struct.pack("<IIQQQQQQ", ptype, 5, 0, 0, 0, 0, 0, align) for _ in range(2))
    else:
        head = b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack("<HHIIIIIHHHHHH", 3, machine, 1, 0, 52, 0, 0, 52, 32, 2, 0, 0, 0)
        phs = b"".join(struct.pack("<IIIIIIII", ptype, 0, 0, 0, 0, 0, 5, align) for _ in range(2))
    with open(out, "wb") as f:
        f.write(head + phs + "".join(" " + (s if ":" in s or s == "NOSYMTAB" else "NM:" + s) for s in symbols).encode() + b"\n")


{"manifest": manifest, "scan": scan, "zip": stub_zip, "elf": stub_elf}[sys.argv[1]](*sys.argv[2:])
APK_PY
}

# The dex reference scan's banned names (Q59 (b): rule 1 binds KeepCrypt's own compiled classes;
# library classes our code never reaches are allowed), as dexdump writes them: the plan's five,
# java.util.Random, kotlin.random.Random (here the whole kotlin.random package), Math.random,
# UUID.randomUUID and java.security.SecureRandom; the java.util.random package, ThreadLocalRandom,
# SplittableRandom and StrictMath.random, which the grep gate's RNG rule also bans; and the
# compiled forms of Kotlin's .shuffle( and .shuffled( (which that rule bans) and .random(:
# java.util.Collections.shuffle (MutableList.shuffle() is inlined to it) and shuffle, shuffled,
# random and randomOrNull of the kotlin.collections, kotlin.ranges and kotlin.text facade classes
# (Iterable.shuffled(), Array.shuffle(), or any of them should a Kotlin release stop inlining it).
# Their forms that take a Random name kotlin.random in the signature. A method reference
# (List<String>::shuffled) gets past the grep gate's patterns; its compiled call does not get past
# these. An ERE for awk.
dex_banned='Ljava/util/Random;|Ljava/util/random/|Ljava/util/SplittableRandom;|Ljava/util/concurrent/ThreadLocalRandom;'
dex_banned="$dex_banned|Ljava/security/SecureRandom;|Lkotlin/random/|Ljava/lang/(Strict)?Math;[.]random:|Ljava/util/UUID;[.]randomUUID:"
dex_banned="$dex_banned|Ljava/util/Collections;[.]shuffle:|Lkotlin/(collections|ranges|text)/[A-Za-z_]*;[.](shuffled?|random|randomOrNull):"

# apkfail MESSAGE: the APK cannot be checked (exit 2).
apkfail() {
  printf 'banned-api-check: --apk: %s\n' "$1" >&2
  exit 2
}

# apk_tool OUT TOOL ARG...: TOOL ARG... with its output in OUT; a tool that fails is exit 2, with
# its error output.
apk_tool() {
  ato=$1
  shift
  "$@" >"$ato" 2>"$aw/log" </dev/null || { sed 's/^/    /' "$aw/log" >&2; apkfail "$* failed"; }
}

# apk_lines FILE: the Python half's lines in FILE: a hit is counted, a native library goes through
# the image scan's elf_check (libkeepcrypt.so through kc_lib), a dex file through dex_scan, and the
# counts are kept.
apk_lines() {
  tab=$(printf '\t')
  while IFS=$tab read -r kind a b c; do
    case $kind in
      HIT) ahit "$a" "$b" "$c" ;;
      SO) elf_check "$a" "$b" ;;
      KC) kc_lib "$a" "$b" ;;
      DEX) dex_scan "$a" "$b" ;;
      COUNT) entries=$a libs=$b ;;
      *) apkfail "the Python half printed an unknown line: $kind" ;;
    esac
  done <"$1"
}

# dex_scan FILE NAME: dexdump -d on one dex file of the APK. In every class whose descriptor starts
# Lcom/keepcrypt/, each line (the class header, its fields, method signatures, code and debug
# information) is searched for $dex_banned: one DexRef hit per class and banned name. Library
# classes are not searched. The com.keepcrypt classes are counted, so a dexdump whose output
# this awk cannot read fails the run (apk_scan) instead of passing it.
dex_scan() {
  apk_tool "$aw/dexdump" dexdump -d "$1"
  ndex=$((ndex + 1))
  awk -v banned="$dex_banned" -v q="'" -v name="$2" '
    BEGIN { head = "  Class descriptor  : " q; t = "\t" }
    index($0, head) == 1 {
      d = substr($0, length(head) + 1)
      sub(q ".*", "", d)
      ours = index(d, "Lcom/keepcrypt/") == 1
      if (ours) classes++
      next
    }
    ours && match($0, banned) {
      ref = substr($0, RSTART, RLENGTH)
      if (!((d, ref) in seen)) {
        seen[d, ref] = 1
        print "HIT" t "DexRef" t name t d " references " ref
      }
    }
    END { print "CLASSES" t (classes + 0) }
  ' "$aw/dexdump" >"$aw/dexrefs" || exit 2
  while IFS=$tab read -r dkind da db dc; do
    case $dkind in
      HIT) ahit "$da" "$db" "$dc" ;;
      CLASSES) classes=$((classes + da)) ;;
    esac
  done <"$aw/dexrefs"
}

# kc_ours and kc_secp: libkeepcrypt.so's exports (lead decisions M5-21 and M5-40), as
# entropy-ci.yml's cross legs check them: exactly our two, and beside them only secp256k1-sys
# 0.10.1's own four #[no_mangle] functions. kc_needed: the only libraries it may need.
kc_ours='JNI_OnLoad Java_com_keepcrypt_entropy_ffi_Native_call'
kc_secp='rustsecp256k1_v0_10_0_context_create rustsecp256k1_v0_10_0_context_destroy rustsecp256k1_v0_10_0_default_error_callback_fn rustsecp256k1_v0_10_0_default_illegal_callback_fn'
kc_needed='libc.so libdl.so libm.so'

# kc_lib FILE NAME: libkeepcrypt.so, which the Python half has matched to android-rust.sh's scanned
# copy and judged for its ABI and 16 KB pages: the whole release-artifact scan for its target, as
# the cross legs scan it (artifact_file: Marker, TestKey, Format with a .symtab, Symbol, StdRandom,
# OSImport), in which the test-registry APK's library must show its registry marker and the test
# key and nothing else, and the shipping APK's nothing; its exports (kc_ours, kc_secp); and its
# DT_NEEDED libraries, libc.so with at most libm.so and libdl.so (llvm-readobj --needed-libs).
kc_lib() {
  kf=$1
  kname=$2
  case $kname in
    lib/arm64-v8a/*) artifact_rules aarch64-linux-android ;;
    lib/armeabi-v7a/*) artifact_rules armv7-linux-androideabi ;;
    lib/x86_64/*) artifact_rules x86_64-linux-android ;;
    *) apkfail "kc_lib: no target for $kname" ;;
  esac
  khits=$hits
  artifact_file "$kf" "$kname" >"$aw/kc-scan" || :
  hits=$khits
  kmarker="Marker: $kname: KC_TEST_REGISTRY_DO_NOT_SHIP"
  kkey="TestKey: $kname: the test registry public key $testkey"
  if [ "$variant" = withTestRegistry ]; then
    grep -q -x -F -e "$kmarker" "$aw/kc-scan" ||
      ahit NativeLib "$kname" 'no KC_TEST_REGISTRY_DO_NOT_SHIP: not the test-registry build of the library'
    grep -q -x -F -e "$kkey" "$aw/kc-scan" ||
      ahit NativeLib "$kname" 'no test registry key: not the test-registry build of the library'
    grep -v -x -F -e "$kmarker" -e "$kkey" "$aw/kc-scan" >"$aw/kc-rest"
    [ $? -le 1 ] || exit 2
  else
    cp "$aw/kc-scan" "$aw/kc-rest" || exit 2
  fi
  while IFS= read -r kline; do
    printf '%s\n' "$kline"
    hits=$((hits + 1))
  done <"$aw/kc-rest"
  symbols "$kf" "$aw/kc-defined" -D --defined-only
  kgot=$(awk -v secp="$kc_secp" '
    BEGIN { n = split(secp, s, " "); for (i = 1; i <= n; i++) theirs[s[i]] = 1 }
    !($0 in theirs)' "$aw/kc-defined" | LC_ALL=C sort -u | paste -s -d ' ' -)
  kwant=$(printf '%s\n' $kc_ours | LC_ALL=C sort | paste -s -d ' ' -)
  [ "$kgot" = "$kwant" ] ||
    ahit NativeLib "$kname" "defines ${kgot:-no symbol} beside secp256k1-sys's four, not exactly $kwant"
  "$bin/llvm-readobj" --needed-libs "$kf" >"$aw/kc-needed" 2>"$aw/log" || {
    sed 's/^/    /' "$aw/log" >&2
    apkfail "llvm-readobj --needed-libs cannot read $kname"
  }
  awk '/^NeededLibraries \[/ { on = 1; next } on && /^\]/ { on = 0 } on { gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "") print }' \
    "$aw/kc-needed" | LC_ALL=C sort >"$aw/kc-libs" || exit 2
  grep -q -x -F -e libc.so "$aw/kc-libs" || ahit NativeLib "$kname" 'no DT_NEEDED libc.so'
  while IFS= read -r klib; do
    case " $kc_needed " in
      *" $klib "*) ;;
      *) ahit NativeLib "$kname" "DT_NEEDED $klib: not libc.so, libm.so or libdl.so" ;;
    esac
  done <"$aw/kc-libs"
  kclean=$((kclean + 1))
}

# apk_scan VARIANT APK EXPECTED_DIR MERGER_REPORT CERT_SHA256 JNILIBS_DIR: the APK check and scan
# (see "APK mode" in the header). Every argument and input file is checked, and every tool found,
# before the APK is read.
apk_scan() {
  variant=$1
  apk=$2
  exp=${3%/}
  report=$4
  cert=$5
  jnilibs=${6%/}
  case $variant in
    shipping | withTestRegistry) ;;
    *) apkfail "VARIANT is shipping or withTestRegistry, not $variant" ;;
  esac
  printf '%s\n' "$cert" | grep -q -x -E '[0-9a-f]{64}' || apkfail "CERT_SHA256 is not 64 lowercase hex digits: $cert"
  [ -d "$exp" ] || apkfail "EXPECTED_DIR $3 is not a directory"
  [ -d "$jnilibs" ] || apkfail "JNILIBS_DIR $6 is not a directory"
  readable "$exp/manifest-$variant.txt" --apk
  readable "$exp/native-libs.txt" --apk
  readable "$report" --apk
  [ -f "$apk" ] && [ -r "$apk" ] || apkfail "cannot read $apk"
  for tool in python3 aapt2 dexdump zipalign apksigner llvm-nm llvm-readobj; do
    command -v "$tool" >/dev/null 2>&1 ||
      apkfail "no $tool on PATH (aapt2, dexdump, zipalign and apksigner from the build-tools, llvm-nm and llvm-readobj from the NDK)"
  done
  nm=$(command -v llvm-nm)
  bin=${nm%/*}
  aw=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-apk.XXXXXX") || exit 2
  trap 'rm -rf "$aw"' EXIT
  trap 'exit 2' HUP INT TERM
  atmp=$aw
  iw=$aw
  # elf_check's patterns: one rule for the three Android targets (the undefined RNG imports, the
  # rand crates, getrandom's fallback).
  artifact_rules aarch64-linux-android
  hits=0
  ndex=0
  classes=0
  entries=0
  libs=0
  kclean=0
  linked=0
  archives=0
  echo "== banned-api-check --apk $variant $apk"
  echo "sha256 $(sha256 "$apk")"
  # 1. The manifest: aapt2's three dumps and the merger report reduced to the summary, which
  # must equal the expected one; the hard rules hit whatever that file says; and the report
  # names no INTERNET (no network permission is ever stripped).
  apk_tool "$aw/badging" aapt2 dump badging "$apk"
  apk_tool "$aw/permissions" aapt2 dump permissions "$apk"
  apk_tool "$aw/xmltree" aapt2 dump xmltree --file AndroidManifest.xml "$apk"
  apk_py manifest "$aw/badging" "$aw/permissions" "$aw/xmltree" "$report" "$aw/summary" "$apk" \
    >"$aw/manifest" || exit 2
  echo "== manifest summary"
  cat "$aw/summary" || exit 2
  echo "=="
  apk_lines "$aw/manifest"
  if ! cmp -s "$aw/summary" "$exp/manifest-$variant.txt"; then
    ahit Manifest "$exp/manifest-$variant.txt" "differs from the APK's manifest summary (the diff is on stderr)"
    show_diff "$exp/manifest-$variant.txt" "$aw/summary"
  fi
  grep -n -e INTERNET -- "$report" >"$aw/internet"
  [ $? -le 1 ] || exit 2
  while IFS= read -r line; do
    ahit Manifest "$report:${line%%:*}" "names INTERNET: ${line#*:}"
  done <"$aw/internet"
  # 2. The APK's bytes and entries, the native libraries (each through elf_check) and the dex
  # files (each through dex_scan).
  apk_py scan "$apk" "$exp/native-libs.txt" "$aw" "$testkey" "$jnilibs" $markers >"$aw/scan" || exit 2
  apk_lines "$aw/scan"
  [ "$classes" -gt 0 ] ||
    apkfail "dexdump listed no com.keepcrypt class in the APK's $ndex dex file(s), so the reference scan read none of KeepCrypt's code"
  # 3. Alignment and the signature.
  if ! zipalign -c -P 16 -v 4 "$apk" >"$aw/zipalign" 2>&1 </dev/null; then
    ahit Zipalign "$apk" 'zipalign -c -P 16 -v 4 fails (its lines but the OK ones are on stderr)'
    grep -v -e '(OK' "$aw/zipalign" | sed 's/^/    /' >&2
  fi
  if ! apksigner verify --print-certs "$apk" >"$aw/apksigner" 2>&1 </dev/null; then
    ahit Signature "$apk" 'apksigner verify fails (its output is on stderr)'
    sed 's/^/    /' "$aw/apksigner" >&2
  else
    signers=$(sed -n 's/^Signer #[0-9][0-9]* certificate SHA-256 digest: //p' "$aw/apksigner")
    [ "$signers" = "$cert" ] ||
      ahit Signature "$apk" "signed by $(printf '%s\n' "${signers:-no certificate}" | paste -s -d ' ' -), not by the run's throwaway key $cert alone"
  fi
  if [ "$hits" -ne 0 ]; then
    echo "banned-api-check --apk $variant $apk: $hits hit(s)"
    exit 1
  fi
  if [ "$variant" = withTestRegistry ]; then
    kwhat="the test-registry build: its registry marker and the test key and no other hit"
  else
    kwhat="no hit"
  fi
  echo "banned-api-check --apk $variant $apk: clean: the manifest summary equals $exp/manifest-$variant.txt, with no network permission, provider, receiver, service or <queries>, backup, cleartext traffic and debugging off and one exported activity, and the merger report names no INTERNET; $libs native libraries exactly as $exp/native-libs.txt lists them, every 64-bit one 16 KB aligned, and no other ELF; $kclean libkeepcrypt.so, each the bytes of $jnilibs's scanned copy, under the release-artifact scan with $kwhat, exporting exactly our two symbols beside secp256k1-sys's four and needing only libc.so, libm.so and libdl.so; the other libraries through elf_check; no marker or test key in the APK or any other entry; $classes com.keepcrypt classes in $ndex dex files with no banned RNG reference; zipalign -c -P 16 -v 4 passes; signed by the run's throwaway key alone ($cert)"
  exit 0
}

# --- APK selftest mode ---------------------------------------------------------------------------

# The hit categories of the APK check, for its selftest.
acats='^(Manifest|NativeLib|Format|Symbol|StdRandom|OSImport|Marker|TestKey|DexRef|Zipalign|Signature): '

# axexpect NAME TEXT ARG...: --apk ARG... in a new process, with the stub tools reading $c first on
# PATH, must exit 2 with TEXT in its output.
axexpect() {
  axname=$1
  want=$2
  shift 2
  out=$(KC_STUB=$c PATH=$st/bin:$PATH sh "$self" --apk "$@" 2>&1)
  rc=$?
  ok=no
  if [ "$rc" -eq 2 ]; then
    case $out in *"$want"*) ok=yes ;; esac
  fi
  if [ "$ok" = yes ]; then
    pass=$((pass + 1))
    printf 'PASS %s -> exit 2: %s\n' "$axname" "${out##*$nl}"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: wanted exit 2 with "%s", got exit %s:\n' "$axname" "$want" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

# anew NAME: $c, a fresh copy of the base case ($st/base): the stub tools' outputs (aapt2's three
# dumps, apksigner's), the merger report, the stub APK's files and its entry list
# (ENTRY=FILE lines, FILE under $c) and the expected directory.
anew() {
  c=$st/$1
  cp -R "$st/base" "$c" || exit 2
}

# abuild: $c/app.apk from $c/entries, with $c/comment as the zip comment.
abuild() {
  set --
  while IFS= read -r e; do
    set -- "$@" "${e%%=*}=$c/${e#*=}"
  done <"$c/entries"
  apk_py zip "$c/app.apk" "$(cat "$c/comment")" "$@" || exit 2
}

# alist: $c/expected/native-libs.txt from every lib/<abi>/<name>.so entry of $c/entries, each
# libkeepcrypt.so as android-rust.sh's.
alist() {
  : >"$c/expected/native-libs.txt" || exit 2
  while IFS= read -r e; do
    case ${e%%=*} in
      lib/*/libkeepcrypt.so)
        n=${e%%=*}
        n=${n#lib/}
        printf '%s libkeepcrypt.so android-rust.sh\n' "${n%%/*}" >>"$c/expected/native-libs.txt" || exit 2
        ;;
      lib/*/*.so)
        n=${e%%=*}
        n=${n#lib/}
        printf '%s %s %s\n' "${n%%/*}" "${n#*/}" "$(sha256 "$c/${e#*=}")" >>"$c/expected/native-libs.txt" || exit 2
        ;;
    esac
  done <"$c/entries"
}

# aregen: $c/expected/manifest-shipping.txt remade from $c's dumps and report, so that only a hard
# rule can fail the case.
aregen() {
  apk_py manifest "$c/badging.txt" "$c/permissions.txt" "$c/xmltree.txt" "$c/report.txt" \
    "$c/expected/manifest-shipping.txt" x >/dev/null || exit 2
}

# aappend FILE LINE...: each LINE appended to FILE.
aappend() {
  af=$1
  shift
  printf '%s\n' "$@" >>"$af" || exit 2
}

# akc ABI WORD...: $c's libkeepcrypt.so for ABI rebuilt as a stub with the base case's words, then
# each WORD given (a symbol, DEF:, NEEDED: or NOSYMTAB; -WORD drops that base word), and its copy in
# $c/jnilibs made the same, so only what the case changes differs from the base.
akc() {
  kabi=$1
  shift
  kwords=$akc_base
  for w; do
    case $w in
      -*) kwords=$(printf '%s\n' $kwords | grep -v -x -F -e "${w#-}" | paste -s -d ' ' -) ;;
      *) kwords="$kwords $w" ;;
    esac
  done
  case $kabi in arm64-v8a | x86_64) kalign=4000 ;; *) kalign=1000 ;; esac
  # $kwords unquoted: its words hold no space.
  apk_py elf "$c/files/kc-$kabi.so" "$kabi" "$kalign" $kwords || exit 2
  akc_copy "$kabi"
}

# akc_copy ABI: $c/jnilibs/ABI/libkeepcrypt.so made a copy of $c's stub for ABI.
akc_copy() {
  mkdir -p "$c/jnilibs/$1" && cp "$c/files/kc-$1.so" "$c/jnilibs/$1/libkeepcrypt.so" || exit 2
}

# akc_registry ABI [marker|key]...: the registry marker and the test key's bytes (both, or the
# ones named) appended to $c's libkeepcrypt.so for ABI and its copy, as a test-registry build holds
# them.
akc_registry() {
  kabi=$1
  shift
  [ $# -gt 0 ] || set -- marker key
  for w; do
    case $w in
      marker) printf ' KC_TEST_REGISTRY_DO_NOT_SHIP\n' >>"$c/files/kc-$kabi.so" || exit 2 ;;
      key) write_testkey "$c/kc-key" && cat "$c/kc-key" >>"$c/files/kc-$kabi.so" || exit 2 ;;
    esac
  done
  akc_copy "$kabi"
}

# acase NAME WANT-HIT: $c's APK built, then --apk on it in a new process (VARIANT $avariant, or
# shipping, with $c/jnilibs as JNILIBS_DIR), with the stub tools reading $c, must exit 1 with exactly
# one hit, which starts with WANT-HIT; with WANT-HIT empty (the control), exit 0 with no hit.
acase() {
  abuild
  aout=$(KC_STUB=$c PATH=$st/bin:$PATH sh "$self" --apk "${avariant:-shipping}" "$c/app.apk" "$c/expected" "$c/report.txt" \
    "$acert" "$c/jnilibs" 2>&1)
  rc=$?
  got=$(printf '%s\n' "$aout" | grep -E "$acats")
  count=$(printf '%s\n' "$aout" | grep -c -E "$acats")
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
    if [ -n "$2" ]; then want_rc=1; else want_rc=0; fi
    printf 'FAIL %s: wanted exit %s with %s, got exit %s:\n' "$1" "$want_rc" "${2:-no hit}" "$rc"
    printf '%s\n' "$aout" | sed 's/^/    /'
  fi
}

# apk_selftest: --apk's refusals and hard rules on stub tools and stub APKs (see "APK selftest
# mode" in the header).
apk_selftest() {
  st=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-selftest-apk.XXXXXX") || exit 2
  trap 'rm -rf "$st"' EXIT
  trap 'exit 2' HUP INT TERM
  td=$here/testdata/apk
  committed=$here/../mobile/android/expected/manifest-shipping.txt
  for f in "$td/badging.txt" "$td/permissions.txt" "$td/xmltree.txt" "$td/merger-report.txt" "$committed"; do
    readable "$f" --selftest-apk
  done
  command -v python3 >/dev/null 2>&1 || { echo 'banned-api-check: --selftest-apk: no python3 on PATH' >&2; exit 2; }
  pass=0
  fail=0
  acert=$(printf '%064d' 0 | tr 0 c)
  # The stub tools. aapt2 prints $KC_STUB's dumps; dexdump -d prints the file it is given (a stub
  # dex file is the text dexdump would print for it; without -d the real one prints no code, so the
  # stub refuses); zipalign -c -P 16 -v 4 passes unless $KC_STUB/zipalign-fails exists; apksigner
  # verify --print-certs prints $KC_STUB/apksigner.txt, or fails if $KC_STUB/apksigner-fails
  # exists; llvm-nm lists the NM:<name> words in its file with -u (undefined symbols), the
  # DEF:<name> words with --defined-only, and both otherwise; llvm-readobj --section-headers lists a
  # .symtab unless the file holds NOSYMTAB, and --needed-libs lists its NEEDED:<library> words.
  # zipalign and apksigner refuse other arguments, as dexdump does without -d, so --apk cannot drop
  # one unseen.
  mkdir "$st/bin" || exit 2
  cat >"$st/bin/aapt2" <<'STUB'
#!/bin/sh
case $1-$2 in
  dump-badging) cat "$KC_STUB/badging.txt" ;;
  dump-permissions) cat "$KC_STUB/permissions.txt" ;;
  dump-xmltree) cat "$KC_STUB/xmltree.txt" ;;
  *) echo "stub aapt2: $*" >&2; exit 1 ;;
esac
STUB
  cat >"$st/bin/dexdump" <<'STUB'
#!/bin/sh
[ $# -eq 2 ] && [ "$1" = -d ] || { echo "stub dexdump: wants -d FILE (the code, not only the headers), got: $*" >&2; exit 1; }
cat "$2"
STUB
  cat >"$st/bin/zipalign" <<'STUB'
#!/bin/sh
[ $# -eq 6 ] && [ "$1 $2 $3 $4 $5" = '-c -P 16 -v 4' ] && [ -f "$6" ] ||
  { echo "stub zipalign: wants -c -P 16 -v 4 APK, got: $*" >&2; exit 1; }
if [ -f "$KC_STUB/zipalign-fails" ]; then
  echo 'lib/arm64-v8a/libandroidx.graphics.path.so (BAD - 4096)'
  echo 'Verification FAILED'
  exit 1
fi
echo 'Verification succesful'
STUB
  cat >"$st/bin/apksigner" <<'STUB'
#!/bin/sh
[ $# -eq 3 ] && [ "$1 $2" = 'verify --print-certs' ] && [ -f "$3" ] ||
  { echo "stub apksigner: wants verify --print-certs APK, got: $*" >&2; exit 1; }
if [ -f "$KC_STUB/apksigner-fails" ]; then
  echo 'DOES NOT VERIFY'
  echo 'ERROR: APK Signature Scheme v2 signer #1: Malformed additional attribute'
  exit 1
fi
cat "$KC_STUB/apksigner.txt"
STUB
  cat >"$st/bin/llvm-nm" <<'STUB'
#!/bin/sh
for f; do :; done
case " $* " in
  *" -u "*) w=NM ;;
  *" --defined-only "*) w=DEF ;;
  *) w='NM|DEF' ;;
esac
grep -a -o -E "($w):[A-Za-z0-9_]*" "$f" | sed 's/^[A-Z]*://'
STUB
  cat >"$st/bin/llvm-readobj" <<'STUB'
#!/bin/sh
[ $# -eq 2 ] || { echo "stub llvm-readobj: wants OPTION FILE, got: $*" >&2; exit 1; }
case $1 in
  --section-headers) grep -q -a -e NOSYMTAB "$2" || printf 'Section {\n  Index: 1\n  Name: .symtab (1)\n}\n' ;;
  --needed-libs)
    printf 'File: %s\nNeededLibraries [\n' "$2"
    grep -a -o -E 'NEEDED:[A-Za-z0-9_.+-]*' "$2" | sed 's/^NEEDED:/  /'
    echo ']'
    ;;
  *) echo "stub llvm-readobj: $*" >&2; exit 1 ;;
esac
STUB
  chmod +x "$st/bin/aapt2" "$st/bin/dexdump" "$st/bin/zipalign" "$st/bin/apksigner" "$st/bin/llvm-nm" \
    "$st/bin/llvm-readobj" || exit 2
  # The base case: aapt2's dumps of the shipping APK and a stand-in merger report
  # (scripts/testdata/apk/), the run's signer, and a stub APK as the real one is laid out: the
  # manifest, two dex files (a library class that names kotlin.random, which passes, and
  # KeepCrypt's classes), resources, graphics-path's three libraries and libkeepcrypt.so for each
  # ABI (each 32-bit one 4 KB aligned, which only 64-bit libraries may not be), the latter importing
  # getrandom, exporting our two symbols and secp256k1-sys's four and needing libc.so, libm.so and
  # libdl.so, with its scanned copy in jnilibs/<abi>/.
  b=$st/base
  mkdir -p "$b/files" "$b/expected" || exit 2
  cp "$td/badging.txt" "$td/permissions.txt" "$td/xmltree.txt" "$b/" && cp "$td/merger-report.txt" "$b/report.txt" || exit 2
  aappend "$b/apksigner.txt" 'Signer #1 certificate DN: CN=KeepCrypt CI throwaway key' "Signer #1 certificate SHA-256 digest: $acert"
  : >"$b/comment" || exit 2
  echo 'stub manifest' >"$b/files/AndroidManifest.xml" && echo 'stub resources' >"$b/files/resources.arsc" || exit 2
  aappend "$b/files/classes.dex" "Processing 'classes.dex'..." "Opened 'classes.dex', DEX version '035'" \
    'Class #0            -' "  Class descriptor  : 'Landroidx/compose/runtime/SnapshotStateKt;'" \
    "  Superclass        : 'Ljava/lang/Object;'" \
    '000100: 7110 0100 0000                         |0000: invoke-static {v0}, Lkotlin/random/RandomKt;.Random:(I)Lkotlin/random/Random; // method@0001' \
    'Class #1            -' "  Class descriptor  : 'Lcom/keepcrypt/entropy/MainActivity;'" \
    "  Superclass        : 'Lcom/keepcrypt/entropy/secure/SecureActivity;'" \
    '0001b0: 7010 0200 0000                         |0000: invoke-direct {v0}, Lcom/keepcrypt/entropy/secure/SecureActivity;.<init>:()V // method@0002'
  aappend "$b/files/classes2.dex" "Processing 'classes2.dex'..." 'Class #0            -' \
    "  Class descriptor  : 'Lcom/keepcrypt/entropy/secure/SecureActivity;'" \
    "  Superclass        : 'Landroidx/activity/ComponentActivity;'"
  apk_py elf "$b/files/arm64.so" arm64-v8a 4000 memcpy __cxa_finalize &&
    apk_py elf "$b/files/arm.so" armeabi-v7a 1000 memcpy __cxa_finalize &&
    apk_py elf "$b/files/x64.so" x86_64 4000 memcpy __cxa_finalize || exit 2
  akc_base="getrandom memcpy DEF:JNI_OnLoad DEF:Java_com_keepcrypt_entropy_ffi_Native_call $(printf 'DEF:%s ' $kc_secp)"
  akc_base="$akc_base NEEDED:libc.so NEEDED:libm.so NEEDED:libdl.so"
  c=$b
  for kabi in arm64-v8a armeabi-v7a x86_64; do
    akc "$kabi"
  done
  aappend "$b/entries" AndroidManifest.xml=files/AndroidManifest.xml classes.dex=files/classes.dex \
    classes2.dex=files/classes2.dex resources.arsc=files/resources.arsc \
    lib/arm64-v8a/libandroidx.graphics.path.so=files/arm64.so lib/armeabi-v7a/libandroidx.graphics.path.so=files/arm.so \
    lib/x86_64/libandroidx.graphics.path.so=files/x64.so lib/arm64-v8a/libkeepcrypt.so=files/kc-arm64-v8a.so \
    lib/armeabi-v7a/libkeepcrypt.so=files/kc-armeabi-v7a.so lib/x86_64/libkeepcrypt.so=files/kc-x86_64.so
  alist
  cp "$committed" "$b/expected/manifest-shipping.txt" || exit 2
  # Refusals, before any tool runs or the APK is read.
  e=$b/expected
  j=$b/jnilibs
  axexpect apk-error-usage 'usage:' shipping "$b/app.apk" "$e" "$b/report.txt" "$acert"
  axexpect apk-error-variant 'VARIANT is shipping or withTestRegistry, not debug' debug "$b/app.apk" "$e" "$b/report.txt" "$acert" "$j"
  axexpect apk-error-cert 'CERT_SHA256 is not 64 lowercase hex digits: CCCC' shipping "$b/app.apk" "$e" "$b/report.txt" CCCC "$j"
  axexpect apk-error-missing-expected-dir "EXPECTED_DIR $st/absent is not a directory" shipping "$b/app.apk" "$st/absent" "$b/report.txt" "$acert" "$j"
  axexpect apk-error-missing-jnilibs-dir "JNILIBS_DIR $st/absent is not a directory" shipping "$b/app.apk" "$e" "$b/report.txt" "$acert" "$st/absent"
  axexpect apk-error-missing-expected-manifest "cannot read $e/manifest-withTestRegistry.txt, or it is empty" withTestRegistry "$b/app.apk" "$e" "$b/report.txt" "$acert" "$j"
  axexpect apk-error-missing-report "cannot read $st/absent.txt, or it is empty" shipping "$b/app.apk" "$e" "$st/absent.txt" "$acert" "$j"
  axexpect apk-error-missing-apk "cannot read $st/absent.apk" shipping "$st/absent.apk" "$e" "$b/report.txt" "$acert" "$j"
  mkdir "$st/nobin" || exit 2
  for t in basename dirname grep python3; do
    ln -s "$(command -v "$t")" "$st/nobin/$t" || exit 2
  done
  shell=$(command -v sh) || exit 2
  touch "$b/app.apk" || exit 2
  out=$(PATH=$st/nobin "$shell" "$self" --apk shipping "$b/app.apk" "$e" "$b/report.txt" "$acert" "$j" 2>&1)
  rc=$?
  want='banned-api-check: --apk: no aapt2 on PATH (aapt2, dexdump, zipalign and apksigner from the build-tools, llvm-nm and llvm-readobj from the NDK)'
  if [ "$rc" -eq 2 ] && [ "$out" = "$want" ]; then
    pass=$((pass + 1))
    printf 'PASS apk-error-no-aapt2 -> exit 2: %s\n' "$out"
  else
    fail=$((fail + 1))
    printf 'FAIL apk-error-no-aapt2: wanted exit 2 with "%s", got exit %s:\n' "$want" "$rc"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
  rm "$b/app.apk" || exit 2
  # The control: the stub APK passes, its manifest summary from the shipping APK's dumps equal to
  # the committed mobile/android/expected/manifest-shipping.txt.
  anew clean
  acase apk-clean ''
  # The manifest's hard rules, each with the case's own summary as the expected one, so that only
  # the rule can fail it; then the comparison itself.
  anew internet
  aappend "$c/permissions.txt" "uses-permission: name='android.permission.INTERNET'"
  aappend "$c/xmltree.txt" '      E: uses-permission (line=60)' \
    '        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.INTERNET" (Raw: "android.permission.INTERNET")'
  aregen
  acase apk-manifest-internet "Manifest: $c/app.apk: a network permission (rule 9): uses-permission android.permission.INTERNET"
  anew provider
  aappend "$c/xmltree.txt" '          E: provider (line=60)' \
    '            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.CanaryProvider" (Raw: "com.example.CanaryProvider")' \
    '            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=false'
  aregen
  acase apk-manifest-provider "Manifest: $c/app.apk: a provider (the app has no provider, receiver or service): provider com.example.CanaryProvider exported=false"
  anew allow-backup
  sed 's/allowBackup(0x01010280)=false/allowBackup(0x01010280)=true/' "$b/xmltree.txt" >"$c/xmltree.txt" || exit 2
  aregen
  acase apk-manifest-allow-backup-true "Manifest: $c/app.apk: application allowBackup=true, not false"
  anew debuggable
  awk '{ print } /allowBackup\(0x01010280\)=false/ { print "        A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=true" }' \
    "$b/xmltree.txt" >"$c/xmltree.txt" || exit 2
  aappend "$c/badging.txt" application-debuggable
  aregen
  acase apk-manifest-debuggable "Manifest: $c/app.apk: application debuggable=true, not false"
  anew exported
  aappend "$c/xmltree.txt" '          E: activity (line=60)' \
    '            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.keepcrypt.entropy.Other" (Raw: "com.keepcrypt.entropy.Other")' \
    '            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true'
  aregen
  acase apk-manifest-extra-exported-activity "Manifest: $c/app.apk: 2 exported activities, not the one launcher: com.keepcrypt.entropy.MainActivity, com.keepcrypt.entropy.Other"
  anew queries
  aappend "$c/xmltree.txt" '      E: queries (line=60)' '          E: package (line=61)' \
    '            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.wallet" (Raw: "com.example.wallet")'
  aregen
  acase apk-manifest-queries "Manifest: $c/app.apk: a <queries> element (package visibility): queries package com.example.wallet"
  for p in ACCESS_NETWORK_STATE ACCESS_WIFI_STATE; do
    anew "network-$p"
    aappend "$c/permissions.txt" "uses-permission: name='android.permission.$p'"
    aregen
    acase "apk-manifest-$p" "Manifest: $c/app.apk: a network permission (rule 9): uses-permission android.permission.$p"
  done
  for k in receiver service; do
    anew "$k"
    aappend "$c/xmltree.txt" "          E: $k (line=60)" \
      '            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.Canary" (Raw: "com.example.Canary")' \
      '            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=false'
    aregen
    acase "apk-manifest-$k" "Manifest: $c/app.apk: a $k (the app has no provider, receiver or service): $k com.example.Canary exported=false"
  done
  anew alias
  aappend "$c/xmltree.txt" '          E: activity-alias (line=60)' \
    '            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.keepcrypt.entropy.Alias" (Raw: "com.keepcrypt.entropy.Alias")' \
    '            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true' \
    '            A: http://schemas.android.com/apk/res/android:targetActivity(0x01010202)="com.keepcrypt.entropy.MainActivity" (Raw: "com.keepcrypt.entropy.MainActivity")'
  aregen
  acase apk-manifest-exported-activity-alias "Manifest: $c/app.apk: 2 exported activities, not the one launcher: com.keepcrypt.entropy.Alias, com.keepcrypt.entropy.MainActivity"
  anew data-extraction
  grep -v -e ':dataExtractionRules(' "$b/xmltree.txt" >"$c/xmltree.txt" || exit 2
  aregen
  acase apk-manifest-data-extraction-rules-unset "Manifest: $c/app.apk: application dataExtractionRules=unset, not set"
  for f in fullBackupContent usesCleartextTraffic; do
    anew "$f"
    sed "s/:$f(\\(0x[0-9a-f]*\\))=false/:$f(\\1)=true/" "$b/xmltree.txt" >"$c/xmltree.txt" || exit 2
    aregen
    acase "apk-manifest-$f-true" "Manifest: $c/app.apk: application $f=true, not false"
  done
  anew differs
  sed 's/^targetSdk 36$/targetSdk 35/' "$committed" >"$c/expected/manifest-shipping.txt" || exit 2
  acase apk-manifest-summary-differs "Manifest: $c/expected/manifest-shipping.txt: differs from the APK's manifest summary"
  # Every attribute of the application and of each component is in the summary: a library that
  # swaps the class instantiating every component, puts its own Application class in place of
  # KeepCryptApp (a second name attribute, which the dump's reader takes last) or moves the
  # activity to another process changes it, against the committed expected one.
  anew app-component-factory
  sed 's/"androidx[.]core[.]app[.]CoreComponentFactory"/"com.example.Factory"/' "$b/xmltree.txt" >"$c/xmltree.txt" || exit 2
  acase apk-manifest-app-component-factory-changed "Manifest: $c/expected/manifest-shipping.txt: differs from the APK's manifest summary"
  anew application-class
  awk '{ print } /allowBackup\(0x01010280\)=false/ { print "        A: http://schemas.android.com/apk/res/android:name(0x01010003)=\"com.example.App\" (Raw: \"com.example.App\")" }' \
    "$b/xmltree.txt" >"$c/xmltree.txt" || exit 2
  acase apk-manifest-application-class-added "Manifest: $c/expected/manifest-shipping.txt: differs from the APK's manifest summary"
  anew activity-process
  awk '{ print } /exported\(0x01010010\)=true/ { print "            A: http://schemas.android.com/apk/res/android:process(0x01010011)=\":x\" (Raw: \":x\")" }' \
    "$b/xmltree.txt" >"$c/xmltree.txt" || exit 2
  acase apk-manifest-activity-attribute-added "Manifest: $c/expected/manifest-shipping.txt: differs from the APK's manifest summary"
  anew report-internet
  n=$(wc -l <"$c/report.txt") || exit 2
  aappend "$c/report.txt" 'uses-permission#android.permission.INTERNET' \
    'ADDED from [com.example:canary:1.0] /stub/canary/AndroidManifest.xml:7:5-67' \
    'REJECTED from /stub/app/src/main/AndroidManifest.xml:14:5-90'
  aregen
  acase apk-merger-report-internet "Manifest: $c/report.txt:$((n + 1)): names INTERNET: uses-permission#android.permission.INTERNET"
  # The native libraries.
  anew unlisted
  aappend "$c/entries" lib/x86_64/libextra.so=files/x64.so
  acase apk-unlisted-so 'NativeLib: lib/x86_64/libextra.so: not in native-libs.txt'
  anew page-4k
  apk_py elf "$c/files/arm64.so" arm64-v8a 1000 memcpy || exit 2
  alist
  acase apk-4kb-aligned-64-bit-so 'NativeLib: lib/arm64-v8a/libandroidx.graphics.path.so: LOAD segments aligned to 0x1000, 0x1000, not 0x4000 on every one'
  anew listed-sha
  sed 's/^\(x86_64 libandroidx[^ ]*\) .*/\1 '"$(printf '%064d' 0)"'/' "$b/expected/native-libs.txt" >"$c/expected/native-libs.txt" || exit 2
  acase apk-so-with-another-sha256 'NativeLib: lib/x86_64/libandroidx.graphics.path.so: SHA-256 '
  anew listed-missing
  aappend "$c/expected/native-libs.txt" "armeabi-v7a libgone.so $(printf '%064d' 0)"
  acase apk-listed-so-missing 'NativeLib: lib/armeabi-v7a/libgone.so: in native-libs.txt but not in the APK'
  anew abi-x86
  aappend "$c/entries" lib/x86/libandroidx.graphics.path.so=files/x64.so
  acase apk-so-for-x86 "NativeLib: lib/x86/libandroidx.graphics.path.so: an ABI outside MA:23's three"
  anew other-machine
  apk_py elf "$c/files/x64.so" armeabi-v7a 4000 memcpy || exit 2
  alist
  acase apk-so-for-another-machine 'NativeLib: lib/x86_64/libandroidx.graphics.path.so: an ELF of class 1 for machine 40'
  anew elf-outside-lib
  aappend "$c/entries" assets/payload.bin=files/x64.so
  acase apk-elf-outside-lib 'NativeLib: assets/payload.bin: an ELF outside lib/<abi>/*.so'
  anew rand
  apk_py elf "$c/files/x64.so" x86_64 4000 memcpy rand || exit 2
  alist
  acase apk-so-importing-rand 'Symbol: lib/x86_64/libandroidx.graphics.path.so: undefined rand'
  anew page-24k
  apk_py elf "$c/files/x64.so" x86_64 6000 memcpy || exit 2
  alist
  acase apk-64-bit-so-aligned-0x6000 'NativeLib: lib/x86_64/libandroidx.graphics.path.so: LOAD segments aligned to 0x6000, 0x6000, not 0x4000 on every one'
  anew no-load
  apk_py elf "$c/files/x64.so" x86_64 none memcpy || exit 2
  alist
  acase apk-64-bit-so-without-load-segment 'NativeLib: lib/x86_64/libandroidx.graphics.path.so: LOAD segments aligned to nothing (no LOAD segment), not 0x4000 on every one'
  anew truncated
  printf '\177ELF\002\001\001' >"$c/files/x64.so" || exit 2
  alist
  acase apk-truncated-elf 'Format: lib/x86_64/libandroidx.graphics.path.so: a truncated ELF header or program header table'
  anew not-elf
  aappend "$c/entries" lib/x86_64/libx.so=files/resources.arsc
  acase apk-so-not-an-elf 'NativeLib: lib/x86_64/libx.so: not an ELF file'
  anew subdirectory
  aappend "$c/entries" lib/x86_64/sub/libx.so=files/x64.so
  acase apk-so-in-a-subdirectory 'NativeLib: lib/x86_64/sub/libx.so: a file under lib/ that is not lib/<abi>/<name>.so'
  # libkeepcrypt.so (M5 commit 14): the scanned copy's bytes, stored, in every ABI, 16 KB pages on
  # 64-bit, the release-artifact scan, our exports beside secp256k1-sys's four, and libc.so, libm.so
  # and libdl.so alone.
  anew kc-differs
  printf 'x' >>"$c/jnilibs/x86_64/libkeepcrypt.so" || exit 2
  acase apk-libkeepcrypt-not-the-scanned-copy "NativeLib: lib/x86_64/libkeepcrypt.so: SHA-256 $(sha256 "$b/files/kc-x86_64.so"), not that of $c/jnilibs/x86_64/libkeepcrypt.so"
  anew kc-missing
  grep -v -e '^lib/x86_64/libkeepcrypt[.]so=' "$b/entries" >"$c/entries" || exit 2
  acase apk-libkeepcrypt-missing-for-an-abi 'NativeLib: lib/x86_64/libkeepcrypt.so: in native-libs.txt but not in the APK'
  anew kc-compressed
  cp "$c/files/kc-x86_64.so" "$c/files/kc-x86_64.so.deflate" || exit 2
  sed 's#^lib/x86_64/libkeepcrypt[.]so=.*#lib/x86_64/libkeepcrypt.so=files/kc-x86_64.so.deflate#' "$b/entries" >"$c/entries" || exit 2
  acase apk-libkeepcrypt-compressed 'NativeLib: lib/x86_64/libkeepcrypt.so: compressed in the APK'
  anew kc-page-4k
  apk_py elf "$c/files/kc-arm64-v8a.so" arm64-v8a 1000 $akc_base || exit 2
  akc_copy arm64-v8a
  acase apk-libkeepcrypt-4kb-aligned 'NativeLib: lib/arm64-v8a/libkeepcrypt.so: LOAD segments aligned to 0x1000, 0x1000, not 0x4000'
  anew kc-stripped
  akc x86_64 NOSYMTAB
  acase apk-libkeepcrypt-stripped 'Format: lib/x86_64/libkeepcrypt.so: a stripped file with no symbol table'
  anew kc-rand
  akc arm64-v8a rand
  acase apk-libkeepcrypt-importing-rand 'Symbol: lib/arm64-v8a/libkeepcrypt.so: undefined rand'
  anew kc-no-getrandom
  akc armeabi-v7a -getrandom
  acase apk-libkeepcrypt-without-the-os-import 'OSImport: lib/armeabi-v7a/libkeepcrypt.so: no undefined getrandom'
  anew kc-extra-export
  akc x86_64 DEF:kc_extra
  acase apk-libkeepcrypt-extra-export 'NativeLib: lib/x86_64/libkeepcrypt.so: defines JNI_OnLoad Java_com_keepcrypt_entropy_ffi_Native_call kc_extra beside'
  anew kc-no-onload
  akc x86_64 -DEF:JNI_OnLoad
  acase apk-libkeepcrypt-without-jni-onload 'NativeLib: lib/x86_64/libkeepcrypt.so: defines Java_com_keepcrypt_entropy_ffi_Native_call beside'
  anew kc-other-secp
  akc arm64-v8a DEF:rustsecp256k1_v0_10_0_context_clone
  acase apk-libkeepcrypt-another-secp256k1-export 'NativeLib: lib/arm64-v8a/libkeepcrypt.so: defines JNI_OnLoad Java_com_keepcrypt_entropy_ffi_Native_call rustsecp256k1_v0_10_0_context_clone beside'
  anew kc-liblog
  akc armeabi-v7a NEEDED:liblog.so
  acase apk-libkeepcrypt-needs-liblog 'NativeLib: lib/armeabi-v7a/libkeepcrypt.so: DT_NEEDED liblog.so: not libc.so, libm.so or libdl.so'
  anew kc-no-libc
  akc x86_64 -NEEDED:libc.so
  acase apk-libkeepcrypt-without-libc 'NativeLib: lib/x86_64/libkeepcrypt.so: no DT_NEEDED libc.so'
  # The shipping APK's library holds no marker and no key; a stored library's bytes are searched
  # once, as the library, not again in the APK's own bytes.
  anew kc-shipping-marker
  akc_registry arm64-v8a marker
  acase apk-libkeepcrypt-registry-marker-in-shipping 'Marker: lib/arm64-v8a/libkeepcrypt.so: KC_TEST_REGISTRY_DO_NOT_SHIP'
  anew kc-shipping-key
  akc_registry x86_64 key
  acase apk-libkeepcrypt-test-key-in-shipping "TestKey: lib/x86_64/libkeepcrypt.so: the test registry public key $testkey"
  # The test-registry APK: each library must hold its registry marker and the test key, and nothing
  # else may, inside it or anywhere in the APK.
  avariant=withTestRegistry
  anew registry
  for kabi in arm64-v8a armeabi-v7a x86_64; do
    akc_registry "$kabi"
  done
  cp "$c/expected/manifest-shipping.txt" "$c/expected/manifest-withTestRegistry.txt" || exit 2
  cp -R "$c" "$st/registry-base" || exit 2
  acase apk-registry-clean ''
  anew2() {
    c=$st/$1
    cp -R "$st/registry-base" "$c" || exit 2
  }
  anew2 registry-no-marker
  akc x86_64
  akc_registry x86_64 key
  acase apk-registry-library-without-its-marker 'NativeLib: lib/x86_64/libkeepcrypt.so: no KC_TEST_REGISTRY_DO_NOT_SHIP'
  anew2 registry-no-key
  akc armeabi-v7a
  akc_registry armeabi-v7a marker
  acase apk-registry-library-without-the-test-key 'NativeLib: lib/armeabi-v7a/libkeepcrypt.so: no test registry key'
  anew2 registry-stub-marker
  printf ' KC_TEST_SOURCE_DO_NOT_SHIP\n' >>"$c/files/kc-arm64-v8a.so" || exit 2
  akc_copy arm64-v8a
  acase apk-registry-library-with-the-stub-marker 'Marker: lib/arm64-v8a/libkeepcrypt.so: KC_TEST_SOURCE_DO_NOT_SHIP'
  anew2 registry-comment
  echo KC_TEST_REGISTRY_DO_NOT_SHIP >"$c/comment" || exit 2
  acase apk-registry-marker-outside-the-library "Marker: $c/app.apk: KC_TEST_REGISTRY_DO_NOT_SHIP"
  anew2 registry-key-in-resources
  printf '%0256d\n' 0 >"$c/files/resources.arsc" && write_testkey "$c/key" && cat "$c/key" >>"$c/files/resources.arsc" || exit 2
  acase apk-registry-test-key-in-resources "TestKey: resources.arsc: the test registry public key $testkey"
  avariant=
  # The byte search and the dex reference scan.
  anew marker-dex
  aappend "$c/files/classes2.dex" '000200: 1a00 0400                              |0000: const-string v0, "KC_TEST_REGISTRY_DO_NOT_SHIP" // string@0004'
  acase apk-marker-in-a-dex 'Marker: classes2.dex: KC_TEST_REGISTRY_DO_NOT_SHIP'
  anew testkey
  printf '%0256d\n' 0 >"$c/files/resources.arsc" && write_testkey "$c/key" && cat "$c/key" >>"$c/files/resources.arsc" || exit 2
  acase apk-test-key-in-resources "TestKey: resources.arsc: the test registry public key $testkey"
  anew comment
  echo KC_SIMULATOR_DO_NOT_SHIP >"$c/comment" || exit 2
  acase apk-marker-in-the-zip-comment "Marker: $c/app.apk: KC_SIMULATOR_DO_NOT_SHIP"
  anew dexref
  aappend "$c/files/classes.dex" '0001b6: 2200 0300                              |0003: new-instance v0, Ljava/util/Random; // type@0003'
  acase apk-banned-reference-in-a-keepcrypt-class 'DexRef: classes.dex: Lcom/keepcrypt/entropy/MainActivity; references Ljava/util/Random;'
  # Every other name of dex_banned, each in MainActivity's code as dexdump -d prints it (the base
  # case's library class naming kotlin.random passes).
  for adx in \
    'kotlin-random-default|sget-object v0, Lkotlin/random/Random;.Default:Lkotlin/random/Random$Default; // field@0005|Lkotlin/random/' \
    'math-random|invoke-static {}, Ljava/lang/Math;.random:()D // method@0006|Ljava/lang/Math;.random:' \
    'strictmath-random|invoke-static {}, Ljava/lang/StrictMath;.random:()D // method@0006|Ljava/lang/StrictMath;.random:' \
    'uuid-random-uuid|invoke-static {}, Ljava/util/UUID;.randomUUID:()Ljava/util/UUID; // method@0007|Ljava/util/UUID;.randomUUID:' \
    'secure-random|new-instance v0, Ljava/security/SecureRandom; // type@0008|Ljava/security/SecureRandom;' \
    'java-util-random-package|invoke-static {}, Ljava/util/random/RandomGenerator;.getDefault:()Ljava/util/random/RandomGenerator; // method@0009|Ljava/util/random/' \
    'splittable-random|new-instance v0, Ljava/util/SplittableRandom; // type@000a|Ljava/util/SplittableRandom;' \
    'thread-local-random|invoke-static {}, Ljava/util/concurrent/ThreadLocalRandom;.current:()Ljava/util/concurrent/ThreadLocalRandom; // method@000b|Ljava/util/concurrent/ThreadLocalRandom;' \
    'collections-shuffle|invoke-static {v0}, Ljava/util/Collections;.shuffle:(Ljava/util/List;)V // method@000c|Ljava/util/Collections;.shuffle:' \
    'kotlin-shuffled|invoke-static {v0}, Lkotlin/collections/CollectionsKt;.shuffled:(Ljava/lang/Iterable;)Ljava/util/List; // method@000d|Lkotlin/collections/CollectionsKt;.shuffled:' \
    'kotlin-array-shuffle|invoke-static {v0}, Lkotlin/collections/ArraysKt___ArraysKt;.shuffle:([I)V // method@000e|Lkotlin/collections/ArraysKt___ArraysKt;.shuffle:' \
    'kotlin-ranges-random|invoke-static {v0, v1}, Lkotlin/ranges/RangesKt___RangesKt;.random:(Lkotlin/ranges/IntRange;Lkotlin/random/Random;)I // method@000f|Lkotlin/ranges/RangesKt___RangesKt;.random:' \
    'kotlin-text-random-or-null|invoke-static {v0}, Lkotlin/text/StringsKt___StringsKt;.randomOrNull:(Ljava/lang/CharSequence;)Ljava/lang/Character; // method@0010|Lkotlin/text/StringsKt___StringsKt;.randomOrNull:'; do
    anew "dexref-${adx%%|*}"
    aline=${adx#*|}
    aappend "$c/files/classes.dex" "0001b6: 7100 0600 0000                         |0003: ${aline%|*}"
    acase "apk-banned-reference-${adx%%|*}" "DexRef: classes.dex: Lcom/keepcrypt/entropy/MainActivity; references ${adx##*|}"
  done
  anew no-keepcrypt
  sed '/^Class #1/,$d' "$b/files/classes.dex" >"$c/files/classes.dex" && : >"$c/files/classes2.dex" || exit 2
  abuild
  axexpect apk-error-no-keepcrypt-class 'dexdump listed no com.keepcrypt class' shipping "$c/app.apk" "$c/expected" "$c/report.txt" "$acert" "$c/jnilibs"
  anew native-list
  echo 'x86 libandroidx.graphics.path.so abc' >"$c/expected/native-libs.txt" || exit 2
  abuild
  axexpect apk-error-native-list-line "native-libs.txt line 1 is not" shipping "$c/app.apk" "$c/expected" "$c/report.txt" "$acert" "$c/jnilibs"
  # libkeepcrypt.so in native-libs.txt: by android-rust.sh's word for each ABI, never by a SHA-256;
  # and the scanned copy it is compared with must be there.
  anew native-list-libkeepcrypt-missing
  grep -v -e '^x86_64 libkeepcrypt[.]so ' "$b/expected/native-libs.txt" >"$c/expected/native-libs.txt" || exit 2
  abuild
  axexpect apk-error-native-list-without-an-abi-libkeepcrypt "native-libs.txt lists libkeepcrypt.so android-rust.sh for arm64-v8a, armeabi-v7a, not for each" \
    shipping "$c/app.apk" "$c/expected" "$c/report.txt" "$acert" "$c/jnilibs"
  anew native-list-libkeepcrypt-sha
  sed "s/^x86_64 libkeepcrypt[.]so .*/x86_64 libkeepcrypt.so $(sha256 "$b/files/kc-x86_64.so")/" "$b/expected/native-libs.txt" \
    >"$c/expected/native-libs.txt" || exit 2
  abuild
  axexpect apk-error-native-list-libkeepcrypt-by-sha256 "is not \"<abi> <name>.so <sha256>\", or \"<abi> libkeepcrypt.so android-rust.sh\"" \
    shipping "$c/app.apk" "$c/expected" "$c/report.txt" "$acert" "$c/jnilibs"
  anew jnilibs-copy-missing
  rm "$c/jnilibs/armeabi-v7a/libkeepcrypt.so" || exit 2
  abuild
  axexpect apk-error-scanned-copy-missing "cannot read $c/jnilibs/armeabi-v7a/libkeepcrypt.so, the scanned output of scripts/android-rust.sh" \
    shipping "$c/app.apk" "$c/expected" "$c/report.txt" "$acert" "$c/jnilibs"
  # Alignment and the signature.
  anew zipalign
  touch "$c/zipalign-fails" || exit 2
  acase apk-zipalign-fails "Zipalign: $c/app.apk: zipalign -c -P 16 -v 4 fails"
  anew signer
  sed "s/$acert/$(printf '%064d' 0 | tr 0 d)/" "$b/apksigner.txt" >"$c/apksigner.txt" || exit 2
  acase apk-another-signer "Signature: $c/app.apk: signed by $(printf '%064d' 0 | tr 0 d), not by the run's throwaway key"
  anew signers
  aappend "$c/apksigner.txt" 'Signer #2 certificate DN: CN=Someone else' "Signer #2 certificate SHA-256 digest: $(printf '%064d' 0 | tr 0 d)"
  acase apk-a-second-signer "Signature: $c/app.apk: signed by $acert $(printf '%064d' 0 | tr 0 d), not by the run's throwaway key $acert alone"
  anew apksigner
  touch "$c/apksigner-fails" || exit 2
  acase apk-apksigner-fails "Signature: $c/app.apk: apksigner verify fails"
  echo "selftest-apk: $pass passed, $fail failed"
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

case ${1-} in
  --artifact) shift; [ $# -ge 1 ] || { usage >&2; exit 2; }; artifact "$@" ;;
  --workflows) shift; [ $# -eq 1 ] || { usage >&2; exit 2; }; workflows "$1" ;;
  --image-lists) shift; [ $# -eq 2 ] || { usage >&2; exit 2; }; image_lists "$1" "$2" ;;
  --image) shift; [ $# -eq 4 ] || { usage >&2; exit 2; }; image_scan "$1" "$2" "$3" "$4" ;;
  --selftest-image) shift; [ $# -eq 2 ] || { usage >&2; exit 2; }; selftest_image "$1" "$2" ;;
  --os-config) shift; [ $# -eq 1 ] || { usage >&2; exit 2; }; os_config "$1" ;;
  --apk) shift; [ $# -eq 6 ] || { usage >&2; exit 2; }; apk_scan "$1" "$2" "$3" "$4" "$5" "$6" ;;
  --selftest-apk) shift; [ $# -eq 0 ] || { usage >&2; exit 2; }; apk_selftest ;;
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
  3)
    [ "$1" = --selftest ] && [ "$2" = --shard ] || { usage >&2; exit 2; }
    shard "$3"
    selftest
    ;;
  *) usage >&2; exit 2 ;;
esac
