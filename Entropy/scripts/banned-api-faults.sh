#!/bin/sh
# The banned-API gate's fault check (tasks/todo.md, lead decision M5-66; Stage L's L6): each tool
# scripts/banned-api-check.sh runs is made to fail, at every place in the gate that runs it, in
# each of three ways, in each mode below, and every such run must stop the gate with exit 2 and
# name the tool: never "clean", never exit 0 or 1, never a hit with no line.
#
#   scripts/banned-api-faults.sh             the whole check (CI: Entropy CI's lint job)
#   scripts/banned-api-faults.sh LINE...     the same trees, traces and baselines, then the fault
#                                            runs at those lines of the gate only (a mutant's run)
#
# The modes ($modes below), each run as CI runs it: the scan of a tree, --workflows on a directory
# of workflows, --artifact on an object built with the pinned toolchain (so this check needs it:
# rustc, llvm-tools-preview and the arm-unknown-linux-gnueabihf target) and --os-config on a copy of
# the os-config fixtures. Each mode's places are those of the gate's text that its function
# reaches; the top level's are every mode's. The toolchain's llvm-nm and llvm-readobj, which the
# gate runs by their paths in the toolchain, are out of a PATH shim's reach: the gate reads their
# statuses itself, and they are not faulted here. Nor are --image-lists, --image and --apk, which
# call fail_closed too: their inputs need a built Pi image with Buildroot's host tools (mtools,
# unsquashfs), or the Android build tools and a built APK, and this check runs where neither is.
#
# A script of its own, not a mode of the gate: it runs the gate as CI does, sh on a tree, with a
# PATH that holds nothing but its shims, so the gate carries no test hook and a tool the shims do
# not wrap fails the baseline ("not found"); and it runs in another job than the gate's selftest.
#
# The tree: the gate's skeleton (as the selftest's fresh() makes it: core's and pi/app's lib.rs and
# main.rs and the root build file, but the release probe, which a clean fixture gives) and the
# files of the clean and hit fixtures that $fixtures names below, each at its own path (two at one
# path are a setup error), as one git work tree with every file added to its index, so the Build
# rule's index reads run too. A hit fixture's file is there so that the check after a helper's
# first tool runs: most helpers run a second tool only on the first one's hits. The gate scans
# this script too, so it names no fixture whose name holds a word a rule refuses. The workflows:
# the workflow fixtures' files $workflow_fixtures names, each copied as entropy-N.yml into one
# directory, chosen as the tree's files were. The artifact: the artifact selftest's std-passengers
# object, built as the gate's selftest builds it, and one of its marker files. The OS configuration:
# the os-config fixture clean-pizero with osconfig-fstab-proc-read-write's one file over it.
#
# The shims: $work/bin holds one script per tool in $tools, and the gate runs with PATH=$work/bin
# alone. Each shim counts its calls (one counter per tool, in the run's own directory: the gate
# runs its tools one at a time, never two at once, see the gate's "The tools the gate runs fail
# closed"), logs "TOOL CALL LINE CALLER" when asked, and runs the real tool by its absolute path,
# but at the one call KC_FAULT names ("TOOL CALL"), where it fails in the way KC_FAULT_WAY names:
#   126 or 127   the tool cannot start: the shim exits so without running it;
#   exit         the tool exits 2 and prints nothing;
#   kill         the tool runs with its output held, then the shim prints the first half of that
#                output's bytes and is killed by SIGKILL (exit 137 to the gate).
# The shim records the fault it gave in the run's directory ("fired"), so a run in which it never
# fired fails the check.
#
# The places, each mode's: a traced run of the gate (bash -x, as no sh exports a line number)
# with a PS4 that exports LINENO as KC_FAULT_LINE before each command, and the line its function
# was called from (BASH_LINENO[0]) as KC_FAULT_CALLER, so each shim call logs the line of the gate
# that ran it and that line's caller. The lines of the gate's own runners (tool_status,
# fail_closed's tool functions and found, which run a tool for their caller) leave both as the
# caller set them. A place is a tool, a line and its caller: a helper that more than one line
# calls (list, kt_text, kept_hits) is a place for each, since each caller reads the helper's
# status itself. Its first call is the one each of its fault runs fails. The traced run's calls
# must be the calls of a plain run under sh (the same tools in the same order, the same output,
# and nothing on the plain run's stderr), so a call number names the same place under both shells.
# And the places must be every place in the gate's text: read without running it
# (static_places), a place is a tool's name where a command starts, outside comments, quotes and
# here-documents, in the gate's top level or in a function that the mode's function can reach (any
# function whose name its code holds, and so on); for each function and tool the traced run must
# have reached as many lines as the text holds, and each function that holds a place from as many
# callers as the text gives it, or the mode's input misses one. The text check that the scan's own
# shell starts no tool as a command of its own (FG, below) is the scan's alone: the other modes'
# shells live seconds, far less than a wrap of the pid space (the gate's "The tools the gate runs
# fail closed").
#
# The runs: one per mode, place and way, four at once, each under sh with the shims. Each must
# exit 2, with the fault fired, a line that names the tool, the way it failed and what the gate
# was reading ("banned-api-check: TOOL could not start (exit 127) on FILE", "... failed (exit 2) on
# ..." or "... was killed by signal 9 (exit 137) on ..."), no clean line ("banned-api-check:
# clean", or "banned-api-check --MODE ...: clean") and no hit "<Category>: <file>:: " (with no
# line). Prints each failure with its output and a summary; exit 0 when every run passed, 1 when
# one failed, 2 on a setup error.
set -u
unset CDPATH
LC_ALL=C
export LC_ALL
nl='
'

fail() {
  printf 'banned-api-faults: %s\n' "$1" >&2
  exit 2
}

d=$(dirname "$0") || fail 'dirname failed'
here=$(cd "$d" && pwd -P) || fail "cannot enter $d"
gate=$here/banned-api-check.sh
testdata=$here/testdata/banned-api
[ -f "$gate" ] && [ -d "$testdata" ] || fail "no $gate or $testdata"
only=$*
for x in $only; do
  case $x in '' | *[!0-9]*) fail "$x is not a line number of the gate" ;; esac
done

# The tools the gate runs in the modes below (each one a function in the gate's fail_closed, but
# dirname and basename, which its top level runs and checks itself).
tools='awk basename cmp dirname find git grep mktemp od rm rustc sed sort tr'
# The fixtures' files in the tree, FIXTURE/PATH: the fewest that reach every place in the gate's
# text and every caller of a helper, found by dropping each file in turn from a tree of whole
# fixtures while the checks below still passed (2026-10-27). The app's, the firmware's and the
# FFI's allowed files reach their own checks; a build file of each kind and the manifest reach
# kt_canary and kept_hits from each caller; the near misses' offline.py names PowerShell's
# clipboard aliases as variables, so psline's second grep runs; and the app's GoAheadScanner.kt
# with a task name and a package mention on one line takes kt_tasks_scanner to
# kt_tasks_and_packages' awk.
fixtures='clean-kt-shipping-allowed/mobile/android/secure-ui/src/main/kotlin/com/keepcrypt/entropy/secure/SecureActivity.kt
clean-kt-shipping-allowed/mobile/android/app/src/main/kotlin/com/keepcrypt/app/MainActivity.kt
clean-kt-shipping-allowed/mobile/android/app/src/main/kotlin/com/keepcrypt/app/Screens.kt
clean-kt-shipping-allowed/mobile/android/app/src/main/kotlin/com/keepcrypt/entropy/AirplaneSettingsIntent.kt
clean-kt-shipping-allowed/mobile/android/app/src/main/kotlin/com/keepcrypt/entropy/CrashHandler.kt
clean-kt-shipping-allowed/mobile/android/app/src/main/kotlin/com/keepcrypt/entropy/KeepCryptApp.kt
clean-kt-shipping-allowed/mobile/android/app/src/main/kotlin/com/keepcrypt/entropy/files/Documents.kt
clean-kt-shipping-allowed/mobile/android/screens/src/commonMain/kotlin/com/keepcrypt/entropy/screens/CeremonyModel.kt
clean-device-allowed/pi/app/src/device/linux.rs
clean-device-allowed/pi/app/src/device/paths.rs
clean-device-allowed/pi/app/src/device/usb.rs
clean-device-allowed/pi/app/src/device/usb/tests.rs
clean-ffi/ffi/guard/src/lib.rs
clean-ffi/ffi/jni/src/lib.rs
clean-ffi/ffi/src/ceremony.rs
clean-release-probe-call-after-closed-comments/core/examples/release_probe.rs
clean-near-misses/tools/verify/offline.py
ktsdk-android-gradle-sh-bootstrap/scripts/android-gradle.sh
clipboard-ios-main-activity-view-controller/mobile/android/screens/src/iosMain/kotlin/com/keepcrypt/screens/Host.ios.kt
clipboard-istextselectable/mobile/android/app/src/main/kotlin/app/Words.kt
clipboard-powershell-uppercase-extension/tools/win/Copy.PS1
clipboard-textselection-custom-static/mobile/ios/KeepCrypt/WordsView.swift
ktcinterop-def-blank-line/mobile/android/core-ffi/src/nativeInterop/cinterop/keepcrypt.def
ktfailopen-catch-task-executor-in-other-scanner/mobile/android/app/src/main/kotlin/com/keepcrypt/entropy/words/camera/GoAheadScanner.kt
shell-games-add-extra/pi/app/src/games/snake.rs
ktsdk-settings-canary-comment-mixed-case/mobile/android/settings.gradle.kts
ktsdk-app-src-dirs-build-path/mobile/android/app/build.gradle.kts
ktmanifest-main-provider/mobile/android/app/src/main/AndroidManifest.xml
ktfailopen-catch-task-fork-join-pool-qualified-in-scanner/mobile/android/app/src/main/kotlin/com/keepcrypt/entropy/camera/GoAheadScanner.kt'
# The workflow fixtures' files in the workflows directory, FIXTURE/FILE, found as the tree's were
# (2026-10-28): the one whose lenient dependency verification is a bootstrap hit that kept_hits
# reads too, so kt_bootstrap runs its sed and its sort.
workflow_fixtures='workflow-dependency-verification-lenient/entropy-android.yml'
# The modes, "MODE:ROOT:WANT": run() gives MODE's arguments, ROOT is the gate's function whose
# reach holds MODE's places, and WANT is the exit status of a run with no fault. Each input has a
# hit, so each rule's second tool runs, and no run prints a clean line before its EXIT trap's rm,
# whose fault then turns exit 1 into exit 2.
modes='scan:scan:1 workflows:workflows:1 artifact:artifact:1 os-config:os_config:1'

# The shells: sh runs the gate as CI does, bash traces it.
shell=$(command -v sh) || fail 'no sh on PATH'
bash=$(command -v bash) || fail 'no bash on PATH (the traced run needs it)'
for x in head wc; do
  p=$(command -v "$x") || fail "no $x on PATH (the shims need it)"
  eval "real_$x=\$p"
done

start=$(date +%s) || fail 'date failed'
work=$(mktemp -d "${TMPDIR:-/tmp}/banned-api-faults.XXXXXX") || fail 'mktemp failed'
trap 'rm -rf "$work"' EXIT
trap 'exit 2' HUP INT TERM

# --- The shims ----------------------------------------------------------------------------------
mkdir "$work/bin" || fail 'mkdir failed'
for t in $tools; do
  real=$(command -v "$t") || fail "no $t on PATH"
  case $real in
    /*\'* | /*\\*) fail "$t is $real, a path the shim cannot quote" ;;
    /*) ;;
    *) fail "$t is $real, not a file on PATH" ;;
  esac
  eval "real_$t=\$real"
  {
    echo '#!/bin/sh'
    echo "t=$t real='$real' wc='$real_wc' head='$real_head'"
    cat <<'EOF'
# A shim of scripts/banned-api-faults.sh: shell builtins only, and the real tools by their paths.
s=$KC_FAULT_DIR
read -r n <"$s/n.$t" || exit 125
n=$((n + 1))
echo "$n" >"$s/n.$t" || exit 125
if [ -n "${KC_FAULT_LOG-}" ]; then
  echo "$t $n ${KC_FAULT_LINE-} ${KC_FAULT_CALLER-} ${KC_FAULT_FN-}" >>"$KC_FAULT_LOG" || exit 125
fi
if [ "$t $n" = "${KC_FAULT-}" ]; then
  echo "$t $n $KC_FAULT_WAY" >"$s/fired" || exit 125
  case $KC_FAULT_WAY in
    126 | 127) exit "$KC_FAULT_WAY" ;;
    exit) exit 2 ;;
    kill)
      "$real" "$@" >"$s/held"
      size=$("$wc" -c <"$s/held") || exit 125
      size=${size##* }
      # (the Mac's head refuses -c 0: an output of one byte or none is killed before any of it)
      [ "$size" -lt 2 ] || "$head" -c $((size / 2)) "$s/held" || exit 125
      kill -KILL $$
      ;;
  esac
  exit 125
fi
exec "$real" "$@"
EOF
  } >"$work/bin/$t" || fail 'cannot write a shim'
  chmod +x "$work/bin/$t" || fail 'chmod failed'
done
# A fault run's PATH, $work/bin-TOOL: TOOL's shim, and links to the other tools themselves, so only
# the tool that fails pays for a shim. The baselines run with $work/bin, all shims, which is what
# shows that the gate runs no tool but these.
for t in $tools; do
  mkdir "$work/bin-$t" && cp "$work/bin/$t" "$work/bin-$t/$t" || fail 'cannot write a fault run PATH'
  for x in $tools; do
    [ "$x" = "$t" ] || eval "ln -s \"\$real_$x\" \"\$work/bin-\$t/\$x\"" || fail 'ln failed'
  done
done

# --- The tree -----------------------------------------------------------------------------------
tree=$work/tree
mkdir -p "$tree/core/src" "$tree/pi/app/src" "$tree/mobile/android" || fail 'mkdir failed'
for f in core/src/lib.rs pi/app/src/lib.rs pi/app/src/main.rs; do
  echo '#![forbid(unsafe_code)]' >"$tree/$f" || fail 'cannot write the skeleton'
done
printf '%s\n' 'dependencyLocking {' '    lockAllConfigurations()' '    lockMode.set(LockMode.STRICT)' '}' \
  >"$tree/mobile/android/build.gradle.kts" || fail 'cannot write the skeleton'
held=' core/src/lib.rs pi/app/src/lib.rs pi/app/src/main.rs mobile/android/build.gradle.kts '
for entry in $fixtures; do
  f=${entry#*/}
  [ -f "$testdata/$entry" ] || fail "no fixture file $entry"
  case $held in *" $f "*) fail "$entry: $f is already in the tree" ;; esac
  held="$held$f "
  mkdir -p "$tree/${f%/*}" && cp "$testdata/$entry" "$tree/$f" || fail "cannot copy $entry"
done
[ -f "$tree/core/examples/release_probe.rs" ] || fail 'no fixture gives the tree its release probe'
git init -q "$tree" || fail 'git init failed'
git -C "$tree" add -A || fail 'git add failed'
nfiles=$(git -C "$tree" ls-files | wc -l) || fail 'cannot count the tree'
nfiles=${nfiles##* }

# --- The workflows ------------------------------------------------------------------------------
wfdir=$work/workflows
mkdir "$wfdir" || fail 'mkdir failed'
nworkflows=0
for entry in $workflow_fixtures; do
  nworkflows=$((nworkflows + 1))
  [ -f "$here/testdata/workflows/$entry" ] || fail "no workflow fixture file $entry"
  cp "$here/testdata/workflows/$entry" "$wfdir/entropy-$nworkflows.yml" || fail "cannot copy $entry"
done

# --- The artifact -------------------------------------------------------------------------------
# The artifact selftest's std-passengers object (scripts/testdata/artifact/fixture.rs, built from
# the repo root as the selftest builds it, so rustup picks the pinned toolchain) for
# arm-unknown-linux-gnueabihf: an ELF with a .symtab whose std random-key symbols are that target's
# passengers, so every rule runs on it, the passengers' awk among them, which passes them. One object
# reaches every place (an archive's own branch runs no tool); the artifact fixture marker-source.txt
# after it is the run's hit.
adir=$work/artifact
mkdir "$adir" || fail 'mkdir failed'
(cd "$here/.." && rustc --edition 2024 --crate-type lib --crate-name std --emit obj -C panic=abort -C opt-level=1 \
  --target arm-unknown-linux-gnueabihf --cfg kc_std_passengers -o "$adir/std-passengers.o" \
  "$here/testdata/artifact/fixture.rs") >"$adir/rustc.log" 2>&1 || {
  sed 's/^/    /' "$adir/rustc.log" >&2
  fail 'rustc could not build the artifact (the pinned toolchain, with its arm-unknown-linux-gnueabihf target)'
}

# --- The OS configuration -----------------------------------------------------------------------
# The clean fixture with one hit fixture's file over it, as the os-config selftest builds a case: a
# proc line that carries rw, one Fstab hit. Every rule runs whatever the files hold.
osdir=$work/os-config
mkdir "$osdir" && cp -R "$here/testdata/os-config/clean-pizero/." "$osdir/" &&
  cp -R "$here/testdata/os-config/osconfig-fstab-proc-read-write/." "$osdir/" ||
  fail 'cannot copy the os-config fixtures'

# --- Runs of the gate ---------------------------------------------------------------------------
# run DIR MODE [SHELL...] : the gate in MODE (scan: the scan of $tree; workflows: --workflows
# $wfdir; artifact: --artifact on $adir's object and a marker file; os-config: --os-config $osdir)
# under SHELL (sh unless given), its standard input empty, with PATH $rbin, the fault $fault ("TOOL
# CALL") in the way $way and the shims' log $log (no fault, no log when empty), its state in DIR
# (made here: the shims' counters, and TMPDIR, so the gate's temporary files, a killed mktemp's
# too, go with it), its stdout and stderr in DIR/out and DIR/err and its exit status in rc. The
# caller sets rbin, fault, way and log as plain assignments, never as a prefix to run: macOS's sh,
# bash 3.2, keeps a prefix to a function call set and exported after the call, so one run's log
# would reach every run after it. PS4 is the traced run's (below); sh without -x reads none of it.
run() {
  rdir=$1
  rmode=$2
  shift 2
  [ "$#" -gt 0 ] || set -- "$shell"
  mkdir "$rdir" || fail "mkdir $rdir failed"
  for t in $tools; do
    echo 0 >"$rdir/n.$t" || fail 'cannot write a counter'
  done
  case $rmode in
    scan) set -- "$@" "$gate" "$tree" ;;
    workflows) set -- "$@" "$gate" --workflows "$wfdir" ;;
    artifact)
      set -- "$@" "$gate" --artifact arm-unknown-linux-gnueabihf "$adir/std-passengers.o" \
        "$here/testdata/artifact/marker-source.txt"
      ;;
    os-config) set -- "$@" "$gate" --os-config "$osdir" ;;
    *) fail "no mode $rmode" ;;
  esac
  PATH=$rbin KC_FAULT_DIR=$rdir TMPDIR=$rdir KC_FAULT=$fault KC_FAULT_WAY=$way KC_FAULT_LOG=$log \
    KC_FAULT_LINE=0 KC_FAULT_CALLER=0 KC_FAULT_FN=0 PS4=$ps4 "$@" >"$rdir/out" 2>"$rdir/err" </dev/null
  rc=$?
}

# The traced run (below): bash -x, KC_FAULT_LINE the line of each command but the runners' (the
# RUNNERS lines) and KC_FAULT_CALLER the line its function was called from. Each is assigned on
# every command, keeping its old value at a runner's line, since bash 3.2 carries out an assignment
# of BASH_LINENO[0] in the branch of ?: that is not taken.
#
# static_places ROOT: the gate's places read from its text, "FUNCTION TOOL LINE" ("-" the top
# level), "RUNNERS FIRST LAST", the lines of tool_status through found, and "CALLS FUNCTION N", the
# callers of each function that the gate's function ROOT reaches; and for ROOT scan the FG lines
# (below).
static_places() {
  awk -v tools="$tools" -v root="$1" '
    {
      line = $0
      n = length(line)
      code = ""
      if (here != "") {
        t = line
        if (strip) sub(/^\t+/, "", t)
        if (t == here) here = ""
        codes[NR] = ""
        next
      }
      for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (q == 1) {
          if (c == "\047") q = 0
          code = code "_"
          continue
        }
        if (q == 2) {
          if (c == "\\") { i++; code = code "__"; continue }
          if (c == "\"") q = 0
          code = code "_"
          continue
        }
        if (c == "\\") { i++; code = code "__"; continue }
        if (c == "\047") { q = 1; code = code "_"; continue }
        if (c == "\"") { q = 2; code = code "_"; continue }
        if (c == "#" && (i == 1 || substr(line, i - 1, 1) ~ /[ \t]/)) break
        code = code c
      }
      codes[NR] = code
      bare[NR] = code
      # a trap string holds the commands of its trap: read it as code
      if (match(line, /trap \047[^\047]*\047/)) codes[NR] = codes[NR] " ; " substr(line, RSTART + 6, RLENGTH - 7)
      # a here-document: its delimiter from the line as written, quoted or not
      if ((h = index(code, "<<")) && match(substr(line, h), /^<<-?[ \t]*[\047"]?[A-Za-z_][A-Za-z0-9_]*/)) {
        here = substr(line, h, RLENGTH)
        strip = here ~ /^<<-/
        sub(/^<<-?[ \t]*[\047"]?/, "", here)
      }
      if (!dispatch && line ~ /^case /) dispatch = NR
      # every function, at any indentation (the tool functions of fail_closed are nested), for the
      # KF_ names of the traced run
      if (match(line, /^[ \t]*[A-Za-z_][A-Za-z0-9_]*\(\) *\{/)) {
        f = line
        sub(/^[ \t]+/, "", f)
        fnline[++nfn] = substr(f, 1, index(f, "(") - 1) " " NR
      }
      if (match(line, /^[A-Za-z_][A-Za-z0-9_]*\(\) *\{/)) {
        name = substr(line, 1, index(line, "(") - 1)
        first[name] = NR
        fn[NR] = name
        if (code ~ /\}[ \t;]*$/) { last[name] = NR; open = "" } else open = name
        names[++nn] = name
      } else if (open != "" && line == "}") {
        last[open] = NR
        open = ""
      }
    }
    # cmd(code, at): the word at character at of code starts a command: it opens the line or follows
    # ( | & ; ! { ) or a keyword, an assignment, command or found; or it is the helper of report
    # CATEGORY HELPER.
    function cmd(code, at,    before, c, tok, toks) {
      before = substr(code, 1, at - 1)
      sub(/[ \t]+$/, "", before)
      if (before == "") return 1
      c = substr(before, length(before), 1)
      if (c ~ /[(|&;!{)]/) return 1
      tok = before
      sub(/.*[ \t]/, "", tok)
      if ((tok in key) || tok ~ /^[A-Za-z_][A-Za-z0-9_]*=/) return 1
      return before ~ /(^|[ \t;(|&])report[ \t]+[A-Za-z0-9]+$/
    }
    END {
      split(tools, tl, " ")
      for (k in tl) tool[tl[k]] = 1
      split("then do else elif if while until found command", kl, " ")
      for (k in kl) key[kl[k]] = 1
      # each line in the function that holds it, "-" outside every function
      for (k = 1; k <= nn; k++) for (l = first[names[k]]; l <= last[names[k]]; l++) owner[l] = names[k]
      runner_first = first["tool_status"]
      runner_last = last["found"]
      # reach: from root, every function a reached one calls; the top level is its lines above the
      # dispatcher (the first case at the start of a line), which call no function but the runners
      reach[root] = 1
      grew = 1
      while (grew) {
        grew = 0
        for (l = 1; l <= NR; l++) {
          o = (l in owner) ? owner[l] : "-"
          if (!(o in reach)) continue
          s = codes[l]
          pos = 0
          while (match(s, /[A-Za-z_][A-Za-z0-9_]*/)) {
            w = substr(s, RSTART, RLENGTH)
            at = pos + RSTART
            pos += RSTART + RLENGTH - 1
            s = substr(s, RSTART + RLENGTH)
            if ((w in first) && !(w in reach) && cmd(codes[l], at)) { reach[w] = 1; grew = 1 }
          }
        }
      }
      # The shell of scan runs no tool as a command of its own, and neither does the top level (see
      # "The tools the gate runs fail closed" in the gate): in their lines, each tool, and each
      # function whose text runs one (runs), starts only inside a command substitution or a
      # subshell, or as the check of report or found. The commands of a trap, which run as the
      # shell exits, are not read (bare). "FG LINE WORD" for each that does not.
      for (l = 1; l <= NR; l++) {
        if (l >= runner_first && l <= runner_last) continue
        o = (l in owner) ? owner[l] : "-"
        if (o == "-" || !(o in reach)) continue
        s = codes[l]
        pos = 0
        while (match(s, /[A-Za-z_][A-Za-z0-9_]*/)) {
          w = substr(s, RSTART, RLENGTH)
          at = pos + RSTART
          pos += RSTART + RLENGTH - 1
          s = substr(s, RSTART + RLENGTH)
          if ((w in tool) && cmd(codes[l], at)) runs[o] = 1
        }
      }
      grew = 1
      while (grew) {
        grew = 0
        for (l = 1; l <= NR; l++) {
          o = (l in owner) ? owner[l] : "-"
          if (o == "-" || (o in runs) || !(o in reach)) continue
          s = codes[l]
          pos = 0
          while (match(s, /[A-Za-z_][A-Za-z0-9_]*/)) {
            w = substr(s, RSTART, RLENGTH)
            at = pos + RSTART
            pos += RSTART + RLENGTH - 1
            s = substr(s, RSTART + RLENGTH)
            if ((w in runs) && cmd(codes[l], at)) { runs[o] = 1; grew = 1; break }
          }
        }
      }
      depth = 0
      for (l = 1; root == "scan" && l <= NR; l++) {
        o = (l in owner) ? owner[l] : "-"
        if (o != "scan" && !(o == "-" && l < dispatch)) continue
        if (l == first["scan"]) { depth = 0; continue }
        s = bare[l]
        # an arithmetic expansion is no subshell
        gsub(/[$][(][(][^()]*[)][)]/, "__", s)
        m = length(s)
        for (i = 1; i <= m; i++) {
          c = substr(s, i, 1)
          if (c == "(") { depth++; continue }
          if (c == ")") { if (depth > 0) depth--; continue }
          if (c !~ /[A-Za-z_]/ || (i > 1 && substr(s, i - 1, 1) ~ /[A-Za-z0-9_]/)) continue
          match(substr(s, i), /^[A-Za-z_][A-Za-z0-9_]*/)
          w = substr(s, i, RLENGTH)
          if (depth == 0 && ((w in tool) || (w in runs)) && cmd(s, i)) {
            before = substr(s, 1, i - 1)
            if (before !~ /(^|[ \t;(|&!])(found|report[ \t]+[A-Za-z0-9]+)[ \t]+$/) print "FG", l, w
          }
          i += RLENGTH - 1
        }
      }
      print "RUNNERS", runner_first, runner_last
      for (k = 1; k <= nfn; k++) print "FN", fnline[k]
      # The callers of each reached function as BASH_LINENO[0] gives them: every line that calls it
      # as a command of its own, the one line in report for all the checks report runs, and the one
      # in found for those found runs: "CALLS FUNCTION N".
      for (l = 1; l <= NR; l++) {
        if (l >= runner_first && l <= runner_last) continue
        o = (l in owner) ? owner[l] : "-"
        if (!(o in reach) && !(o == "-" && l < dispatch)) continue
        s = codes[l]
        pos = 0
        while (match(s, /[A-Za-z_][A-Za-z0-9_]*/)) {
          w = substr(s, RSTART, RLENGTH)
          at = pos + RSTART
          pos += RSTART + RLENGTH - 1
          s = substr(s, RSTART + RLENGTH)
          if (!(w in first) || (at == 1 && fn[l] == w)) continue
          before = substr(codes[l], 1, at - 1)
          if (before ~ /(^|[ \t;(|&])report[ \t]+[A-Za-z0-9]+[ \t]+$/) by = "report"
          else if (before ~ /(^|[ \t;(|&!])found[ \t]+$/) by = "found"
          else if (cmd(codes[l], at)) by = l
          else continue
          if (!((w, by) in caller)) { caller[w, by] = 1; ncaller[w]++ }
        }
      }
      for (w in ncaller) print "CALLS", w, ncaller[w]
      for (l = 1; l <= NR; l++) {
        if (l >= runner_first && l <= runner_last) continue
        o = (l in owner) ? owner[l] : "-"
        if (!(o in reach) && !(o == "-" && l < dispatch)) continue
        s = codes[l]
        pos = 0
        while (match(s, /[A-Za-z_][A-Za-z0-9_.-]*/)) {
          w = substr(s, RSTART, RLENGTH)
          at = pos + RSTART
          pos += RSTART + RLENGTH - 1
          s = substr(s, RSTART + RLENGTH)
          if (!(w in tool)) continue
          after = substr(codes[l], pos + 1, 1)
          if (after != "" && after !~ /[ \t;)|&]/) continue
          if (cmd(codes[l], at) && !((w, l) in done)) {
            done[w, l] = 1
            print o, w, l
          }
        }
      }
    }' "$gate"
}

# The runners' lines and the FG check: the scan's reading of the text.
places=$(static_places scan) || fail 'cannot read the gate'
runners=$(printf '%s\n' "$places" | sed -n 's/^RUNNERS //p') || fail 'sed failed'
rfirst=${runners% *}
rlast=${runners#* }
case $rfirst:$rlast in
  *[!0-9:]* | :* | *:) fail "cannot find the gate's runners (tool_status to found): $runners" ;;
esac
fg=$(printf '%s\n' "$places" | sed -n 's/^FG //p') || fail 'sed failed'
[ -z "$fg" ] || {
  printf '%s\n' "$fg" | sed 's/^/    line /' >&2
  fail "the scan's own shell, or the top level, runs a tool as a command of its own (above), whose finished job bash 3.2 can later hand a tool of a command substitution (the gate's \"The tools the gate runs fail closed\")"
}
ps4="+\$((KC_FAULT_LINE = LINENO < $rfirst || LINENO > $rlast ? LINENO : KC_FAULT_LINE)):\$((KC_FAULT_CALLER = LINENO < $rfirst || LINENO > $rlast ? BASH_LINENO[0] : KC_FAULT_CALLER)):\$((KC_FAULT_FN = LINENO < $rfirst || LINENO > $rlast ? KF_\${FUNCNAME[0]-} : KC_FAULT_FN)) "
# The gate's functions, "FN NAME FIRST", and the traced run's environment that numbers each by its
# first line (KF_NAME=FIRST, and KF_=0 for the top level), for its PS4's KC_FAULT_FN.
fnlines=$(printf '%s\n' "$places" | sed -n '/^FN /p') || fail 'sed failed'
kfenv=$(printf '%s\n' "$fnlines" | awk '{ printf "KF_%s=%s ", $2, $3 } END { print "KF_=0" }') || fail 'awk failed'
# env by its path: dash's command -v names any file called env on PATH, a sourced script among them.
envp=/usr/bin/env
[ -x "$envp" ] || fail 'no /usr/bin/env (the traced run needs it)'

# Each mode in turn: its places in the text, its traced and plain runs, the checks of one against
# the other, and its fault cases appended to $work/cases, "MODE TOOL LINE CALL CALLER WAY": the tool
# cannot start (126 at every other place, 127 at the rest), exits 2 with nothing, or is killed
# partway through its output. Given LINEs, only the places at those lines or called from them.
: >"$work/cases" || fail 'cannot write the cases'
: >"$work/summary" || fail 'cannot write the summary'
for m in $modes; do
  mode=${m%%:*}
  root=${m#*:}
  want=${root#*:}
  root=${root%%:*}
  if [ "$root" = scan ]; then
    mplaces=$places
  else
    mplaces=$(static_places "$root") || fail 'cannot read the gate'
  fi
  calls=$(printf '%s\n' "$mplaces" | sed -n 's/^CALLS //p') || fail 'sed failed'
  static=$(printf '%s\n' "$mplaces" | sed '/^RUNNERS /d; /^CALLS /d; /^FG /d; /^FN /d') || fail 'sed failed'
  nstatic=$(printf '%s\n' "$static" | wc -l) || fail 'wc failed'
  nstatic=${nstatic##* }

  base=$work/trace-$mode
  rbin=$work/bin
  fault=
  way=
  log=$base.log
  run "$base" "$mode" "$envp" $kfenv "$bash" -x
  [ "$rc" -eq "$want" ] || {
    sed 's/^/    /' "$base/out"
    fail "$mode: the traced run exited $rc, not $want (its input's hits)"
  }
  # Under sh, plainly: the same calls, the same output, and nothing on stderr (a tool the shims do
  # not wrap is "not found" there).
  log=$work/plain-$mode.log
  run "$work/plain-$mode" "$mode"
  [ "$rc" -eq "$want" ] && [ ! -s "$work/plain-$mode/err" ] || {
    sed 's/^/    /' "$work/plain-$mode/out" "$work/plain-$mode/err"
    fail "$mode: the gate under sh exited $rc, not $want, or wrote to stderr (above)"
  }
  cmp -s "$base/out" "$work/plain-$mode/out" || fail "$mode: the traced run's output differs from sh's"
  awk '{ print $1, $2 }' "$base.log" >"$work/trace-$mode.calls" || fail 'awk failed'
  awk '{ print $1, $2 }' "$work/plain-$mode.log" >"$work/plain-$mode.calls" || fail 'awk failed'
  cmp -s "$work/trace-$mode.calls" "$work/plain-$mode.calls" || fail "$mode: the traced run's tool calls differ from sh's"
  ncalls=$(wc -l <"$base.log") || fail 'wc failed'
  ncalls=${ncalls##* }

  # The traced places, "TOOL LINE CALL CALLER FN" for each place's first call; then each traced
  # line beside the static places: per function and tool, the same number of lines. A traced call's
  # function is the one KC_FAULT_FN numbers (FN, its first line; 0 the top level), not the one whose
  # lines hold LINENO: bash 3.2 gives a tool inside a command substitution that spans lines a
  # LINENO past the substitution's end, which can be past its function's end.
  traced=$(awk '!(($1, $3, $4) in seen) { seen[$1, $3, $4] = 1; print $1, $3, $2, $4, $5 }' "$base.log") ||
    fail 'awk failed'
  lines=$(printf '%s\n' "$traced" | awk '!(($1, $2) in seen) { seen[$1, $2] = 1; print $1, $2, $5 }') || fail 'awk failed'
  check=$(printf '%s\n' "$fnlines" "$static" TRACED "$lines" | awk '
    $1 == "FN" { byfirst[$3] = $2; next }
    $0 == "TRACED" { t = 1; next }
    !t { s[$1 " " $2]++; sl[$1 " " $2] = sl[$1 " " $2] " " $3; next }
    {
      o = ($3 in byfirst) ? byfirst[$3] : "-"
      r[o " " $1]++
      rl[o " " $1] = rl[o " " $1] " " $2
    }
    END {
      for (k in s) if (s[k] != r[k]) print k ": the gate holds " s[k] " (lines" sl[k] "), the run reached " r[k] + 0 (rl[k] == "" ? "" : " (lines" rl[k] ")")
      for (k in r) if (!(k in s)) print k ": reached at lines" rl[k] ", which no place of the text holds"
    }') || fail 'awk failed'
  [ -z "$check" ] || {
    printf '%s\n' "$check" | sed 's/^/    /' >&2
    fail "$mode: the traced places are not the places in the gate (above)"
  }
  # And each function that holds a place (but the mode's own, which the dispatcher calls, and the
  # top level) must have been reached from as many callers as the text gives it (CALLS), so each
  # caller's reading of its status is faulted.
  check=$(printf '%s\n' "$fnlines" "$calls" TRACED "$traced" | awk -v root="$root" '
    $1 == "FN" { byfirst[$3] = $2; next }
    $0 == "TRACED" { t = 1; next }
    !t { want[$1] = $2; next }
    {
      o = ($5 in byfirst) ? byfirst[$5] : "-"
      if (o == "-" || o == root) next
      held[o] = 1
      if (!((o, $4) in seen)) { seen[o, $4] = 1; got[o]++; from[o] = from[o] " " $4 }
    }
    END {
      for (o in held) if (got[o] != want[o]) print o ": called from " want[o] + 0 " places in the text, reached from " got[o] " (lines" from[o] ")"
    }') || fail 'awk failed'
  [ -z "$check" ] || {
    printf '%s\n' "$check" | sed 's/^/    /' >&2
    fail "$mode: the traced places' callers are not the callers in the gate (above)"
  }
  nplaces=$(printf '%s\n' "$traced" | wc -l) || fail 'wc failed'
  nplaces=${nplaces##* }
  nlines=$(printf '%s\n' "$lines" | wc -l) || fail 'wc failed'
  nlines=${nlines##* }
  ntools=$(printf '%s\n' "$traced" | awk '!($1 in t) { t[$1] = 1; n++ } END { print n }') || fail 'awk failed'
  # The places of each tool, "awk 19, basename 1, ...", in the tools' order, none for a tool the
  # mode does not run.
  pertool=$(printf '%s\n' "$traced" | awk -v tools="$tools" '
    { n[$1]++ }
    END { k = split(tools, t, " "); for (i = 1; i <= k; i++) if (n[t[i]]) s = s (s == "" ? "" : ", ") t[i] " " n[t[i]]; print s }') ||
    fail 'awk failed'
  case $mode in
    scan) input="$nfiles files in the tree" ;;
    workflows) input="$nworkflows workflow(s)" ;;
    artifact) input='1 object and 1 marker file' ;;
    os-config) input='1 OS configuration' ;;
  esac
  {
    echo "banned-api-faults: $mode: places by tool: $pertool"
    echo "banned-api-faults: $mode: $input, $ncalls tool calls; $nplaces places, at $nlines lines ($nstatic in the gate's text), of $ntools tools"
  } >>"$work/summary" || fail 'cannot write the summary'
  printf '%s\n' "$traced" | awk -v mode="$mode" -v only=" $only " '
    only == "  " || index(only, " " $2 " ") || index(only, " " $4 " ") {
      p = mode " " $1 " " $2 " " $3 " " $4
      k++; print p, (k % 2 ? 127 : 126); print p, "exit"; print p, "kill"
    }' >>"$work/cases" || fail 'awk failed'
done

# --- The fault runs -----------------------------------------------------------------------------
[ -s "$work/cases" ] || fail "no place at the lines $only"
ncases=$(wc -l <"$work/cases") || fail 'wc failed'
ncases=${ncases##* }

# judge MODE TOOL LINE CALL CALLER WAY: run one case and print its result line, "PASS ..." or
# "FAIL ...: why" with its output after it. The gate must name the tool, the way it failed and what
# it read: "banned-api-check: TOOL could not start (exit 126) on FILE", "... failed (exit 2) on ..."
# or "... was killed by signal 9 (exit 137) on ...".
judge() {
  id=$1-$2-$3-$4-$6
  rbin=$work/bin-$2
  fault="$2 $4"
  way=$6
  log=
  run "$work/r/$id" "$1"
  out=$(cat "$work/r/$id/out" "$work/r/$id/err") || fail 'cat failed'
  fired=
  [ ! -f "$work/r/$id/fired" ] || read -r fired <"$work/r/$id/fired" || fail 'cannot read a fired record'
  why=
  [ "$rc" -eq 2 ] || why="exit $rc, not 2"
  [ "$fired" = "$2 $4 $6" ] || why="${why:+$why; }the fault did not fire"
  printf '%s\n' "$out" | grep -q -E '^banned-api-check(: | --[a-z-]+ [^:]*: )clean'
  case $? in
    0) why="${why:+$why; }it printed clean" ;;
    1) ;;
    *) fail 'grep failed' ;;
  esac
  case $6 in
    126 | 127) named="could not start (exit $6)" ;;
    exit) named='failed (exit 2)' ;;
    kill) named='was killed by signal 9 (exit 137)' ;;
  esac
  case $nl$out in
    *"${nl}banned-api-check: $2 $named on "?*) ;;
    *) why="${why:+$why; }no line \"banned-api-check: $2 $named on ...\"" ;;
  esac
  printf '%s\n' "$out" | grep -q -E '^[A-Za-z0-9]+: [^ ]+:: '
  case $? in
    0) why="${why:+$why; }a hit with no line" ;;
    1) ;;
    *) fail 'grep failed' ;;
  esac
  if [ -z "$why" ]; then
    echo "PASS $1: $2 at line $3 from line $5 (call $4), $6"
    rm -rf "$work/r/$id" || fail 'rm failed'
  else
    echo "FAIL $1: $2 at line $3 from line $5 (call $4), $6: $why"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

mid=$(date +%s) || fail 'date failed'
mkdir "$work/r" || fail 'mkdir failed'
jobs=4
k=1
while [ "$k" -le "$jobs" ]; do
  awk -v k="$k" -v n="$jobs" '(NR - 1) % n == k - 1' "$work/cases" >"$work/cases.$k" || fail 'awk failed'
  (
    while read -r m t l c f w; do
      judge "$m" "$t" "$l" "$c" "$f" "$w"
    done <"$work/cases.$k" >"$work/res.$k"
    echo done >"$work/done.$k"
  ) &
  k=$((k + 1))
done
wait
k=1
while [ "$k" -le "$jobs" ]; do
  [ -f "$work/done.$k" ] || fail "worker $k did not finish"
  k=$((k + 1))
done
cat "$work"/res.* >"$work/res" || fail 'cat failed'
npass=$(grep -c '^PASS ' "$work/res")
[ $? -le 1 ] || fail 'grep failed'
nfail=$(grep -c '^FAIL ' "$work/res")
[ $? -le 1 ] || fail 'grep failed'
grep -v '^PASS ' "$work/res"
[ $? -le 1 ] || fail 'grep failed'
[ $((npass + nfail)) -eq "$ncases" ] || fail "$ncases cases, but $npass passed and $nfail failed"
end=$(date +%s) || fail 'date failed'
cat "$work/summary" || fail 'cat failed'
echo "banned-api-faults: the gate under $shell, traced under $bash"
echo "banned-api-faults: $ncases runs (3 ways): $npass passed, $nfail failed, in $((end - start)) s ($((mid - start)) s before the runs)"
[ "$nfail" -eq 0 ] || exit 1
exit 0
