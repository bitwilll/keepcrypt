#!/bin/sh
# The banned-API gate's fault check (tasks/todo.md, lead decision M5-66; Stage L's L6): each tool
# scripts/banned-api-check.sh's scan runs is made to fail, at every place in the gate that runs it,
# in each of three ways, and every such run must stop the gate with exit 2 and name the tool: never
# "clean", never exit 0 or 1, never a hit with no line.
#
#   scripts/banned-api-faults.sh             the whole check (CI: Entropy CI's lint job)
#   scripts/banned-api-faults.sh LINE...     the same tree, trace and baselines, then the fault runs
#                                            at those lines of the gate only (a mutant's run)
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
# this script too, so it names no fixture whose name holds a word a rule refuses.
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
# The places: a traced run of the gate (bash -x, as no sh exports a line number) with a PS4 that
# exports LINENO as KC_FAULT_LINE before each command, and the line its function was called from
# (BASH_LINENO[0]) as KC_FAULT_CALLER, so each shim call logs the line of the gate that ran it and
# that line's caller. The lines of the gate's own runners (tool_status, fail_closed's tool
# functions and found, which run a tool for their caller) leave both as the caller set them. A
# place is a tool, a line and its caller: a helper that more than one line calls (list, kt_text,
# kept_hits) is a place for each, since each caller reads the helper's status itself. Its first
# call is the one each of its fault runs fails. The traced run's calls must be the calls of a plain
# run under sh (the same tools in the same order, the same output, and nothing on the plain run's
# stderr), so a call number names the same place under both shells. And the places must be every
# place in the gate's text: read without running it (static_places), a place is a tool's name
# where a command starts, outside comments, quotes and here-documents, in the gate's top level or in
# a function that scan() can reach (any function whose name its code holds, and so on); for each
# function and tool the traced run must have reached as many lines as the text holds, and each
# function that holds a place from as many callers as the text gives it, or the tree misses one.
#
# The runs: one per place and way, four at once, each under sh with the shims. Each must exit 2,
# with the fault fired, a line that names the tool, the way it failed and what the gate was reading
# ("banned-api-check: TOOL could not start (exit 127) on FILE", "... failed (exit 2) on ..." or "...
# was killed by signal 9 (exit 137) on ..."), no "banned-api-check: clean" and no hit
# "<Category>: <file>:: " (with no line). Prints each failure with its output and a summary; exit 0
# when every run passed, 1 when one failed, 2 on a setup error.
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

# The tools the gate's scan runs (each one a function in the gate's fail_closed, but dirname and
# basename, which its top level runs and checks itself).
tools='awk basename dirname find git grep mktemp od rm sed sort tr'
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
  echo "$t $n ${KC_FAULT_LINE-} ${KC_FAULT_CALLER-}" >>"$KC_FAULT_LOG" || exit 125
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

# --- Runs of the gate ---------------------------------------------------------------------------
# run DIR [SHELL...] : the gate's scan of $tree under SHELL (sh unless given), with PATH $rbin, the
# fault $fault ("TOOL CALL") in the way $way and the shims' log $log (no fault, no log when empty),
# its state in DIR (made here: the shims' counters, and TMPDIR, so the gate's temporary files, a
# killed mktemp's too, go with it), its stdout and stderr in DIR/out and DIR/err and its exit status
# in rc. The caller sets rbin, fault, way and log as plain assignments, never as a prefix to run:
# macOS's sh, bash 3.2, keeps a prefix to a function call set and exported after the call, so one
# run's log would reach every run after it. PS4 is the traced run's (below); sh without -x reads
# none of it.
run() {
  rdir=$1
  shift
  [ "$#" -gt 0 ] || set -- "$shell"
  mkdir "$rdir" || fail "mkdir $rdir failed"
  for t in $tools; do
    echo 0 >"$rdir/n.$t" || fail 'cannot write a counter'
  done
  PATH=$rbin KC_FAULT_DIR=$rdir TMPDIR=$rdir KC_FAULT=$fault KC_FAULT_WAY=$way KC_FAULT_LOG=$log \
    KC_FAULT_LINE=0 KC_FAULT_CALLER=0 PS4=$ps4 "$@" "$gate" "$tree" >"$rdir/out" 2>"$rdir/err"
  rc=$?
}

# The traced run (below): bash -x, KC_FAULT_LINE the line of each command but the runners' (the
# RUNNERS lines) and KC_FAULT_CALLER the line its function was called from. Each is assigned on
# every command, keeping its old value at a runner's line, since bash 3.2 carries out an assignment
# of BASH_LINENO[0] in the branch of ?: that is not taken.
#
# static_places: the gate's places read from its text, "FUNCTION TOOL LINE" ("-" the top level),
# "RUNNERS FIRST LAST", the lines of tool_status through found, and "CALLS FUNCTION N", the callers
# of each function that scan() reaches.
static_places() {
  awk -v tools="$tools" '
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
      # reach: from scan, every function a reached one calls; the top level is its lines above the
      # dispatcher (the first case at the start of a line), which call no function but the runners
      reach["scan"] = 1
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
      for (l = 1; l <= NR; l++) {
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

places=$(static_places) || fail 'cannot read the gate'
runners=$(printf '%s\n' "$places" | sed -n 's/^RUNNERS //p') || fail 'sed failed'
rfirst=${runners% *}
rlast=${runners#* }
case $rfirst:$rlast in
  *[!0-9:]* | :* | *:) fail "cannot find the gate's runners (tool_status to found): $runners" ;;
esac
calls=$(printf '%s\n' "$places" | sed -n 's/^CALLS //p') || fail 'sed failed'
fg=$(printf '%s\n' "$places" | sed -n 's/^FG //p') || fail 'sed failed'
[ -z "$fg" ] || {
  printf '%s\n' "$fg" | sed 's/^/    line /' >&2
  fail "the scan's own shell, or the top level, runs a tool as a command of its own (above), whose finished job bash 3.2 can later hand a tool of a command substitution (the gate's \"The tools the gate runs fail closed\")"
}
static=$(printf '%s\n' "$places" | sed '/^RUNNERS /d; /^CALLS /d; /^FG /d') || fail 'sed failed'
nstatic=$(printf '%s\n' "$static" | wc -l) || fail 'wc failed'
nstatic=${nstatic##* }

base=$work/trace
ps4="+\$((KC_FAULT_LINE = LINENO < $rfirst || LINENO > $rlast ? LINENO : KC_FAULT_LINE)):\$((KC_FAULT_CALLER = LINENO < $rfirst || LINENO > $rlast ? BASH_LINENO[0] : KC_FAULT_CALLER)) "
rbin=$work/bin
fault=
way=
log=$base.log
run "$base" "$bash" -x
[ "$rc" -eq 1 ] || {
  sed 's/^/    /' "$base/out"
  fail "the traced run exited $rc, not 1 (the tree's hits)"
}
# Under sh, plainly: the same calls, the same output, and nothing on stderr (a tool the shims do not
# wrap is "not found" there).
log=$work/plain.log
run "$work/plain"
[ "$rc" -eq 1 ] && [ ! -s "$work/plain/err" ] || {
  sed 's/^/    /' "$work/plain/out" "$work/plain/err"
  fail "the gate under sh exited $rc on the tree, not 1, or wrote to stderr (above)"
}
cmp -s "$base/out" "$work/plain/out" || fail "the traced run's output differs from sh's"
awk '{ print $1, $2 }' "$base.log" >"$work/trace.calls" || fail 'awk failed'
awk '{ print $1, $2 }' "$work/plain.log" >"$work/plain.calls" || fail 'awk failed'
cmp -s "$work/trace.calls" "$work/plain.calls" || fail "the traced run's tool calls differ from sh's"
ncalls=$(wc -l <"$base.log") || fail 'wc failed'
ncalls=${ncalls##* }

# The traced places, "TOOL LINE CALL CALLER" for each place's first call; then each traced line's
# function beside the static places: per function and tool, the same number of lines.
traced=$(awk '!(($1, $3, $4) in seen) { seen[$1, $3, $4] = 1; print $1, $3, $2, $4 }' "$base.log") ||
  fail 'awk failed'
lines=$(printf '%s\n' "$traced" | awk '!(($1, $2) in seen) { seen[$1, $2] = 1; print $1, $2 }') || fail 'awk failed'
check=$(printf '%s\n' "$static" TRACED "$lines" | awk -v gate="$gate" '
  BEGIN {
    while ((getline l < gate) > 0) {
      nr++
      if (l ~ /^[A-Za-z_][A-Za-z0-9_]*\(\) *\{/) {
        name = substr(l, 1, index(l, "(") - 1)
        if (l ~ /\}[ \t;]*$/) { a[name] = nr; b[name] = nr } else { a[name] = nr; open = name }
        list[++nn] = name
      } else if (open != "" && l == "}") { b[open] = nr; open = "" }
    }
  }
  $0 == "TRACED" { t = 1; next }
  !t { s[$1 " " $2]++; sl[$1 " " $2] = sl[$1 " " $2] " " $3; next }
  {
    o = "-"
    for (k = 1; k <= nn; k++) if ($2 >= a[list[k]] && $2 <= b[list[k]]) o = list[k]
    r[o " " $1]++
    rl[o " " $1] = rl[o " " $1] " " $2
  }
  END {
    for (k in s) if (s[k] != r[k]) print k ": the gate holds " s[k] " (lines" sl[k] "), the tree reached " r[k] + 0 (rl[k] == "" ? "" : " (lines" rl[k] ")")
    for (k in r) if (!(k in s)) print k ": reached at lines" rl[k] ", which no place of the text holds"
  }') || fail 'awk failed'
[ -z "$check" ] || {
  printf '%s\n' "$check" | sed 's/^/    /' >&2
  fail 'the traced places are not the places in the gate (above)'
}
# And each function that holds a place (but scan, the dispatcher's, and the top level) must have
# been reached from as many callers as the text gives it (CALLS), so each caller's reading of its
# status is faulted.
check=$(printf '%s\n' "$calls" TRACED "$traced" | awk -v gate="$gate" '
  BEGIN {
    while ((getline l < gate) > 0) {
      nr++
      if (l ~ /^[A-Za-z_][A-Za-z0-9_]*\(\) *\{/) {
        name = substr(l, 1, index(l, "(") - 1)
        if (l ~ /\}[ \t;]*$/) { a[name] = nr; b[name] = nr } else { a[name] = nr; open = name }
        list[++nn] = name
      } else if (open != "" && l == "}") { b[open] = nr; open = "" }
    }
  }
  $0 == "TRACED" { t = 1; next }
  !t { want[$1] = $2; next }
  {
    o = "-"
    for (k = 1; k <= nn; k++) if ($2 >= a[list[k]] && $2 <= b[list[k]]) o = list[k]
    if (o == "-" || o == "scan") next
    held[o] = 1
    if (!((o, $4) in seen)) { seen[o, $4] = 1; got[o]++; from[o] = from[o] " " $4 }
  }
  END {
    for (o in held) if (got[o] != want[o]) print o ": called from " want[o] + 0 " places in the text, reached from " got[o] " (lines" from[o] ")"
  }') || fail 'awk failed'
[ -z "$check" ] || {
  printf '%s\n' "$check" | sed 's/^/    /' >&2
  fail "the traced places' callers are not the callers in the gate (above)"
}
nplaces=$(printf '%s\n' "$traced" | wc -l) || fail 'wc failed'
nplaces=${nplaces##* }
nlines=$(printf '%s\n' "$lines" | wc -l) || fail 'wc failed'
nlines=${nlines##* }
ntools=$(printf '%s\n' "$traced" | awk '!($1 in t) { t[$1] = 1; n++ } END { print n }') || fail 'awk failed'
# The places of each tool, "awk 19, basename 1, ...", in the tools' order.
pertool=$(printf '%s\n' "$traced" | awk -v tools="$tools" '
  { n[$1]++ }
  END { k = split(tools, t, " "); for (i = 1; i <= k; i++) s = s (i > 1 ? ", " : "") t[i] " " n[t[i]] + 0; print s }') ||
  fail 'awk failed'

# --- The fault runs -----------------------------------------------------------------------------
# One case per place and way, "TOOL LINE CALL CALLER WAY": the tool cannot start (126 at every other
# place, 127 at the rest), exits 2 with nothing, or is killed partway through its output. Given
# LINEs, only the places at those lines or called from them.
cases=$(printf '%s\n' "$traced" | awk -v only=" $only " '
  only == "  " || index(only, " " $2 " ") || index(only, " " $4 " ") {
    k++; print $0, (k % 2 ? 127 : 126); print $0, "exit"; print $0, "kill"
  }') ||
  fail 'awk failed'
[ -n "$cases" ] || fail "no place at the lines $only"
printf '%s\n' "$cases" >"$work/cases" || fail 'cannot write the cases'
ncases=$(wc -l <"$work/cases") || fail 'wc failed'
ncases=${ncases##* }

# judge TOOL LINE CALL CALLER WAY: run one case and print its result line, "PASS ..." or
# "FAIL ...: why" with its output after it. The gate must name the tool, the way it failed and what
# it read: "banned-api-check: TOOL could not start (exit 126) on FILE", "... failed (exit 2) on ..."
# or "... was killed by signal 9 (exit 137) on ...".
judge() {
  id=$1-$2-$3-$5
  rbin=$work/bin-$1
  fault="$1 $3"
  way=$5
  log=
  run "$work/r/$id"
  out=$(cat "$work/r/$id/out" "$work/r/$id/err") || fail 'cat failed'
  fired=
  [ ! -f "$work/r/$id/fired" ] || read -r fired <"$work/r/$id/fired" || fail 'cannot read a fired record'
  why=
  [ "$rc" -eq 2 ] || why="exit $rc, not 2"
  [ "$fired" = "$1 $3 $5" ] || why="${why:+$why; }the fault did not fire"
  case $out in
    *"banned-api-check: clean"*) why="${why:+$why; }it printed clean" ;;
  esac
  case $5 in
    126 | 127) named="could not start (exit $5)" ;;
    exit) named='failed (exit 2)' ;;
    kill) named='was killed by signal 9 (exit 137)' ;;
  esac
  case $nl$out in
    *"${nl}banned-api-check: $1 $named on "?*) ;;
    *) why="${why:+$why; }no line \"banned-api-check: $1 $named on ...\"" ;;
  esac
  printf '%s\n' "$out" | grep -q -E '^[A-Za-z0-9]+: [^ ]+:: '
  case $? in
    0) why="${why:+$why; }a hit with no line" ;;
    1) ;;
    *) fail 'grep failed' ;;
  esac
  if [ -z "$why" ]; then
    echo "PASS $1 at line $2 from line $4 (call $3), $5"
    rm -rf "$work/r/$id" || fail 'rm failed'
  else
    echo "FAIL $1 at line $2 from line $4 (call $3), $5: $why"
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
    while read -r t l c f w; do
      judge "$t" "$l" "$c" "$f" "$w"
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
echo "banned-api-faults: places by tool: $pertool"
echo "banned-api-faults: the gate under $shell, traced under $bash"
echo "banned-api-faults: $nfiles files in the tree, $ncalls tool calls; $nplaces places, at $nlines lines ($nstatic in the gate's text), of $ntools tools; $ncases runs (3 ways): $npass passed, $nfail failed, in $((end - start)) s ($((mid - start)) s before the runs)"
[ "$nfail" -eq 0 ] || exit 1
exit 0
