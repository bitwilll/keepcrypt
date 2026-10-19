#!/usr/bin/env python3
"""The raw-frame checker of the Android workflow's capture harness (tasks/todo.md, M5 group 6; Q55; M5-17).

Python 3.9+, standard library only. It reads screenrecord's raw frames from an emulator through adb and
keeps none of them: each frame lives in memory only while it is checked, nothing is written to any file,
and only counts and pass or fail are printed. scripts/android-emulator.sh runs it.

  android-frames.py record ADB SERIAL --size WxH --format F --duration S --expect E
                    [--display WxH --region L,T,R,B] [--max-gap S] [--min-known K]
      records one continuous stream, `ADB -s SERIAL exec-out screenrecord --output-format=raw-frames
      --size WxH -`, with no --time-limit: in raw-frames mode screenrecord never reads its time limit
      and records until SIGINT or SIGTERM sets its stop flag (frameworks/av cmds/screenrecord/
      screenrecord.cpp, android12-release lines 845-860 and 138). The caller says the scenario is done
      by sending this process SIGTERM; it then stops the device's recorder, `ADB -s SERIAL shell pkill
      -INT -x screenrecord`, and the stream must end, and adb exit, within 5 s of that. At --duration S
      seconds it stops the recorder the same way and fails (the scenario outlasted its cap). A stream
      that ends before it is stopped, a first frame later than --max-gap seconds after the start (5
      by default; none by then stops the recorder), and an adb that exits non-zero fail too. adb's exec
      service puts the remote stderr on the same stream, so the device's shell sends screenrecord's
      stderr to /dev/null, and it carries no remote exit status: the recorder exit printed and checked
      is adb's own (adb that cannot reach the device), never screenrecord's.
      Raw frames have no header: each is W*H pixels of F (rgb888, what screenrecord's FrameOutput writes,
      3 bytes a pixel; rgba8888 and rgb565 too), and a stream that is not a whole number of frames fails.
      --expect black: every pixel of every frame inside the app's window is black (no channel above 16).
        The window is --region, in the display's pixels (--display WxH, the size the instrumentation
        reported), scaled to the recorded size and shrunk by one recorded pixel on each side (the scaler
        blends the edge); the recorded size must have the display's aspect ratio (no letterbox).
      --expect visible (the positive control): in some frame, at least K pixels anywhere (10 by default)
        have the known colour, the warning line of the first screen (Color(0xFFFFD54F), within 40, 40
        and 48 of it), so the same pipeline is shown to see a screen that is not protected. Their mean
        row tells the frames' orientation.
      Prints "android-frames: first frame after T s" when the first frame arrives (the caller waits for
      it), then, once the stream has ended, why and when it was stopped, a line of counts and a PASS or
      FAIL line.
  android-frames.py probe ADB SERIAL API WxH...
      the platform probe's screenrecord facts (tasks/todo.md, M5 group 0), one "probe: api=API ..." line
      each: for each size, whether screenrecord --output-format=raw-frames accepts it (still recording
      after 4 s: accepted; else its exit status and stderr's first line, through adb's shell protocol)
      and whether the SIGINT then ends it; and, at the first size, a raw-frame stream stopped by SIGINT
      after 2 s: the seconds to its first W*H bytes, its bytes in all, for each pixel format the bytes a
      frame, the seconds to the first whole frame and whether the bytes are whole frames, and the
      seconds from the SIGINT to the stream's end. It judges nothing.
  android-frames.py --selftest
      the frame logic on frames built in memory (each format, a pixel lit in each channel alone inside
      the region and lit pixels outside it, the known colour, the region's scaling and its rounding) and
      the stream on stand-in recorders (python -c) that, like screenrecord, end only on SIGINT: a lit
      frame, a partial frame, no frame, a late first frame, a recorder that exits non-zero, one that
      ignores the stop, one that exits 0 on the stop but leaves its stream open (that check alone), one
      that ends before it is stopped and a scenario that outlasts --duration each fail; --duration that
      is not above 0 and --expect black without --display or --region are refused; and --expect
      visible's default --min-known refuses 9 known pixels and takes 10.

Exit codes: 0 pass, 1 fail, 2 usage or a tool that cannot run.
"""

import argparse
import contextlib
import io
import os
import select
import signal
import subprocess
import sys
import time

FORMATS = {"rgb888": 3, "rgba8888": 4, "rgb565": 2}
BLACK_MAX = 16
KNOWN = (0xFF, 0xD5, 0x4F)
KNOWN_TOLERANCE = (40, 40, 48)
CHUNK = 1 << 20
STOP_GRACE = 5.0
POLL = 0.1


class Usage(Exception):
    """A bad argument or a tool that cannot run: exit 2."""


def parse_size(text):
    parts = text.split("x")
    if len(parts) != 2 or not all(p.isdigit() and int(p) > 0 for p in parts):
        raise Usage("not a size WxH: " + text)
    return int(parts[0]), int(parts[1])


def parse_region(text):
    parts = text.split(",")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        raise Usage("not a region L,T,R,B: " + text)
    return tuple(int(p) for p in parts)


def scale_region(region, display, size):
    """The region (display pixels) in the recorded frame's pixels, one recorded pixel in on each side."""
    left, top, right, bottom = region
    dw, dh = display
    rw, rh = size
    if dw * rh != dh * rw:
        raise Usage("the recorded size %dx%d does not have the display's aspect ratio %dx%d" % (rw, rh, dw, dh))
    if not (0 <= left < right <= dw and 0 <= top < bottom <= dh):
        raise Usage("the region %d,%d,%d,%d is not inside the display %dx%d" % (left, top, right, bottom, dw, dh))
    scaled = (-(-left * rw // dw) + 1, -(-top * rh // dh) + 1, right * rw // dw - 1, bottom * rh // dh - 1)
    if scaled[0] >= scaled[2] or scaled[1] >= scaled[3]:
        raise Usage("the region is empty at the recorded size")
    return scaled


def channels(frame, fmt, width, y, x0, x1):
    """The red, green and blue values of row y, columns x0 to x1 (exclusive), as three bytes objects."""
    bpp = FORMATS[fmt]
    row = frame[(y * width + x0) * bpp:(y * width + x1) * bpp]
    if fmt != "rgb565":
        return row[0::bpp], row[1::bpp], row[2::bpp]
    reds, greens, blues = bytearray(), bytearray(), bytearray()
    for i in range(0, len(row), 2):
        v = row[i] | row[i + 1] << 8
        reds.append((v >> 11) * 255 // 31)
        greens.append((v >> 5 & 63) * 255 // 63)
        blues.append((v & 31) * 255 // 31)
    return bytes(reds), bytes(greens), bytes(blues)


def lit_pixels(frame, fmt, width, region):
    """How many pixels inside region have a channel above BLACK_MAX."""
    left, top, right, bottom = region
    count = 0
    for y in range(top, bottom):
        reds, greens, blues = channels(frame, fmt, width, y, left, right)
        if max(reds) > BLACK_MAX or max(greens) > BLACK_MAX or max(blues) > BLACK_MAX:
            count += sum(1 for p in zip(reds, greens, blues) if max(p) > BLACK_MAX)
    return count


def known_pixels(frame, fmt, width, height):
    """How many pixels have the known colour, and the sum of their rows."""
    count = rows = 0
    for y in range(height):
        reds, greens, blues = channels(frame, fmt, width, y, 0, width)
        if max(reds) < KNOWN[0] - KNOWN_TOLERANCE[0]:
            continue
        for r, g, b in zip(reds, greens, blues):
            if (abs(r - KNOWN[0]) <= KNOWN_TOLERANCE[0] and abs(g - KNOWN[1]) <= KNOWN_TOLERANCE[1]
                    and abs(b - KNOWN[2]) <= KNOWN_TOLERANCE[2]):
                count += 1
                rows += y
    return count, rows


def say(line):
    print("android-frames: " + line, flush=True)


def device_stop(adb, serial):
    """The stop of a recorder on the device: SIGINT to screenrecord (pkill -x, its exact name)."""
    def stop(proc):
        try:
            subprocess.run([adb, "-s", serial, "shell", "pkill -INT -x screenrecord"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=STOP_GRACE)
        except OSError as e:
            raise Usage("cannot run %s: %s" % (adb, e.strerror))
        except subprocess.TimeoutExpired:
            say("the stop (adb shell pkill) did not return within %g s" % STOP_GRACE)
    return stop


def stream(command, stop, frame_size, on_frame, should_stop, duration, max_gap, grace):
    """Streams one recorder's stdout frame by frame into on_frame; nothing of a frame outlives the call.
    The recorder is stopped (stop(proc), once) when should_stop() turns true, at duration seconds, or
    when no frame has come max_gap seconds after the start; it then has grace seconds to end its stream
    and exit, or it is killed. Returns a dict: frames; first, stopped and ended, seconds after the start
    (None: never); why, the reason for the stop; status, the recorder's exit status; left, the bytes of
    a partial frame at the end; in_time, whether it ended and exited within grace of the stop."""
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
    except OSError as e:
        raise Usage("cannot run %s: %s" % (command[0], e.strerror))
    start = time.monotonic()
    fd = proc.stdout.fileno()
    buf = bytearray()
    out = {"frames": 0, "first": None, "stopped": None, "ended": None, "why": None}
    while True:
        now = time.monotonic() - start
        if out["stopped"] is None:
            if should_stop():
                out["why"] = "the caller's stop"
            elif now >= duration:
                out["why"] = "the --duration cap of %g s" % duration
            elif out["first"] is None and now > max_gap:
                out["why"] = "no frame within --max-gap %g s" % max_gap
            if out["why"]:
                out["stopped"] = now
                stop(proc)
        elif now > out["stopped"] + grace:
            break
        if not select.select([fd], [], [], POLL)[0]:
            continue
        chunk = os.read(fd, CHUNK)
        if not chunk:
            out["ended"] = time.monotonic() - start
            break
        buf += chunk
        while len(buf) >= frame_size:
            frame = bytes(buf[:frame_size])
            del buf[:frame_size]
            out["frames"] += 1
            if out["first"] is None:
                out["first"] = time.monotonic() - start
            on_frame(frame, out["frames"], out["first"])
            frame = None
    proc.stdout.close()
    out["left"] = len(buf)
    buf = None
    deadline = (out["stopped"] if out["stopped"] is not None else out["ended"]) + grace
    try:
        out["status"] = proc.wait(timeout=max(0.0, deadline - (time.monotonic() - start)))
        out["in_time"] = out["ended"] is not None
    except subprocess.TimeoutExpired:
        proc.kill()
        out["status"] = proc.wait()
        out["in_time"] = False
    return out


def record(args, recorder=None, should_stop=None, grace=STOP_GRACE):
    """The record subcommand. recorder, a (command, stop) pair, and should_stop replace the adb command
    line, the device's stop and the caller's SIGTERM (the selftest's stand-ins)."""
    width, height = parse_size(args.size)
    bpp = FORMATS[args.format]
    frame_size = width * height * bpp
    if not args.duration > 0:
        raise Usage("--duration must be above 0")
    if args.expect == "black":
        if args.display is None or args.region is None:
            raise Usage("--expect black needs --display and --region")
        region = scale_region(parse_region(args.region), parse_size(args.display), (width, height))
    if recorder is None:
        remote = "screenrecord --output-format=raw-frames --size %dx%d - 2>/dev/null" % (width, height)
        recorder = ([args.adb, "-s", args.serial, "exec-out", remote], device_stop(args.adb, args.serial))
    if should_stop is None:
        signals = []
        signal.signal(signal.SIGTERM, lambda number, frame: signals.append(number))
        should_stop = lambda: bool(signals)
    state = {"lit_frames": 0, "best": 0, "best_rows": 0}

    def on_frame(frame, index, first):
        if index == 1:
            say("first frame after %.1f s" % first)
        if args.expect == "black":
            if lit_pixels(frame, args.format, width, region):
                state["lit_frames"] += 1
        else:
            count, rows = known_pixels(frame, args.format, width, height)
            if count > state["best"]:
                state["best"], state["best_rows"] = count, rows

    say("recording (screenrecord --output-format=raw-frames --size %dx%d, no time limit) until the caller's "
        "stop, at most %g s" % (width, height, args.duration))
    out = stream(recorder[0], recorder[1], frame_size, on_frame, should_stop, args.duration, args.max_gap, grace)
    problems = []
    if out["stopped"] is None:
        say("the stream ended by itself after %.1f s" % out["ended"])
        problems.append("the stream ended after %.1f s, before it was stopped (raw frames end only on a stop)"
                        % out["ended"])
    else:
        ended = ("the stream ended %.1f s later" % (out["ended"] - out["stopped"]) if out["ended"] is not None
                 else "the stream had not ended %g s later (the recorder was killed)" % grace)
        say("stopped (%s) after %.1f s: SIGINT to the recorder; %s" % (out["why"], out["stopped"], ended))
        if out["why"].startswith("the --duration cap"):
            problems.append("the scenario outlasted %s" % out["why"])
    if not out["in_time"]:
        problems.append("the recorder did not end and exit within %g s of the stop" % grace)
    if out["first"] is None:
        problems.append("no frame")
    elif out["first"] > args.max_gap:
        problems.append("the first frame came after %.1f s (at most %.1f s)" % (out["first"], args.max_gap))
    if out["left"]:
        problems.append("the stream ends in a partial frame (%d bytes)" % out["left"])
    if out["status"] != 0:
        problems.append("the recorder exited %d" % out["status"])
    say("%d frames of %d bytes (%s %dx%d), recorder exit %d, %d bytes left over"
        % (out["frames"], frame_size, args.format, width, height, out["status"], out["left"]))
    total = out["frames"]
    if args.expect == "black":
        if state["lit_frames"]:
            problems.append("%d of %d frames show a lit pixel in the app's window" % (state["lit_frames"], total))
        verdict = "%d frames, the app's window %d,%d,%d,%d of %dx%d" % ((total,) + region + (width, height))
    else:
        if state["best"] < args.min_known:
            problems.append("no frame shows %d pixels of the known colour (the most: %d)" % (args.min_known, state["best"]))
        mean = state["best_rows"] // state["best"] if state["best"] else -1
        verdict = ("%d frames; the most known-colour pixels in one frame %d (at least %d), their mean row %d of %d"
                   % (total, state["best"], args.min_known, mean, height))
    if problems:
        say("FAIL %s: %s; %s" % (args.expect, "; ".join(problems), verdict))
        return 1
    say("PASS %s: %s%s" % (args.expect, "every frame black over the app's window; " if args.expect == "black" else "",
                            verdict))
    return 0


def probe(args):
    sizes = [parse_size(s) for s in args.sizes]
    tag = "probe: api=%s screenrecord raw-frames" % args.api
    stop = device_stop(args.adb, args.serial)
    for w, h in sizes:
        command = "screenrecord --output-format=raw-frames --size %dx%d - > /dev/null" % (w, h)
        try:
            proc = subprocess.Popen([args.adb, "-s", args.serial, "shell", command], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except OSError as e:
            raise Usage("cannot run %s: %s" % (args.adb, e.strerror))
        try:
            err = proc.communicate(timeout=4)[1].decode("utf-8", "replace").strip().splitlines()
            print("%s --size %dx%d: refused, exit %d%s" % (tag, w, h, proc.returncode,
                                                            ", stderr: " + err[0] if err else ""), flush=True)
            continue
        except subprocess.TimeoutExpired:
            pass
        stopped = time.monotonic()
        stop(proc)
        try:
            proc.communicate(timeout=10)
            ended = "SIGINT ended it %.1f s later, exit %d" % (time.monotonic() - stopped, proc.returncode)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            ended = "still running 10 s after SIGINT (then killed)"
        print("%s --size %dx%d: accepted (still recording after 4 s); %s" % (tag, w, h, ended), flush=True)
    w, h = sizes[0]
    # The stream in units of W*H bytes, which every format's frame is a whole number of: the times the
    # units reached each format's frame, and nothing kept.
    reached = {}
    t0 = time.monotonic()

    def on_unit(unit, count, first):
        for f, b in FORMATS.items():
            if count == b:
                reached[f] = time.monotonic() - t0

    remote = "screenrecord --output-format=raw-frames --size %dx%d - 2>/dev/null" % (w, h)
    out = stream([args.adb, "-s", args.serial, "exec-out", remote], stop, w * h, on_unit,
                 lambda: time.monotonic() - t0 >= 2, 60, 60, 10)
    n = out["frames"] * w * h + out["left"]
    if out["stopped"] is None:
        ended = "the stream ended by itself after %.1f s, before the SIGINT" % out["ended"]
    elif out["ended"] is None:
        ended = "SIGINT after %.1f s; the stream had not ended 10 s later (killed)" % out["stopped"]
    else:
        ended = "SIGINT after %.1f s; the stream ended %.1f s later" % (out["stopped"], out["ended"] - out["stopped"])
    print("%s --size %dx%d: the first %d bytes after %s, %d bytes in all; %s; adb exit %d" % (
        tag, w, h, w * h, "%.1f s" % out["first"] if out["first"] is not None else "none", n, ended, out["status"]),
        flush=True)
    for f, b in sorted(FORMATS.items()):
        size = w * h * b
        whole = ("no bytes" if n == 0 else "%d whole frames" % (n // size) if n % size == 0
                 else "not a whole number of frames")
        print("%s --size %dx%d as %s: %d bytes a frame; %s; %s" % (
            tag, w, h, f, size, "first whole frame after %.1f s" % reached[f] if f in reached else "no whole frame",
            whole), flush=True)
    return 0


# --- selftest ------------------------------------------------------------------------------------

def frame_of(fmt, width, height, pixels):
    """A frame of fmt, black but for pixels {(x, y): (r, g, b)}."""
    bpp = FORMATS[fmt]
    out = bytearray(width * height * bpp)
    if bpp == 4:
        out[3::4] = b"\xff" * (width * height)
    for (x, y), (r, g, b) in pixels.items():
        at = (y * width + x) * bpp
        if fmt == "rgb565":
            v = (r * 31 // 255) << 11 | (g * 63 // 255) << 5 | b * 31 // 255
            out[at:at + 2] = bytes((v & 255, v >> 8))
        else:
            out[at:at + 3] = bytes((r, g, b))
    return bytes(out)


def stand_in(frames, tail=b"", sleep=0.0, status=0, on_stop="exit"):
    """A recorder that writes the given frames (after sleep seconds) and then tail, and records on, as
    screenrecord does in raw-frames mode, until SIGINT, when it exits status. on_stop "ignore": it
    ignores SIGINT (and gives up after 30 s); "none": it exits at once, before any stop; "orphan": on
    SIGINT it exits status at once but leaves a child holding its stdout open for 4 s, so the stream
    does not end."""
    code = ("import signal, subprocess, sys, time\nstopped = []\nsignal.signal(signal.SIGINT, %s)\n"
            "time.sleep(%r)\nsys.stdout.buffer.write(%r)\nsys.stdout.buffer.flush()\nend = time.monotonic() + 30\n"
            "while %s and time.monotonic() < end:\n    time.sleep(0.02)\n%ssys.exit(%d)\n"
            % ("signal.SIG_IGN" if on_stop == "ignore" else "lambda *a: stopped.append(1)", sleep,
               b"".join(frames) + tail, "False" if on_stop == "none" else "not stopped",
               "subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(4)'])\n"
               if on_stop == "orphan" else "", status))
    return ([sys.executable, "-I", "-c", code], lambda proc: proc.send_signal(signal.SIGINT))


def selftest():
    results = []

    def check(name, ok):
        results.append(ok)
        print("%s %s" % ("PASS" if ok else "FAIL", name), flush=True)

    w, h = 8, 6
    region = (1, 1, 7, 5)
    yellow = KNOWN
    for fmt in sorted(FORMATS):
        alpha_only = frame_of(fmt, w, h, {})
        check("%s black frame has no lit pixel (rgba's alpha is not a colour)" % fmt,
              lit_pixels(alpha_only, fmt, w, region) == 0)
        inside = frame_of(fmt, w, h, {(3, 2): (40, 0, 0)})
        check("%s a lit pixel inside the region counts" % fmt, lit_pixels(inside, fmt, w, region) == 1)
        for name, colour in (("green", (0, 40, 0)), ("blue", (0, 0, 40))):
            only = frame_of(fmt, w, h, {(3, 2): colour})
            check("%s a pixel lit in %s alone counts" % (fmt, name), lit_pixels(only, fmt, w, region) == 1)
        outside = frame_of(fmt, w, h, {(0, 0): (255, 255, 255), (7, 5): (255, 255, 255)})
        check("%s lit pixels outside the region do not" % fmt, lit_pixels(outside, fmt, w, region) == 0)
        dim = frame_of(fmt, w, h, {(3, 2): (16, 16, 16)})
        check("%s a pixel at the black limit is black" % fmt, lit_pixels(dim, fmt, w, region) == 0)
        marked = frame_of(fmt, w, h, {(2, 4): yellow, (5, 4): yellow, (6, 0): (255, 255, 255)})
        check("%s the known colour is counted, white is not" % fmt, known_pixels(marked, fmt, w, h) == (2, 8))
    check("the region scales and shrinks by one recorded pixel",
          scale_region((0, 48, 720, 1184), (720, 1280), (360, 640)) == (1, 25, 359, 591))
    check("a region that does not scale exactly rounds inwards",
          scale_region((1, 3, 719, 1183), (720, 1280), (360, 640)) == (2, 3, 358, 590))
    for name, bad in (("another aspect ratio", ((0, 0, 10, 10), (720, 1280), (360, 600))),
                      ("a region outside the display", ((0, 0, 721, 10), (720, 1280), (360, 640)))):
        try:
            scale_region(*bad)
            check("refused: " + name, False)
        except Usage:
            check("refused: " + name, True)

    def run(expect, recorder, region_text="0,0,16,12", min_known=1, max_gap=5.0, duration=30.0, display="16x12",
            stop_after=0.6, parsed=None):
        """record on a stand-in, the caller's stop coming stop_after seconds after the start."""
        args = parsed or argparse.Namespace(adb="adb", serial="emulator-5554", size="%dx%d" % (w, h), format="rgb888",
                                            duration=duration, expect=expect, display=display, region=region_text,
                                            max_gap=max_gap, min_known=min_known)
        t0 = time.monotonic()
        return record(args, recorder, lambda: time.monotonic() - t0 >= stop_after, grace=1.0)

    def refused(name, call):
        try:
            call()
            check("refused: " + name, False)
        except Usage:
            check("refused: " + name, True)

    black = frame_of("rgb888", w, h, {})
    lit = frame_of("rgb888", w, h, {(4, 3): (255, 255, 255)})
    seen = frame_of("rgb888", w, h, {(4, 3): yellow})
    check("record: black frames pass, the stream ending on the stop",
          run("black", stand_in([black, black, black])) == 0)
    check("record: a lit frame among black ones fails", run("black", stand_in([black, lit, black])) == 1)
    check("record: a partial frame fails", run("black", stand_in([black], tail=b"\0\0\0")) == 1)
    check("record: no frame fails", run("black", stand_in([]), max_gap=0.5, stop_after=3.0) == 1)
    check("record: a first frame within --max-gap passes",
          run("black", stand_in([black], sleep=0.3), max_gap=1.5, stop_after=1.0) == 0)
    check("record: a first frame later than --max-gap fails",
          run("black", stand_in([black], sleep=1.5), max_gap=1.0, stop_after=3.0) == 1)
    check("record: a recorder (adb) that exits non-zero fails", run("black", stand_in([black], status=1)) == 1)
    check("record: a recorder that ignores the stop fails", run("black", stand_in([black], on_stop="ignore")) == 1)
    check("record: a stream that ends before the stop fails", run("black", stand_in([black], on_stop="none")) == 1)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        got = run("black", stand_in([black], on_stop="orphan"))
    sys.stdout.write(out.getvalue())
    check("record: a recorder that exits 0 on the stop but leaves its stream open fails on that alone",
          got == 1 and "android-frames: FAIL black: the recorder did not end and exit within 1 s of the stop; 1 frames"
          in out.getvalue())
    check("record: a scenario that outlasts --duration fails",
          run("black", stand_in([black]), duration=0.5, stop_after=5.0) == 1)
    check("record: visible passes on the known colour", run("visible", stand_in([black, seen])) == 0)
    check("record: visible fails on black frames", run("visible", stand_in([black, lit])) == 1)
    for duration in (0, -1):
        refused("record --duration %d" % duration, lambda: run("black", stand_in([black]), duration=duration))
    refused("record --expect black without --display", lambda: run("black", stand_in([black]), display=None))
    refused("record --expect black without --region", lambda: run("black", stand_in([black]), region_text=None))
    parsed = build_parser().parse_args(["record", "adb", "emulator-5554", "--size", "%dx%d" % (w, h), "--format",
                                        "rgb888", "--duration", "30", "--expect", "visible"])
    nine = frame_of("rgb888", w, h, {(x, 1): yellow for x in range(8)} | {(0, 2): yellow})
    ten = frame_of("rgb888", w, h, {(x, 1): yellow for x in range(8)} | {(0, 2): yellow, (1, 2): yellow})
    check("record: visible's default --min-known (10) refuses 9 known pixels",
          run("visible", stand_in([nine]), parsed=parsed) == 1)
    check("record: visible's default --min-known (10) takes 10 known pixels",
          run("visible", stand_in([ten]), parsed=parsed) == 0)
    failed = results.count(False)
    print("android-frames selftest: %d passed, %d failed" % (results.count(True), failed), flush=True)
    return 1 if failed else 0


def build_parser():
    parser = argparse.ArgumentParser(prog="android-frames.py")
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record")
    rec.add_argument("adb")
    rec.add_argument("serial")
    rec.add_argument("--size", required=True)
    rec.add_argument("--format", required=True, choices=sorted(FORMATS))
    rec.add_argument("--duration", type=float, required=True)
    rec.add_argument("--expect", required=True, choices=["black", "visible"])
    rec.add_argument("--display")
    rec.add_argument("--region")
    rec.add_argument("--max-gap", type=float, default=5.0)
    rec.add_argument("--min-known", type=int, default=10)
    pro = sub.add_parser("probe")
    pro.add_argument("adb")
    pro.add_argument("serial")
    pro.add_argument("api")
    pro.add_argument("sizes", nargs="+")
    return parser


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    args = build_parser().parse_args(argv)
    try:
        return record(args) if args.command == "record" else probe(args)
    except Usage as e:
        print("android-frames: " + str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
