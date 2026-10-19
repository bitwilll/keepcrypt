#!/usr/bin/env python3
"""The raw-frame checker of the Android workflow's capture harness (tasks/todo.md, M5 group 6; Q55).

Python 3.9+, standard library only. It reads screenrecord's raw frames from an emulator through adb and
keeps none of them: each frame lives in memory only while it is checked, nothing is written to any file,
and only counts and pass or fail are printed. scripts/android-emulator.sh runs it.

  android-frames.py record ADB SERIAL --size WxH --format F --time-limit T --segments N --expect E
                    [--display WxH --region L,T,R,B] [--max-gap S] [--min-known K]
      records N back-to-back segments, each `ADB -s SERIAL exec-out screenrecord --output-format=raw-frames
      --size WxH --time-limit T -` (T at most 180: screenrecord stops there on API 31, which also refuses
      --time-limit 0, so a long recording is a chain of segments). A segment ends at its time limit or when
      the caller stops screenrecord (pkill -INT); the next one starts at once. adb's exec service puts the
      remote stderr on the same stream, so the device's shell sends screenrecord's stderr to /dev/null.
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
      Every segment needs a frame, and the gap from one segment's end to the next one's first frame must
      be at most --max-gap seconds (5 by default): a longer gap is time no segment recorded. Prints
      "android-frames: segment K first frame" when each segment's first frame arrives (the caller waits
      for it), a line of counts per segment and a PASS or FAIL line.
  android-frames.py probe ADB SERIAL API WxH...
      the platform probe's screenrecord facts (tasks/todo.md, M5 group 0), one "probe: api=API ..." line
      each: for each size, whether screenrecord --output-format=raw-frames accepts it (exit status and
      stderr's first line, through adb's shell protocol); whether it accepts --time-limit 180, 181 and 0
      (still running after 4 s: accepted, then stopped); and, at the first size, the bytes a 2-second
      raw-frame stream holds and which pixel formats divide them into whole frames. It judges nothing.
  android-frames.py --selftest
      the frame logic on frames built in memory (each format, a lit pixel inside and outside the region,
      the known colour, the region's scaling) and the segment chain on stand-in recorders (python -c):
      a partial frame, a segment with no frame, a gap and a failing recorder each fail.

Exit codes: 0 pass, 1 fail, 2 usage or a tool that cannot run.
"""

import argparse
import subprocess
import sys
import time

FORMATS = {"rgb888": 3, "rgba8888": 4, "rgb565": 2}
BLACK_MAX = 16
KNOWN = (0xFF, 0xD5, 0x4F)
KNOWN_TOLERANCE = (40, 40, 48)
CHUNK = 1 << 20
TIME_LIMIT_MAX = 180


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


def run_segment(index, command, frame_size, on_frame):
    """Stream one recorder's stdout frame by frame into on_frame; nothing of a frame outlives the call.
    Returns (frames, time of the first frame or None, time of the end, exit status, bytes left over)."""
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
    except OSError as e:
        raise Usage("cannot run %s: %s" % (command[0], e.strerror))
    buf = bytearray()
    frames = 0
    first = None
    while True:
        chunk = proc.stdout.read1(CHUNK)
        if not chunk:
            break
        buf += chunk
        while len(buf) >= frame_size:
            frame = bytes(buf[:frame_size])
            del buf[:frame_size]
            frames += 1
            if first is None:
                first = time.monotonic()
                say("segment %d first frame" % index)
            on_frame(frame)
            frame = None
    end = time.monotonic()
    proc.stdout.close()
    status = proc.wait()
    left = len(buf)
    buf = None
    return frames, first, end, status, left


def record(args, commands=None):
    """The record subcommand; commands (the selftest's stand-in recorders) replaces the adb command lines."""
    width, height = parse_size(args.size)
    bpp = FORMATS[args.format]
    frame_size = width * height * bpp
    if not 1 <= args.time_limit <= TIME_LIMIT_MAX:
        raise Usage("--time-limit must be 1 to %d (never 0: API 31 refuses it)" % TIME_LIMIT_MAX)
    if args.segments < 1:
        raise Usage("--segments must be at least 1")
    if args.expect == "black":
        if args.display is None or args.region is None:
            raise Usage("--expect black needs --display and --region")
        region = scale_region(parse_region(args.region), parse_size(args.display), (width, height))
    remote = ("screenrecord --output-format=raw-frames --size %dx%d --time-limit %d - 2>/dev/null"
              % (width, height, args.time_limit))
    state = {"lit_frames": 0, "best": 0, "best_rows": 0}

    def on_frame(frame):
        if args.expect == "black":
            if lit_pixels(frame, args.format, width, region):
                state["lit_frames"] += 1
        else:
            count, rows = known_pixels(frame, args.format, width, height)
            if count > state["best"]:
                state["best"], state["best_rows"] = count, rows

    problems = []
    total = 0
    previous_end = None
    for index in range(1, args.segments + 1):
        command = commands[index - 1] if commands else [args.adb, "-s", args.serial, "exec-out", remote]
        say("segment %d started (screenrecord --output-format=raw-frames --size %dx%d --time-limit %d)"
            % (index, width, height, args.time_limit))
        start = time.monotonic()
        frames, first, end, status, left = run_segment(index, command, frame_size, on_frame)
        total += frames
        gap = "-"
        if previous_end is not None and first is not None:
            gap = "%.1f s" % (first - previous_end)
            if first - previous_end > args.max_gap:
                problems.append("a gap of %s before segment %d (at most %.1f s)" % (gap, index, args.max_gap))
        say("segment %d ended after %.1f s: %d frames of %d bytes (%s %dx%d), gap before its first frame %s, "
            "recorder exit %d, %d bytes left over" % (index, end - start, frames, frame_size, args.format, width,
                                                       height, gap, status, left))
        if frames == 0:
            problems.append("no frame in segment %d" % index)
        if left:
            problems.append("segment %d ends in a partial frame (%d bytes)" % (index, left))
        if status != 0:
            problems.append("the recorder of segment %d exited %d" % (index, status))
        previous_end = end
    if args.expect == "black":
        if state["lit_frames"]:
            problems.append("%d of %d frames show a lit pixel in the app's window" % (state["lit_frames"], total))
        verdict = ("%d frames in %d segments, the app's window %d,%d,%d,%d of %dx%d"
                   % ((total, args.segments) + region + (width, height)))
    else:
        if state["best"] < args.min_known:
            problems.append("no frame shows %d pixels of the known colour (the most: %d)" % (args.min_known, state["best"]))
        mean = state["best_rows"] // state["best"] if state["best"] else -1
        verdict = ("%d frames in %d segments; the most known-colour pixels in one frame %d (at least %d), their "
                   "mean row %d of %d" % (total, args.segments, state["best"], args.min_known, mean, height))
    if problems:
        say("FAIL %s: %s; %s" % (args.expect, "; ".join(problems), verdict))
        return 1
    say("PASS %s: %s%s" % (args.expect, "every frame black over the app's window; " if args.expect == "black" else "",
                            verdict))
    return 0


def shell(adb, serial, command, timeout):
    """Run command on the device through adb's shell protocol: (exit status, stderr's first line)."""
    try:
        done = subprocess.run([adb, "-s", serial, "shell", command], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout)
    except OSError as e:
        raise Usage("cannot run %s: %s" % (adb, e.strerror))
    lines = done.stderr.decode("utf-8", "replace").strip().splitlines()
    return done.returncode, lines[0] if lines else ""


def probe(args):
    sizes = [parse_size(s) for s in args.sizes]
    tag = "probe: api=%s screenrecord" % args.api
    for w, h in sizes:
        status, err = shell(args.adb, args.serial,
                            "screenrecord --output-format=raw-frames --size %dx%d --time-limit 1 - > /dev/null" % (w, h), 30)
        print("%s raw-frames --size %dx%d --time-limit 1: exit %d%s" % (tag, w, h, status, ", stderr: " + err if err else ""),
              flush=True)
    w, h = sizes[0]
    for limit in (180, 181, 0):
        command = "screenrecord --output-format=raw-frames --size %dx%d --time-limit %d - > /dev/null" % (w, h, limit)
        proc = subprocess.Popen([args.adb, "-s", args.serial, "shell", command], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            err = proc.communicate(timeout=4)[1].decode("utf-8", "replace").strip().splitlines()
            print("%s --time-limit %d: refused, exit %d%s" % (tag, limit, proc.returncode,
                                                              ", stderr: " + err[0] if err else ""), flush=True)
        except subprocess.TimeoutExpired:
            shell(args.adb, args.serial, "pkill -INT screenrecord", 30)
            proc.communicate(timeout=30)
            print("%s --time-limit %d: accepted (still recording after 4 s, then stopped)" % (tag, limit), flush=True)
    done = subprocess.run([args.adb, "-s", args.serial, "exec-out",
                           "screenrecord --output-format=raw-frames --size %dx%d --time-limit 2 - 2>/dev/null" % (w, h)],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, timeout=60)
    n = len(done.stdout)
    fits = ["%s (%d bytes a frame, %d frames)" % (f, w * h * b, n // (w * h * b))
            for f, b in sorted(FORMATS.items()) if n and n % (w * h * b) == 0]
    print("%s raw-frames --size %dx%d --time-limit 2: %d bytes; whole frames of %s" % (
        tag, w, h, n, ", ".join(fits) if fits else "no format"), flush=True)
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


def stand_in(frames, tail=b"", sleep=0.0, status=0):
    """A recorder that writes the given frames (after sleep seconds), then tail, then exits status."""
    code = ("import sys, time\ntime.sleep(%r)\nsys.stdout.buffer.write(%r)\nsys.stdout.buffer.flush()\nsys.exit(%d)\n"
            % (sleep, b"".join(frames) + tail, status))
    return [sys.executable, "-I", "-c", code]


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
        outside = frame_of(fmt, w, h, {(0, 0): (255, 255, 255), (7, 5): (255, 255, 255)})
        check("%s lit pixels outside the region do not" % fmt, lit_pixels(outside, fmt, w, region) == 0)
        dim = frame_of(fmt, w, h, {(3, 2): (16, 16, 16)})
        check("%s a pixel at the black limit is black" % fmt, lit_pixels(dim, fmt, w, region) == 0)
        marked = frame_of(fmt, w, h, {(2, 4): yellow, (5, 4): yellow, (6, 0): (255, 255, 255)})
        check("%s the known colour is counted, white is not" % fmt, known_pixels(marked, fmt, w, h) == (2, 8))
    check("the region scales and shrinks by one recorded pixel",
          scale_region((0, 48, 720, 1184), (720, 1280), (360, 640)) == (1, 25, 359, 591))
    for name, bad in (("another aspect ratio", ((0, 0, 10, 10), (720, 1280), (360, 600))),
                      ("a region outside the display", ((0, 0, 721, 10), (720, 1280), (360, 640)))):
        try:
            scale_region(*bad)
            check("refused: " + name, False)
        except Usage:
            check("refused: " + name, True)

    def run(expect, commands, region_text="0,0,16,12", min_known=1, max_gap=5.0):
        args = argparse.Namespace(adb="adb", serial="emulator-5554", size="%dx%d" % (w, h), format="rgb888",
                                  time_limit=170, segments=len(commands), expect=expect, display="16x12",
                                  region=region_text, max_gap=max_gap, min_known=min_known)
        return record(args, commands)

    black = frame_of("rgb888", w, h, {})
    lit = frame_of("rgb888", w, h, {(4, 3): (255, 255, 255)})
    seen = frame_of("rgb888", w, h, {(4, 3): yellow})
    check("record: two black segments pass", run("black", [stand_in([black, black]), stand_in([black])]) == 0)
    check("record: a lit frame in the second segment fails", run("black", [stand_in([black]), stand_in([black, lit])]) == 1)
    check("record: a partial frame fails", run("black", [stand_in([black], tail=b"\0\0\0")]) == 1)
    check("record: a segment with no frame fails", run("black", [stand_in([black]), stand_in([])]) == 1)
    check("record: a gap before a segment's first frame fails",
          run("black", [stand_in([black]), stand_in([black], sleep=1.5)], max_gap=1.0) == 1)
    check("record: a recorder that exits non-zero fails", run("black", [stand_in([black], status=1)]) == 1)
    check("record: visible passes on the known colour", run("visible", [stand_in([black, seen])]) == 0)
    check("record: visible fails on black frames", run("visible", [stand_in([black, lit])]) == 1)
    failed = results.count(False)
    print("android-frames selftest: %d passed, %d failed" % (results.count(True), failed), flush=True)
    return 1 if failed else 0


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    parser = argparse.ArgumentParser(prog="android-frames.py")
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record")
    rec.add_argument("adb")
    rec.add_argument("serial")
    rec.add_argument("--size", required=True)
    rec.add_argument("--format", required=True, choices=sorted(FORMATS))
    rec.add_argument("--time-limit", type=int, required=True)
    rec.add_argument("--segments", type=int, required=True)
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
    args = parser.parse_args(argv)
    try:
        return record(args) if args.command == "record" else probe(args)
    except Usage as e:
        print("android-frames: " + str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
