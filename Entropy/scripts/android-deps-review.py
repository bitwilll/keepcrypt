#!/usr/bin/env python3
"""Review of the Android build's dependency pins (tasks/todo.md, M5 group 4; Q54; docs/mobile-apps.md:126).

Python 3.9+, standard library only. It never opens a connection itself: every file it needs from Google's
Maven, Maven Central or a key server is read from MIRROR, a directory laid out as host/path (dl.google.com/
dl/android/maven2/..., repo.maven.apache.org/maven2/..., keyserver.ubuntu.com/pks/lookup/...), where a file
the server answered 404 for is an empty PATH.404 marker. scripts/android-deps-review.sh fills MIRROR with
curl from the "urls" list, round after round, then runs "review" (or "write-keys"); the selftest feeds
recorded mirrors, so it needs no network.

  android-deps-review.py urls MIRROR [--gradle-files DIR] [--keys] [--root DIR]
      print "URL<TAB>PATH" for every file the review (with --keys: write-keys) still needs and MIRROR
      holds neither as PATH nor as PATH.404. A file read from another one (a parent POM, a signer's key)
      appears once that one is in MIRROR, so the list is asked for again until it is empty.
  android-deps-review.py review MIRROR [--gradle-files DIR] [--skip-pgp] [--root DIR]
      the review. mobile/android/gradle/verification-metadata.xml must hold exactly one SHA-256 per
      artifact (every jar, aar, POM and Gradle module file, plugins included), no trusted-artifact,
      ignored-key or also-trust entry and no other checksum, and verify-metadata on; its trusted keys,
      each scoped to one or more whole groups (no name, version, file or regex scope), must be exactly
      the keys of mobile/android/gradle/verification-keyring.keys, and each must sign something in its
      groups. Then each artifact passes one of two checks, by the repository Gradle took it from
      (mobile/android/settings.gradle.kts: Google's Maven for the androidx, com.android and com.google
      groups when it holds the module, else Maven Central; the script checks that the settings file
      still says so):
        Google     the published .sha256 equals the metadata's SHA-256 (Google's Maven publishes only
                   .sha1 and .md5 for some old androidx releases: those are listed, and fail but
                   SHA1_ONLY's);
        Central    Central publishes no .sha256 for many artifacts, so: the file's bytes (from
                   --gradle-files, Gradle's own files-2.1 cache, when their SHA-256 is the metadata's,
                   else from MIRROR) have the metadata's SHA-256, their SHA-1 equals the published
                   .sha1, and gpg verifies the published .asc over them with a key of the keyring
                   whose primary fingerprint is a trusted key scoped to the artifact's group. An
                   expired key passes (old releases outlive their keys) and is counted; a revoked key,
                   a bad signature or a missing .sha1 or .asc fails.
      The files named in SHA1_ONLY (lead decision M5-11), which publish neither a .sha256 nor an .asc,
      are accepted by name when their bytes have the metadata's SHA-256 and their SHA-1 equals the
      published .sha1, and each is printed with that reason; no other file is.
      Any artifact that passes none of these is listed, and the review fails. Every module of every
      lockfile must have its component in the metadata. The shipping runtime classpath (the lockfile
      configuration shippingReleaseRuntimeClasspath of mobile/android/app/gradle.lockfile) must equal
      mobile/android/expected/shipping-runtime-classpath.txt, the dependency allow-list, line for line.
      And each of its modules' licences, read from its POM (or a parent POM's, followed up the chain;
      each POM checked against the metadata's SHA-256 when it is listed there, else against its
      repository's published .sha256 or .sha1), must be a known licence name (LICENCE_NAMES) whose
      SPDX id is on deny.toml's [licenses] allow list. Prints the counts, every trusted key with its groups, and every module's licence.
      --skip-pgp (only where gpg is missing, never in CI) leaves out the signature checks and exits 3
      even when everything else passes, so a run without them can never read as a pass.
  android-deps-review.py write-keys MIRROR [--root DIR]
      the one-time key step behind the committed trusted keys: for each Central artifact, the signer
      named in its .asc (the issuer fingerprint subpacket, or the issuer key ID), its key fetched once
      by fingerprint from keyserver.ubuntu.com (keys.openpgp.org when that has none) and reduced to
      what verification needs (the primary key, its user IDs and subkeys with their self-signatures,
      revocations included; no third-party certification or photo). Writes the keys to
      verification-keyring.keys in the armored form Gradle writes (a "pub" line, the "uid" and "sub"
      lines, the armored key), and the <trusted-keys> block, every signer's primary fingerprint scoped
      to the groups it signs, into the metadata's <configuration>; nothing else of the metadata changes.
      The review then checks every signature with gpg. Each Central artifact with no .asc (but
      SHA1_ONLY's, which have no signer), or whose signer no server has, is listed (STOP) and the exit
      is 1: those need the lead.
  android-deps-review.py classpath [--write] [--root DIR]
      compare (or, with --write, write) the expected shipping runtime classpath from the lockfile.
  android-deps-review.py --selftest [--skip-pgp]
      the recorded cases in scripts/testdata/android-deps-review/: the base passes, each fail-* case
      fails with its message (expect.txt). The cases that need gpg exit 3 with --skip-pgp.

--root names the tree that holds mobile/android and deny.toml (default: this script's repository).
Exit codes: 0 pass, 1 a check failed, 2 usage, a file that cannot be read or a file still to fetch,
3 passed without the signature checks (--skip-pgp).
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTDATA = Path(__file__).resolve().parent / "testdata" / "android-deps-review"
METADATA = "mobile/android/gradle/verification-metadata.xml"
KEYRING = "mobile/android/gradle/verification-keyring.keys"
SETTINGS = "mobile/android/settings.gradle.kts"
EXPECTED = "mobile/android/expected/shipping-runtime-classpath.txt"
APP_LOCKFILE = "mobile/android/app/gradle.lockfile"
SHIPPING_CONFIGURATION = "shippingReleaseRuntimeClasspath"
DENY = "deny.toml"

GOOGLE_URL = "https://dl.google.com/dl/android/maven2/"
CENTRAL_URL = "https://repo.maven.apache.org/maven2/"
# The groups settings.gradle.kts lets Google's Maven answer for (includeGroupByRegex, whole group).
GOOGLE_GROUPS = ("androidx\\..*", "com\\.android(\\..*)?", "com\\.google\\..*")
UBUNTU_KEYS = "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&exact=on&search=0x"
OPENPGP_KEYS = "https://keys.openpgp.org/vks/v1/"
NS = "{https://schema.gradle.org/dependency-verification}"
SAFE_NAME = re.compile(r"[A-Za-z0-9._+-]+\Z")
FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")
POM_DEPTH = 10

# Lead decision M5-11 (tasks/todo.md): the files that publish neither a .sha256 (Google's Maven) nor an .asc
# (Maven Central), accepted by name only, as (group, name, version, file name). Each still needs its bytes to
# have the metadata's SHA-256 and its SHA-1 to equal the published .sha1; any other file without a .sha256 or
# .asc still fails. Four of these modules ship: autofill, concurrent-futures, interpolator, versionedparcelable.
SHA1_ONLY = {
    ("androidx.arch.core", "core-common", "2.1.0", "core-common-2.1.0.pom"),
    ("androidx.autofill", "autofill", "1.0.0", "autofill-1.0.0.aar"),
    ("androidx.autofill", "autofill", "1.0.0", "autofill-1.0.0.pom"),
    ("androidx.concurrent", "concurrent-futures", "1.0.0", "concurrent-futures-1.0.0.jar"),
    ("androidx.concurrent", "concurrent-futures", "1.0.0", "concurrent-futures-1.0.0.pom"),
    ("androidx.interpolator", "interpolator", "1.0.0", "interpolator-1.0.0.aar"),
    ("androidx.interpolator", "interpolator", "1.0.0", "interpolator-1.0.0.pom"),
    ("androidx.versionedparcelable", "versionedparcelable", "1.1.1", "versionedparcelable-1.1.1.aar"),
    ("androidx.versionedparcelable", "versionedparcelable", "1.1.1", "versionedparcelable-1.1.1.pom"),
    ("javax.inject", "javax.inject", "1", "javax.inject-1.jar"),
    ("javax.inject", "javax.inject", "1", "javax.inject-1.pom"),
    ("net.sf.kxml", "kxml2", "2.3.0", "kxml2-2.3.0.jar"),
    ("net.sf.kxml", "kxml2", "2.3.0", "kxml2-2.3.0.pom"),
    ("org.sonatype.oss", "oss-parent", "7", "oss-parent-7.pom"),
}
SHA1_ONLY_REASON = ("SHA-1 only: no .sha256 or .asc published; published SHA-1 matches and the bytes match the "
                    "pinned SHA-256")
# check_artifact's third value for a SHA1_ONLY file that passed: nothing for gpg to verify.
ACCEPTED_BY_NAME = "accepted by name"

# The POM licence names on the shipping classpath (lower case, spaces collapsed) and the SPDX id each
# stands for. Any other name stops the review: a new one is added here after reading the licence.
LICENCE_NAMES = {
    "apache-2.0": "Apache-2.0",
    "the apache license, version 2.0": "Apache-2.0",
    "the apache software license, version 2.0": "Apache-2.0",
}


class Usage(Exception):
    """Exit 2: bad usage or a file that cannot be read."""


class Missing(Exception):
    """A file the review needs is not in the mirror yet (url, path)."""

    def __init__(self, url, path):
        super().__init__(path)
        self.url = url
        self.path = path


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha1_hex(data):
    # The published checksum of Maven Central (and of old Google releases): compared, never trusted
    # alone (the metadata's SHA-256 and the signature are checked over the same bytes).
    return hashlib.sha1(data).hexdigest()


def read_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError as e:
        raise Usage("cannot read %s: %s" % (path, e.strerror))


# --- The mirror ---------------------------------------------------------------------------------


class Mirror:
    """Files fetched from the repositories, as MIRROR/host/path, PATH.404 for a 404."""

    def __init__(self, base, gradle_files=None):
        self.base = Path(base)
        self.gradle_files = Path(gradle_files) if gradle_files else None
        self.needed = {}

    def get(self, url):
        """The bytes at url, None for a 404; Missing when the mirror holds neither."""
        rel = mirror_path(url)
        f = self.base / rel
        if f.is_file():
            if Path(str(f) + ".404").exists():
                raise Usage("%s and its .404 marker both exist" % f)
            return read_bytes(f)
        if Path(str(f) + ".404").is_file():
            return None
        raise Missing(url, rel)

    def get_all(self, urls):
        """get() of each url; when any is missing, every missing one is recorded before Missing is
        raised, so one urls round lists them all."""
        out, first = [], None
        for url in urls:
            try:
                out.append(self.get(url))
            except Missing as m:
                self.needed[m.path] = m.url
                first = first or m
                out.append(None)
        if first is not None:
            raise first
        return out

    def from_gradle(self, group, name, version, filename, want_sha256):
        """The file from Gradle's files-2.1 cache (group/name/version/<sha1>/file) when one copy there
        has the wanted SHA-256, else None."""
        if self.gradle_files is None:
            return None
        d = self.gradle_files / group / name / version
        if not d.is_dir():
            return None
        for sub in sorted(d.iterdir()):
            f = sub / filename
            if f.is_file():
                data = read_bytes(f)
                if sha256_hex(data) == want_sha256:
                    return data
        return None


def mirror_path(url):
    """MIRROR's relative path for url: host/path, a key server's query as host/pks/lookup/0xID.asc."""
    if url.startswith(UBUNTU_KEYS):
        rel = "keyserver.ubuntu.com/pks/lookup/0x" + url[len(UBUNTU_KEYS):] + ".asc"
    elif url.startswith("https://"):
        rel = url[len("https://"):]
    else:
        raise Usage("not an https URL: %s" % url)
    parts = rel.split("/")
    if any(p in ("", ".", "..") or not SAFE_NAME.match(p) for p in parts):
        raise Usage("unsafe mirror path for %s" % url)
    return rel


# --- Settings, lockfiles, deny.toml ---------------------------------------------------------------


def check_settings(root):
    """settings.gradle.kts must give Google's Maven exactly GOOGLE_GROUPS, in both repository blocks."""
    text = read_bytes(root / SETTINGS).decode("utf-8")
    found = [g.replace("\\\\", "\\") for g in re.findall(r'includeGroupByRegex\("([^"]*)"\)', text)]
    if sorted(found) != sorted(GOOGLE_GROUPS * 2):
        raise Usage("%s's Google groups are %s, not this script's %s (change both together)"
                    % (SETTINGS, sorted(set(found)), list(GOOGLE_GROUPS)))


def is_google_group(group):
    return any(re.fullmatch(g, group) for g in GOOGLE_GROUPS)


def lockfile_modules(path, configuration=None):
    """The modules (group:name:version) of a gradle.lockfile, all of them or one configuration's."""
    out = set()
    for line in read_bytes(path).decode("utf-8").splitlines():
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coords, sep, confs = line.partition("=")
        if not sep or coords.count(":") != 2:
            raise Usage("%s: not a lockfile line: %s" % (path, line[:80]))
        if configuration is None or configuration in confs.split(","):
            out.add(coords)
    return out


def all_lockfiles(root):
    return sorted((root / "mobile/android").glob("*/gradle.lockfile"))


def deny_allowed(root):
    """deny.toml's [licenses] allow list."""
    text = read_bytes(root / DENY).decode("utf-8")
    m = re.search(r"^\[licenses\]$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    a = m and re.search(r'^allow = \[([^\]]*)\]$', m.group(1), re.M)
    if not a:
        raise Usage("no allow list under [licenses] in %s" % DENY)
    return set(re.findall(r'"([^"]+)"', a.group(1)))


# --- The verification metadata --------------------------------------------------------------------


class Metadata:
    def __init__(self, path):
        self.path = path
        try:
            tree = ET.fromstring(read_bytes(path))
        except ET.ParseError as e:
            raise Usage("%s: %s" % (path, e))
        self.problems = []
        self.trusted = {}  # fingerprint -> set of groups
        self.artifacts = []  # (group, name, version, file, sha256)
        if tree.tag != NS + "verification-metadata":
            raise Usage("%s: not Gradle verification metadata" % path)
        for child in tree:
            if child.tag == NS + "configuration":
                self._configuration(child)
            elif child.tag == NS + "components":
                self._components(child)
            else:
                self.problems.append("unexpected element <%s>" % local(child.tag))

    def _configuration(self, conf):
        seen = {}
        for c in conf:
            tag = local(c.tag)
            seen[tag] = (c.text or "").strip()
            if tag == "trusted-keys":
                self._trusted_keys(c)
            elif tag not in ("verify-metadata", "verify-signatures"):
                # trusted-artifacts, ignored-keys, key-servers and anything newer: none is allowed.
                self.problems.append("configuration holds <%s>" % tag)
        if seen.get("verify-metadata") != "true":
            self.problems.append("verify-metadata is not true")
        if seen.get("verify-signatures") not in ("true", "false"):
            self.problems.append("verify-signatures is missing")

    def _trusted_keys(self, block):
        for k in block:
            fpr = k.get("id", "")
            if local(k.tag) != "trusted-key" or not FINGERPRINT.match(fpr):
                self.problems.append("trusted keys: <%s id=%r> is not a key by full fingerprint" % (local(k.tag), fpr))
                continue
            groups = set()
            if set(k.attrib) == {"id", "group"} and len(k) == 0:
                groups.add(k.get("group"))
            elif set(k.attrib) == {"id"} and len(k):
                for t in k:
                    if local(t.tag) != "trusting" or set(t.attrib) != {"group"} or len(t):
                        self.problems.append("trusted key %s: a scope other than a whole group" % fpr)
                    groups.add(t.get("group", ""))
            else:
                self.problems.append("trusted key %s: a scope other than whole groups" % fpr)
            if fpr in self.trusted:
                self.problems.append("trusted key %s listed twice" % fpr)
            self.trusted.setdefault(fpr, set()).update(groups)

    def _components(self, components):
        seen = set()
        for comp in components:
            coords = (comp.get("group", ""), comp.get("name", ""), comp.get("version", ""))
            if local(comp.tag) != "component" or set(comp.attrib) != {"group", "name", "version"} \
                    or not all(SAFE_NAME.match(x) for x in coords):
                self.problems.append("a component that is not group, name and version: %r" % (comp.attrib,))
                continue
            for art in comp:
                name = art.get("name", "")
                where = "%s %s" % (":".join(coords), name)
                if local(art.tag) != "artifact" or set(art.attrib) != {"name"} or not SAFE_NAME.match(name):
                    self.problems.append("%s: not an artifact by file name" % where)
                    continue
                kids = list(art)
                if len(kids) != 1 or local(kids[0].tag) != "sha256" \
                        or set(kids[0].attrib) - {"value", "origin"} \
                        or not re.fullmatch(r"[0-9a-f]{64}", kids[0].get("value", "")):
                    self.problems.append("%s: not exactly one SHA-256 (no other checksum, pgp or also-trust)" % where)
                    continue
                if coords + (name,) in seen:
                    self.problems.append("%s: listed twice" % where)
                seen.add(coords + (name,))
                self.artifacts.append(coords + (name, kids[0].get("value")))

    def components(self):
        return {"%s:%s:%s" % a[:3] for a in self.artifacts}

    def sha256_of(self, group, name, version, filename):
        for a in self.artifacts:
            if a[:4] == (group, name, version, filename):
                return a[4]
        return None


def local(tag):
    return tag.rsplit("}", 1)[-1]


def rel_path(group, name, version, filename):
    return "%s/%s/%s/%s" % (group.replace(".", "/"), name, version, filename)


# --- OpenPGP packets (parsing only; gpg does every signature check) ----------------------------------


def dearmor(data):
    """The binary packets of every armored block in data (text around and between blocks ignored)."""
    out = b""
    blocks = re.findall(rb"-----BEGIN PGP [A-Z ]+-----\r?\n(.*?)-----END PGP [A-Z ]+-----", data, re.S)
    for block in blocks:
        lines = block.replace(b"\r", b"").split(b"\n")
        # Armor headers end at the first empty line, when there are any.
        if b"" in lines and any(b":" in ln for ln in lines[: lines.index(b"")]):
            lines = lines[lines.index(b"") + 1:]
        body = b"".join(ln for ln in lines if ln and not ln.startswith(b"="))
        try:
            out += base64.b64decode(body, validate=True)
        except ValueError:
            raise Usage("bad armor")
    if not blocks:
        raise Usage("no armored block")
    return out


def packets(data):
    """[(tag, header and body bytes, body bytes)] of an OpenPGP packet stream."""
    out, i = [], 0
    while i < len(data):
        start, b = i, data[i]
        if not b & 0x80:
            raise Usage("not an OpenPGP packet")
        if b & 0x40:
            tag = b & 0x3F
            l1 = data[i + 1]
            if l1 < 192:
                n, i = l1, i + 2
            elif l1 < 224:
                n, i = ((l1 - 192) << 8) + data[i + 2] + 192, i + 3
            elif l1 == 255:
                n, i = int.from_bytes(data[i + 2:i + 6], "big"), i + 6
            else:
                raise Usage("partial packet lengths in a key or signature")
        else:
            tag, lt = (b >> 2) & 0x0F, b & 3
            if lt == 3:
                raise Usage("indeterminate packet length")
            w = 1 << lt
            n, i = int.from_bytes(data[i + 1:i + 1 + w], "big"), i + 1 + w
        if i + n > len(data):
            raise Usage("truncated OpenPGP packet")
        out.append((tag, data[start:i + n], data[i:i + n]))
        i += n
    return out


def subpackets(blob):
    out, i = [], 0
    while i < len(blob):
        l1 = blob[i]
        if l1 < 192:
            n, i = l1, i + 1
        elif l1 < 255:
            n, i = ((l1 - 192) << 8) + blob[i + 1] + 192, i + 2
        else:
            n, i = int.from_bytes(blob[i + 1:i + 5], "big"), i + 5
        out.append((blob[i] & 0x7F, blob[i + 1:i + n]))
        i += n
    return out


def signature_issuer(body):
    """(sig type, issuer fingerprint or None, issuer key ID) of a v3 or v4 signature packet body."""
    if body[0] == 3:
        return body[2], None, body[7:15].hex().upper()
    if body[0] != 4:
        raise Usage("signature version %d" % body[0])
    hl = int.from_bytes(body[4:6], "big")
    hashed = body[6:6 + hl]
    ul = int.from_bytes(body[6 + hl:8 + hl], "big")
    unhashed = body[8 + hl:8 + hl + ul]
    fpr = keyid = None
    for t, d in subpackets(hashed) + subpackets(unhashed):
        if t == 33 and d[:1] == b"\x04" and len(d) == 21:
            fpr = d[1:].hex().upper()
        elif t == 16 and len(d) == 8:
            keyid = d.hex().upper()
    if fpr and not keyid:
        keyid = fpr[-16:]
    if not keyid:
        raise Usage("a signature without an issuer")
    return body[1], fpr, keyid


def key_fingerprint(body):
    if body[0] != 4:
        raise Usage("key version %d (only v4 keys are read)" % body[0])
    # RFC 4880's v4 fingerprint, which names the key; gpg checks every signature.
    return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()


def transferable_keys(data):
    """Split a key file into keys: [{'fpr', 'subkeys': [fpr], 'uids': [str], 'minimal': bytes}]. The
    minimal form keeps the primary key, user IDs and subkeys with the primary key's own signatures on
    them (self-certifications, bindings, direct-key signatures and revocations); third-party
    certifications, user attributes (photos) and trust packets go."""
    keys, cur, keep = [], None, False
    for tag, raw, body in packets(data):
        if tag == 6:
            cur = {"fpr": key_fingerprint(body), "subkeys": [], "uids": [], "parts": [raw]}
            keys.append(cur)
            keep = True
        elif cur is None:
            raise Usage("a key file that does not start with a public key")
        elif tag == 13:
            cur["uids"].append(uid_text(body))
            cur["parts"].append(raw)
            keep = True
        elif tag == 14:
            cur["subkeys"].append(key_fingerprint(body))
            cur["parts"].append(raw)
            keep = True
        elif tag == 17:
            keep = False
        elif tag == 2:
            _, fpr, keyid = signature_issuer(body)
            if keep and (fpr == cur["fpr"] or (fpr is None and keyid == cur["fpr"][-16:])):
                cur["parts"].append(raw)
        elif tag != 12:
            raise Usage("unexpected packet %d in a key file" % tag)
    for k in keys:
        k["minimal"] = b"".join(k.pop("parts"))
    return keys


def uid_text(body):
    """A user ID as one line of text: UTF-8 as RFC 4880 says (Latin-1 for the old keys that are not),
    with any control character shown as ?."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("latin-1")
    return " ".join("".join(c if c.isprintable() else "?" for c in text).split())


def crc24(data):
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor_key(data):
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    crc = base64.b64encode(crc24(data).to_bytes(3, "big")).decode("ascii")
    return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + "\n".join(lines) + "\n=" + crc + \
        "\n-----END PGP PUBLIC KEY BLOCK-----\n"


def keyring_keys(path):
    """The keys of a committed keyring file: {primary fingerprint: key}."""
    out = {}
    for k in transferable_keys(dearmor(read_bytes(path))):
        if k["fpr"] in out:
            raise Usage("%s holds key %s twice" % (path, k["fpr"]))
        out[k["fpr"]] = k
    return out


# --- What each check needs from the mirror -----------------------------------------------------------


class ReviewFailure(Exception):
    pass


def repository(mirror, group, rel):
    """Where Gradle took a file from: "google" (Google's Maven, which publishes its .sha256), "google-sha1"
    (Google's Maven, which publishes only .sha1 and .md5 for it, as for androidx releases of 2018-2019)
    or "central". Google's Maven is asked first for its groups, as Gradle asks it first; a file it does
    not have came from Maven Central."""
    if is_google_group(group):
        if mirror.get(GOOGLE_URL + rel + ".sha256") is not None:
            return "google"
        if mirror.get(GOOGLE_URL + rel + ".sha1") is not None:
            return "google-sha1"
    return "central"


REPOSITORY_NAMES = {"google": "Google's Maven", "google-sha1": "Google's Maven", "central": "Maven Central",
                    "unknown": "no repository read"}


def base_url(repo):
    return CENTRAL_URL if repo == "central" else GOOGLE_URL


def first_token(data):
    t = data.decode("ascii", "replace").split()
    return t[0].lower() if t else ""


def file_url_name(mirror, meta, art):
    """The file name a metadata artifact has in its repository. A Gradle module file may give a file a
    name of its own (animation.aar) beside its URL (animation-android-1.12.1.aar), and the metadata
    records the name, so the URL is read from the component's .module file, checked first against the
    metadata's SHA-256."""
    group, name, version, filename, _ = art
    if filename.startswith("%s-%s" % (name, version)):
        return filename
    module = "%s-%s.module" % (name, version)
    want = meta.sha256_of(group, name, version, module)
    if want is None:
        raise ReviewFailure("named %s, but the component has no .module file to give its URL" % filename)
    rel = rel_path(group, name, version, module)
    data = mirror.from_gradle(group, name, version, module, want) or \
        mirror.get(base_url(repository(mirror, group, rel)) + rel)
    if data is None or sha256_hex(data) != want:
        raise ReviewFailure("%s does not match the metadata's SHA-256" % module)
    try:
        doc = json.loads(data.decode("utf-8"))
        urls = {f["url"] for v in doc.get("variants", []) for f in v.get("files", []) if f.get("name") == filename}
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ReviewFailure("%s is not a Gradle module file" % module)
    if len(urls) != 1 or not SAFE_NAME.match(next(iter(urls))):
        raise ReviewFailure("%s gives %s no single plain file URL" % (module, filename))
    return urls.pop()


def check_artifact(mirror, meta, art):
    """(repository, failure reason or None, Central (asc, bytes) to verify, ACCEPTED_BY_NAME, or None)."""
    group, name, version, filename, want = art
    try:
        rel = rel_path(group, name, version, file_url_name(mirror, meta, art))
    except ReviewFailure as f:
        return "unknown", str(f), None
    repo = repository(mirror, group, rel)
    base = base_url(repo)
    if repo == "google":
        published = first_token(mirror.get(GOOGLE_URL + rel + ".sha256"))
        if published != want:
            return repo, "Google's published SHA-256 is %s, the metadata's %s" % (published, want), None
        return repo, None, None
    urls = [base + rel + ".sha1"] + ([base + rel + ".asc"] if repo == "central" else [])
    local_copy = mirror.from_gradle(group, name, version, filename, want)
    got = mirror.get_all(urls + ([base + rel] if local_copy is None else []))
    data = local_copy if local_copy is not None else got[-1]
    sha1, asc = got[0], (got[1] if repo == "central" else None)
    if data is None:
        return repo, "neither Google's Maven nor Maven Central has the file", None
    facts = "its SHA-256 %s the metadata's, its SHA-1 %s the published .sha1" % (
        "equals" if sha256_hex(data) == want else "differs from",
        "equals" if sha1 is not None and first_token(sha1) == sha1_hex(data) else "differs from")
    named = art[:4] in SHA1_ONLY and sha1 is not None and sha256_hex(data) == want \
        and first_token(sha1) == sha1_hex(data)
    if repo == "google-sha1":
        if named:
            return repo, None, ACCEPTED_BY_NAME
        return repo, "Google's Maven publishes no .sha256 for it, only .sha1 and .md5 (%s)" % facts, None
    if sha1 is None:
        return repo, "Maven Central publishes no .sha1", None
    if sha256_hex(data) != want:
        return repo, "the file's SHA-256 is %s, the metadata's %s" % (sha256_hex(data), want), None
    if first_token(sha1) != sha1_hex(data):
        return repo, "the published .sha1 %s is not the file's %s" % (first_token(sha1), sha1_hex(data)), None
    if asc is None:
        if named:
            return repo, None, ACCEPTED_BY_NAME
        return repo, "Maven Central publishes no .asc signature (%s)" % facts, None
    return repo, None, (asc, data)


def central_asc(mirror, meta, art):
    """An artifact's .asc when Gradle took it from Maven Central (b"" when it did not, None for a 404)."""
    try:
        rel = rel_path(*art[:3], file_url_name(mirror, meta, art))
    except ReviewFailure:
        return b""
    if repository(mirror, art[0], rel) != "central":
        return b""
    return mirror.get(CENTRAL_URL + rel + ".asc")


def central_artifacts(mirror, meta):
    """[(artifact, .asc or None)] of the metadata's artifacts Gradle took from Maven Central."""
    out = []
    for art in meta.artifacts:
        asc = central_asc(mirror, meta, art)
        if asc != b"":
            out.append((art, asc))
    return out


def pom(mirror, meta, group, name, version):
    """A module's POM, checked against the metadata's SHA-256 or the repository's published checksum."""
    filename = "%s-%s.pom" % (name, version)
    rel = rel_path(group, name, version, filename)
    repo = repository(mirror, group, rel)
    data = mirror.get(base_url(repo) + rel)
    if data is None:
        raise ReviewFailure("%s:%s:%s: no POM" % (group, name, version))
    listed = meta.sha256_of(group, name, version, filename)
    if listed is not None:
        ok = sha256_hex(data) == listed
    elif repo == "google":
        ok = sha256_hex(data) == first_token(mirror.get(GOOGLE_URL + rel + ".sha256"))
    else:
        sha1 = mirror.get(base_url(repo) + rel + ".sha1")
        ok = sha1 is not None and first_token(sha1) == sha1_hex(data)
    if not ok:
        raise ReviewFailure("%s: the POM does not match its checksum" % filename)
    return data


def pom_licences(mirror, meta, coords):
    """The SPDX ids of a module's licences, from its POM or the nearest parent POM that names any."""
    group, name, version = coords.split(":")
    for _ in range(POM_DEPTH):
        try:
            root = ET.fromstring(pom(mirror, meta, group, name, version))
        except ET.ParseError:
            raise ReviewFailure("%s:%s:%s: the POM is not XML" % (group, name, version))
        strip_ns(root)
        found = root.findall("licenses/license")
        if found:
            ids = []
            for lic in found:
                lname = " ".join((lic.findtext("name") or "").split()).lower()
                lurl = (lic.findtext("url") or "").strip().lower().rstrip("/")
                spdx = LICENCE_NAMES.get(lname)
                if spdx is None:
                    raise ReviewFailure("%s: an unknown licence %r (%s)" % (coords, lname, lurl))
                ids.append(spdx)
            return sorted(set(ids))
        parent = root.find("parent")
        if parent is None:
            raise ReviewFailure("%s: no licence in its POM or any parent POM" % coords)
        group, name, version = (parent.findtext(x, "").strip() for x in ("groupId", "artifactId", "version"))
        if not all(SAFE_NAME.match(x) for x in (group, name, version)):
            raise ReviewFailure("%s: a parent POM that is not group, name and version" % coords)
    raise ReviewFailure("%s: more than %d parent POMs" % (coords, POM_DEPTH))


def strip_ns(root):
    for e in root.iter():
        if isinstance(e.tag, str):
            e.tag = local(e.tag)


def expected_classpath(root):
    return read_bytes(root / EXPECTED).decode("utf-8").splitlines()


def shipping_classpath(root):
    """The shipping runtime classpath as the strict build resolves it: the lockfile's configuration."""
    return sorted(lockfile_modules(root / APP_LOCKFILE, SHIPPING_CONFIGURATION))


def classpath_diff(root):
    """(missing from the lockfile, extra in the lockfile, problems) against the expected list."""
    want = expected_classpath(root)
    problems = []
    if want != sorted(set(want)) or any(ln.count(":") != 2 or ln != ln.strip() for ln in want):
        problems.append("%s is not sorted, unique group:name:version lines" % EXPECTED)
    got = set(shipping_classpath(root))
    if not got:
        problems.append("%s has no %s" % (APP_LOCKFILE, SHIPPING_CONFIGURATION))
    return sorted(set(want) - got), sorted(got - set(want)), problems


# --- urls -------------------------------------------------------------------------------------------


def collect_needs(mirror, func):
    """Run func, collecting every Missing file it meets, item by item, instead of stopping at the first."""
    try:
        return func()
    except Missing as m:
        mirror.needed[m.path] = m.url
        return None


def needs(root, mirror, keys=False):
    meta = Metadata(root / METADATA)
    for art in meta.artifacts:
        collect_needs(mirror, lambda a=art: check_artifact(mirror, meta, a))
    for coords in shipping_classpath(root):
        collect_needs(mirror, lambda c=coords: licences_or_failure(mirror, meta, c))
    if keys:
        for art in meta.artifacts:
            collect_needs(mirror, lambda a=art: key_needs(mirror, meta, a))
    return mirror.needed


def licences_or_failure(mirror, meta, coords):
    try:
        return pom_licences(mirror, meta, coords)
    except ReviewFailure as f:
        return str(f)


def key_url(issuer):
    return UBUNTU_KEYS + issuer


def key_needs(mirror, meta, art):
    asc = central_asc(mirror, meta, art)
    for issuer in asc_issuers(asc) if asc else []:
        fetch_key(mirror, issuer)


def asc_issuers(asc):
    out = []
    for tag, _, body in packets(dearmor(asc)):
        if tag == 2:
            _, fpr, keyid = signature_issuer(body)
            out.append(fpr or keyid)
    if not out:
        raise Usage("an .asc file without a signature")
    return out


def fetch_key(mirror, issuer):
    """The key file for an issuer (fingerprint or key ID): keyserver.ubuntu.com, else keys.openpgp.org,
    None when neither has it."""
    data = mirror.get(key_url(issuer))
    if data is not None:
        return data
    kind = "by-fingerprint/" if len(issuer) == 40 else "by-keyid/"
    return mirror.get(OPENPGP_KEYS + kind + issuer)


def cmd_urls(root, mirror_dir, gradle_files, keys):
    check_settings(root)
    mirror = Mirror(mirror_dir, gradle_files)
    for path, url in sorted(needs(root, mirror, keys).items()):
        print("%s\t%s" % (url, path))
    return 0


# --- write-keys ---------------------------------------------------------------------------------------


def cmd_write_keys(root, mirror_dir):
    check_settings(root)
    mirror = Mirror(mirror_dir)
    if needs(root, mirror, keys=True):
        raise Usage("the mirror still lacks files: run the urls list first")
    meta = Metadata(root / METADATA)
    if meta.problems:
        raise Usage("%s: %s" % (METADATA, "; ".join(meta.problems)))
    trusted, keys, stop = {}, {}, []
    for art, asc in central_artifacts(mirror, meta):
        where = "%s:%s:%s %s" % art[:4]
        if asc is None:
            if art[:4] not in SHA1_ONLY:
                stop.append("%s: no .asc" % where)
            continue
        for issuer in asc_issuers(asc):
            data = fetch_key(mirror, issuer)
            if data is None:
                stop.append("%s: no key server has signer %s" % (where, issuer))
                continue
            match = [k for k in transferable_keys(dearmor(data))
                     if any(f == issuer or f[-16:] == issuer for f in [k["fpr"]] + k["subkeys"])]
            if len(match) != 1:
                stop.append("%s: signer %s is not exactly one key of the fetched file" % (where, issuer))
                continue
            k = match[0]
            keys[k["fpr"]] = k
            trusted.setdefault(k["fpr"], set()).add(art[0])
    with open(root / KEYRING, "w", encoding="utf-8", newline="\n") as f:
        for fpr in sorted(keys):
            k = keys[fpr]
            f.write("pub    %s\n" % fpr)
            for uid in k["uids"]:
                f.write("uid    %s\n" % uid)
            f.write("\n")
            for sub in k["subkeys"]:
                f.write("sub    %s\n" % sub)
            f.write(armor_key(k["minimal"]))
            f.write("\n")
    text = read_bytes(root / METADATA).decode("utf-8")
    block = ["      <trusted-keys>"]
    for fpr in sorted(trusted):
        groups = sorted(trusted[fpr])
        if len(groups) == 1:
            block.append('         <trusted-key id="%s" group="%s"/>' % (fpr, groups[0]))
        else:
            block.append('         <trusted-key id="%s">' % fpr)
            block += ['            <trusting group="%s"/>' % g for g in groups]
            block.append("         </trusted-key>")
    block.append("      </trusted-keys>")
    text = re.sub(r"\n      <trusted-keys>.*?</trusted-keys>", "", text, flags=re.S)
    anchor = "</verify-signatures>\n"
    if text.count(anchor) != 1:
        raise Usage("%s: no single verify-signatures line to put the trusted keys after" % METADATA)
    text = text.replace(anchor, anchor + "\n".join(block) + "\n")
    with open(root / METADATA, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("android-deps-review: wrote %d keys to %s and %d trusted keys (%d group scopes) to %s"
          % (len(keys), KEYRING, len(trusted), sum(len(g) for g in trusted.values()), METADATA))
    for line in stop:
        print("STOP %s" % line)
    if stop:
        print("android-deps-review: %d Maven Central artifact(s) have no signer to pin: the lead decides" % len(stop))
        return 1
    return 0


# --- review ------------------------------------------------------------------------------------------


class Gpg:
    """gpg in a fresh home directory holding only the committed keyring; no key server, no agent use."""

    def __init__(self, keyring):
        exe = shutil.which("gpg")
        if exe is None:
            raise Usage("gpg is not on PATH (run with --skip-pgp only where it cannot be installed)")
        self.exe = exe
        self.home = tempfile.mkdtemp(prefix="kc-deps-gpg.")
        os.chmod(self.home, 0o700)
        for conf in ("common.conf", "gpg.conf"):
            Path(self.home, conf).write_text("")
        out = self.run(["--import", str(keyring)])
        if out.returncode != 0:
            raise Usage("gpg cannot import %s:\n%s" % (keyring, out.stderr))
        listing = self.run(["--list-keys", "--with-colons"]).stdout
        self.primaries = set()
        expect_primary = False
        for line in listing.splitlines():
            f = line.split(":")
            if f[0] == "pub":
                expect_primary = True
            elif f[0] == "sub":
                expect_primary = False
            elif f[0] == "fpr" and expect_primary:
                self.primaries.add(f[9])
                expect_primary = False

    def run(self, args, stdin=None):
        return subprocess.run([self.exe, "--homedir", self.home, "--batch", "--no-tty", "--no-auto-key-retrieve",
                               "--trust-model", "always", "--status-fd", "1"] + args,
                              input=stdin, capture_output=True, encoding="utf-8", errors="replace", check=False)

    def verify(self, asc, data):
        """(primary fingerprints of good signatures, expired-key flag, failure reason or None)."""
        d = tempfile.mkdtemp(prefix="kc-deps-sig.", dir=self.home)
        try:
            Path(d, "a.asc").write_bytes(asc)
            Path(d, "f").write_bytes(data)
            out = self.run(["--verify", str(Path(d, "a.asc")), str(Path(d, "f"))])
        finally:
            shutil.rmtree(d)
        status = [ln.split()[1:] for ln in out.stdout.splitlines() if ln.startswith("[GNUPG:] ")]
        kinds = {s[0] for s in status if s}
        bad = kinds & {"BADSIG", "REVKEYSIG", "EXPSIG", "ERRSIG"}
        valid = [s[10] for s in status if s and s[0] == "VALIDSIG" and len(s) > 10]
        if bad or not valid or not kinds & {"GOODSIG", "EXPKEYSIG"}:
            return [], False, "gpg: %s" % (", ".join(sorted(bad)) or "no good signature")
        return valid, "EXPKEYSIG" in kinds, None

    def close(self):
        if shutil.which("gpgconf"):
            subprocess.run(["gpgconf", "--homedir", self.home, "--kill", "all"], capture_output=True, check=False)
        shutil.rmtree(self.home, ignore_errors=True)


def cmd_review(root, mirror_dir, gradle_files, skip_pgp):
    check_settings(root)
    mirror = Mirror(mirror_dir, gradle_files)
    missing = needs(root, mirror)
    if missing:
        for path in sorted(missing):
            print("NOT FETCHED %s" % path)
        raise Usage("%d file(s) still to fetch (scripts/android-deps-review.sh fetches them)" % len(missing))
    meta = Metadata(root / METADATA)
    failures = ["metadata: %s" % p for p in meta.problems]
    keyring = keyring_keys(root / KEYRING)
    if set(keyring) != set(meta.trusted):
        failures.append("keyring and trusted keys differ: %s only in the keyring, %s only trusted"
                        % (sorted(set(keyring) - set(meta.trusted)), sorted(set(meta.trusted) - set(keyring))))
    gpg = None if skip_pgp else Gpg(root / KEYRING)
    try:
        if gpg is not None and gpg.primaries != set(keyring):
            failures.append("gpg read other keys from the keyring: %s" % sorted(gpg.primaries ^ set(keyring)))
        counts = {"google": 0, "central": 0, "expired": 0, "named": 0}
        used = set()
        for art in meta.artifacts:
            where = "%s:%s:%s %s" % art[:4]
            repo, reason, signed = check_artifact(mirror, meta, art)
            if signed is ACCEPTED_BY_NAME:
                print("accepted by name %s (%s): %s" % (where, REPOSITORY_NAMES[repo], SHA1_ONLY_REASON))
                counts["named"] += 1
                continue
            if reason is None and gpg is not None:
                if signed is not None:
                    fprs, expired, reason = gpg.verify(*signed)
                    pinned = [f for f in fprs if art[0] in meta.trusted.get(f, ())]
                    if reason is None and not pinned:
                        reason = "signed by %s, not a trusted key for group %s" % (", ".join(fprs), art[0])
                    if reason is None:
                        used.update((f, art[0]) for f in pinned)
                        counts["expired"] += expired
            if reason is not None:
                failures.append("%s (%s): %s" % (where, REPOSITORY_NAMES[repo], reason))
            else:
                counts[repo] += 1
        if gpg is not None:
            for fpr, groups in sorted(meta.trusted.items()):
                for g in sorted(groups):
                    if (fpr, g) not in used:
                        failures.append("trusted key %s for group %s signs nothing in that group" % (fpr, g))
    finally:
        if gpg is not None:
            gpg.close()
    components = meta.components()
    for lockfile in all_lockfiles(root):
        for coords in sorted(lockfile_modules(lockfile) - components):
            failures.append("%s: %s has no component in the metadata" % (lockfile.relative_to(root), coords))
    missing_cp, extra_cp, problems = classpath_diff(root)
    failures += problems
    failures += ["classpath: %s is in the lockfile's %s but not in %s" % (c, SHIPPING_CONFIGURATION, EXPECTED)
                 for c in extra_cp]
    failures += ["classpath: %s is in %s but not in the lockfile's %s" % (c, EXPECTED, SHIPPING_CONFIGURATION)
                 for c in missing_cp]
    allowed = deny_allowed(root)
    tally = {}
    for coords in shipping_classpath(root):
        try:
            ids = pom_licences(mirror, meta, coords)
        except ReviewFailure as f:
            failures.append("licence: %s" % f)
            continue
        print("licence %s %s" % (coords, " AND ".join(ids)))
        for spdx in ids:
            tally[spdx] = tally.get(spdx, 0) + 1
            if spdx not in allowed:
                failures.append("licence: %s is %s, not on %s's allow list" % (coords, spdx, DENY))
    for fpr in sorted(meta.trusted):
        uid = keyring[fpr]["uids"][0] if fpr in keyring and keyring[fpr]["uids"] else "?"
        print("trusted key %s (%s): %s" % (fpr, uid, ", ".join(sorted(meta.trusted[fpr]))))
    for f in failures:
        print("FAIL %s" % f)
    pgp = "SHA-1 matched, PGP NOT CHECKED" if skip_pgp else "SHA-1 and PGP matched"
    failed = len(meta.artifacts) - counts["google"] - counts["central"] - counts["named"]
    print("android-deps-review: %d artifacts: %d Google's Maven (SHA-256 matched), %d Maven Central (%s; %d by a key "
          "since expired), %d accepted by name (SHA-1 only, lead decision M5-11), %d failed"
          % (len(meta.artifacts), counts["google"], counts["central"], pgp, counts["expired"], counts["named"],
             failed))
    print("android-deps-review: %d trusted keys, %d group scopes; shipping runtime classpath %d modules; licences %s"
          % (len(meta.trusted), sum(len(g) for g in meta.trusted.values()), len(shipping_classpath(root)),
             ", ".join("%s %d" % kv for kv in sorted(tally.items()))))
    if failures:
        print("android-deps-review: FAILED, %d problem(s)" % len(failures))
        return 1
    if skip_pgp:
        print("android-deps-review: incomplete: the signatures were not checked (--skip-pgp)")
        return 3
    print("android-deps-review: passed")
    return 0


# --- classpath ----------------------------------------------------------------------------------------


def cmd_classpath(root, write):
    got = shipping_classpath(root)
    if write:
        if not got:
            raise Usage("%s has no %s" % (APP_LOCKFILE, SHIPPING_CONFIGURATION))
        (root / EXPECTED).parent.mkdir(parents=True, exist_ok=True)
        with open(root / EXPECTED, "w", encoding="utf-8", newline="\n") as f:
            f.write("".join(c + "\n" for c in got))
        print("android-deps-review: wrote %d modules to %s" % (len(got), EXPECTED))
        return 0
    missing, extra, problems = classpath_diff(root)
    for p in problems:
        print("FAIL %s" % p)
    for c in extra:
        print("FAIL classpath: %s is in the lockfile's %s but not in %s" % (c, SHIPPING_CONFIGURATION, EXPECTED))
    for c in missing:
        print("FAIL classpath: %s is in %s but not in the lockfile's %s" % (c, EXPECTED, SHIPPING_CONFIGURATION))
    if missing or extra or problems:
        return 1
    print("android-deps-review: the shipping runtime classpath (%s, %d modules) equals %s"
          % (SHIPPING_CONFIGURATION, len(got), EXPECTED))
    return 0


# --- selftest -----------------------------------------------------------------------------------------


# The base case's artifact count line: exit 0 (or 3 with --skip-pgp) says it passed, and this says the two
# listed files were counted as accepted by name, not as failures.
BASE_SUMMARY = "2 accepted by name (SHA-1 only, lead decision M5-11), 0 failed"


def run_self(args):
    """This script in a new process (-I), its exit code and output."""
    p = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve())] + args,
                       capture_output=True, encoding="utf-8", errors="replace", check=False)
    return p.returncode, p.stdout + p.stderr


def overlay(src, dst):
    """Copy a case's files over the base tree (root/ and mirror/); a file named X.deleted removes X."""
    for f in sorted(src.rglob("*")):
        if not f.is_file() or f.relative_to(src).as_posix() == "expect.txt":
            continue
        target = dst / f.relative_to(src)
        if f.name.endswith(".deleted"):
            Path(str(target)[: -len(".deleted")]).unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, target)


def selftest(skip_pgp):
    """Every case of TESTDATA: base must pass (BASE_SUMMARY); each fail-* case, base with its files laid
    over, must exit as its expect.txt says ("<exit code>[ pgp]", then a line the output must hold; "pgp":
    only gpg can see the failure, so --skip-pgp skips the case). A case with a gradle/ directory is
    reviewed with it as --gradle-files. Then the urls list on the base."""
    base = TESTDATA / "base"
    cases = [("base", None)] + [(c.name, c) for c in sorted(TESTDATA.iterdir()) if c.is_dir() and c.name != "base"]
    passed = failed = skipped = 0
    for name, case in cases:
        if case is None:
            want_rc, want_text, needs_pgp = 0, BASE_SUMMARY, False
        elif not name.startswith("fail-"):
            print("FAIL %s: a case is base or fail-*" % name)
            failed += 1
            continue
        else:
            head, _, text = read_bytes(case / "expect.txt").decode("utf-8").partition("\n")
            want_rc, needs_pgp, want_text = int(head.split()[0]), head.split()[1:] == ["pgp"], text.strip()
        if skip_pgp and needs_pgp:
            print("SKIP %s (only gpg sees it)" % name)
            skipped += 1
            continue
        if skip_pgp and want_rc == 0:
            want_rc = 3
        tmp = Path(tempfile.mkdtemp(prefix="kc-deps-selftest."))
        try:
            shutil.copytree(base, tmp / "t")
            if case is not None:
                overlay(case, tmp / "t")
            gradle = tmp / "t" / "gradle"
            rc, out = run_self(["review", str(tmp / "t" / "mirror"), "--root", str(tmp / "t" / "root")]
                               + (["--gradle-files", str(gradle)] if gradle.is_dir() else [])
                               + (["--skip-pgp"] if skip_pgp else []))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if rc == want_rc and want_text in out:
            print("PASS %s -> exit %d, %s" % (name, rc, want_text))
            passed += 1
        else:
            print("FAIL %s: wanted exit %d with %r, got exit %d:" % (name, want_rc, want_text, rc))
            print("\n".join("    " + ln for ln in out.splitlines()))
            failed += 1
    # The urls list: empty for the recorded base; without one of its .sha1 files, exactly that URL.
    rc, out = run_self(["urls", str(base / "mirror"), "--root", str(base / "root")])
    results = [("urls-base-complete", rc == 0 and out == "")]
    tmp = Path(tempfile.mkdtemp(prefix="kc-deps-selftest."))
    try:
        shutil.copytree(base, tmp / "t")
        gone = sorted((tmp / "t" / "mirror").rglob("*.sha1"))[0]
        gone.unlink()
        rel = gone.relative_to(tmp / "t" / "mirror").as_posix()
        rc, out = run_self(["urls", str(tmp / "t" / "mirror"), "--root", str(tmp / "t" / "root")])
        results.append(("urls-lists-a-missing-sha1", rc == 0 and out == "https://%s\t%s\n" % (rel, rel)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for label, ok in results:
        print("%s %s" % ("PASS" if ok else "FAIL", label))
        passed, failed = passed + ok, failed + (not ok)
    print("android-deps-review --selftest: %d passed, %d failed, %d skipped" % (passed, failed, skipped))
    if failed:
        return 1
    return 3 if skip_pgp else 0


# --- main ---------------------------------------------------------------------------------------------


def main(argv):
    if argv[:1] == ["--selftest"]:
        if argv[1:] not in ([], ["--skip-pgp"]):
            raise Usage("usage: --selftest [--skip-pgp]")
        return selftest(argv[1:] == ["--skip-pgp"])
    p = argparse.ArgumentParser(prog="android-deps-review.py")
    sub = p.add_subparsers(dest="cmd")
    for name in ("urls", "review", "write-keys"):
        s = sub.add_parser(name)
        s.add_argument("mirror")
        s.add_argument("--root", default=str(ROOT))
        if name != "write-keys":
            s.add_argument("--gradle-files")
        if name == "urls":
            s.add_argument("--keys", action="store_true")
        if name == "review":
            s.add_argument("--skip-pgp", action="store_true")
    s = sub.add_parser("classpath")
    s.add_argument("--write", action="store_true")
    s.add_argument("--root", default=str(ROOT))
    a = p.parse_args(argv)
    if a.cmd is None:
        p.print_usage(sys.stderr)
        return 2
    root = Path(a.root)
    if a.cmd == "urls":
        return cmd_urls(root, a.mirror, a.gradle_files, a.keys)
    if a.cmd == "review":
        return cmd_review(root, a.mirror, a.gradle_files, a.skip_pgp)
    if a.cmd == "write-keys":
        return cmd_write_keys(root, a.mirror)
    return cmd_classpath(root, a.write)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Usage as e:
        print("android-deps-review: %s" % e, file=sys.stderr)
        sys.exit(2)
