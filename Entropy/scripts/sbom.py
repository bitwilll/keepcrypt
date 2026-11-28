#!/usr/bin/env python3
"""Software bills of materials, CycloneDX 1.6 JSON, one per artifact (tasks/todo.md, M7 item B2; the
owner chose a committed script over `cargo metadata` to a new tool, 2026-11-21).

- workspace: every shipped Rust root (keepcrypt-pi, keepcrypt-jni, keepcrypt-capi) over `cargo
  metadata --locked --format-version 1` (all platforms);
- apk: keepcrypt-jni over the metadata of each Android triple (`--filter-platform`), and the APK's
  runtime classpath, mobile/android/expected/shipping-runtime-classpath.txt (the reviewed list CI
  holds the shipping APK to), with each artifact's SHA-256 from gradle/verification-metadata.xml;
- pi-image: keepcrypt-pi over arm-unknown-linux-gnueabihf's metadata, and Buildroot's legal-info
  manifest.csv (`make -C pi/os legal-info` after an image build).

Rust packages come from crates.io or the workspace, nothing else: a crates.io package is a pkg:cargo
purl with Cargo.lock's SHA-256 and its manifest's licence expression; a workspace crate is named by
its bom-ref alone. Normal dependencies are scope "required"; a package reached only through build
dependencies (build scripts, proc macros) is "excluded", built with but not into the artifact; dev
dependencies are left out. The output is the same bytes for the same inputs: sorted, no timestamp,
no serial number. Any input it cannot account for (a package from another source, a crates.io
package with no checksum, a licence that is no SPDX expression, a classpath line the verification
metadata lacks, a malformed manifest) fails, and nothing is written.

Usage:
  sbom.py workspace --metadata META --lock Cargo.lock --out OUT
  sbom.py apk --metadata META [--metadata META ...] --lock Cargo.lock --classpath TXT
              --verification XML --out OUT
  sbom.py pi-image --metadata META --lock Cargo.lock --manifest CSV --out OUT
  sbom.py --selftest
Exit 0 written (or self-test passed), 1 refused (or a self-test case failed), 2 usage. Python 3.9+,
standard library only, no network; run with python3 -I.
"""

import argparse
import csv
import io
import json
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
GRADLE_NS = "{https://schema.gradle.org/dependency-verification}"
ROOTS = {
    "workspace": ["keepcrypt-capi", "keepcrypt-jni", "keepcrypt-pi"],
    "apk": ["keepcrypt-jni"],
    "pi-image": ["keepcrypt-pi"],
}
SUBJECT = {
    "workspace": ("application", "keepcrypt-entropy"),
    "apk": ("application", "com.keepcrypt.entropy"),
    "pi-image": ("firmware", "keepcrypt-pi-image"),
}
SPDX_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
MAVEN_LINE = re.compile(r"^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.+-]+)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Refused(Exception):
    """An input the SBOM cannot account for."""


def purl_part(text):
    """Percent-encodes everything outside purl's unreserved characters."""
    return "".join(c if re.match(r"[A-Za-z0-9._~-]$", c) else "".join("%%%02X" % b for b in c.encode("utf-8"))
                   for c in text)


def licence_expression(text, who):
    """Cargo's licence field as an SPDX expression: the old "A/B" form is "A OR B"; anything else
    that is not ids joined by AND, OR, WITH and parentheses is refused."""
    if not text:
        raise Refused("%s: no licence expression" % who)
    if "/" in text:
        text = " OR ".join(part.strip() for part in text.split("/"))
    # Operands (ids, or parenthesised expressions) and operators alternate: id (op id)*.
    depth, operand = 0, True
    for token in re.findall(r"\(|\)|[^\s()]+", text):
        if token == "(" and operand:
            depth += 1
        elif token == ")" and not operand and depth > 0:
            depth -= 1
        elif token in ("AND", "OR", "WITH") and not operand:
            operand = True
        elif operand and token not in ("AND", "OR", "WITH", "(", ")") and SPDX_ID.match(token):
            operand = False
        else:
            raise Refused("%s: licence %r is not an SPDX expression" % (who, text))
    if depth != 0 or operand:
        raise Refused("%s: licence %r is not an SPDX expression" % (who, text))
    return text


def lock_checksums(lock_text):
    """(name, version) -> SHA-256 for Cargo.lock's crates.io packages."""
    sums = {}
    for block in lock_text.split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"]*)"$', block, re.M))
        if fields.get("source") == CRATES_IO:
            if not SHA256.match(fields.get("checksum", "")):
                raise Refused("Cargo.lock: %s %s from crates.io has no checksum"
                              % (fields.get("name"), fields.get("version")))
            sums[(fields["name"], fields["version"])] = fields["checksum"]
    return sums


def rust_components(metas, checksums, roots):
    """Components of the packages the roots reach, over every metadata; and the roots' one version."""
    found, versions = {}, set()
    for n, meta in enumerate(metas):
        packages = {p["id"]: p for p in meta["packages"]}
        nodes = {node["id"]: node for node in meta["resolve"]["nodes"]}
        root_ids = []
        for name in roots:
            ids = [i for i, p in packages.items() if p["name"] == name and p["source"] is None]
            if len(ids) != 1:
                raise Refused("metadata %d: no workspace package %s" % (n + 1, name))
            root_ids.append(ids[0])
            versions.add(packages[ids[0]]["version"])

        def closure(kinds):
            seen, todo = set(root_ids), list(root_ids)
            while todo:
                for dep in nodes[todo.pop()]["deps"]:
                    if any(k["kind"] in kinds for k in dep["dep_kinds"]) and dep["pkg"] not in seen:
                        seen.add(dep["pkg"])
                        todo.append(dep["pkg"])
            return seen

        runtime, built = closure({None}), closure({None, "build"})
        for pid in built - set(root_ids):
            package = packages[pid]
            name, version, source = package["name"], package["version"], package["source"]
            who = "%s %s" % (name, version)
            scope = "required" if pid in runtime else "excluded"
            if source == CRATES_IO:
                if (name, version) not in checksums:
                    raise Refused("%s: from crates.io but not in Cargo.lock" % who)
                ref = "pkg:cargo/%s@%s" % (purl_part(name), purl_part(version))
                component = {"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
                             "hashes": [{"alg": "SHA-256", "content": checksums[(name, version)]}]}
            elif source is None:
                ref = "keepcrypt-workspace:%s@%s" % (name, version)
                component = {"type": "library", "bom-ref": ref, "name": name, "version": version}
            else:
                raise Refused("%s: source %s is neither crates.io nor the workspace" % (who, source))
            component["licenses"] = [{"expression": licence_expression(package.get("license"), who)}]
            component["scope"] = scope
            old = found.get(ref)
            if old is not None and old["scope"] == "required":
                component["scope"] = "required"
            found[ref] = component
    if len(versions) != 1:
        raise Refused("the roots name %d versions, not one: %s" % (len(versions), sorted(versions)))
    return found, versions.pop()


def maven_components(classpath_text, verification_text):
    """Components of the classpath's group:name:version lines, each with its .aar or .jar's SHA-256."""
    try:
        root = ET.fromstring(verification_text)
    except ET.ParseError as error:
        raise Refused("the verification metadata is not XML: %s" % error)
    artifacts = {}
    for c in root.iter(GRADLE_NS + "component"):
        key = (c.get("group"), c.get("name"), c.get("version"))
        for a in c.iter(GRADLE_NS + "artifact"):
            sums = [s.get("value") for s in a.iter(GRADLE_NS + "sha256")]
            artifacts.setdefault(key, {})[a.get("name")] = sums
    found = {}
    lines = classpath_text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise Refused("the classpath is empty")
    for number, line in enumerate(lines, 1):
        hit = MAVEN_LINE.match(line)
        if not hit:
            raise Refused("classpath line %d: %r is not group:name:version" % (number, line))
        group, name, version = hit.groups()
        files = artifacts.get((group, name, version))
        if files is None:
            raise Refused("classpath line %d: %s is not in the verification metadata" % (number, line))
        if not files or any(len(sums) != 1 or not SHA256.match(sums[0]) for sums in files.values()):
            raise Refused("classpath line %d: %s has no files, or a file without one SHA-256" % (number, line))
        # The binary packaged into the APK: Maven's primary file, name-version.aar or .jar, when the
        # metadata holds it; otherwise the one .aar or .jar a Gradle variant names its own way
        # (animation.aar), Kotlin Multiplatform's -metadata jars aside (common code's metadata,
        # compiled against, never packaged). A Multiplatform root or a BOM has none: its .module or
        # .pom only points at a variant, which the classpath lists in its own line.
        primary = [f for f in ("%s-%s.aar" % (name, version), "%s-%s.jar" % (name, version)) if f in files]
        binaries = primary or [f for f in files if f.endswith(".aar")
                               or (f.endswith(".jar") and not f.endswith("-metadata-%s.jar" % version))]
        if len(binaries) > 1 or (not binaries and not any(f.endswith((".module", ".pom")) for f in files)):
            raise Refused("classpath line %d: %s has %d binaries and no descriptor to stand for none"
                          % (number, line, len(binaries)))
        ref = "pkg:maven/%s/%s@%s" % (purl_part(group), purl_part(name), purl_part(version))
        if ref in found:
            raise Refused("classpath line %d: %s is listed twice" % (number, line))
        component = {"type": "library", "bom-ref": ref, "group": group, "name": name, "version": version,
                     "purl": ref, "scope": "required",
                     "properties": [{"name": "keepcrypt:sha256:%s" % f, "value": files[f][0]} for f in sorted(files)]}
        if binaries:
            component["hashes"] = [{"alg": "SHA-256", "content": files[binaries[0]][0]}]
        found[ref] = component
    return found


def buildroot_components(manifest_text):
    """Components of Buildroot's legal-info manifest.csv rows."""
    rows = list(csv.DictReader(io.StringIO(manifest_text)))
    need = ("PACKAGE", "VERSION", "LICENSE", "SOURCE ARCHIVE")
    if not rows or any(column not in rows[0] for column in need):
        raise Refused("the manifest has no rows or lacks a column of %s" % ", ".join(need))
    found = {}
    for number, row in enumerate(rows, 2):
        name, version = (row["PACKAGE"] or "").strip(), (row["VERSION"] or "").strip()
        if not name or not version:
            raise Refused("manifest line %d: no package or no version" % number)
        ref = "pkg:generic/buildroot/%s@%s" % (purl_part(name), purl_part(version))
        if ref in found:
            raise Refused("manifest line %d: %s %s is listed twice" % (number, name, version))
        component = {"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
                     "scope": "required"}
        licence = (row["LICENSE"] or "").strip()
        if licence:
            component["licenses"] = [{"license": {"name": licence}}]
        archive = (row["SOURCE ARCHIVE"] or "").strip()
        if archive:
            component["properties"] = [{"name": "keepcrypt:source-archive", "value": archive}]
        found[ref] = component
    return found


def document(kind, version, components):
    """The CycloneDX document, every list sorted, as bytes."""
    kind_type, name = SUBJECT[kind]
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": kind_type, "bom-ref": "%s@%s" % (name, version), "name": name,
                          "version": version},
            "tools": {"components": [{"type": "application", "name": "keepcrypt scripts/sbom.py"}]},
        },
        "components": [components[ref] for ref in sorted(components)],
    }
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def build(kind, metas, lock_text, classpath_text=None, verification_text=None, manifest_text=None):
    components, version = rust_components(metas, lock_checksums(lock_text), ROOTS[kind])
    if kind == "apk":
        components.update(maven_components(classpath_text, verification_text))
    if kind == "pi-image":
        components.update(buildroot_components(manifest_text))
    return document(kind, version, components)


# --- self-test -------------------------------------------------------------------------------------

def fixture_meta(extra_packages=(), extra_deps=()):
    """A small workspace: keepcrypt-pi, -jni and -capi on keepcrypt-core, which takes sha2 (normal),
    cc (build) and proptest (dev)."""
    def pkg(name, version, source, licence="MIT OR Apache-2.0"):
        pid = ("%s#%s@%s" % (source, name, version)) if source else ("path+file:///w/%s#%s" % (name, version))
        return {"id": pid, "name": name, "version": version, "source": source, "license": licence}
    packages = [pkg("keepcrypt-pi", "0.1.0", None), pkg("keepcrypt-jni", "0.1.0", None),
                pkg("keepcrypt-capi", "0.1.0", None), pkg("keepcrypt-core", "0.1.0", None),
                pkg("sha2", "0.11.0", CRATES_IO), pkg("cc", "1.2.0", CRATES_IO, "MIT/Apache-2.0"),
                pkg("proptest", "1.7.0", CRATES_IO)] + [pkg(*p) for p in extra_packages]
    ids = {p["name"]: p["id"] for p in packages}

    def dep(name, kind=None):
        return {"pkg": ids[name], "dep_kinds": [{"kind": kind, "target": None}]}
    deps = {"keepcrypt-pi": [dep("keepcrypt-core")], "keepcrypt-jni": [dep("keepcrypt-core")],
            "keepcrypt-capi": [dep("keepcrypt-core")],
            "keepcrypt-core": [dep("sha2"), dep("cc", "build"), dep("proptest", "dev")]}
    for parent, child, kind in extra_deps:
        deps.setdefault(parent, []).append(dep(child, kind))
    nodes = [{"id": p["id"], "deps": deps.get(p["name"], [])} for p in packages]
    return {"packages": packages, "resolve": {"nodes": nodes}}


FIXTURE_LOCK = "".join('\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "%s"\nchecksum = "%s"\n'
                       % (n, v, CRATES_IO, c * 64) for n, v, c in
                       [("sha2", "0.11.0", "a"), ("cc", "1.2.0", "b"), ("proptest", "1.7.0", "c")])
FIXTURE_VERIFICATION = """<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification"><components>
<component group="androidx.core" name="core" version="1.17.0">
<artifact name="core-1.17.0.aar"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
<artifact name="core-1.17.0.module"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
</component>
<component group="org.jetbrains" name="annotations" version="23.0.0">
<artifact name="annotations-23.0.0.jar"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
</component>
<component group="androidx.compose" name="compose-bom" version="2026.01.00">
<artifact name="compose-bom-2026.01.00.pom"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
</component>
<component group="org.jetbrains.kotlin" name="kotlin-stdlib" version="2.4.20">
<artifact name="kotlin-stdlib-2.4.20-all.jar"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
<artifact name="kotlin-stdlib-2.4.20.jar"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
</component>
<component group="androidx.x" name="two" version="1.0">
<artifact name="two.aar"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
<artifact name="two-release.aar"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
</component>
<component group="androidx.x" name="metaonly" version="1.0">
<artifact name="metaonly-metadata-1.0.jar"><sha256 value="%s" origin="Generated by Gradle"/></artifact>
</component>
</components></verification-metadata>
""" % ("d" * 64, "e" * 64, "f" * 64, "1" * 64, "5" * 64, "6" * 64, "2" * 64, "3" * 64, "4" * 64)
FIXTURE_CLASSPATH = "androidx.compose:compose-bom:2026.01.00\nandroidx.core:core:1.17.0\norg.jetbrains:annotations:23.0.0\n"
FIXTURE_MANIFEST = ('"PACKAGE","VERSION","LICENSE","LICENSE FILES","SOURCE ARCHIVE","SOURCE SITE",'
                    '"DEPENDENCIES WITH LICENSES"\n'
                    '"busybox","1.37.0","GPL-2.0","LICENSE","busybox-1.37.0.tar.bz2","https://busybox.net",""\n'
                    '"linux","21b4101","GPL-2.0","COPYING","linux-21b4101.tar.gz","https://github.com",""\n')


def selftest():
    passed = failed = 0

    def case(label, run, want=None):
        nonlocal passed, failed
        try:
            got = run()
        except Refused as error:
            problem = None if want is None else "refused: %s" % error
        else:
            problem = "not refused" if want is None else (None if want(got) else "unexpected output")
        if problem:
            failed += 1
            print("FAIL %s: %s" % (label, problem))
        else:
            passed += 1

    def parsed(data):
        return {c["bom-ref"]: c for c in json.loads(data)["components"]}

    meta = fixture_meta()
    ws = lambda: build("workspace", [meta], FIXTURE_LOCK)
    case("workspace: core, sha2 and cc; proptest (dev) left out", ws,
         lambda d: sorted(parsed(d)) == ["keepcrypt-workspace:keepcrypt-core@0.1.0", "pkg:cargo/cc@1.2.0",
                                         "pkg:cargo/sha2@0.11.0"])
    case("workspace: sha2 required, cc (build only) excluded", ws,
         lambda d: parsed(d)["pkg:cargo/sha2@0.11.0"]["scope"] == "required"
         and parsed(d)["pkg:cargo/cc@1.2.0"]["scope"] == "excluded")
    case("workspace: Cargo.lock's SHA-256 on a crates.io package", ws,
         lambda d: parsed(d)["pkg:cargo/sha2@0.11.0"]["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}])
    case("workspace: MIT/Apache-2.0 written as an expression", ws,
         lambda d: parsed(d)["pkg:cargo/cc@1.2.0"]["licenses"] == [{"expression": "MIT OR Apache-2.0"}])
    case("workspace: the subject and its version", ws,
         lambda d: json.loads(d)["metadata"]["component"]["bom-ref"] == "keepcrypt-entropy@0.1.0")
    case("workspace: the same bytes twice", lambda: (ws(), ws()), lambda pair: pair[0] == pair[1])
    case("workspace: a crate both normal and build is required",
         lambda: build("workspace", [fixture_meta(extra_deps=[("keepcrypt-pi", "cc", None)])], FIXTURE_LOCK),
         lambda d: parsed(d)["pkg:cargo/cc@1.2.0"]["scope"] == "required")
    case("refused: a crates.io package with no Cargo.lock checksum",
         lambda: build("workspace", [fixture_meta([("libc", "0.2.0", CRATES_IO)],
                                                  [("keepcrypt-core", "libc", None)])], FIXTURE_LOCK))
    case("refused: Cargo.lock lists a crates.io package without a checksum",
         lambda: build("workspace", [meta], FIXTURE_LOCK + '\n[[package]]\nname = "x"\nversion = "1.0.0"\n'
                       'source = "%s"\n' % CRATES_IO))
    case("refused: a git source",
         lambda: build("workspace", [fixture_meta([("evil", "1.0.0", "git+https://example.invalid/evil")],
                                                  [("keepcrypt-core", "evil", None)])], FIXTURE_LOCK))
    case("refused: a licence that is no SPDX expression",
         lambda: build("workspace", [fixture_meta([("odd", "1.0.0", CRATES_IO, "see LICENSE file")],
                                                  [("keepcrypt-core", "odd", None)])],
                       FIXTURE_LOCK + '\n[[package]]\nname = "odd"\nversion = "1.0.0"\nsource = "%s"\n'
                       'checksum = "%s"\n' % (CRATES_IO, "9" * 64)))
    case("refused: no licence", lambda: licence_expression(None, "x"))
    case("refused: unbalanced parentheses", lambda: licence_expression("(MIT OR Apache-2.0", "x"))
    case("refused: a trailing operator", lambda: licence_expression("MIT OR", "x"))
    case("an expression in parentheses", lambda: licence_expression("(MIT OR Apache-2.0) AND Unicode-3.0", "x"),
         lambda e: e == "(MIT OR Apache-2.0) AND Unicode-3.0")
    case("refused: a root missing", lambda: rust_components([meta], {}, ["keepcrypt-nope"]))
    two = fixture_meta()
    two["packages"][1]["version"] = "0.2.0"
    case("refused: roots of two versions", lambda: build("workspace", [two], FIXTURE_LOCK))
    apk = lambda cp=FIXTURE_CLASSPATH, xml=FIXTURE_VERIFICATION: build("apk", [meta, meta], FIXTURE_LOCK, cp, xml)
    case("apk: the classpath with its binaries' SHA-256", apk,
         lambda d: parsed(d)["pkg:maven/androidx.core/core@1.17.0"]["hashes"][0]["content"] == "d" * 64
         and parsed(d)["pkg:maven/org.jetbrains/annotations@23.0.0"]["hashes"][0]["content"] == "f" * 64
         and "keepcrypt-workspace:keepcrypt-core@0.1.0" in parsed(d))
    case("refused: a classpath line the metadata lacks",
         lambda: apk(FIXTURE_CLASSPATH + "com.example:x:1.0\n"))
    case("apk: a BOM stands with its .pom's SHA-256 and no binary hash", apk,
         lambda d: "hashes" not in parsed(d)["pkg:maven/androidx.compose/compose-bom@2026.01.00"]
         and parsed(d)["pkg:maven/androidx.compose/compose-bom@2026.01.00"]["properties"]
         == [{"name": "keepcrypt:sha256:compose-bom-2026.01.00.pom", "value": "1" * 64}])
    case("apk: Maven's primary jar before a second one", lambda: apk("org.jetbrains.kotlin:kotlin-stdlib:2.4.20\n"),
         lambda d: parsed(d)["pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.4.20"]["hashes"][0]["content"] == "6" * 64)
    case("refused: a classpath line with two binaries", lambda: apk("androidx.x:two:1.0\n"))
    case("refused: a metadata jar and no descriptor", lambda: apk("androidx.x:metaonly:1.0\n"))
    case("refused: a classpath line twice", lambda: apk(FIXTURE_CLASSPATH + "androidx.core:core:1.17.0\n"))
    case("refused: a malformed classpath line", lambda: apk("androidx.core core 1.17.0\n"))
    case("refused: an empty classpath", lambda: apk(""))
    pi = lambda m=FIXTURE_MANIFEST: build("pi-image", [meta], FIXTURE_LOCK, manifest_text=m)
    case("pi-image: the manifest's packages, licence and archive", pi,
         lambda d: parsed(d)["pkg:generic/buildroot/busybox@1.37.0"]["licenses"] == [{"license": {"name": "GPL-2.0"}}]
         and json.loads(d)["metadata"]["component"]["type"] == "firmware")
    case("refused: a manifest without a VERSION column",
         lambda: pi('"PACKAGE","LICENSE","SOURCE ARCHIVE"\n"busybox","GPL-2.0","b.tar"\n'))
    case("refused: a manifest row without a version",
         lambda: pi(FIXTURE_MANIFEST + '"zlib","","Zlib","","z.tar","",""\n'))
    case("refused: a manifest row twice", lambda: pi(FIXTURE_MANIFEST + FIXTURE_MANIFEST.split("\n", 1)[1]))
    case("purl parts percent-encoded", lambda: purl_part("a b/c+d"), lambda s: s == "a%20b%2Fc%2Bd")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "bom.json"
        case("refused: nothing written",
             lambda: main(["workspace", "--metadata", str(write(tmp, "m.json", json.dumps(two))),
                           "--lock", str(write(tmp, "Cargo.lock", FIXTURE_LOCK)), "--out", str(out)]),
             lambda code: code == 1 and not out.exists())
    print("sbom selftest: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


def write(directory, name, text):
    path = Path(directory) / name
    path.write_text(text, encoding="utf-8")
    return path


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    parser = argparse.ArgumentParser(prog="sbom.py")
    parser.add_argument("kind", choices=sorted(ROOTS))
    parser.add_argument("--metadata", action="append", required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--classpath")
    parser.add_argument("--verification")
    parser.add_argument("--manifest")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    wants = {"apk": ("classpath", "verification"), "pi-image": ("manifest",), "workspace": ()}[args.kind]
    for name in ("classpath", "verification", "manifest"):
        if (getattr(args, name) is not None) != (name in wants):
            parser.error("%s %s --%s" % (args.kind, "needs" if name in wants else "takes no", name))
    if args.kind != "apk" and len(args.metadata) != 1:
        parser.error("%s takes one --metadata" % args.kind)
    read = lambda p: Path(p).read_text(encoding="utf-8") if p else None
    try:
        data = build(args.kind, [json.loads(read(m)) for m in args.metadata], read(args.lock),
                     read(args.classpath), read(args.verification), read(args.manifest))
    except (Refused, ValueError, KeyError, csv.Error) as error:
        print("sbom: refused: %s" % error, file=sys.stderr)
        return 1
    Path(args.out).write_bytes(data)
    print("sbom: %s: %d components, %s" % (args.kind, len(json.loads(data)["components"]), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
