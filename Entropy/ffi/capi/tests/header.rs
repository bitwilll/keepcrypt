//! include/keepcrypt.h agrees with the library (tasks/todo.md, M6 item B3): the header holds exactly
//! its two prototypes, and the staticlib, built here for the host with this toolchain's cargo, defines
//! exactly those two `kc_` symbols, read with this toolchain's llvm-nm (llvm-tools-preview, which
//! rust-toolchain.toml installs). It needs no Xcode and runs on the macOS and Linux hosts alike: a
//! Mach-O symbol carries a leading underscore, an ELF one none. The comparison itself is checked on
//! a planted extra export, a missing one and a planted prototype, so a check that passes everything
//! fails here.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The header, as the app includes it.
const HEADER: &str = include_str!("../include/keepcrypt.h");

/// The two prototypes, exactly as written there (include/keepcrypt.h; lead decision M6-1).
const PROTOTYPES: [&str; 2] = [
    "size_t kc_max_out(void);",
    "int64_t kc_call(uint32_t op, const uint8_t *input, size_t input_len, uint8_t *out, size_t out_cap);",
];

/// The names the header declares: each line outside its block comments that ends in `);` is a
/// prototype, its name the word before its first `(`. A prototype not exactly one of `PROTOTYPES`
/// fails, so the types are pinned with the names.
fn declared(header: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut comment = false;
    for line in header.lines().map(str::trim) {
        if comment || line.starts_with("/*") {
            comment = !line.ends_with("*/");
            continue;
        }
        if !line.ends_with(");") {
            continue;
        }
        if !PROTOTYPES.contains(&line) {
            return Err(format!("a prototype that is not one of the two: {line}"));
        }
        let before = line.split('(').next().ok_or("no name")?;
        let name = before.rsplit(' ').next().ok_or("no name")?;
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

/// The `kc_` symbols llvm-nm's output names as defined (`--defined-only --extern-only`), each once,
/// sorted; `underscore` strips Mach-O's leading underscore. A line is "<value> <type> <name>" (an
/// archive's member headers and blank lines are skipped).
fn defined(nm: &str, underscore: bool) -> Vec<String> {
    let mut names: Vec<String> = nm
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields[..] {
                [_, kind, name] if kind.len() == 1 => Some(name),
                _ => None,
            }
        })
        .map(|name| match name.strip_prefix('_') {
            Some(rest) if underscore => rest,
            _ => name,
        })
        .filter(|name| name.starts_with("kc_"))
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The header's names against the library's: equal, or what differs.
fn agree(header: &str, nm: &str, underscore: bool) -> Result<(), String> {
    let declared = declared(header)?;
    let defined = defined(nm, underscore);
    if declared != ["kc_call", "kc_max_out"] {
        return Err(format!(
            "the header declares {declared:?}, not kc_call and kc_max_out"
        ));
    }
    if defined != declared {
        return Err(format!(
            "the library defines {defined:?}, the header declares {declared:?}"
        ));
    }
    Ok(())
}

/// This toolchain's binaries: the cargo that runs this test, and its rustc beside it.
fn toolchain_bin(name: &str) -> PathBuf {
    Path::new(env!("CARGO")).with_file_name(name)
}

/// The staticlib, built for the host into this test's own target directory (the workspace's is
/// held by the cargo that runs the test), offline, from the locked graph.
fn staticlib() -> PathBuf {
    let target_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("capi-header");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--quiet",
            "--locked",
            "--offline",
            "-p",
            "keepcrypt-capi",
            "--lib",
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .expect("cargo runs");
    assert!(status.success(), "the staticlib builds");
    let lib = target_dir.join("debug").join("libkeepcrypt_capi.a");
    assert!(lib.is_file(), "the staticlib is there");
    lib
}

/// This toolchain's llvm-nm, as entropy-ci.yml's scan steps find it: beside the host's target
/// libdir.
fn llvm_nm() -> PathBuf {
    let out = Command::new(toolchain_bin("rustc"))
        .args(["--print", "target-libdir"])
        .output()
        .expect("rustc runs");
    assert!(out.status.success(), "rustc prints its target libdir");
    let libdir = String::from_utf8(out.stdout).expect("a path");
    let nm = Path::new(libdir.trim()).join("../bin/llvm-nm");
    assert!(nm.is_file(), "llvm-tools-preview's llvm-nm");
    nm
}

#[test]
fn the_header_names_exactly_the_librarys_exports() {
    let out = Command::new(llvm_nm())
        .args(["--defined-only", "--extern-only"])
        .arg(staticlib())
        .output()
        .expect("llvm-nm runs");
    assert!(out.status.success(), "llvm-nm reads the staticlib");
    let nm = String::from_utf8(out.stdout).expect("text");
    let underscore = cfg!(target_vendor = "apple");
    assert_eq!(agree(HEADER, &nm, underscore), Ok(()));
    assert_eq!(defined(&nm, underscore), ["kc_call", "kc_max_out"]);
}

/// The comparison fails where it should: a planted extra export, a missing one, a planted
/// prototype and a changed one; a symbol inside a commented-out prototype is no declaration.
#[test]
fn the_comparison_fails_on_a_planted_export_or_prototype() {
    let nm = "\nlib.o:\n0000000000000000 T _kc_call\n0000000000000010 T _kc_max_out\n0000000000000020 T _other\n";
    assert_eq!(agree(HEADER, nm, true), Ok(()));
    let planted = format!("{nm}0000000000000030 T _kc_planted\n");
    assert_eq!(
        agree(HEADER, &planted, true),
        Err(r#"the library defines ["kc_call", "kc_max_out", "kc_planted"], the header declares ["kc_call", "kc_max_out"]"#.to_owned())
    );
    let elf = "0000000000000000 T kc_call\n0000000000000010 T kc_max_out\n0000000000000020 W kc_planted\n";
    assert!(agree(HEADER, elf, false).is_err(), "an ELF planted export");
    assert!(
        agree(HEADER, "0000000000000000 T _kc_call\n", true).is_err(),
        "a missing export"
    );
    let extra = HEADER.replace(
        "#endif",
        "int64_t kc_call(uint32_t op, const uint8_t *input, size_t input_len, uint8_t *out, size_t out_cap);\n#endif",
    );
    assert!(agree(&extra, nm, true).is_err(), "a prototype twice");
    let changed = HEADER.replace("int64_t kc_call", "int32_t kc_call");
    assert!(agree(&changed, nm, true).is_err(), "a changed prototype");
    let planted = HEADER.replace("#endif", "void kc_planted(void);\n#endif");
    assert!(agree(&planted, nm, true).is_err(), "a planted prototype");
    let commented = HEADER.replace("#endif", "/* void kc_old(void); */\n#endif");
    assert_eq!(agree(&commented, nm, true), Ok(()));
}
