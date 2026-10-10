//! Strict ASCII armor for age files (C2SP age "ASCII armor", RFC 7468 strict encoding;
//! docs/build-plan.md "Container"; tasks/todo.md, M1 group 8; vectors/backup.json spec "armor").
//!
//! - Encode: `-----BEGIN AGE ENCRYPTED FILE-----`, the padded base64 of the binary file in lines of
//!   exactly 64 columns (the last 1 to 64), `-----END AGE ENCRYPTED FILE-----`, each line ended by
//!   LF.
//! - Decode accepts exactly that, with LF or CRLF line ends and an END line that may end the input
//!   (alone or with a CR), BEGIN at the first byte, and ASCII whitespace (space, tab, CR, LF)
//!   after the END line only, fewer than 1,024 bytes of it. Those are the age CLI's own limits:
//!   age before 1.3.0 (Ubuntu's 1.1.1 among them) reads a file as armor only when BEGIN is its
//!   first byte (1.3.0 and later skip up to 1,024 bytes of whitespace before it), and every
//!   version refuses 1,024 bytes after END, so no armor this reader accepts is one age refuses for
//!   its whitespace. The base64 must be canonical (base64ct checks the padding and the unused low
//!   bits). Anything else is `Backup(Armor)`, an input that starts with `-----BEGIN` only after
//!   whitespace included.
//!
//! The armored text is ciphertext, so these buffers need no wiping.

use base64ct::{Base64, Encoding};

use crate::error::{BackupError, CoreError, InternalFault};

/// The BEGIN line, without its line end.
pub(crate) const BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
/// The END line, without its line end.
pub(crate) const END: &[u8] = b"-----END AGE ENCRYPTED FILE-----";
/// What marks an input as armored, after leading whitespace: any PEM BEGIN line, so a wrong label
/// is an armor error rather than a header error.
const BEGIN_PREFIX: &[u8] = b"-----BEGIN";
/// Base64 characters per full line.
const COLUMNS: usize = 64;
/// One more than the whitespace allowed after END (the age CLI's limit; vectors/backup.json spec
/// "armor").
const MAX_WHITESPACE: usize = 1024;

/// The ASCII whitespace allowed after the armor: space, tab, CR and LF (the same four as
/// verify.py's `BACKUP_WHITESPACE`; not form feed, which `u8::is_ascii_whitespace` also takes).
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// How many whitespace bytes `data` starts with.
fn leading_space(data: &[u8]) -> usize {
    data.iter().take_while(|&&b| is_space(b)).count()
}

/// Whether to read `data` as armor: after leading whitespace it starts with `-----BEGIN`. Anything
/// else is read as a binary age file.
pub(crate) fn is_armored(data: &[u8]) -> bool {
    data[leading_space(data)..].starts_with(BEGIN_PREFIX)
}

/// The armor of a binary age file, as age writes it: LF line ends and a final LF.
pub(crate) fn encode(binary: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut text = vec![0u8; Base64::encoded_len(binary)];
    let encoded = Base64::encode(binary, &mut text)
        .map_err(|_| CoreError::Internal(InternalFault::Length))?
        .as_bytes();
    let lines = encoded.len().div_ceil(COLUMNS);
    let mut out = Vec::with_capacity(BEGIN.len() + 1 + encoded.len() + lines + END.len() + 1);
    out.extend_from_slice(BEGIN);
    out.push(b'\n');
    for line in encoded.chunks(COLUMNS) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(END);
    out.push(b'\n');
    Ok(out)
}

/// Lines of the armor, each without its LF or CRLF.
struct Lines<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Lines<'a> {
    /// The next line and whether it ended in LF, or `None` at the end of the input.
    fn next_line(&mut self) -> Option<(&'a [u8], bool)> {
        let rest = self.data.get(self.at..).filter(|rest| !rest.is_empty())?;
        let (line, ended) = match rest.iter().position(|&b| b == b'\n') {
            Some(end) => {
                self.at += end + 1;
                (&rest[..end], true)
            }
            None => {
                self.at = self.data.len();
                (rest, false)
            }
        };
        let line = match line.strip_suffix(b"\r") {
            Some(line) => line,
            None => line,
        };
        Some((line, ended))
    }

    /// Everything after the last line read.
    fn rest(&self) -> &'a [u8] {
        match self.data.get(self.at..) {
            Some(rest) => rest,
            None => &[],
        }
    }
}

/// The binary age file inside strict armor, or `Backup(Armor)`. The BEGIN line is the first line,
/// with no whitespace before it.
pub(crate) fn decode(data: &[u8]) -> Result<Vec<u8>, CoreError> {
    let refused = CoreError::Backup(BackupError::Armor);
    let mut lines = Lines { data, at: 0 };
    match lines.next_line() {
        Some((line, true)) if line == BEGIN => {}
        _ => return Err(refused),
    }
    let mut body = Vec::with_capacity(data.len());
    let mut previous = None;
    loop {
        let Some((line, ended)) = lines.next_line() else {
            return Err(refused);
        };
        if line == END {
            break;
        }
        // Every line before the last is a full one; each holds 1 to 64 characters.
        if !ended
            || line.is_empty()
            || line.len() > COLUMNS
            || previous.is_some_and(|n| n != COLUMNS)
        {
            return Err(refused);
        }
        body.extend_from_slice(line);
        previous = Some(line.len());
    }
    let rest = lines.rest();
    if previous.is_none() || rest.len() >= MAX_WHITESPACE || !rest.iter().all(|&b| is_space(b)) {
        return Err(refused);
    }
    let mut binary = vec![0u8; body.len() / 4 * 3];
    let decoded = Base64::decode(&body, &mut binary)
        .map_err(|_| refused)?
        .len();
    binary.truncate(decoded);
    Ok(binary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// SHA-256 counter-mode test bytes.
    fn stream(len: usize) -> Vec<u8> {
        (0u64..)
            .flat_map(|i| {
                Sha256::new()
                    .chain_update(b"armor")
                    .chain_update(i.to_be_bytes())
                    .finalize()
            })
            .take(len)
            .collect()
    }

    // Every length round-trips, in lines of exactly 64 with a last line of 1 to 64.
    #[test]
    fn every_length_round_trips_in_64_column_lines() {
        for len in 1..=200 {
            let binary = stream(len);
            let text = encode(&binary).expect("encoded");
            assert!(text.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----\n"));
            assert!(text.ends_with(b"\n-----END AGE ENCRYPTED FILE-----\n"));
            let lines: Vec<&[u8]> = text.split(|&b| b == b'\n').collect();
            let body = &lines[1..lines.len() - 2];
            assert!(
                body[..body.len() - 1].iter().all(|line| line.len() == 64),
                "{len}"
            );
            assert!((1..=64).contains(&body[body.len() - 1].len()), "{len}");
            assert!(is_armored(&text));
            assert_eq!(decode(&text).expect("decoded"), binary, "{len}");
        }
    }

    #[test]
    fn line_ends_and_surrounding_whitespace() {
        let text = encode(&stream(100)).expect("encoded");
        let crlf: Vec<u8> = text
            .iter()
            .flat_map(|&b| {
                if b == b'\n' {
                    vec![b'\r', b'\n']
                } else {
                    vec![b]
                }
            })
            .collect();
        let crlf_trailing = [crlf.as_slice(), b"\t \r\n\n"].concat();
        let end_cr = [&text[..text.len() - 1], b"\r"].concat();
        // Whitespace after END up to its limit, 1,023 bytes; none before BEGIN, even a lone LF or
        // 1,024 bytes of blank lines, which age 1.3.0 and later skip but age 1.1.1 does not.
        let blank_lines = b" \t\r\n".repeat(MAX_WHITESPACE / 4);
        let trailing = [&text, &blank_lines[1..]].concat();
        for accepted in [
            crlf.as_slice(),
            &crlf_trailing,
            &text[..text.len() - 1],
            &end_cr,
            &trailing,
        ] {
            assert_eq!(decode(accepted).expect("decoded"), stream(100));
        }
        let refused = CoreError::Backup(BackupError::Armor);
        let begin_only = [BEGIN, b"\n".as_slice()].concat();
        let mut form_feed = text.clone();
        form_feed.push(0x0c);
        let mut inner_cr = text.clone();
        inner_cr[BEGIN.len() + 5] = b'\r';
        let space_before = [b" ".as_slice(), &text].concat();
        let newline_before = [b"\n".as_slice(), &text].concat();
        let tab_after_line = [b"\n\t".as_slice(), &text].concat();
        let around = [b" \t\r\n".as_slice(), &text, b"\t \r\n\n"].concat();
        let leading_1024 = [blank_lines.as_slice(), &text].concat();
        let trailing_1024 = [&text, blank_lines.as_slice()].concat();
        for bad in [
            BEGIN,
            &begin_only,
            &form_feed,
            &inner_cr,
            &space_before,
            &newline_before,
            &tab_after_line,
            &around,
            &leading_1024,
            &trailing_1024,
        ] {
            assert!(is_armored(bad));
            assert_eq!(decode(bad), Err(refused));
        }
        // Form feed is not whitespace here: before BEGIN it makes the input a binary file.
        let mut form_feed_first = vec![0x0c];
        form_feed_first.extend_from_slice(&text);
        assert!(!is_armored(&form_feed_first));
    }
}
