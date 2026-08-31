use anyhow::{bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use std::io::{Cursor, Read, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use super::stub::AUTO_KEY_LEN;

pub const WRAPPER_MAGIC: &[u8; 8] = b"DEOBFW01";
pub const WRAPPER_HEADER_LEN: usize = 34;
const LOADER_CLASS: &[u8] = include_bytes!("../../vendor/java/deobf/Loader.class");
const PYTHON_TEMPLATE: &str = include_str!("../../vendor/python/loader_template.py");

pub fn encrypt_wrapper(key: &[u8; AUTO_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    encrypt_wrapper_with_nonce(key, &nonce, plaintext)
}

pub fn encrypt_wrapper_with_nonce(
    key: &[u8; AUTO_KEY_LEN],
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("wrapper encryption failed"))?;
    let mut out = Vec::with_capacity(WRAPPER_HEADER_LEN + ct.len());
    out.extend_from_slice(WRAPPER_MAGIC);
    out.push(1);
    out.push(0);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_wrapper(key: &[u8; AUTO_KEY_LEN], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < WRAPPER_HEADER_LEN + 16 {
        bail!("truncated DEOBF wrapper");
    }
    if &wrapped[..8] != WRAPPER_MAGIC {
        bail!("not a DEOBF wrapper");
    }
    if wrapped[8] != 1 {
        bail!("unsupported wrapper version {}", wrapped[8]);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(&wrapped[10..34]), &wrapped[34..])
        .map_err(|_| anyhow::anyhow!("wrapper authentication failed"))
}

pub fn jar_main_class(data: &[u8]) -> Option<String> {
    let mut archive = ZipArchive::new(Cursor::new(data)).ok()?;
    let mut entry = archive.by_name("META-INF/MANIFEST.MF").ok()?;
    let mut text = String::new();
    entry.read_to_string(&mut text).ok()?;
    parse_main_class(&text)
}

fn parse_main_class(manifest: &str) -> Option<String> {
    let mut continued = String::new();
    for raw in manifest.lines() {
        let line = raw.trim_end().trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix(' ') {
            continued.push_str(rest);
            continue;
        }
        if !continued.is_empty() {
            if let Some(found) = main_class_from_line(&continued) {
                return Some(found);
            }
            continued.clear();
        }
        continued.push_str(line);
    }
    if !continued.is_empty() {
        main_class_from_line(&continued)
    } else {
        None
    }
}

fn main_class_from_line(line: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix("Main-Class:")?;
    let name = rest.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

pub fn looks_like_zipapp(data: &[u8]) -> bool {
    if data.len() < 4 || &data[..2] != b"PK" {
        return false;
    }
    let mut archive = match ZipArchive::new(Cursor::new(data)) {
        Ok(z) => z,
        Err(_) => return false,
    };
    let ok = archive.by_name("__main__.py").is_ok();
    drop(archive);
    ok
}

pub fn wrap_jar(payload: &[u8], key: &[u8; AUTO_KEY_LEN]) -> Result<Vec<u8>> {
    let envelope = encrypt_wrapper(key, payload)?;
    let main = jar_main_class(payload).unwrap_or_default();
    let mut cursor = Cursor::new(Vec::with_capacity(
        LOADER_CLASS.len() + envelope.len() + 256,
    ));
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);
        zip.start_file("META-INF/MANIFEST.MF", opts)?;
        zip.write_all(
            b"Manifest-Version: 1.0\r\nMain-Class: deobf.Loader\r\nCreated-By: DEOBF\r\n\r\n",
        )?;
        zip.start_file("deobf/Loader.class", opts)?;
        zip.write_all(LOADER_CLASS)?;
        zip.start_file("deobf/key.bin", opts)?;
        zip.write_all(key)?;
        zip.start_file("deobf/payload.bin", opts)?;
        zip.write_all(&envelope)?;
        zip.start_file("deobf/meta.properties", opts)?;
        zip.write_all(format!("original-main-class={main}\n").as_bytes())?;
        zip.finish().context("finish self-running JAR")?;
    }
    Ok(cursor.into_inner())
}

pub fn wrap_python(payload: &[u8], key: &[u8; AUTO_KEY_LEN], as_zipapp: bool) -> Result<Vec<u8>> {
    let envelope = encrypt_wrapper(key, payload)?;
    let stub = render_python_stub(key, &envelope);
    if as_zipapp {
        zipapp_from_stub(&stub)
    } else {
        Ok(stub)
    }
}

fn render_python_stub(key: &[u8; AUTO_KEY_LEN], envelope: &[u8]) -> Vec<u8> {
    let key_hex = hex_encode(key);
    let blob = wrap76(&b64_encode(envelope));
    PYTHON_TEMPLATE
        .replace("__DEOBF_KEY_HEX__", &key_hex)
        .replace("__DEOBF_BLOB_B64__", &blob)
        .into_bytes()
}

fn zipapp_from_stub(stub: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::with_capacity(stub.len() + 64));
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o755);
        zip.start_file("__main__.py", opts)?;
        zip.write_all(stub)?;
        zip.finish().context("finish self-running zipapp")?;
    }
    Ok(cursor.into_inner())
}

pub fn is_selfrun_jar(data: &[u8]) -> bool {
    data.len() >= 4
        && data.starts_with(b"PK")
        && zip_has(data, "deobf/payload.bin")
        && zip_has(data, "deobf/Loader.class")
}

pub fn is_selfrun_python(data: &[u8]) -> bool {
    if data.len() >= 4 && data.starts_with(b"PK") {
        if let Some(main) = zip_bytes(data, "__main__.py") {
            return std::str::from_utf8(&main)
                .map(|s| s.contains("# DEOBF-PY-V1"))
                .unwrap_or(false);
        }
        return false;
    }
    std::str::from_utf8(data)
        .map(|s| s.contains("# DEOBF-PY-V1"))
        .unwrap_or(false)
}

pub fn embedded_key(data: &[u8]) -> Option<[u8; AUTO_KEY_LEN]> {
    if data.len() >= 4 && data.starts_with(b"PK") {
        if let Some(bytes) = zip_bytes(data, "deobf/key.bin") {
            if bytes.len() == AUTO_KEY_LEN {
                let mut key = [0u8; AUTO_KEY_LEN];
                key.copy_from_slice(&bytes);
                return Some(key);
            }
        }
        if let Some(main) = zip_bytes(data, "__main__.py") {
            if let Ok(text) = std::str::from_utf8(&main) {
                if let Some((key, _)) = parse_python_stub(text) {
                    return Some(key);
                }
            }
        }
        return None;
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some((key, _)) = parse_python_stub(text) {
            return Some(key);
        }
    }
    None
}

pub fn try_unwrap(data: &[u8]) -> Result<Option<Vec<u8>>> {
    if data.len() >= 4 && data.starts_with(b"PK") {
        if zip_has(data, "deobf/payload.bin") {
            let key_bytes = zip_bytes(data, "deobf/key.bin")
                .context("self-running JAR is missing deobf/key.bin")?;
            if key_bytes.len() != AUTO_KEY_LEN {
                bail!("self-running JAR has an invalid key");
            }
            let mut key = [0u8; AUTO_KEY_LEN];
            key.copy_from_slice(&key_bytes);
            let payload = zip_bytes(data, "deobf/payload.bin")
                .context("self-running JAR is missing deobf/payload.bin")?;
            return Ok(Some(decrypt_wrapper(&key, &payload)?));
        }
        if let Some(main) = zip_bytes(data, "__main__.py") {
            if let Ok(text) = std::str::from_utf8(&main) {
                if let Some((key, blob)) = parse_python_stub(text) {
                    return Ok(Some(decrypt_wrapper(&key, &blob)?));
                }
            }
        }
        return Ok(None);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some((key, blob)) = parse_python_stub(text) {
            return Ok(Some(decrypt_wrapper(&key, &blob)?));
        }
    }
    Ok(None)
}

fn zip_has(data: &[u8], name: &str) -> bool {
    let mut archive = match ZipArchive::new(Cursor::new(data)) {
        Ok(z) => z,
        Err(_) => return false,
    };
    let ok = archive.by_name(name).is_ok();
    drop(archive);
    ok
}

fn zip_bytes(data: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = ZipArchive::new(Cursor::new(data)).ok()?;
    let mut entry = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn parse_python_stub(src: &str) -> Option<([u8; AUTO_KEY_LEN], Vec<u8>)> {
    if !src.contains("# DEOBF-PY-V1") {
        return None;
    }
    let key_hex = between(src, "_DEOBF_KEY = bytes.fromhex(\"", "\")")?;
    let blob_b64 = between(src, "_DEOBF_BLOB = base64.b64decode(\"\"\"", "\"\"\")")?;
    let key_vec = hex_decode(key_hex)?;
    if key_vec.len() != AUTO_KEY_LEN {
        return None;
    }
    let mut key = [0u8; AUTO_KEY_LEN];
    key.copy_from_slice(&key_vec);
    let blob = b64_decode(blob_b64)?;
    Some((key, blob))
}

fn between<'a>(src: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = src.find(start)? + start.len();
    let rest = src.get(i..)?;
    let j = rest.find(end)?;
    Some(&rest[..j])
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let raw: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if raw.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    let bytes = raw.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        out.push(nibble(bytes[i])? << 4 | nibble(bytes[i + 1])?);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        out.push(B64[(b0 >> 2) as usize] as char);
        out.push(B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < data.len() {
            out.push(B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(B64[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn wrap76(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 76 + 1);
    for (n, ch) in s.chars().enumerate() {
        if n > 0 && n % 76 == 0 {
            out.push('\n');
        }
        out.push(ch);
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let filtered: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if filtered.is_empty() || filtered.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(filtered.len() / 4 * 3);
    for chunk in filtered.chunks(4) {
        let v0 = b64_val(chunk[0])?;
        let v1 = b64_val(chunk[1])?;
        let v2 = if chunk[2] == b'=' {
            0
        } else {
            b64_val(chunk[2])?
        };
        let v3 = if chunk[3] == b'=' {
            0
        } else {
            b64_val(chunk[3])?
        };
        out.push((v0 << 2) | (v1 >> 4));
        if chunk[2] != b'=' {
            out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
        }
        if chunk[3] != b'=' {
            out.push(((v2 & 0x03) << 6) | v3);
        }
    }
    Some(out)
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_matches_known_xchacha_vector() {
        let key =
            hex_decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = hex_decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = hex_decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52ef7e62efbf45089db18f9c8a3f0e4\
             1e5f",
        )
        .unwrap();
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key);
        let mut nonce_arr = [0u8; 24];
        nonce_arr.copy_from_slice(&nonce);
        let wrapped = encrypt_wrapper_with_nonce(&key_arr, &nonce_arr, pt).unwrap();
        assert_eq!(&wrapped[..8], WRAPPER_MAGIC);
        assert_eq!(&wrapped[34..], expected.as_slice());
        assert_eq!(decrypt_wrapper(&key_arr, &wrapped).unwrap(), pt);
    }

    #[test]
    fn python_stub_roundtrip_parse() {
        let key = [0x5Au8; 32];
        let payload = b"print('hello-deobf')\n";
        let wrapped = wrap_python(payload, &key, false).unwrap();
        let text = std::str::from_utf8(&wrapped).unwrap();
        assert!(text.contains("# DEOBF-PY-V1"));
        assert_eq!(embedded_key(&wrapped).unwrap(), key);
        assert_eq!(try_unwrap(&wrapped).unwrap().unwrap(), payload);
    }
}
