use anyhow::{bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{Cursor, Read, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use super::stub::AUTO_KEY_LEN;

pub const WRAPPER_MAGIC: &[u8; 8] = b"DEOBFW01";
pub const WRAPPER_HEADER_LEN: usize = 34;
const LOADER_CLASS: &[u8] = include_bytes!("../../vendor/java/deobf/Loader.class");
const LOADER_LOCATED_CLASS: &[u8] =
    include_bytes!("../../vendor/java/deobf/Loader$Located.class");
const LOADER_SYNTH_CLASS: &[u8] = include_bytes!("../../vendor/java/deobf/Loader$1.class");
const BOOT_CLASS: &[u8] = include_bytes!("../../vendor/java/deobf/Boot.class");
const FORGE_SERVICE_CLASS: &[u8] = include_bytes!("../../vendor/java/deobf/ForgeService.class");
const BUKKIT_PLUGIN_CLASS: &[u8] = include_bytes!("../../vendor/java/deobf/BukkitPlugin.class");
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
    let files = read_zip_files(payload)?;
    let original_main = jar_main_class(payload).unwrap_or_default();
    let mut plugin_main = String::new();
    let mut has_forge_meta = false;
    let mut mixin_config_names: Vec<String> = Vec::new();

    let mut out_entries: Vec<(String, Vec<u8>)> = Vec::new();
    let mut seen = HashSet::new();

    for (name, data) in files {
        let norm = name.replace('\\', "/");
        if norm.split('/').any(|p| p == "..") {
            continue;
        }
        let lower = norm.to_ascii_lowercase();
        let base = file_name_lower(&norm);

        if lower == "meta-inf/manifest.mf" {
            continue;
        }

        if base == "fabric.mod.json" || base == "quilt.mod.json" {
            match prepend_prelaunch(&data) {
                Ok((edited, names)) => {
                    for n in names {
                        if !mixin_config_names.iter().any(|e| e == &n) {
                            mixin_config_names.push(n);
                        }
                    }
                    push_entry(&mut out_entries, &mut seen, &norm, edited);
                }
                Err(_) => {
                    push_entry(&mut out_entries, &mut seen, &norm, data);
                }
            }
            continue;
        }

        if base == "plugin.yml" || base == "paper-plugin.yml" || base == "bungee.yml" {
            let (edited, orig) = rewrite_plugin_main(&data);
            if plugin_main.is_empty() {
                plugin_main = orig;
            }
            push_entry(&mut out_entries, &mut seen, &norm, edited);
            continue;
        }

        if lower == "meta-inf/mods.toml"
            || lower == "meta-inf/neoforge.mods.toml"
            || base == "mods.toml"
            || base == "neoforge.mods.toml"
        {
            has_forge_meta = true;
            push_entry(&mut out_entries, &mut seen, &norm, data);
            continue;
        }

        if should_skip_passthrough(&norm) {
            continue;
        }

        push_entry(&mut out_entries, &mut seen, &norm, data);
    }

    let orig_manifest = zip_bytes(payload, "META-INF/MANIFEST.MF");
    let manifest = merge_manifest(orig_manifest.as_deref(), &original_main);
    push_entry(
        &mut out_entries,
        &mut seen,
        "META-INF/MANIFEST.MF",
        manifest,
    );

    if has_forge_meta {
        let path = "META-INF/services/cpw.mods.modlauncher.api.ITransformationService";
        if let Some(existing) = out_entries.iter_mut().find(|(n, _)| n == path) {
            let text = String::from_utf8_lossy(&existing.1);
            if !text.lines().any(|l| l.trim() == "deobf.ForgeService") {
                if !existing.1.ends_with(b"\n") {
                    existing.1.push(b'\n');
                }
                existing.1.extend_from_slice(b"deobf.ForgeService\n");
            }
        } else {
            push_entry(
                &mut out_entries,
                &mut seen,
                path,
                b"deobf.ForgeService\n".to_vec(),
            );
        }
    }

    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/Loader.class",
        LOADER_CLASS.to_vec(),
    );
    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/Loader$Located.class",
        LOADER_LOCATED_CLASS.to_vec(),
    );
    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/Loader$1.class",
        LOADER_SYNTH_CLASS.to_vec(),
    );
    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/Boot.class",
        BOOT_CLASS.to_vec(),
    );
    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/ForgeService.class",
        FORGE_SERVICE_CLASS.to_vec(),
    );
    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/BukkitPlugin.class",
        BUKKIT_PLUGIN_CLASS.to_vec(),
    );
    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/key.bin",
        key.to_vec(),
    );
    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/payload.bin",
        envelope,
    );

    let mut meta = format!("original-main-class={original_main}\n");
    if !plugin_main.is_empty() {
        meta.push_str(&format!("original-plugin-main={plugin_main}\n"));
    }
    meta.push_str("full-original=true\n");
    meta.push_str(&format!("mixin-configs={}\n", mixin_config_names.join(",")));
    push_entry(
        &mut out_entries,
        &mut seen,
        "deobf/meta.properties",
        meta.into_bytes(),
    );

    write_zip(out_entries)
}

fn push_entry(
    out: &mut Vec<(String, Vec<u8>)>,
    seen: &mut HashSet<String>,
    name: &str,
    data: Vec<u8>,
) {
    if seen.insert(name.to_string()) {
        out.push((name.to_string(), data));
    }
}

fn file_name_lower(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase()
}

fn is_nested_jar_entry(lower: &str) -> bool {
    if lower.ends_with(".jar") {
        return true;
    }
    if !lower.ends_with(".zip") {
        return false;
    }
    lower.contains("/jars/")
        || lower.contains("/jarjar/")
        || lower.contains("/libraries/")
        || lower.starts_with("jars/")
        || lower.starts_with("libraries/")
        || lower.starts_with("meta-inf/jars/")
        || lower.starts_with("meta-inf/jarjar/")
        || lower.starts_with("meta-inf/libraries/")
}

fn should_skip_passthrough(name: &str) -> bool {
    let lower = name.replace('\\', "/").to_ascii_lowercase();
    if lower.starts_with("deobf/") {
        return true;
    }
    if lower.contains("/.git/")
        || lower.starts_with(".git/")
        || lower == ".git"
        || lower.ends_with("/.gitignore")
        || lower == ".gitignore"
        || lower.ends_with("/.gitattributes")
        || lower == ".gitattributes"
        || lower.contains("/.svn/")
        || lower.starts_with(".svn/")
    {
        return true;
    }
    // Classes and nested jars live only in encrypted payload.bin. Mixin JSON,
    // refmap JSON, access wideners, assets, and patched fabric.mod.json stay.
    if lower.ends_with(".class")
        || lower.ends_with(".java")
        || lower.ends_with(".kt")
        || lower.ends_with(".kts")
        || lower.ends_with(".scala")
        || lower.ends_with(".mjs")
        || lower.ends_with(".map")
    {
        return true;
    }
    if is_nested_jar_entry(&lower) {
        return true;
    }
    if is_signature_name(&lower) {
        return true;
    }
    false
}

fn is_signature_name(lower: &str) -> bool {
    lower.starts_with("meta-inf/")
        && (lower.ends_with(".sf")
            || lower.ends_with(".rsa")
            || lower.ends_with(".dsa")
            || lower.ends_with(".ec"))
}

fn read_zip_files(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = ZipArchive::new(Cursor::new(data)).context("payload is not a JAR/ZIP")?;
    let mut files = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("cannot read JAR entry")?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_owned();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        files.push((name, buf));
    }
    Ok(files)
}

fn write_zip(entries: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);
        for (name, data) in entries {
            zip.start_file(name, opts)?;
            zip.write_all(&data)?;
        }
        zip.finish().context("finish self-running JAR")?;
    }
    Ok(cursor.into_inner())
}

fn prepend_prelaunch(json_bytes: &[u8]) -> Result<(Vec<u8>, Vec<String>)> {
    let mut v: Value = serde_json::from_slice(json_bytes).context("mod JSON")?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("mod JSON is not an object"))?;
    let mixin_config_names = extract_mixin_config_names(obj);
    obj.remove("mixins");
    obj.remove("mixin");
    obj.remove("jars");
    let entrypoints = obj
        .entry("entrypoints")
        .or_insert_with(|| json!({}));
    let map = entrypoints
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("entrypoints is not an object"))?;
    let pre = map.entry("preLaunch").or_insert_with(|| json!([]));
    let already = match pre {
        Value::Array(arr) => arr.iter().any(is_boot_entry),
        Value::String(s) => s == "deobf.Boot",
        Value::Object(o) => o.get("value").and_then(|x| x.as_str()) == Some("deobf.Boot"),
        _ => false,
    };
    if !already {
        match pre {
            Value::Array(arr) => arr.insert(0, json!("deobf.Boot")),
            Value::String(s) => {
                let prev = s.clone();
                *pre = json!(["deobf.Boot", prev]);
            }
            _ => *pre = json!(["deobf.Boot"]),
        }
    }
    Ok((serde_json::to_vec_pretty(&v)?, mixin_config_names))
}

fn extract_mixin_config_names(obj: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut names = Vec::new();
    for key in ["mixins", "mixin"] {
        if let Some(v) = obj.get(key) {
            collect_mixin_config_names(v, &mut names);
        }
    }
    names
}

fn collect_mixin_config_names(v: &Value, names: &mut Vec<String>) {
    match v {
        Value::String(s) => push_mixin_name(names, s),
        Value::Array(arr) => {
            for item in arr {
                collect_mixin_config_names(item, names);
            }
        }
        Value::Object(o) => {
            if let Some(Value::String(s)) = o.get("config") {
                push_mixin_name(names, s);
            }
        }
        _ => {}
    }
}

fn push_mixin_name(names: &mut Vec<String>, s: &str) {
    let t = s.trim();
    if !t.is_empty() && !names.iter().any(|e| e == t) {
        names.push(t.to_string());
    }
}

fn is_boot_entry(v: &Value) -> bool {
    match v {
        Value::String(s) => s == "deobf.Boot",
        Value::Object(o) => o.get("value").and_then(|x| x.as_str()) == Some("deobf.Boot"),
        _ => false,
    }
}

fn rewrite_plugin_main(data: &[u8]) -> (Vec<u8>, String) {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return (data.to_vec(), String::new()),
    };
    let mut orig = String::new();
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let ended = line.ends_with('\n');
        let raw = line.trim_end_matches('\n').trim_end_matches('\r');
        let trimmed = raw.trim_start();
        if let Some(rest) = trimmed.strip_prefix("main:") {
            if orig.is_empty() {
                orig = rest
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
            }
            let indent_len = raw.len() - trimmed.len();
            out.push_str(&raw[..indent_len]);
            out.push_str("main: deobf.BukkitPlugin");
            if ended {
                out.push('\n');
            }
        } else {
            out.push_str(line);
        }
    }
    (out.into_bytes(), orig)
}

fn merge_manifest(original: Option<&[u8]>, original_main: &str) -> Vec<u8> {
    let mut attrs: Vec<(String, String)> = Vec::new();
    if let Some(bytes) = original {
        if let Ok(text) = std::str::from_utf8(bytes) {
            attrs = manifest_main_attrs(text);
        }
    }
    if attrs
        .iter()
        .all(|(k, _)| !k.eq_ignore_ascii_case("Manifest-Version"))
    {
        attrs.insert(0, ("Manifest-Version".into(), "1.0".into()));
    }

    let had_main = !original_main.is_empty()
        || attrs
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("Main-Class") && !v.is_empty());
    let start = if original_main.is_empty() {
        attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Main-Class"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    } else {
        original_main.to_string()
    };

    attrs.retain(|(k, _)| {
        !k.eq_ignore_ascii_case("Main-Class") && !k.eq_ignore_ascii_case("Start-Class")
    });
    if had_main && !start.is_empty() {
        attrs.push(("Main-Class".into(), "deobf.Loader".into()));
        attrs.push(("Start-Class".into(), start));
    }
    if attrs
        .iter()
        .all(|(k, _)| !k.eq_ignore_ascii_case("Created-By"))
    {
        attrs.push(("Created-By".into(), "DEOBF".into()));
    }

    let mut out = String::new();
    for (k, v) in attrs {
        write_manifest_line(&mut out, &k, &v);
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn manifest_main_attrs(text: &str) -> Vec<(String, String)> {
    let mut continued = String::new();
    let mut attrs = Vec::new();
    let mut in_main = true;
    for raw in text.lines() {
        if !in_main {
            break;
        }
        let line = raw.trim_end().trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix(' ') {
            continued.push_str(rest);
            continue;
        }
        if !continued.is_empty() {
            if continued.trim().is_empty() {
                in_main = false;
            } else if let Some((k, v)) = split_manifest_attr(&continued) {
                attrs.push((k, v));
            }
            continued.clear();
        }
        if line.is_empty() {
            in_main = false;
            continue;
        }
        continued.push_str(line);
    }
    if in_main && !continued.is_empty() {
        if let Some((k, v)) = split_manifest_attr(&continued) {
            attrs.push((k, v));
        }
    }
    attrs
}

fn split_manifest_attr(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once(':')?;
    let k = k.trim();
    if k.is_empty() {
        return None;
    }
    Some((k.to_string(), v.trim().to_string()))
}

fn write_manifest_line(out: &mut String, key: &str, value: &str) {
    let line = format!("{key}: {value}");
    let bytes = line.as_bytes();
    if bytes.len() <= 70 {
        out.push_str(&line);
        out.push_str("\r\n");
        return;
    }
    let mut first = true;
    let mut i = 0;
    while i < bytes.len() {
        let take = if first { 70 } else { 69 };
        let mut end = (i + take).min(bytes.len());
        while end > i && !bytes[i..end].is_ascii() && (bytes[end - 1] & 0xc0) == 0x80 {
            end -= 1;
        }
        if end == i {
            end = (i + take).min(bytes.len());
        }
        if !first {
            out.push(' ');
        }
        out.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or(""));
        out.push_str("\r\n");
        first = false;
        i = end;
    }
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
