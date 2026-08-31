use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use super::artifact::ArtifactKind;
use super::backends::{backend_for, BackendReport};
use super::pipeline::Pipeline;
use super::selfrun;
use super::stub::{self, KIND_JAR, KIND_PE, KIND_PYTHON};
use super::validation::validate;
use super::{analyze, Analysis, CapabilityGuard, IntegrityGuard, ProtectionProfile, SizeInvariant};

const MAGIC: &[u8; 8] = b"DEOBF01\0";
const VERSION: u8 = 2;
const CHUNK: usize = 1024 * 1024;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_PAD: usize = 4096;
// Matches the CLI/GUI extra-lock requirement. Auto-key protect uses a random
// 32-byte AEAD key instead of a user password, so this floor applies only when
// a caller actually supplies a password.
const MIN_PASSWORD_LEN: usize = 12;

#[derive(Clone, Copy)]
enum Unlock<'a> {
    Password(&'a [u8]),
    RawKey(&'a [u8; 32]),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineOptions {
    pub profile: String,
    pub verify: bool,
    pub add_integrity: bool,
}
impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            profile: "balanced".into(),
            verify: true,
            add_integrity: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJson {
    pub kind: String,
    pub architecture: String,
    pub executable: bool,
    pub has_debug_markers: bool,
    pub has_archive_signature: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    pub analysis: AnalysisJson,
    pub input_size: u64,
    pub output_size: u64,
    pub elapsed_ms: u128,
    pub input_hash: String,
    pub output_hash: String,
    pub passes: Vec<String>,
    pub compatibility_mode: bool,
    pub format_preserved: bool,
}

impl From<Analysis> for AnalysisJson {
    fn from(a: Analysis) -> Self {
        Self {
            kind: format!("{:?}", a.kind),
            architecture: format!("{:?}", a.architecture),
            executable: a.executable,
            has_debug_markers: a.has_debug_markers,
            has_archive_signature: a.has_archive_signature,
        }
    }
}
fn profile(name: &str) -> ProtectionProfile {
    match name.to_ascii_lowercase().as_str() {
        "safe" => ProtectionProfile::safe(),
        "maximum" | "max" => ProtectionProfile::maximum(),
        _ => ProtectionProfile::balanced(),
    }
}
fn digest(data: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize().to_hex().to_string()
}
fn derive_key(pass: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
    let params = Params::new(32 * 1024, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e:?}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(pass, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e:?}"))?;
    Ok(key)
}
fn cipher_key(unlock: Unlock<'_>, salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
    match unlock {
        Unlock::Password(pass) => derive_key(pass, salt),
        Unlock::RawKey(key) => Ok(*key),
    }
}
fn nonce(base: &[u8; NONCE_LEN], index: u64) -> XNonce {
    let mut h = Hasher::new();
    h.update(b"DEOBF-NONCE-V2");
    h.update(base);
    h.update(&index.to_le_bytes());
    let digest = h.finalize();
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    XNonce::from(n)
}
fn aad(index: u64, plain_len: u64, flags: u8) -> Vec<u8> {
    let mut a = Vec::with_capacity(26);
    a.extend_from_slice(MAGIC);
    a.push(VERSION);
    a.push(flags);
    a.extend_from_slice(&index.to_le_bytes());
    a.extend_from_slice(&plain_len.to_le_bytes());
    a
}

pub fn analyze_only(data: &[u8]) -> Result<AnalysisJson> {
    Ok(analyze(data)?.into())
}

/// `foo.exe` -> `foo.exe.deobf-write-tmp` rather than `foo.deobf-write-tmp`.
fn sibling_temp(path: &Path, tag: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "out".into());
    name.push(".");
    name.push(tag);
    path.with_file_name(name)
}

pub fn is_deobf_container(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == MAGIC
}

/// Returns the authenticated DEOBF v2 container bytes, whether the file is a
/// legacy `.deobf` package or a stub-wrapped PE with an overlay trailer.
pub fn package_bytes(data: &[u8]) -> Result<&[u8]> {
    if is_deobf_container(data) {
        return Ok(data);
    }
    if let Some(container) = stub::extract_container(data) {
        return Ok(container);
    }
    bail!("not a DEOBF v2 package")
}

fn stub_kind_for(input: &Path, analysis_kind: &str) -> u8 {
    match analysis_kind {
        "Pe" => KIND_PE,
        "Jar" => KIND_JAR,
        _ => {
            let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("py") || ext.eq_ignore_ascii_case("pyc") {
                KIND_PYTHON
            } else if ext.eq_ignore_ascii_case("jar") {
                KIND_JAR
            } else {
                KIND_PE
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WrapKind {
    Pe,
    Jar,
    Python,
    PythonZipapp,
    Container,
}

fn wrap_kind(input: &Path, zipapp: bool, analysis_kind: &str) -> WrapKind {
    match analysis_kind {
        "Pe" => WrapKind::Pe,
        "Jar" => WrapKind::Jar,
        _ => {
            let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("jar") {
                WrapKind::Jar
            } else if ext.eq_ignore_ascii_case("py") || ext.eq_ignore_ascii_case("pyw") {
                WrapKind::Python
            } else if ext.eq_ignore_ascii_case("pyz") || ext.eq_ignore_ascii_case("pyzw") {
                WrapKind::PythonZipapp
            } else if zipapp {
                WrapKind::PythonZipapp
            } else {
                WrapKind::Container
            }
        }
    }
}

/// True when the file carries an embedded auto-key (PE overlay, trailing
/// DEOBFK01, or a self-running JAR/Python wrapper).
pub fn has_auto_key(data: &[u8]) -> bool {
    stub::extract_embedded_key(data).is_some() || selfrun::embedded_key(data).is_some()
}

pub fn protect(data: Vec<u8>, options: &EngineOptions) -> Result<(Vec<u8>, EngineResult)> {
    let started = Instant::now();
    if data.is_empty() {
        bail!("artifact is empty");
    }
    let analysis = analyze(&data).context("artifact analysis failed")?;
    let selected = profile(&options.profile);
    selected.validate().context("invalid protection profile")?;

    // Reject artifacts that look like an executable format but carry
    // incomplete/inconsistent metadata (e.g. a truncated or hand-edited PE
    // header) instead of silently protecting a file that will not run. This
    // check existed in validation.rs but, like the format backends above,
    // was never actually called from the protect path.
    let report = validate(&analysis, &selected).context("artifact validation failed")?;
    if !report.supported {
        bail!("artifact failed validation: {}", report.warnings.join("; "));
    }

    let input_size = data.len() as u64;
    let input_hash = digest(&data);

    // Run the format-specific backend (PE validation, JAR bytecode/debug-info
    // transform, or the Generic passthrough used for plain files like .txt)
    // BEFORE the byte stream enters the generic pipeline + AEAD container.
    // Previously this backend layer existed in backends.rs but was never
    // invoked from the CLI's protect path, so `deobf protect` only ever
    // encrypted the untouched bytes and none of the JAR/PE-specific
    // protection logic actually ran.
    let backend = backend_for(&data);
    let backend_kind = backend.kind();
    let original_for_verify = if options.verify {
        Some(data.clone())
    } else {
        None
    };
    let (data, backend_report): (Vec<u8>, BackendReport) = backend
        .protect(data)
        .with_context(|| format!("{backend_kind:?} protection backend failed"))?;
    if let Some(original) = original_for_verify {
        backend
            .verify(&original, &data)
            .with_context(|| format!("{backend_kind:?} backend verification failed"))?;
    }

    let mut pipeline = Pipeline::new().with(SizeInvariant).with(CapabilityGuard);
    if options.add_integrity {
        pipeline = pipeline.with(IntegrityGuard);
    }
    if options.verify {
        pipeline = pipeline.with(super::pipeline::VerifyPass);
    }
    let mut passes: Vec<String> = pipeline.names().into_iter().map(str::to_owned).collect();
    passes.insert(0, format!("backend:{backend_kind:?}"));
    passes.extend(backend_report.notes.iter().cloned());
    passes.extend(report.warnings.iter().map(|w| format!("warning: {w}")));

    let output = pipeline
        .run(data, &selected)
        .context("protection pipeline failed")?;
    let output_size = output.len() as u64;
    let output_hash = digest(&output);
    Ok((
        output,
        EngineResult {
            analysis: analysis.into(),
            input_size,
            output_size,
            elapsed_ms: started.elapsed().as_millis(),
            input_hash,
            output_hash,
            passes,
            compatibility_mode: false,
            format_preserved: true,
        },
    ))
}

fn encrypt_container(payload: &[u8], unlock: Unlock<'_>) -> Result<Vec<u8>> {
    let plain_len = payload.len() as u64;
    let mut salt = [0u8; SALT_LEN];
    let mut base = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut base);
    let key = cipher_key(unlock, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut dst = Vec::new();
    dst.write_all(MAGIC)?;
    dst.write_all(&[VERSION, 1])?;
    dst.write_all(&salt)?;
    dst.write_all(&base)?;
    dst.write_all(&plain_len.to_le_bytes())?;
    let mut src = payload;
    let mut index = 0u64;
    let mut digest = Hasher::new();
    digest.update(b"DEOBF-CONTENT-V2");
    let mut buf = vec![0u8; CHUNK];
    while !src.is_empty() {
        let n = src.len().min(CHUNK);
        buf[..n].copy_from_slice(&src[..n]);
        src = &src[n..];
        digest.update(&buf[..n]);
        let compressed = zstd::bulk::compress(&buf[..n], 3).unwrap_or_else(|_| buf[..n].to_vec());
        let encrypted = cipher
            .encrypt(
                &nonce(&base, index),
                Payload {
                    msg: &compressed,
                    aad: &aad(index, plain_len, 1),
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        dst.write_all(&(n as u32).to_le_bytes())?;
        dst.write_all(&(encrypted.len() as u32).to_le_bytes())?;
        dst.write_all(&encrypted)?;
        let mut p = [0u8; 2];
        OsRng.fill_bytes(&mut p);
        let pad = (u16::from_le_bytes(p) as usize) % (MAX_PAD + 1);
        dst.write_all(&(pad as u16).to_le_bytes())?;
        if pad != 0 {
            let mut padding = vec![0u8; pad];
            OsRng.fill_bytes(&mut padding);
            dst.write_all(&padding)?;
        }
        index += 1;
    }
    let trailer = cipher
        .encrypt(
            &nonce(&base, u64::MAX),
            Payload {
                msg: digest.finalize().as_bytes(),
                aad: &aad(u64::MAX, plain_len, 1),
            },
        )
        .map_err(|_| anyhow::anyhow!("trailer encryption failed"))?;
    dst.write_all(b"TRLR")?;
    dst.write_all(&(trailer.len() as u32).to_le_bytes())?;
    dst.write_all(&trailer)?;
    Ok(dst)
}

fn decrypt_container(package: &[u8], unlock: Unlock<'_>) -> Result<Vec<u8>> {
    let mut src = Cursor::new(package);
    let mut magic = [0u8; 8];
    src.read_exact(&mut magic).context("reading DEOBF header")?;
    if &magic != MAGIC {
        bail!("not a DEOBF v2 package");
    }
    let mut one = [0u8; 1];
    src.read_exact(&mut one)?;
    if one[0] != VERSION {
        bail!("unsupported DEOBF version {}", one[0]);
    }
    let mut flags = [0u8; 1];
    src.read_exact(&mut flags)?;
    if flags[0] & 1 == 0 {
        bail!("unsupported DEOBF flags");
    }
    let mut salt = [0u8; SALT_LEN];
    let mut base = [0u8; NONCE_LEN];
    let mut len = [0u8; 8];
    src.read_exact(&mut salt)?;
    src.read_exact(&mut base)?;
    src.read_exact(&mut len)?;
    let plain_len = u64::from_le_bytes(len);
    let key = cipher_key(unlock, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut dst = Vec::with_capacity(usize::try_from(plain_len).unwrap_or(0));
    let mut total = 0u64;
    let mut index = 0u64;
    let mut digest = Hasher::new();
    digest.update(b"DEOBF-CONTENT-V2");
    loop {
        let mut marker = [0u8; 4];
        src.read_exact(&mut marker)?;
        if &marker == b"TRLR" {
            let mut l = [0u8; 4];
            src.read_exact(&mut l)?;
            if u32::from_le_bytes(l) as usize != 48 {
                bail!("invalid trailer");
            }
            let mut enc = vec![0u8; 48];
            src.read_exact(&mut enc)?;
            let expected = cipher
                .decrypt(
                    &nonce(&base, u64::MAX),
                    Payload {
                        msg: &enc,
                        aad: &aad(u64::MAX, plain_len, flags[0]),
                    },
                )
                .map_err(|_| {
                    anyhow::anyhow!("authentication failed: wrong password or modified package")
                })?;
            if expected.as_slice() != digest.finalize().as_bytes() {
                bail!("content integrity check failed");
            }
            break;
        }
        let n = u32::from_le_bytes(marker) as usize;
        let mut enc_len = [0u8; 4];
        src.read_exact(&mut enc_len)?;
        let enc_n = u32::from_le_bytes(enc_len) as usize;
        if n == 0 || n > CHUNK || !(TAG_LEN..=CHUNK + TAG_LEN).contains(&enc_n) {
            bail!("invalid container chunk");
        }
        let mut enc = vec![0u8; enc_n];
        src.read_exact(&mut enc)?;
        let mut pad_len = [0u8; 2];
        src.read_exact(&mut pad_len)?;
        let pad = u16::from_le_bytes(pad_len) as usize;
        if pad > MAX_PAD {
            bail!("invalid padding");
        }
        if pad != 0 {
            let mut junk = vec![0u8; pad];
            src.read_exact(&mut junk)?;
        }
        let compressed = cipher
            .decrypt(
                &nonce(&base, index),
                Payload {
                    msg: &enc,
                    aad: &aad(index, plain_len, flags[0]),
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("authentication failed: wrong password or modified package")
            })?;
        let plain = zstd::bulk::decompress(&compressed, CHUNK).unwrap_or(compressed);
        if plain.len() != n {
            bail!("invalid decompressed chunk");
        }
        digest.update(&plain);
        dst.write_all(&plain)?;
        total += n as u64;
        index += 1;
    }
    if total != plain_len {
        bail!("length mismatch: container is damaged");
    }
    Ok(dst)
}

fn atomic_write(output: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let tmp = sibling_temp(output, "deobf-write-tmp");
    let result = (|| -> Result<()> {
        let mut dst = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        dst.write_all(bytes)?;
        dst.sync_all()?;
        drop(dst);
        fs::rename(&tmp, output)
            .with_context(|| format!("rename {} -> {}", tmp.display(), output.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn protect_file(
    input: &Path,
    output: &Path,
    pass: &[u8],
    options: &EngineOptions,
) -> Result<EngineResult> {
    if input == output {
        bail!("input and output must differ");
    }
    let auto_key = pass.is_empty();
    if !auto_key && pass.len() < MIN_PASSWORD_LEN {
        bail!("password must contain at least {MIN_PASSWORD_LEN} characters");
    }
    let data = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let zipapp = selfrun::looks_like_zipapp(&data);
    let (payload, mut report) = protect(data, options)?;
    let kind = wrap_kind(input, zipapp, &report.analysis.kind);
    let mut raw_key = [0u8; 32];
    if auto_key {
        OsRng.fill_bytes(&mut raw_key);
        report.passes.push("runtime:embedded-auto-key".into());
    }
    let (out_bytes, wrapped) = match (auto_key, kind) {
        (_, WrapKind::Pe) => {
            let container = if auto_key {
                encrypt_container(&payload, Unlock::RawKey(&raw_key))?
            } else {
                encrypt_container(&payload, Unlock::Password(pass))?
            };
            let stub_bytes = stub::load_stub_or_fallback();
            let wrapped = stub::wrap_stub(
                &stub_bytes,
                &container,
                stub_kind_for(input, &report.analysis.kind),
                auto_key.then_some(&raw_key),
            )
            .context("wrap Windows runtime stub")?;
            report.passes.push("runtime:windows-stub".into());
            if stub::parse_trailer(&stub_bytes).is_none() && stub_bytes.len() < 4096 {
                report.passes.push("runtime:fallback-pe".into());
            }
            (wrapped, true)
        }
        (true, WrapKind::Jar) => {
            let bytes = selfrun::wrap_jar(&payload, &raw_key).context("build self-running JAR")?;
            report.passes.push("runtime:jar-loader".into());
            (bytes, true)
        }
        (true, WrapKind::Python) => {
            let bytes = selfrun::wrap_python(&payload, &raw_key, false)
                .context("build self-running Python stub")?;
            report.passes.push("runtime:python-loader".into());
            (bytes, true)
        }
        (true, WrapKind::PythonZipapp) => {
            let bytes = selfrun::wrap_python(&payload, &raw_key, true)
                .context("build self-running Python zipapp")?;
            report.passes.push("runtime:python-loader".into());
            (bytes, true)
        }
        (true, WrapKind::Container) => {
            let mut out = encrypt_container(&payload, Unlock::RawKey(&raw_key))?;
            out.extend_from_slice(&stub::encode_key_record(&raw_key));
            (out, false)
        }
        (false, _) => {
            // Extra password lock: authenticated v2 container. JAR/Python are
            // not self-running in this mode; use `deobf run` / Studio Runtime.
            (encrypt_container(&payload, Unlock::Password(pass))?, false)
        }
    };
    atomic_write(output, &out_bytes)?;
    report.output_size = fs::metadata(output)?.len();
    report.output_hash = digest(&fs::read(output)?);
    report.compatibility_mode = false;
    report.format_preserved = wrapped;
    Ok(report)
}

pub fn unprotect_bytes(input: &[u8], pass: &[u8]) -> Result<Vec<u8>> {
    if let Some(plain) = selfrun::try_unwrap(input)? {
        return Ok(plain);
    }
    let package = package_bytes(input)?;
    if let Some(key) = stub::extract_embedded_key(input) {
        match decrypt_container(package, Unlock::RawKey(&key)) {
            Ok(plain) => return Ok(plain),
            Err(_) if pass.len() >= MIN_PASSWORD_LEN => {}
            Err(err) => return Err(err),
        }
    }
    if pass.is_empty() {
        bail!("this package requires a password (no embedded auto-key)");
    }
    if pass.len() < MIN_PASSWORD_LEN {
        bail!("password must contain at least {MIN_PASSWORD_LEN} characters");
    }
    decrypt_container(package, Unlock::Password(pass))
}

pub fn unprotect_file(input: &Path, output: &Path, pass: &[u8]) -> Result<()> {
    if input == output {
        bail!("input and output must differ");
    }
    let data = fs::read(input).with_context(|| format!("open {}", input.display()))?;
    let plain = unprotect_bytes(&data, pass)?;
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let tmp = sibling_temp(output, "deobf-restore-tmp");
    let result = (|| -> Result<()> {
        let mut dst = File::create(&tmp)?;
        dst.write_all(&plain)?;
        dst.sync_all()?;
        drop(dst);
        fs::rename(&tmp, output)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Pe => "PE",
        ArtifactKind::Elf => "ELF",
        ArtifactKind::MachO => "Mach-O",
        ArtifactKind::Jar => "JAR",
        ArtifactKind::Zip => "ZIP",
        ArtifactKind::Raw => "Raw",
    }
}
