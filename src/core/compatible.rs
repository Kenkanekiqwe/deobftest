use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};

const MAGIC: &[u8; 8] = b"DEOBFCMP1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityManifest {
    pub version: u32,
    pub artifact: String,
    pub original_size: u64,
    pub original_hash: String,
    pub profile: String,
}

fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
    let params = Params::new(32 * 1024, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e:?}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon.hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e:?}"))?;
    Ok(key)
}

fn hash(data: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize().to_hex().to_string()
}

fn meta_path(output: &Path) -> PathBuf {
    let mut p = output.as_os_str().to_owned();
    p.push(".deobfmeta");
    PathBuf::from(p)
}

/// Compatibility mode deliberately leaves the executable/data bytes unchanged.
/// The original artifact remains directly runnable/openable while an authenticated,
/// encrypted sidecar records its identity and selected protection profile.
pub fn protect_compatible(
    input: &Path,
    output: &Path,
    password: &[u8],
    artifact: &str,
    profile: &str,
) -> Result<PathBuf> {
    if input == output {
        bail!("input and output must differ");
    }

    let data = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    if data.is_empty() {
        bail!("input artifact is empty");
    }

    fs::copy(input, output)
        .with_context(|| format!("copy {} to {}", input.display(), output.display()))?;

    let manifest = CompatibilityManifest {
        version: 1,
        artifact: artifact.to_owned(),
        original_size: data.len() as u64,
        original_hash: hash(&data),
        profile: profile.to_owned(),
    };
    let plain = serde_json::to_vec(&manifest).context("serialize compatibility manifest")?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let encrypted = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload { msg: &plain, aad: MAGIC },
        )
        .map_err(|_| anyhow::anyhow!("compatibility metadata encryption failed"))?;

    let mut sidecar = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + encrypted.len());
    sidecar.extend_from_slice(MAGIC);
    sidecar.extend_from_slice(&salt);
    sidecar.extend_from_slice(&nonce);
    sidecar.extend_from_slice(&encrypted);

    let meta = meta_path(output);
    let tmp = meta.with_extension("deobfmeta-tmp");
    fs::write(&tmp, &sidecar).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &meta).with_context(|| format!("finalize {}", meta.display()))?;
    Ok(meta)
}

pub fn verify_compatible(
    input: &Path,
    password: &[u8],
) -> Result<CompatibilityManifest> {
    let data = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let meta = fs::read(meta_path(input)).context("compatibility metadata not found")?;
    if meta.len() < MAGIC.len() + SALT_LEN + NONCE_LEN + 16 || &meta[..MAGIC.len()] != MAGIC {
        bail!("invalid compatibility metadata");
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&meta[MAGIC.len()..MAGIC.len() + SALT_LEN]);
    let nonce_start = MAGIC.len() + SALT_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&meta[nonce_start..nonce_start + NONCE_LEN]);
    let encrypted = &meta[nonce_start + NONCE_LEN..];

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plain = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload { msg: encrypted, aad: MAGIC },
        )
        .map_err(|_| anyhow::anyhow!("metadata authentication failed"))?;
    let manifest: CompatibilityManifest =
        serde_json::from_slice(&plain).context("invalid compatibility manifest")?;

    if manifest.original_size != data.len() as u64 || manifest.original_hash != hash(&data) {
        bail!("protected file integrity check failed");
    }
    Ok(manifest)
}
