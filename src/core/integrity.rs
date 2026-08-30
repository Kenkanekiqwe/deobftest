use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

pub fn hash(data: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"DEOBF-INTEGRITY-V1");
    hasher.update(data);
    Digest(*hasher.finalize().as_bytes())
}

pub fn verify(data: &[u8], expected: &Digest) -> Result<()> {
    let actual = hash(data);
    if actual != *expected {
        bail!("integrity verification failed");
    }
    Ok(())
}
