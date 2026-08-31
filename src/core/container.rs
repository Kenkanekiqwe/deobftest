use anyhow::{bail, Context, Result};
use blake3::Hasher;
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"DEOBF3\0\0";
const VERSION: u16 = 3;
const HASH_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub version: u16,
    pub original_size: u64,
    pub content_hash: [u8; HASH_LEN],
}

pub fn pack<W: Write>(mut out: W, input: &[u8]) -> Result<ContainerInfo> {
    let mut hasher = Hasher::new();
    hasher.update(b"DEOBF3-CONTENT");
    hasher.update(input);
    let hash = *hasher.finalize().as_bytes();

    out.write_all(MAGIC)?;
    out.write_all(&VERSION.to_le_bytes())?;
    out.write_all(&0u16.to_le_bytes())?;
    out.write_all(&(input.len() as u64).to_le_bytes())?;
    out.write_all(&hash)?;
    out.write_all(input)?;

    Ok(ContainerInfo {
        version: VERSION,
        original_size: input.len() as u64,
        content_hash: hash,
    })
}

pub fn unpack<R: Read>(mut input: R) -> Result<(ContainerInfo, Vec<u8>)> {
    let mut magic = [0u8; 8];
    input
        .read_exact(&mut magic)
        .context("reading container magic")?;
    if &magic != MAGIC {
        bail!("invalid DEOBF container magic")
    }

    let mut u16buf = [0u8; 2];
    input.read_exact(&mut u16buf)?;
    let version = u16::from_le_bytes(u16buf);
    if version != VERSION {
        bail!("unsupported DEOBF container version: {version}")
    }
    input.read_exact(&mut u16buf)?;

    let mut u64buf = [0u8; 8];
    input.read_exact(&mut u64buf)?;
    let original_size = u64::from_le_bytes(u64buf);
    let mut expected = [0u8; HASH_LEN];
    input.read_exact(&mut expected)?;

    let size = usize::try_from(original_size).context("container size does not fit platform")?;
    let mut data = vec![0u8; size];
    input
        .read_exact(&mut data)
        .context("reading container payload")?;

    let mut hasher = Hasher::new();
    hasher.update(b"DEOBF3-CONTENT");
    hasher.update(&data);
    if hasher.finalize().as_bytes() != &expected {
        bail!("container integrity check failed")
    }

    Ok((
        ContainerInfo {
            version,
            original_size,
            content_hash: expected,
        },
        data,
    ))
}
