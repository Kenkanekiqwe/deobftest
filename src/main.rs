use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::{aead::{Aead, KeyInit}, XChaCha20Poly1305, XNonce};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use std::{fs::{self, File}, io::{Read, Write}, path::{Path, PathBuf}, process::Command};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"DEOBF01\0";
const VERSION: u8 = 1;
const CHUNK: usize = 1024 * 1024;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Parser)]
#[command(name = "deobf", version, about = "Custom authenticated file protection")]
struct Cli { #[command(subcommand)] command: Cmd }

#[derive(Subcommand)]
enum Cmd {
    Protect { input: PathBuf, #[arg(short, long)] output: PathBuf, #[arg(long)] password: Option<String> },
    Unprotect { input: PathBuf, #[arg(short, long)] output: PathBuf, #[arg(long)] password: Option<String> },
    Inspect { input: PathBuf },
    RunJar { input: PathBuf, #[arg(long, default_value = "java")] java: String, #[arg(long)] password: Option<String>, #[arg(last = true)] args: Vec<String> },
}

fn password(v: Option<String>, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    let interactive = v.is_none();
    let p = match v { Some(x) => x, None => prompt_password("Password: ")? };
    if confirm && interactive {
        let q = prompt_password("Confirm password: ")?;
        if p != q { bail!("passwords do not match"); }
    }
    if p.len() < 8 { bail!("password must contain at least 8 characters"); }
    Ok(Zeroizing::new(p.into_bytes()))
}

fn derive_key(pass: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(19 * 1024, 2, 1, Some(32)).context("invalid Argon2 parameters")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon.hash_password_into(pass, salt, &mut key).context("key derivation failed")?;
    Ok(key)
}

fn nonce(base: &[u8; NONCE_LEN], index: u64) -> XNonce {
    let mut h = Hasher::new(); h.update(base); h.update(&index.to_le_bytes());
    let mut n = [0u8; NONCE_LEN]; n.copy_from_slice(h.finalize().as_bytes()); XNonce::from(n)
}

fn aad(index: u64, plain_len: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(25); a.extend_from_slice(MAGIC); a.push(VERSION); a.extend_from_slice(&index.to_le_bytes()); a.extend_from_slice(&plain_len.to_le_bytes()); a
}

fn protect(input: &Path, output: &Path, pass: &[u8]) -> Result<()> {
    if input == output { bail!("input and output must differ"); }
    let mut src = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let plain_len = src.metadata()?.len();
    let mut salt = [0u8; SALT_LEN]; let mut base = [0u8; NONCE_LEN]; OsRng.fill_bytes(&mut salt); OsRng.fill_bytes(&mut base);
    let key = derive_key(pass, &salt)?; let cipher = XChaCha20Poly1305::new((&key).into());
    let mut dst = File::create(output).with_context(|| format!("create {}", output.display()))?;
    dst.write_all(MAGIC)?; dst.write_all(&[VERSION])?; dst.write_all(&salt)?; dst.write_all(&base)?; dst.write_all(&plain_len.to_le_bytes())?;
    let mut buf = vec![0u8; CHUNK]; let mut index = 0u64;
    loop {
        let n = src.read(&mut buf)?; if n == 0 { break; }
        let encrypted = cipher.encrypt(&nonce(&base, index), chacha20poly1305::aead::Payload { msg: &buf[..n], aad: &aad(index, plain_len) }).map_err(|_| anyhow::anyhow!("encryption failed"))?;
        dst.write_all(&(n as u32).to_le_bytes())?; dst.write_all(&(encrypted.len() as u32).to_le_bytes())?; dst.write_all(&encrypted)?;
        index += 1;
    }
    dst.sync_all()?; Ok(())
}

fn read_header(src: &mut File) -> Result<([u8; SALT_LEN], [u8; NONCE_LEN], u64)> {
    let mut magic = [0u8; 8]; src.read_exact(&mut magic)?; if &magic != MAGIC { bail!("not a DEOBF container"); }
    let mut ver = [0u8; 1]; src.read_exact(&mut ver)?; if ver[0] != VERSION { bail!("unsupported container version {}", ver[0]); }
    let mut salt = [0u8; SALT_LEN]; let mut base = [0u8; NONCE_LEN]; let mut len = [0u8; 8]; src.read_exact(&mut salt)?; src.read_exact(&mut base)?; src.read_exact(&mut len)?;
    Ok((salt, base, u64::from_le_bytes(len)))
}

fn unprotect(input: &Path, output: &Path, pass: &[u8]) -> Result<()> {
    if input == output { bail!("input and output must differ"); }
    let mut src = File::open(input)?; let (salt, base, plain_len) = read_header(&mut src); let (salt, base, plain_len) = (salt?, base?, plain_len?);
    let key = derive_key(pass, &salt)?; let cipher = XChaCha20Poly1305::new((&key).into());
    let tmp = output.with_extension("deobf-tmp"); let mut dst = File::create(&tmp)?; let mut total = 0u64; let mut index = 0u64;
    loop {
        let mut p = [0u8; 4]; match src.read_exact(&mut p) { Ok(_) => {}, Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, Err(e) => return Err(e.into()) }
        let n = u32::from_le_bytes(p) as usize; src.read_exact(&mut p)?; let enc_n = u32::from_le_bytes(p) as usize;
        if n == 0 || n > CHUNK || enc_n != n + 16 { let _ = fs::remove_file(&tmp); bail!("invalid container chunk"); }
        let mut enc = vec![0u8; enc_n]; src.read_exact(&mut enc)?;
        let plain = match cipher.decrypt(&nonce(&base, index), chacha20poly1305::aead::Payload { msg: &enc, aad: &aad(index, plain_len) }) { Ok(v) => v, Err(_) => { let _ = fs::remove_file(&tmp); bail!("authentication failed: wrong password or modified file"); } };
        if plain.len() != n { let _ = fs::remove_file(&tmp); bail!("invalid decrypted chunk"); }
        dst.write_all(&plain)?; total += n as u64; index += 1;
    }
    if total != plain_len { let _ = fs::remove_file(&tmp); bail!("length mismatch: container is damaged"); }
    dst.sync_all()?; drop(dst); fs::rename(tmp, output)?; Ok(())
}

fn inspect(input: &Path) -> Result<()> {
    let mut f = File::open(input)?; let (_, _, len) = read_header(&mut f)?;
    println!("format: DEOBF v{}\noriginal size: {} bytes\nchunk size: {} KiB\nsecurity: Argon2id + XChaCha20-Poly1305", VERSION, len, CHUNK / 1024); Ok(())
}

fn run_jar(input: &Path, java: &str, pass: &[u8], args: &[String]) -> Result<()> {
    let dir = tempfile_dir()?; let jar = dir.join("payload.jar");
    if let Err(e) = unprotect(input, &jar, pass) { let _ = fs::remove_dir_all(&dir); return Err(e); }
    let status = Command::new(java).arg("-jar").arg(&jar).args(args).status().with_context(|| format!("failed to start {}", java));
    let _ = fs::remove_dir_all(&dir); let status = status?;
    if !status.success() { bail!("java exited with {}", status); } Ok(())
}

fn tempfile_dir() -> Result<PathBuf> {
    let mut r = [0u8; 16]; OsRng.fill_bytes(&mut r); let name = format!("deobf-{}", hex(&r)); let p = std::env::temp_dir().join(name); fs::create_dir(&p)?; Ok(p)
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Protect { input, output, password: p } => { let pass = password(p, true)?; protect(&input, &output, &pass)?; println!("protected: {}", output.display()); }
        Cmd::Unprotect { input, output, password: p } => { let pass = password(p, false)?; unprotect(&input, &output, &pass)?; println!("restored: {}", output.display()); }
        Cmd::Inspect { input } => inspect(&input)?,
        Cmd::RunJar { input, java, password: p, args } => { let pass = password(p, false)?; run_jar(&input, &java, &pass, &args)?; }
    }
    Ok(())
}
