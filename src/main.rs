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
const VERSION: u8 = 2;
const LEGACY_VERSION: u8 = 1;
const CHUNK: usize = 1024 * 1024;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_PAD: usize = 4096;

#[derive(Parser)]
#[command(name = "deobf", version, about = "Hardened custom authenticated file protection")]
struct Cli { #[command(subcommand)] command: Cmd }

#[derive(Subcommand)]
enum Cmd {
    Protect { input: PathBuf, #[arg(short, long)] output: PathBuf, #[arg(long)] password: Option<String> },
    Unprotect { input: PathBuf, #[arg(short, long)] output: PathBuf, #[arg(long)] password: Option<String> },
    Inspect { input: PathBuf },
    RunJar { input: PathBuf, #[arg(long, default_value = "java")] java: String, #[arg(long)] password: Option<String>, #[arg(last = true)] args: Vec<String> },
    Text { #[command(subcommand)] command: TextCmd },
}

#[derive(Subcommand)]
enum TextCmd {
    Encrypt { text: Option<String>, #[arg(long)] password: Option<String> },
    Decrypt { text: Option<String>, #[arg(long)] password: Option<String> },
}

fn password(v: Option<String>, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    let interactive = v.is_none();
    let p = match v { Some(x) => x, None => prompt_password("Password: ")? };
    if confirm && interactive { let q = prompt_password("Confirm password: ")?; if p != q { bail!("passwords do not match"); } }
    if p.len() < 12 { bail!("password must contain at least 12 characters"); }
    Ok(Zeroizing::new(p.into_bytes()))
}

fn derive_key(pass: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(32 * 1024, 3, 1, Some(32)).map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e:?}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon.hash_password_into(pass, salt, &mut key).map_err(|e| anyhow::anyhow!("key derivation failed: {e:?}"))?;
    Ok(key)
}

fn nonce(base: &[u8; NONCE_LEN], index: u64) -> XNonce {
    let mut h = Hasher::new(); h.update(b"DEOBF-NONCE-V2"); h.update(base); h.update(&index.to_le_bytes());
    let digest = h.finalize(); let mut n = [0u8; NONCE_LEN]; n.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]); XNonce::from(n)
}

fn aad(index: u64, plain_len: u64, flags: u8) -> Vec<u8> {
    let mut a = Vec::with_capacity(32); a.extend_from_slice(MAGIC); a.push(VERSION); a.push(flags); a.extend_from_slice(&index.to_le_bytes()); a.extend_from_slice(&plain_len.to_le_bytes()); a
}

// Compact printable symbol encoding: 3 bytes -> 4 characters (~33% expansion).
const TEXT_ALPHABET: &[u8; 64] = b"!@#$%^&*()-_=+[]{};:,.<>?/|~`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn text_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(TEXT_ALPHABET[(a >> 2) as usize] as char);
        out.push(TEXT_ALPHABET[((a & 3) << 4 | b >> 4) as usize] as char);
        out.push(if chunk.len() > 1 { TEXT_ALPHABET[((b & 15) << 2 | c >> 6) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TEXT_ALPHABET[(c & 63) as usize] as char } else { '=' });
    }
    out
}

fn text_decode(s: &str) -> Result<Vec<u8>> {
    let mut map = [255u8; 256];
    for (i, &c) in TEXT_ALPHABET.iter().enumerate() { map[c as usize] = i as u8; }
    let bytes = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect::<Vec<_>>();
    if bytes.len() % 4 != 0 { bail!("invalid encrypted text"); }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for q in bytes.chunks_exact(4) {
        let a = map[q[0] as usize]; let b = map[q[1] as usize];
        if a == 255 || b == 255 { bail!("invalid encrypted text"); }
        let c = if q[2] == b'=' { 0 } else { map[q[2] as usize] };
        let d = if q[3] == b'=' { 0 } else { map[q[3] as usize] };
        if c == 255 || d == 255 { bail!("invalid encrypted text"); }
        out.push((a << 2) | (b >> 4));
        if q[2] != b'=' { out.push((b << 4) | (c >> 2)); }
        if q[3] != b'=' { out.push((c << 6) | d); }
    }
    Ok(out)
}

fn text_encrypt(text: Option<String>, pass: &[u8]) -> Result<()> {
    let input = match text { Some(v) => v, None => { print!("✦ Text: "); std::io::stdout().flush()?; let mut v = String::new(); std::io::stdin().read_line(&mut v)?; v.trim_end_matches(['\r', '\n']).to_owned() } };
    let mut salt = [0u8; SALT_LEN]; let mut base = [0u8; NONCE_LEN]; OsRng.fill_bytes(&mut salt); OsRng.fill_bytes(&mut base);
    let key = derive_key(pass, &salt)?; let cipher = XChaCha20Poly1305::new((&key).into());
    let encrypted = cipher.encrypt(&XNonce::from(base), chacha20poly1305::aead::Payload { msg: input.as_bytes(), aad: b"DEOBF-TEXT-V2" }).map_err(|_| anyhow::anyhow!("text encryption failed"))?;
    let mut payload = Vec::with_capacity(SALT_LEN + NONCE_LEN + encrypted.len());
    payload.extend_from_slice(&salt); payload.extend_from_slice(&base); payload.extend_from_slice(&encrypted);
    println!("{}", text_encode(&payload));
    Ok(())
}

fn text_decrypt(text: Option<String>, pass: &[u8]) -> Result<()> {
    let input = match text { Some(v) => v, None => { print!("✦ Ciphertext: "); std::io::stdout().flush()?; let mut v = String::new(); std::io::stdin().read_line(&mut v)?; v } };
    let payload = text_decode(&input)?;
    if payload.len() < SALT_LEN + NONCE_LEN + TAG_LEN { bail!("invalid encrypted text"); }
    let (salt_bytes, rest) = payload.split_at(SALT_LEN); let (nonce_bytes, encrypted) = rest.split_at(NONCE_LEN);
    let mut salt = [0u8; SALT_LEN]; salt.copy_from_slice(salt_bytes);
    let mut nonce = [0u8; NONCE_LEN]; nonce.copy_from_slice(nonce_bytes);
    let key = derive_key(pass, &salt)?; let cipher = XChaCha20Poly1305::new((&key).into());
    let plain = cipher.decrypt(&XNonce::from(nonce), chacha20poly1305::aead::Payload { msg: encrypted, aad: b"DEOBF-TEXT-V2" }).map_err(|_| anyhow::anyhow!("authentication failed: wrong password or modified text"))?;
    let text = String::from_utf8(plain).map_err(|_| anyhow::anyhow!("decrypted data is not valid UTF-8"))?;
    println!("{}", text); Ok(())
}

fn protect(input: &Path, output: &Path, pass: &[u8]) -> Result<()> {
    if input == output { bail!("input and output must differ"); }
    let mut src = File::open(input).with_context(|| format!("open {}", input.display()))?; let plain_len = src.metadata()?.len();
    let mut salt = [0u8; SALT_LEN]; let mut base = [0u8; NONCE_LEN]; OsRng.fill_bytes(&mut salt); OsRng.fill_bytes(&mut base);
    let key = derive_key(pass, &salt)?; let cipher = XChaCha20Poly1305::new((&key).into()); let tmp = output.with_extension("deobf-write-tmp"); let mut dst = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
    dst.write_all(MAGIC)?; dst.write_all(&[VERSION])?; dst.write_all(&[1u8])?; dst.write_all(&salt)?; dst.write_all(&base)?; dst.write_all(&plain_len.to_le_bytes())?;
    let mut buf = vec![0u8; CHUNK]; let mut index = 0u64; let mut digest = Hasher::new(); digest.update(b"DEOBF-CONTENT-V2");
    loop { let n = src.read(&mut buf)?; if n == 0 { break; } digest.update(&buf[..n]); let compressed = zstd::bulk::compress(&buf[..n], 3).unwrap_or_else(|_| buf[..n].to_vec()); let encrypted = cipher.encrypt(&nonce(&base, index), chacha20poly1305::aead::Payload { msg: &compressed, aad: &aad(index, plain_len, 1) }).map_err(|_| anyhow::anyhow!("encryption failed"))?; dst.write_all(&(n as u32).to_le_bytes())?; dst.write_all(&(encrypted.len() as u32).to_le_bytes())?; dst.write_all(&encrypted)?; let mut p = [0u8; 2]; OsRng.fill_bytes(&mut p); let pad = (u16::from_le_bytes(p) as usize) % (MAX_PAD + 1); dst.write_all(&(pad as u16).to_le_bytes())?; if pad != 0 { let mut padding = vec![0u8; pad]; OsRng.fill_bytes(&mut padding); dst.write_all(&padding)?; } index += 1; }
    let final_hash = digest.finalize(); let trailer = cipher.encrypt(&nonce(&base, u64::MAX), chacha20poly1305::aead::Payload { msg: final_hash.as_bytes(), aad: &aad(u64::MAX, plain_len, 1) }).map_err(|_| anyhow::anyhow!("trailer encryption failed"))?; dst.write_all(b"TRLR")?; dst.write_all(&(trailer.len() as u32).to_le_bytes())?; dst.write_all(&trailer)?; dst.sync_all()?; drop(dst); fs::rename(tmp, output)?; Ok(())
}

struct Header { version: u8, flags: u8, salt: [u8; SALT_LEN], base: [u8; NONCE_LEN], plain_len: u64 }
fn read_header(src: &mut File) -> Result<Header> { let mut magic = [0u8; 8]; src.read_exact(&mut magic)?; if &magic != MAGIC { bail!("not a DEOBF container"); } let mut ver = [0u8; 1]; src.read_exact(&mut ver)?; if ver[0] != VERSION && ver[0] != LEGACY_VERSION { bail!("unsupported container version {}", ver[0]); } let mut flags = [0u8; 1]; if ver[0] == VERSION { src.read_exact(&mut flags)?; } let mut salt = [0u8; SALT_LEN]; let mut base = [0u8; NONCE_LEN]; let mut len = [0u8; 8]; src.read_exact(&mut salt)?; src.read_exact(&mut base)?; src.read_exact(&mut len)?; Ok(Header { version: ver[0], flags: flags[0], salt, base, plain_len: u64::from_le_bytes(len) }) }

fn unprotect_v1(src: &mut File, output: &Path, pass: &[u8], salt: &[u8; SALT_LEN], base: &[u8; NONCE_LEN], plain_len: u64) -> Result<()> {
    let key = derive_key(pass, salt)?; let cipher = XChaCha20Poly1305::new((&key).into()); let tmp = output.with_extension("deobf-tmp"); let mut dst = File::create(&tmp)?; let mut total = 0u64; let mut index = 0u64;
    loop { let mut p = [0u8; 4]; match src.read_exact(&mut p) { Ok(_) => {}, Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, Err(e) => return Err(e.into()) } let n = u32::from_le_bytes(p) as usize; src.read_exact(&mut p)?; let enc_n = u32::from_le_bytes(p) as usize; if n == 0 || n > CHUNK || enc_n != n + TAG_LEN { let _ = fs::remove_file(&tmp); bail!("invalid container chunk"); } let mut enc = vec![0u8; enc_n]; src.read_exact(&mut enc)?; let plain = cipher.decrypt(&nonce_v1(base, index), chacha20poly1305::aead::Payload { msg: &enc, aad: &aad_v1(index, plain_len) }).map_err(|_| anyhow::anyhow!("authentication failed: wrong password or modified file"))?; if plain.len() != n { let _ = fs::remove_file(&tmp); bail!("invalid decrypted chunk"); } dst.write_all(&plain)?; total += n as u64; index += 1; }
    if total != plain_len { let _ = fs::remove_file(&tmp); bail!("length mismatch: container is damaged"); } dst.sync_all()?; drop(dst); fs::rename(tmp, output)?; Ok(())
}
fn nonce_v1(base: &[u8; NONCE_LEN], index: u64) -> XNonce { let mut h = Hasher::new(); h.update(base); h.update(&index.to_le_bytes()); let digest = h.finalize(); let mut n = [0u8; NONCE_LEN]; n.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]); XNonce::from(n) }
fn aad_v1(index: u64, plain_len: u64) -> Vec<u8> { let mut a = Vec::with_capacity(25); a.extend_from_slice(MAGIC); a.push(LEGACY_VERSION); a.extend_from_slice(&index.to_le_bytes()); a.extend_from_slice(&plain_len.to_le_bytes()); a }

fn unprotect(input: &Path, output: &Path, pass: &[u8]) -> Result<()> {
    if input == output { bail!("input and output must differ"); } let mut src = File::open(input)?; let header = read_header(&mut src)?; if header.version == LEGACY_VERSION { return unprotect_v1(&mut src, output, pass, &header.salt, &header.base, header.plain_len); } if header.flags & 1 == 0 { bail!("unsupported DEOBF v2 flags"); }
    let key = derive_key(pass, &header.salt)?; let cipher = XChaCha20Poly1305::new((&key).into()); let tmp = output.with_extension("deobf-tmp"); let mut dst = File::create(&tmp)?; let mut total = 0u64; let mut index = 0u64; let mut digest = Hasher::new(); digest.update(b"DEOBF-CONTENT-V2");
    loop { let mut marker = [0u8; 4]; src.read_exact(&mut marker)?; if &marker == b"TRLR" { let mut l = [0u8; 4]; src.read_exact(&mut l)?; let n = u32::from_le_bytes(l) as usize; if n != 48 { let _ = fs::remove_file(&tmp); bail!("invalid trailer"); } let mut enc = vec![0u8; n]; src.read_exact(&mut enc)?; let expected = cipher.decrypt(&nonce(&header.base, u64::MAX), chacha20poly1305::aead::Payload { msg: &enc, aad: &aad(u64::MAX, header.plain_len, header.flags) }).map_err(|_| anyhow::anyhow!("trailer authentication failed"))?; if expected.len() != 32 || expected.as_slice() != digest.finalize().as_bytes() { let _ = fs::remove_file(&tmp); bail!("content integrity check failed"); } break; }
        let n = u32::from_le_bytes(marker) as usize; let mut e = [0u8; 4]; src.read_exact(&mut e)?; let enc_n = u32::from_le_bytes(e) as usize; if n == 0 || n > CHUNK || !(TAG_LEN..=CHUNK + TAG_LEN).contains(&enc_n) { let _ = fs::remove_file(&tmp); bail!("invalid container chunk"); } let mut enc = vec![0u8; enc_n]; src.read_exact(&mut enc)?; let mut p = [0u8; 2]; src.read_exact(&mut p)?; let pad = u16::from_le_bytes(p) as usize; if pad > MAX_PAD { let _ = fs::remove_file(&tmp); bail!("invalid padding"); } if pad != 0 { let mut junk = vec![0u8; pad]; src.read_exact(&mut junk)?; }
        let compressed = cipher.decrypt(&nonce(&header.base, index), chacha20poly1305::aead::Payload { msg: &enc, aad: &aad(index, header.plain_len, header.flags) }).map_err(|_| anyhow::anyhow!("authentication failed: wrong password or modified file"))?; let plain = zstd::bulk::decompress(&compressed, CHUNK).unwrap_or(compressed); if plain.len() != n { let _ = fs::remove_file(&tmp); bail!("invalid decompressed chunk"); } digest.update(&plain); dst.write_all(&plain)?; total += n as u64; index += 1;
    }
    if total != header.plain_len { let _ = fs::remove_file(&tmp); bail!("length mismatch: container is damaged"); } dst.sync_all()?; drop(dst); fs::rename(tmp, output)?; Ok(())
}

fn inspect(input: &Path) -> Result<()> { let mut f = File::open(input)?; let header = read_header(&mut f)?; println!("format: DEOBF v{}\noriginal size: {} bytes\nchunk size: {} KiB\nflags: 0x{:02x}", header.version, header.plain_len, CHUNK / 1024, header.flags); Ok(()) }
fn run_jar(input: &Path, java: &str, pass: &[u8], args: &[String]) -> Result<()> { if debugger_present() { bail!("debugger detected"); } let dir = std::env::temp_dir().join(format!("deobf-{}", std::process::id())); fs::create_dir_all(&dir)?; let jar = dir.join("payload.jar"); let result = unprotect(input, &jar, pass).and_then(|_| { let mut c = Command::new(java); c.arg("-jar").arg(&jar).args(args); Ok(c.status()?) }); let _ = fs::remove_dir_all(&dir); result.map(|_| ()) }
fn debugger_present() -> bool { #[cfg(windows)] { unsafe { windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() != 0 } } #[cfg(target_os = "linux")] { fs::read_to_string("/proc/self/status").map(|s| s.lines().any(|l| l.trim_start().starts_with("TracerPid:") && l.split_whitespace().nth(1).unwrap_or("0") != "0")).unwrap_or(false) } #[cfg(not(any(windows, target_os = "linux")))] { false } }

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Protect { input, output, password: p } => { let pass = password(p, true)?; protect(&input, &output, &pass) }
        Cmd::Unprotect { input, output, password: p } => { let pass = password(p, false)?; unprotect(&input, &output, &pass) }
        Cmd::Inspect { input } => inspect(&input),
        Cmd::RunJar { input, java, password: p, args } => { let pass = password(p, false)?; run_jar(&input, &java, &pass, &args) }
        Cmd::Text { command } => match command {
            TextCmd::Encrypt { text, password: p } => { let pass = password(p, true)?; text_encrypt(text, &pass) }
            TextCmd::Decrypt { text, password: p } => { let pass = password(p, false)?; text_decrypt(text, &pass) }
        },
    }
}
