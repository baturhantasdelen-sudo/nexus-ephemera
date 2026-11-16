//! Install package: config, policy, permissions, and a health source.
//!
//! Boot rejects a missing field, a drifted allowlist, or a file that is not
//! private. The HMAC covers the policy bytes under `nexus-package-policy-v1`.
//! It is not the request MAC and it is not mTLS. The broker secret is not read.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use orion::hazardous::mac::hmac::sha256::{HmacSha256, SecretKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::adapters::github::GithubIssuePolicy;
use crate::enterprise_runtime::RedisIdempotency;
use crate::ipc::{HealthFacts, HealthSource, IpcError};

const FILES: [&str; 5] = [
    "config.toml",
    ".env",
    "pilot_support_agent.json",
    "hmac.key",
    "policy.hmac",
];
const POLICY_DOMAIN: &[u8] = b"nexus-package-policy-v1\0";
const REDIS_NAMESPACE: &str = "pilot";

pub struct LoadedPackage {
    listen: String,
    allow: String,
    timeout: Duration,
    watch: PackageWatch,
}

impl LoadedPackage {
    pub fn listen(&self) -> &str {
        &self.listen
    }

    pub fn allow(&self) -> &str {
        &self.allow
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn watch(&self) -> Arc<dyn HealthSource> {
        Arc::new(self.watch.clone())
    }
}

impl std::fmt::Debug for LoadedPackage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedPackage")
            .field("listen", &self.listen)
            .field("allow", &self.allow)
            .finish()
    }
}

#[derive(Clone)]
struct PackageWatch {
    directory: PathBuf,
    policy_sha256: String,
    redis_url: String,
}

impl Drop for PackageWatch {
    fn drop(&mut self) {
        self.redis_url.zeroize();
    }
}

impl HealthSource for PackageWatch {
    fn facts(&self) -> HealthFacts {
        let (policy_intact, hmac_ready) = match reread(&self.directory, &self.policy_sha256) {
            Ok(()) => (true, true),
            Err(_) => (false, false),
        };
        HealthFacts {
            policy_intact,
            hmac_ready,
            idempotency: probe_redis(&self.redis_url),
        }
    }
}

pub fn write_template(directory: &Path, listen: &str, policy: &[u8]) -> Result<(), IpcError> {
    if !valid_listen(listen) || policy.is_empty() || policy.len() > 65_536 {
        return Err(IpcError::Protocol("package template is invalid"));
    }
    nexus_ephemera_ipc_os::create_private_directory(directory)?;
    let policy_name = "pilot_support_agent.json";
    let config = format!(
        "listen = \"{listen}\"\ntimeout_ms = 5000\npolicy = \"{policy_name}\"\nallow = \"https://api.github.com/repos/pilot-org/support-queue/issues\"\nredis = \"\"\n"
    );
    let env = format!(
        "NEXUS_LISTEN={listen}\nNEXUS_POLICY={policy_name}\nNEXUS_TIMEOUT_MS=5000\nNEXUS_REDIS_URL=\n"
    );
    write_new(&directory.join("config.toml"), config.as_bytes())?;
    write_new(&directory.join(".env"), env.as_bytes())?;
    write_new(&directory.join(policy_name), policy)?;
    Ok(())
}

pub fn seal(directory: &Path) -> Result<(), IpcError> {
    nexus_ephemera_ipc_os::assert_private_directory(directory)?;
    let policy = read_capped(&directory.join("pilot_support_agent.json"))?;
    let key_path = directory.join("hmac.key");
    if !key_path.exists() {
        let mut key = Zeroizing::new(vec![0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key.as_mut_slice());
        write_new(&key_path, &key)?;
    }
    let key = Zeroizing::new(read_capped(&key_path)?);
    let tag = policy_tag(&key, &policy)?;
    let signature_path = directory.join("policy.hmac");
    if signature_path.exists() {
        // Do not follow an attacker-controlled path during re-sealing.
        nexus_ephemera_ipc_os::assert_private_file(&signature_path)?;
        fs::remove_file(&signature_path)?;
    }
    write_new(&signature_path, hex(&tag).as_bytes())?;
    for name in FILES {
        nexus_ephemera_ipc_os::lock_file_to_current_user(&directory.join(name))?;
    }
    load(directory).map(|_| ())
}

pub fn load(directory: &Path) -> Result<LoadedPackage, IpcError> {
    nexus_ephemera_ipc_os::assert_private_directory(directory)?;
    if !directory.is_dir() {
        return Err(IpcError::Protocol("package directory is missing"));
    }
    for name in FILES {
        nexus_ephemera_ipc_os::assert_private_file(&directory.join(name)).map_err(|_| {
            IpcError::Protocol("package file must be mode 0600 or a current-user DACL")
        })?;
    }
    let config = Zeroizing::new(read_capped(&directory.join("config.toml"))?);
    let env = Zeroizing::new(read_capped(&directory.join(".env"))?);
    let policy_bytes = read_capped(&directory.join("pilot_support_agent.json"))?;
    let key = Zeroizing::new(read_capped(&directory.join("hmac.key"))?);
    let signature = read_capped(&directory.join("policy.hmac"))?;
    let mut fields = parse_config(&config)?;
    let env_fields = parse_env(&env)?;
    if env_fields.listen != fields.listen
        || env_fields.policy != fields.policy
        || env_fields.timeout_ms != fields.timeout_ms
        || env_fields.redis != fields.redis
    {
        return Err(IpcError::Protocol("package env does not match config.toml"));
    }
    if fields.policy != "pilot_support_agent.json" {
        return Err(IpcError::Protocol(
            "package policy path is not the pilot file",
        ));
    }
    let policy = GithubIssuePolicy::load(&policy_bytes)?;
    if fields.allow != policy.endpoint() {
        return Err(IpcError::Protocol(
            "package allowlist does not match the policy",
        ));
    }
    verify_tag(&key, &policy_bytes, &signature)?;
    if !fields.redis.is_empty() {
        RedisIdempotency::new(&fields.redis, REDIS_NAMESPACE, 32, Duration::from_secs(2))?;
    }
    Ok(LoadedPackage {
        listen: std::mem::take(&mut fields.listen),
        allow: std::mem::take(&mut fields.allow),
        timeout: Duration::from_millis(fields.timeout_ms),
        watch: PackageWatch {
            directory: directory.to_path_buf(),
            policy_sha256: hex(&Sha256::digest(&policy_bytes)),
            redis_url: std::mem::take(&mut fields.redis),
        },
    })
}

pub fn policy_tag(key: &[u8], policy: &[u8]) -> Result<[u8; 32], IpcError> {
    if key.len() != 32 || policy.is_empty() || policy.len() > 65_536 {
        return Err(IpcError::Malformed);
    }
    let secret = SecretKey::try_from(key).map_err(|_| IpcError::Malformed)?;
    let mut mac = HmacSha256::new(&secret);
    mac.update(POLICY_DOMAIN).map_err(|_| IpcError::Malformed)?;
    mac.update(policy).map_err(|_| IpcError::Malformed)?;
    let tag = mac.finalize().map_err(|_| IpcError::Malformed)?;
    let bytes = tag.unprotected_as_ref();
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return Err(IpcError::Malformed);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

fn reread(directory: &Path, expected_sha: &str) -> Result<(), IpcError> {
    for name in FILES {
        nexus_ephemera_ipc_os::assert_private_file(&directory.join(name))
            .map_err(|_| IpcError::Protocol("package file permission check failed"))?;
    }
    let policy = read_capped(&directory.join("pilot_support_agent.json"))?;
    if hex(&Sha256::digest(&policy)) != expected_sha {
        return Err(IpcError::Protocol("package policy hash changed"));
    }
    let key = Zeroizing::new(read_capped(&directory.join("hmac.key"))?);
    let signature = read_capped(&directory.join("policy.hmac"))?;
    verify_tag(&key, &policy, &signature)
}

fn verify_tag(key: &[u8], policy: &[u8], signature: &[u8]) -> Result<(), IpcError> {
    let presented = std::str::from_utf8(signature)
        .map_err(|_| IpcError::Malformed)?
        .trim_ascii();
    let decoded = decode_hex(presented)?;
    let expected = policy_tag(key, policy)?;
    if bool::from(expected.ct_eq(&decoded)) {
        Ok(())
    } else {
        Err(IpcError::Protocol("package policy hmac does not match"))
    }
}

fn probe_redis(url: &str) -> &'static str {
    if url.is_empty() {
        return "local";
    }
    match RedisIdempotency::new(url, REDIS_NAMESPACE, 32, Duration::from_secs(2))
        .and_then(|store| store.health())
    {
        Ok(()) => "ready",
        Err(IpcError::Protocol(_)) | Err(IpcError::Malformed) => "unhealthy",
        Err(_) => "degraded",
    }
}

struct Fields {
    listen: String,
    timeout_ms: u64,
    policy: String,
    allow: String,
    redis: String,
}

impl Drop for Fields {
    fn drop(&mut self) {
        self.redis.zeroize();
    }
}

fn parse_config(bytes: &[u8]) -> Result<Fields, IpcError> {
    let text = std::str::from_utf8(bytes).map_err(|_| IpcError::Malformed)?;
    let mut listen = None;
    let mut timeout_ms = None;
    let mut policy = None;
    let mut allow = None;
    let mut redis = None;
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(IpcError::Protocol("package config has a malformed line"))?;
        let key = key.trim();
        let value = value.trim();
        let assign = |slot: &mut Option<String>, parsed: String| -> Result<(), IpcError> {
            if slot.is_some() {
                return Err(IpcError::Protocol("package config repeats a field"));
            }
            *slot = Some(parsed);
            Ok(())
        };
        match key {
            "listen" => assign(&mut listen, quoted(value)?)?,
            "policy" => assign(&mut policy, quoted(value)?)?,
            "allow" => assign(&mut allow, quoted(value)?)?,
            "redis" => assign(&mut redis, quoted(value)?)?,
            "timeout_ms" => {
                if timeout_ms.is_some() {
                    return Err(IpcError::Protocol("package config repeats a field"));
                }
                let parsed: u64 = value
                    .parse()
                    .map_err(|_| IpcError::Protocol("package timeout is invalid"))?;
                if !(1..=120_000).contains(&parsed) {
                    return Err(IpcError::Protocol("package timeout is outside 1ms..=120s"));
                }
                timeout_ms = Some(parsed);
            }
            _ => return Err(IpcError::Protocol("package config has an unknown field")),
        }
    }
    Ok(Fields {
        listen: listen.ok_or(IpcError::Protocol(
            "package config is missing a required field",
        ))?,
        timeout_ms: timeout_ms.ok_or(IpcError::Protocol(
            "package config is missing a required field",
        ))?,
        policy: policy.ok_or(IpcError::Protocol(
            "package config is missing a required field",
        ))?,
        allow: allow.ok_or(IpcError::Protocol(
            "package config is missing a required field",
        ))?,
        redis: redis.ok_or(IpcError::Protocol(
            "package config is missing a required field",
        ))?,
    })
    .and_then(|fields| {
        if !valid_listen(&fields.listen)
            || fields.redis.len() > 2048
            || fields.redis.contains(['\n', '\r', ' '])
        {
            return Err(IpcError::Protocol(
                "package listen or redis field is invalid",
            ));
        }
        Ok(fields)
    })
}

fn parse_env(bytes: &[u8]) -> Result<Fields, IpcError> {
    let text = std::str::from_utf8(bytes).map_err(|_| IpcError::Malformed)?;
    let mut listen = None;
    let mut policy = None;
    let mut timeout_ms = None;
    let mut redis = None;
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(IpcError::Protocol("package env has a malformed line"))?;
        if value.chars().any(|char| char.is_control()) {
            return Err(IpcError::Malformed);
        }
        let assign_text = |slot: &mut Option<String>| -> Result<(), IpcError> {
            if slot.is_some() {
                return Err(IpcError::Protocol("package env repeats a field"));
            }
            *slot = Some(value.to_string());
            Ok(())
        };
        match key {
            "NEXUS_LISTEN" => assign_text(&mut listen)?,
            "NEXUS_POLICY" => assign_text(&mut policy)?,
            "NEXUS_REDIS_URL" => assign_text(&mut redis)?,
            "NEXUS_TIMEOUT_MS" => {
                if timeout_ms.is_some() {
                    return Err(IpcError::Protocol("package env repeats a field"));
                }
                timeout_ms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| IpcError::Protocol("package timeout is invalid"))?,
                );
            }
            _ => return Err(IpcError::Protocol("package env has an unknown field")),
        }
    }
    Ok(Fields {
        listen: listen.ok_or(IpcError::Protocol(
            "package env is missing a required field",
        ))?,
        timeout_ms: timeout_ms.ok_or(IpcError::Protocol(
            "package env is missing a required field",
        ))?,
        policy: policy.ok_or(IpcError::Protocol(
            "package env is missing a required field",
        ))?,
        allow: String::new(),
        redis: redis.unwrap_or_default(),
    })
}

fn quoted(value: &str) -> Result<String, IpcError> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return Err(IpcError::Protocol(
            "package config value must be a quoted string",
        ));
    }
    Ok(value[1..value.len() - 1].to_string())
}

fn valid_listen(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value != "."
        && !value.chars().any(|char| char.is_control())
        && !value.split(['/', '\\']).any(|part| part == "..")
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), IpcError> {
    if path.exists() {
        return Err(IpcError::Protocol("package file already exists"));
    }
    use std::io::Write;
    let mut file = nexus_ephemera_ipc_os::create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_capped(path: &Path) -> Result<Vec<u8>, IpcError> {
    Ok(nexus_ephemera_ipc_os::read_private_file(path, 65_536)?)
}

fn decode_hex(value: &str) -> Result<[u8; 32], IpcError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(IpcError::Malformed);
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| IpcError::Malformed)?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_hmac_matches_the_independent_vector() {
        let tag = policy_tag(
            &core::array::from_fn::<u8, 32, _>(|index| index as u8),
            b"{}",
        )
        .unwrap();
        assert_eq!(
            hex(&tag),
            "dd3cfdce70b2eb93e34e8719d9f2a217edff4535a75195882c1d924b971630c6"
        );
    }
}
