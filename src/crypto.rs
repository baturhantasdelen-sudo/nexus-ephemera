//! Scout / mesh arasında paylaşılan AEAD şifreleme (yalnızca koordinatör oturumu).
//!
//! Üretim şifre çözme yolu: yalnızca `open_to_plaintext` / `open_into` (kilitli tampon).
//! Pageable `Vec` döndüren `open()` yalnızca testlerde kullanılabilir.

#![forbid(unsafe_code)]

use std::sync::{Mutex, MutexGuard};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce, Tag,
    aead::{AeadInPlace, KeyInit, OsRng},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::apoptosis::{
    self, ApoptosisError, EphemeralBuffer, acquire_operation_permit, lock_or_recover,
    record_aux_unlock_failure, with_locked_mut,
};
use nexus_ephemera_memlock::LockedBuffer;

pub const KEY_LEN: usize = 32;
/// Receiver clock may differ from the signer by at most five seconds.
pub const SIGNATURE_SKEW_MS: u64 = 5_000;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedBlob {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

fn zeroize_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    bytes.zeroize();
    *s = String::new();
}

impl SealedBlob {
    pub fn wipe(&mut self) {
        zeroize_string(&mut self.nonce_b64);
        zeroize_string(&mut self.ciphertext_b64);
    }
}

struct SessionState {
    key_vault: EphemeralBuffer,
}

fn session_slot() -> &'static Mutex<Option<SessionState>> {
    static SESSION: Mutex<Option<SessionState>> = Mutex::new(None);
    &SESSION
}

fn session_guard() -> MutexGuard<'static, Option<SessionState>> {
    lock_or_recover(session_slot())
}

fn with_key_vault<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&[u8]) -> Result<R, String>,
{
    let _permit = acquire_operation_permit()?;
    let guard = session_guard();
    let state = guard
        .as_ref()
        .ok_or_else(|| "crypto session not initialized".to_string())?;
    state.key_vault.with_sensitive_bytes(f)
}

pub fn init_session_from_entropy() -> Result<(), String> {
    let _permit = acquire_operation_permit()?;
    nexus_ephemera_memlock::harden_process_memory().map_err(apoptosis::memlock_err_public)?;
    let mut slot = session_guard();
    if slot.is_some() {
        return Ok(());
    }
    let key_vault = EphemeralBuffer::from_os_rng(KEY_LEN)?;
    *slot = Some(SessionState { key_vault });
    Ok(())
}

#[cfg(test)]
pub fn init_session_for_tests(key: [u8; KEY_LEN]) -> Result<(), String> {
    let _permit = acquire_operation_permit()?;
    let mut slot = session_guard();
    let key_vault = EphemeralBuffer::from_bytes(key.as_slice())?;
    *slot = Some(SessionState { key_vault });
    Ok(())
}

/// Kilitli plaintext üzerinde yerinde AEAD şifreleme (pageable plaintext `Vec` yok).
pub fn seal_plaintext(plaintext: &EphemeralBuffer) -> Result<SealedBlob, String> {
    let _permit = acquire_operation_permit()?;
    with_key_vault(|key| {
        let pt_len = plaintext.len();
        let total_ct = pt_len
            .checked_add(TAG_LEN)
            .ok_or_else(|| "plaintext length overflow".to_string())?;

        let mut work =
            LockedBuffer::try_new_zeroed(total_ct.max(1)).map_err(apoptosis::memlock_err_public)?;

        plaintext.with_sensitive_bytes(|pt| {
            work.try_set_len(total_ct)
                .map_err(apoptosis::memlock_err_public)?;
            let dst = work
                .try_as_mut_slice()
                .map_err(apoptosis::memlock_err_public)?;
            if pt.len() > dst.len() {
                return Err("plaintext exceeds work buffer".into());
            }
            dst[..pt.len()].copy_from_slice(pt);
            Ok(())
        })?;

        let mut nonce_bytes = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|err| format!("cipher init: {err}"))?;

        let tag = with_locked_mut(&mut work, |buf| {
            let dst = buf
                .try_as_mut_slice()
                .map_err(ApoptosisError::BufferError)?;
            cipher
                .encrypt_in_place_detached(&nonce, b"", &mut dst[..pt_len])
                .map_err(|_| ApoptosisError::CryptoError("encrypt in place failed"))
        })
        .map_err(|e| e.to_string())?;

        {
            let dst = work
                .try_as_mut_slice()
                .map_err(apoptosis::memlock_err_public)?;
            dst[pt_len..total_ct].copy_from_slice(tag.as_slice());
        }

        let wire = work.as_slice();
        let blob = SealedBlob {
            nonce_b64: B64.encode(nonce_bytes),
            ciphertext_b64: B64.encode(wire),
        };
        nonce_bytes.zeroize();
        if work.wipe().is_err() {
            record_aux_unlock_failure();
        }
        Ok(blob)
    })
}

fn decrypt_into_locked_blob(
    key: &[u8],
    blob: &SealedBlob,
    destination: &EphemeralBuffer,
) -> Result<(), ApoptosisError> {
    destination.with_locked_mut(|locked| {
        let mut nonce_buf = Zeroizing::new([0_u8; 16]);
        let nonce_len = B64
            .decode_slice(blob.nonce_b64.as_bytes(), &mut nonce_buf[..])
            .map_err(|_| ApoptosisError::CryptoError("Invalid base64 nonce"))?;

        if nonce_len != NONCE_LEN {
            return Err(ApoptosisError::CryptoError(
                "Invalid nonce length: must be 12 bytes",
            ));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| ApoptosisError::CryptoError("Invalid key length"))?;
        let nonce = Nonce::from_slice(&nonce_buf[..NONCE_LEN]);

        let ct_b64 = blob.ciphertext_b64.as_bytes();
        let est_len = base64::decoded_len_estimate(ct_b64.len());
        if locked.capacity() < est_len {
            return Err(ApoptosisError::CryptoError(
                "Destination capacity too small",
            ));
        }

        locked
            .try_set_len(est_len)
            .map_err(ApoptosisError::BufferError)?;
        let raw_slice = locked
            .try_as_mut_slice()
            .map_err(ApoptosisError::BufferError)?;

        let actual_ct_len = B64
            .decode_slice(ct_b64, raw_slice)
            .map_err(|_| ApoptosisError::CryptoError("Invalid base64 ciphertext"))?;

        if actual_ct_len < TAG_LEN {
            return Err(ApoptosisError::CryptoError(
                "Ciphertext shorter than AEAD tag",
            ));
        }

        let pt_len = actual_ct_len - TAG_LEN;
        let (ct_slice, tag_part) = raw_slice[..actual_ct_len].split_at_mut(pt_len);
        let tag = Tag::from_slice(&tag_part[..TAG_LEN]);

        cipher
            .decrypt_in_place_detached(nonce, b"", ct_slice, tag)
            .map_err(|_| ApoptosisError::CryptoError("AEAD authentication failed"))?;

        locked
            .try_set_len(pt_len)
            .map_err(ApoptosisError::BufferError)?;
        Ok(())
    })
}

struct DestinationWipeOnErr<'a> {
    destination: &'a EphemeralBuffer,
    success: bool,
}

impl Drop for DestinationWipeOnErr<'_> {
    fn drop(&mut self) {
        if !self.success && self.destination.try_wipe().is_err() {
            crate::apoptosis::record_aux_unlock_failure();
        }
    }
}

pub fn open_into(blob: &SealedBlob, destination: &EphemeralBuffer) -> Result<(), String> {
    let mut dest_guard = DestinationWipeOnErr {
        destination,
        success: false,
    };
    let _permit = acquire_operation_permit()?;
    with_key_vault(|key| {
        decrypt_into_locked_blob(key, blob, destination).map_err(|e| e.to_string())
    })?;
    dest_guard.success = true;
    Ok(())
}

pub fn open_to_plaintext(blob: &SealedBlob) -> Result<EphemeralBuffer, String> {
    let cap = EphemeralBuffer::b64_capacity_estimate(&blob.ciphertext_b64);
    let destination = EphemeralBuffer::with_capacity(cap)?;
    open_into(blob, &destination)?;
    Ok(destination)
}

pub fn wipe_session_on_apoptosis() -> Result<(), &'static str> {
    let mut slot = session_guard();
    if let Some(state) = slot.take() {
        state.key_vault.try_wipe()?;
    }
    *slot = None;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    Missing,
    Malformed,
    Expired,
    Invalid,
}

/// HMAC-SHA256 over the length-prefixed canonical request.
///
/// The header is `t=<unix ms>,v1=<hex>`. It is not the binding digest and it
/// is not mTLS. The derived signing key is wiped before this returns. The
/// header value is what the receiver checks; it is not the secret.
pub fn sign_request_header(
    secret: &[u8],
    timestamp_unix_ms: u64,
    idempotency_key: &str,
    payload_hash: &str,
    endpoint: &str,
) -> String {
    let mac = request_mac(
        secret,
        timestamp_unix_ms,
        idempotency_key,
        payload_hash,
        endpoint,
    );
    let header = format!("t={timestamp_unix_ms},v1={}", hex_encode(mac.as_slice()));
    header
}

/// Check `X-Nexus-Signature` against the same secret and a 5 second skew.
pub fn verify_request_header(
    secret: &[u8],
    header: &str,
    idempotency_key: &str,
    payload_hash: &str,
    endpoint: &str,
    now_unix_ms: u64,
) -> Result<(), SignatureError> {
    if header.is_empty() {
        return Err(SignatureError::Missing);
    }
    let (timestamp, presented) = parse_signature_header(header)?;
    if timestamp.abs_diff(now_unix_ms) > SIGNATURE_SKEW_MS {
        return Err(SignatureError::Expired);
    }
    let expected = request_mac(secret, timestamp, idempotency_key, payload_hash, endpoint);
    if presented.len() != expected.len() || !bool::from(presented.ct_eq(expected.as_slice())) {
        return Err(SignatureError::Invalid);
    }
    Ok(())
}

fn request_mac(
    secret: &[u8],
    timestamp_unix_ms: u64,
    idempotency_key: &str,
    payload_hash: &str,
    endpoint: &str,
) -> Zeroizing<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let signing_key = derive_signing_key(secret);
    let mut canonical = Zeroizing::new(Vec::with_capacity(128));
    canonical.extend_from_slice(b"v1");
    canonical.extend_from_slice(&timestamp_unix_ms.to_le_bytes());
    push_len(&mut canonical, idempotency_key.as_bytes());
    push_len(&mut canonical, payload_hash.as_bytes());
    push_len(&mut canonical, endpoint.as_bytes());
    let mut mac = <HmacSha256 as Mac>::new_from_slice(signing_key.as_slice())
        .expect("sha256 hmac accepts any key");
    mac.update(canonical.as_slice());
    let bytes = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    out
}

fn derive_signing_key(secret: &[u8]) -> Zeroizing<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut extract = <HmacSha256 as Mac>::new_from_slice(b"nexus-ephemera-hmac-v1")
        .expect("sha256 hmac accepts any key");
    extract.update(secret);
    let prk_raw = extract.finalize().into_bytes();
    let mut prk = Zeroizing::new([0u8; 32]);
    prk.copy_from_slice(&prk_raw);
    let mut expand =
        <HmacSha256 as Mac>::new_from_slice(prk.as_slice()).expect("sha256 hmac accepts any key");
    expand.update(b"nexus-ephemera-request-signature-v1");
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&okm);
    out
}

fn push_len(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn parse_signature_header(header: &str) -> Result<(u64, Zeroizing<Vec<u8>>), SignatureError> {
    let mut timestamp = None;
    let mut mac_hex = None;
    for part in header.split(',') {
        if let Some(value) = part.strip_prefix("t=") {
            if timestamp.is_some() {
                return Err(SignatureError::Malformed);
            }
            timestamp = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| SignatureError::Malformed)?,
            );
        } else if let Some(value) = part.strip_prefix("v1=") {
            if mac_hex.is_some() {
                return Err(SignatureError::Malformed);
            }
            mac_hex = Some(value);
        } else {
            return Err(SignatureError::Malformed);
        }
    }
    let timestamp = timestamp.ok_or(SignatureError::Missing)?;
    let mac_hex = mac_hex.ok_or(SignatureError::Missing)?;
    let mac = decode_hex(mac_hex)?;
    Ok((timestamp, mac))
}

fn decode_hex(hex: &str) -> Result<Zeroizing<Vec<u8>>, SignatureError> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SignatureError::Malformed);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(32));
    let bytes = hex.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let hi = hex_value(bytes[index])?;
        let lo = hex_value(bytes[index + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, SignatureError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SignatureError::Malformed),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
pub fn seal(plaintext: &[u8]) -> Result<SealedBlob, String> {
    let buf = EphemeralBuffer::from_bytes(plaintext)?;
    seal_plaintext(&buf)
}

#[cfg(test)]
pub fn open(blob: &SealedBlob) -> Result<Zeroizing<Vec<u8>>, String> {
    let plain = open_to_plaintext(blob)?;
    plain.with_sensitive_bytes(|b| Ok(Zeroizing::new(b.to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_session_seal_open() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();
        init_session_for_tests([0x55; KEY_LEN]).expect("init");
        let blob = seal(b"payload").expect("seal");
        let open = open(&blob).expect("open");
        assert_eq!(&*open, b"payload");
    }

    #[test]
    fn seal_and_open_in_place_reject_short_nonce() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();
        init_session_for_tests([0x57; KEY_LEN]).expect("init");
        let plain = EphemeralBuffer::from_bytes(b"locked").expect("plain");
        let sealed = seal_plaintext(&plain).expect("seal");
        let mut bad = sealed.clone();
        bad.nonce_b64 = B64.encode([0x01, 0x02, 0x03]);
        assert!(open_to_plaintext(&bad).is_err());
        let reopened = open_to_plaintext(&sealed).expect("open");
        assert_eq!(
            reopened
                .with_sensitive_bytes(|b| Ok(b.to_vec()))
                .expect("r"),
            b"locked".to_vec()
        );
    }

    #[test]
    fn nonce_error_wipes_destination() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();
        init_session_for_tests([0x58; KEY_LEN]).expect("init");
        let plain = EphemeralBuffer::from_bytes(b"secret-plain").expect("plain");
        let sealed = seal_plaintext(&plain).expect("seal");
        let mut dest = EphemeralBuffer::with_capacity(512).expect("dest");
        dest.fill(b"marker-bytes-before-decrypt").expect("prefill");

        let mut bad = sealed.clone();
        bad.nonce_b64 = B64.encode([0x01, 0x02, 0x03]);

        assert!(open_into(&bad, &dest).is_err());
        let snap = dest.snapshot();
        assert!(
            snap.iter().all(|b| *b == 0),
            "destination must be wiped after nonce error"
        );
    }

    #[test]
    fn hmac_rejects_missing_forged_and_stale_signatures() {
        let secret = Zeroizing::new(b"hmac-canary-secret".to_vec());
        let now = 1_700_000_000_000u64;
        let header = sign_request_header(
            secret.as_slice(),
            now,
            "idem-1",
            "hash-a",
            "https://provider.example/charge",
        );
        assert!(header.starts_with("t="));
        assert!(header.contains(",v1="));
        verify_request_header(
            secret.as_slice(),
            &header,
            "idem-1",
            "hash-a",
            "https://provider.example/charge",
            now,
        )
        .expect("fresh signature");
        assert_eq!(
            verify_request_header(
                secret.as_slice(),
                "",
                "idem-1",
                "hash-a",
                "https://provider.example/charge",
                now,
            ),
            Err(SignatureError::Missing)
        );
        let forged = header.replace("v1=", "v1=00");
        assert_eq!(
            verify_request_header(
                secret.as_slice(),
                &forged,
                "idem-1",
                "hash-a",
                "https://provider.example/charge",
                now,
            ),
            Err(SignatureError::Malformed)
        );
        let mut flipped = header.clone();
        let last = flipped.pop().expect("hex");
        flipped.push(if last == 'a' { 'b' } else { 'a' });
        assert_eq!(
            verify_request_header(
                secret.as_slice(),
                &flipped,
                "idem-1",
                "hash-a",
                "https://provider.example/charge",
                now,
            ),
            Err(SignatureError::Invalid)
        );
        assert_eq!(
            verify_request_header(
                secret.as_slice(),
                &header,
                "idem-1",
                "hash-b",
                "https://provider.example/charge",
                now,
            ),
            Err(SignatureError::Invalid)
        );
        assert_eq!(
            verify_request_header(
                secret.as_slice(),
                &header,
                "idem-1",
                "hash-a",
                "https://provider.example/charge",
                now + SIGNATURE_SKEW_MS + 1,
            ),
            Err(SignatureError::Expired)
        );
        assert!(secret.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn wipe_session_clears_slot() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();
        init_session_for_tests([0x66; KEY_LEN]).expect("init");
        let blob = seal(b"before wipe").expect("seal");
        wipe_session_on_apoptosis().expect("wipe");
        assert!(open_to_plaintext(&blob).is_err());
    }
}
