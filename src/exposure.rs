//! Veri maruz kalma etiketleri ve log redaksiyonu.
//!
//! # Tehdit sınırı (Sensitive-Memory Lifecycle Protection)
//! `NoPlaintextExport` düz metni `String` / `Vec<u8>` olarak dışarı vermez.
//! `LocalOnly` sağlayıcı çağrısına çıkmaz. `ProviderBound` yalnızca bağlı
//! uç noktaya gider. Log süzgeci sır görürse satırı `[REDACTED]` yapar.
//! Redaksiyon kilitli dilimleri ödünç alır; hata yolunda sır içeren ara
//! `String` oluşturulmaz. Eşleşme yalnızca UTF-8 karakter sınırında yapılır.
//! Cold boot, DMA ve fiziksel DRAM kapsam dışıdır.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::SystemTime;

use zeroize::Zeroizing;

use crate::apoptosis::EphemeralBuffer;

/// `Vec<u8>` ve `String` düz metin ihraç edebilir. Kasadaki tipler etmez.
pub trait ExportBoundary {
    const ALLOWS_PLAINTEXT_EXPORT: bool;
}

impl ExportBoundary for Vec<u8> {
    const ALLOWS_PLAINTEXT_EXPORT: bool = true;
}

impl ExportBoundary for String {
    const ALLOWS_PLAINTEXT_EXPORT: bool = true;
}

/// Düz metin ihraç etmeyen kilitli kayıt. `Display` ve `Debug` sır taşımaz.
pub struct NoPlaintextExport {
    buf: EphemeralBuffer,
}

impl ExportBoundary for NoPlaintextExport {
    const ALLOWS_PLAINTEXT_EXPORT: bool = false;
}

impl NoPlaintextExport {
    pub fn admit(bytes: &[u8]) -> Result<Self, ExposureError> {
        if bytes.is_empty() {
            return Err(ExposureError::EmptySecret);
        }
        let buf = EphemeralBuffer::from_bytes(bytes).map_err(ExposureError::Memlock)?;
        Ok(Self { buf })
    }

    /// Kilitli yükün uzunluğu. Baytların kendisi dönmez.
    pub fn sealed_len(&self) -> usize {
        self.buf.len()
    }
}

impl fmt::Display for NoPlaintextExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Debug for NoPlaintextExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoPlaintextExport([REDACTED])")
    }
}

/// Sağlayıcıya çıkıp çıkmayacağının etiketi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    LocalOnly,
    ProviderBound {
        endpoint: String,
    },
    /// Yalnızca listelenen uçlar. Eşleşme tam metindir; önek kabul edilmez.
    Allowlist {
        endpoints: Vec<String>,
    },
}

/// Tek kullanımlık, süreli ve hedef kısıtı birlikte tutulur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureTags {
    pub scope: Scope,
    pub no_plaintext_export: bool,
    pub single_use: bool,
    pub expires_at: Option<SystemTime>,
}

impl ExposureTags {
    pub fn provider_bound(
        endpoint: impl Into<String>,
        single_use: bool,
        expires_at: Option<SystemTime>,
    ) -> Result<Self, ExposureError> {
        let endpoint = endpoint.into();
        if endpoint.is_empty() {
            return Err(ExposureError::EmptyEndpoint);
        }
        Ok(Self {
            scope: Scope::ProviderBound { endpoint },
            no_plaintext_export: true,
            single_use,
            expires_at,
        })
    }

    pub fn local_only(expires_at: Option<SystemTime>) -> Self {
        Self {
            scope: Scope::LocalOnly,
            no_plaintext_export: true,
            single_use: false,
            expires_at,
        }
    }

    pub fn allowlist(
        endpoints: impl IntoIterator<Item = impl Into<String>>,
        single_use: bool,
        expires_at: Option<SystemTime>,
    ) -> Result<Self, ExposureError> {
        let endpoints: Vec<String> = endpoints.into_iter().map(Into::into).collect();
        if endpoints.is_empty() || endpoints.iter().any(|endpoint| endpoint.is_empty()) {
            return Err(ExposureError::EmptyEndpoint);
        }
        Ok(Self {
            scope: Scope::Allowlist { endpoints },
            no_plaintext_export: true,
            single_use,
            expires_at,
        })
    }

    pub(crate) fn validate_for_broker(&self) -> Result<(), ExposureError> {
        if !self.no_plaintext_export {
            return Err(ExposureError::PlaintextExportForbidden);
        }
        if let Scope::ProviderBound { endpoint } = &self.scope
            && endpoint.is_empty()
        {
            return Err(ExposureError::EmptyEndpoint);
        }
        if let Scope::Allowlist { endpoints } = &self.scope
            && (endpoints.is_empty() || endpoints.iter().any(|endpoint| endpoint.is_empty()))
        {
            return Err(ExposureError::EmptyEndpoint);
        }
        Ok(())
    }
}

/// Kayıtlı sırları log satırından `[REDACTED]` ile değiştirir.
pub struct LogSanitizer {
    secrets: Vec<EphemeralBuffer>,
}

impl LogSanitizer {
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
        }
    }

    pub fn register(&mut self, secret: &[u8]) -> Result<(), ExposureError> {
        if secret.is_empty() {
            return Err(ExposureError::EmptySecret);
        }
        let buf = EphemeralBuffer::from_bytes(secret).map_err(ExposureError::Memlock)?;
        self.secrets.push(buf);
        Ok(())
    }

    pub fn sanitize(&self, line: &str) -> Result<String, ExposureError> {
        if self.secrets.is_empty() {
            return Ok(line.to_string());
        }
        // İzin, herhangi bir satır kopyasından önce alınır. Reddedilirse heap'e sır yazılmaz.
        let _permit =
            crate::apoptosis::acquire_operation_permit().map_err(ExposureError::Memlock)?;
        let mut guards = Vec::with_capacity(self.secrets.len());
        for secret in &self.secrets {
            guards.push(secret.lock_sensitive().map_err(ExposureError::Memlock)?);
        }
        let needles: Vec<&[u8]> = guards.iter().map(|guard| guard.bytes()).collect();
        Ok(redact_all(line, &needles))
    }

    pub fn wipe(&mut self) -> usize {
        let mut failed = 0;
        for secret in &self.secrets {
            if secret.try_wipe().is_err() {
                failed += 1;
            }
        }
        self.secrets.clear();
        failed
    }
}

impl Default for LogSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LogSanitizer {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn redact_all(haystack: &str, needles: &[&[u8]]) -> String {
    let mut out = Zeroizing::new(String::with_capacity(haystack.len()));
    let bytes = haystack.as_bytes();
    let mut index = 0;
    for (start, ch) in haystack.char_indices() {
        if start < index {
            continue;
        }
        let mut matched_end = None;
        for needle in needles {
            if needle.is_empty() {
                continue;
            }
            let end = start.saturating_add(needle.len());
            let hits = end <= bytes.len()
                && haystack.is_char_boundary(end)
                && &bytes[start..end] == *needle;
            if hits {
                matched_end = Some(matched_end.map_or(end, |prev: usize| prev.max(end)));
            }
        }
        if let Some(end) = matched_end {
            out.push_str("[REDACTED]");
            index = end;
            continue;
        }
        out.push(ch);
        index = start + ch.len_utf8();
    }
    std::mem::take(&mut *out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposureError {
    EmptySecret,
    EmptyEndpoint,
    PlaintextExportForbidden,
    WipeFailed,
    Memlock(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apoptosis;

    /// Tehdit: `println!` veya `Debug` düz metin sır döker.
    /// Sınır: `NoPlaintextExport` ihraç bayrağı kapalıdır ve görüntü `[REDACTED]`'dir.
    #[test]
    fn no_plaintext_export_does_not_render_secret() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let canary = "sk-export-canary-77";
        let secret = NoPlaintextExport::admit(canary.as_bytes()).expect("admit");
        const {
            assert!(!NoPlaintextExport::ALLOWS_PLAINTEXT_EXPORT);
            assert!(Vec::<u8>::ALLOWS_PLAINTEXT_EXPORT);
            assert!(String::ALLOWS_PLAINTEXT_EXPORT);
        }
        let rendered = format!("{secret} {secret:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(canary));
        assert_eq!(secret.sealed_len(), canary.len());
    }

    /// Tehdit: hata ve telemetry satırı API anahtarını olduğu gibi yazar.
    #[test]
    fn sanitizer_masks_registered_secret() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut filter = LogSanitizer::new();
        filter.register(b"sk-log-canary").expect("register");
        let clean = filter
            .sanitize("authorization=sk-log-canary; retry sk-log-canary")
            .expect("sanitize");
        assert_eq!(clean, "authorization=[REDACTED]; retry [REDACTED]");
        assert!(!clean.contains("sk-log-canary"));
        filter.wipe();
        let after = filter
            .sanitize("authorization=sk-log-canary")
            .expect("after");
        assert!(after.contains("sk-log-canary"));
    }

    /// Tehdit: çok baytlı karakterin içindeki bayt iğnesi dilim paniği veya sahte eşleşme üretir.
    #[test]
    fn sanitizer_ignores_needle_inside_multibyte_char() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut filter = LogSanitizer::new();
        filter.register(&[0x82]).expect("register");
        let line = "price € ok";
        let clean = filter.sanitize(line).expect("sanitize");
        assert_eq!(clean, line);

        filter.register("€".as_bytes()).expect("euro");
        let redacted = filter.sanitize(line).expect("euro redact");
        assert_eq!(redacted, "price [REDACTED] ok");
        assert!(!redacted.contains('€'));
    }

    /// Tehdit: permit reddinde satır kopyası `String::drop` ile sır bırakır.
    /// Sınır: hata, kopyadan önce döner ve redakte edilmemiş sonuç üretmez.
    #[test]
    fn sanitize_denial_returns_before_copying_the_line() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut filter = LogSanitizer::new();
        filter.register(b"sk-error-path").expect("register");
        apoptosis::trigger_apoptosis().expect("apoptosis");
        let err = filter.sanitize("token=sk-error-path").expect_err("denied");
        assert!(matches!(err, ExposureError::Memlock(_)));
        assert!(!format!("{err:?}").contains("sk-error-path"));
    }
}
