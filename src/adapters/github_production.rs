//! Native provider edge. Only the enterprise daemon wires this transport:
//! tenant verification, payload policy, worker admission, durable Redis claim,
//! and pre-dispatch audit precede entry. No search-based automatic retry exists.
#![forbid(unsafe_code)]

use super::github::GithubIssuePolicy;
use crate::apoptosis::EphemeralBuffer;
use crate::broker::{AuthorizedCall, BrokerError, SecureTransport, TransportReply};
use crate::enterprise_runtime::{BoundPayload, HttpPayloadTransport, Parameter};
use crate::ipc::IpcError;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct GithubTransport {
    http: HttpPayloadTransport,
    policy: GithubIssuePolicy,
    token: EphemeralBuffer,
    #[cfg(test)]
    test_endpoint: Option<String>,
}

impl GithubTransport {
    pub fn new(
        http: HttpPayloadTransport,
        policy: GithubIssuePolicy,
        token: &mut [u8],
    ) -> Result<Self, IpcError> {
        use zeroize::Zeroize;
        let result = (|| {
            nexus_ephemera_memlock::harden_process_memory().map_err(|_| IpcError::TargetDenied)?;
            if token.is_empty()
                || token.len() > 256
                || !token.iter().all(u8::is_ascii_graphic)
                || token.windows(7).any(|part| part == b"Bearer ")
            {
                return Err(IpcError::Malformed);
            }
            Ok(Self {
                http,
                policy,
                token: EphemeralBuffer::from_bytes(&*token).map_err(|_| IpcError::TargetDenied)?,
                #[cfg(test)]
                test_endpoint: None,
            })
        })();
        token.zeroize();
        result
    }
}

impl SecureTransport for GithubTransport {
    fn dispatch(&mut self, _: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        Err(BrokerError::Transport(
            "GitHub requires enterprise bound payload",
        ))
    }

    fn dispatch_payload(
        &mut self,
        call: &AuthorizedCall<'_>,
        payload: &[u8],
    ) -> Result<TransportReply, BrokerError> {
        // This native edge has a strict HTTP deadline and no application
        // callback. Keep its lifecycle admission through I/O and response
        // validation so Complete cannot precede an outstanding native request.
        let _lifecycle = crate::apoptosis::acquire_permit()
            .map_err(|_| BrokerError::Transport("provider lifecycle closed"))?;
        self.policy
            .authorize_target(call.target_endpoint)
            .map_err(|_| BrokerError::Transport("provider target denied"))?;
        let hash: String = Sha256::digest(payload)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if call.payload_hash != hash {
            return Err(BrokerError::Transport("provider payload mismatch"));
        }
        let bound: BoundPayload = serde_json::from_slice(payload)
            .map_err(|_| BrokerError::Transport("provider schema denied"))?;
        if !matches!(&bound.tool, Parameter::Text(role) if role.as_str() == "support_agent")
            || bound.params.0.len() != 2
        {
            return Err(BrokerError::Transport("provider schema denied"));
        }
        let title = match bound.params.0.get("title") {
            Some(Parameter::Text(value)) if !value.is_empty() => value,
            _ => return Err(BrokerError::Transport("provider title denied")),
        };
        let body = match bound.params.0.get("body") {
            Some(Parameter::Text(value)) => value,
            _ => return Err(BrokerError::Transport("provider body denied")),
        };
        #[derive(serde::Serialize)]
        struct Issue<'a> {
            title: &'a str,
            body: &'a str,
        }
        let mut encoded = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *encoded, &Issue { title, body })
            .map_err(|_| BrokerError::Transport("provider encoding failed"))?;
        let client = self.http.client()?;
        #[cfg(test)]
        let destination = self
            .test_endpoint
            .as_deref()
            .unwrap_or(call.target_endpoint);
        #[cfg(not(test))]
        let destination = call.target_endpoint;
        // Copy into the HTTP stack only at the provider boundary. The HTTP/TLS
        // stack is outside the locked-memory guarantee; no token reaches IPC.
        let request = self
            .token
            .with_sensitive_bytes(|token| {
                let mut authorization = Zeroizing::new(String::from("Bearer "));
                authorization.push_str(
                    std::str::from_utf8(token).map_err(|_| "invalid credential".to_string())?,
                );
                client
                    .post(destination)
                    .header("Authorization", authorization.as_str())
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header("User-Agent", "nexus-ephemera")
                    .header("Content-Type", "application/json")
                    .body(encoded.to_vec())
                    .build()
                    .map_err(|_| "provider request unavailable".to_string())
            })
            .map_err(|_| BrokerError::Transport("provider credential unavailable"))?;
        let mut response = client
            .execute(request)
            .map_err(|_| BrokerError::Inconclusive)?;
        // Even a 5xx may follow an accepted write. The durable claim must never
        // be converted into a new POST based on response/search uncertainty.
        if response.status().as_u16() != 201 {
            return Err(BrokerError::Inconclusive);
        }
        use std::io::Read;
        let mut reply = Zeroizing::new(Vec::new());
        response
            .by_ref()
            .take(65537)
            .read_to_end(&mut reply)
            .map_err(|_| BrokerError::Inconclusive)?;
        if reply.len() > 65536 {
            return Err(BrokerError::Inconclusive);
        }
        #[derive(serde::Deserialize)]
        struct CreatedIssue {
            id: u64,
            number: u64,
        }
        let created: CreatedIssue =
            serde_json::from_slice(&reply).map_err(|_| BrokerError::Inconclusive)?;
        if created.id == 0 || created.number == 0 {
            return Err(BrokerError::Inconclusive);
        }
        Ok(TransportReply { status: 201 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn verified_tls_native_provider_acceptance_and_lost_ack_are_not_retried() {
        let _guard = crate::apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        let http = HttpPayloadTransport::new(Duration::from_secs(2)).unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let http = http.with_ca_der(certificate.cert.der()).unwrap();
        let key = tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
            certificate.signing_key.serialize_der(),
        );
        let tls = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], key.into())
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
                let mut creates = 0;
                for lost_ack in [false, true] {
                    let (socket, _) = tokio::time::timeout(Duration::from_secs(8), listener.accept()).await.unwrap().unwrap();
                    let mut stream = acceptor.accept(socket).await.unwrap();
                    let mut bytes = Vec::new();
                    loop {
                        let mut part = [0; 1024];
                        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut part)).await.unwrap().unwrap();
                        assert!(n > 0);
                        bytes.extend_from_slice(&part[..n]);
                        assert!(bytes.len() < 8192);
                        if bytes.ends_with(br#"{"title":"fixture","body":"fixture"}"#) { break; }
                    }
                    let text = std::str::from_utf8(&bytes).unwrap().to_ascii_lowercase();
                    assert!(text.starts_with("post /issues http/1.1"));
                    assert!(text.contains("authorization: bearer public-fixture"));
                    creates += 1;
                    if lost_ack {
                        accepted_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    if !lost_ack {
                        let body = br#"{"id":42,"number":7}"#;
                        let header = format!("HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        stream.write_all(header.as_bytes()).await.unwrap();
                        stream.write_all(body).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                }
                creates
            })
        });
        let policy =
            GithubIssuePolicy::load(include_bytes!("../../policies/pilot_support_agent.json"))
                .unwrap();
        let endpoint = policy.endpoint().to_string();
        let mut transport =
            GithubTransport::new(http, policy, &mut b"public-fixture".to_vec()).unwrap();
        transport.test_endpoint = Some(format!("https://localhost:{port}/issues"));
        let payload = br#"{"tool":"support_agent","params":{"title":"fixture","body":"fixture"}}"#;
        let hash: String = Sha256::digest(payload)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let call = AuthorizedCall {
            target_endpoint: &endpoint,
            payload_hash: &hash,
            binding_digest_hex: "fixture",
            call_nonce: 1,
            issued_at_unix_ms: 1,
            idempotency_key: "fixture",
            nexus_signature: "fixture",
        };
        assert_eq!(
            transport.dispatch_payload(&call, payload).unwrap().status,
            201
        );
        let pending = std::thread::spawn(move || {
            let call = AuthorizedCall {
                target_endpoint: &endpoint,
                payload_hash: &hash,
                binding_digest_hex: "fixture",
                call_nonce: 2,
                issued_at_unix_ms: 1,
                idempotency_key: "lost-ack",
                nexus_signature: "fixture",
            };
            transport.dispatch_payload(&call, payload)
        });
        accepted_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        crate::apoptosis::request_apoptosis().unwrap();
        assert!(
            crate::apoptosis::wait_apoptosis_complete(Duration::from_millis(20)).is_err(),
            "wipe must not complete while native provider I/O is outstanding"
        );
        release_tx.send(()).unwrap();
        assert!(matches!(
            pending.join().unwrap(),
            Err(BrokerError::Inconclusive)
        ));
        assert_eq!(
            crate::apoptosis::wait_apoptosis_complete(Duration::from_secs(5)).unwrap(),
            crate::apoptosis::WipeStatus::Complete
        );
        assert_eq!(
            worker.join().unwrap(),
            2,
            "each admitted invocation sends one POST only"
        );
    }
}
