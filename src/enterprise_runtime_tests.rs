use super::*;

#[test]
fn server_role_payload_and_closed_authority_are_enforced() {
    let _guard = crate::apoptosis::test_serial();
    crate::apoptosis::reset_coordinator_for_tests();
    let endpoint = "https://provider.example/charge";
    let directory = TenantDirectory::try_new(vec![crate::enterprise::ServiceAccount {
        id: "billing".into(),
        roles: vec!["charge".into()],
        attributes: vec![],
        allowlist: vec![endpoint.into()],
        role_endpoints: Default::default(),
        role_params: std::collections::BTreeMap::from([("charge".into(), vec!["amount".into()])]),
    }])
    .unwrap();
    let authority = TenantAuthority::new(directory, b"public-fixture").unwrap();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let proof = TenantCredential {
        account: "billing".into(),
        token: authority
            .issue_token("billing", "charge", now + 60_000, now)
            .unwrap(),
    };
    assert!(
        authority
            .verify(
                &proof,
                endpoint,
                br#"{"tool":"charge","params":{"amount":7}}"#
            )
            .is_ok()
    );
    for payload in [
        br#"{"tool":"read","params":{"amount":7}}"#.as_slice(),
        br#"{"tool":"charge","params":{"amount":7,"amount":8}}"#.as_slice(),
        br#"{"tool":"charge","params":{"api_key":"canary"}}"#.as_slice(),
        br#"{"tool":"charge","params":{"url":"https://foreign.example"}}"#.as_slice(),
        br#"{"tool":"charge","params":{"amount":{"nested":7}}}"#.as_slice(),
    ] {
        assert!(authority.verify(&proof, endpoint, payload).is_err());
    }
    authority.close().unwrap();
    assert!(
        authority
            .verify(
                &proof,
                endpoint,
                br#"{"tool":"charge","params":{"amount":7}}"#
            )
            .is_err()
    );
}

fn fixture_call(key: &str) -> VerifiedCall {
    VerifiedCall {
        account: "fixture".into(),
        endpoint: "https://provider.example/charge".into(),
        hash: hex(&Sha256::digest(b"fixture")),
        original_key: key.into(),
        store_id: digest_parts(&["fixture", key]),
        fingerprint: digest_parts(&["fixture", "payload"]),
        payload: Zeroizing::new(b"fixture".to_vec()),
    }
}

fn redis_fixture(namespace: &str, capacity: usize) -> RedisIdempotency {
    RedisIdempotency::new(
        &std::env::var("NEXUS_TEST_REDIS_URL").expect("real Redis URL required"),
        namespace,
        capacity,
        Duration::from_secs(2),
    )
    .unwrap()
}

#[test]
#[ignore = "CI restart protocol: seed before actual Redis restart"]
fn restart_seed_committed_receipt() {
    let namespace =
        std::env::var("NEXUS_TEST_RESTART_NAMESPACE").expect("dedicated restart namespace");
    let store = redis_fixture(&namespace, 2);
    store.provision().unwrap();
    let call = fixture_call("restart");
    let Claim::Leader(fence) = store.claim(&call).unwrap() else {
        panic!("leader")
    };
    store
        .finish(
            &call,
            &fence,
            Some(&TransactionReceipt {
                target_endpoint: call.endpoint.clone(),
                payload_hash: call.hash.clone(),
                binding_digest_hex: "ab".repeat(32),
                transport_status: 204,
                seal_report: SealReport::Retained,
                idempotency_key: call.store_id.clone(),
            }),
        )
        .unwrap();
}

#[test]
#[ignore = "CI restart protocol: verify after actual Redis restart"]
fn restart_verify_committed_receipt() {
    let namespace =
        std::env::var("NEXUS_TEST_RESTART_NAMESPACE").expect("dedicated restart namespace");
    let store = redis_fixture(&namespace, 2);
    store.health().unwrap();
    let Claim::Cached(receipt) = store.claim(&fixture_call("restart")).unwrap() else {
        panic!("AOF receipt lost")
    };
    assert_eq!(receipt.transport_status, 204);
    assert_eq!(receipt.seal_report, SealReport::Retained);
}

/// Mandatory in the Linux enterprise-redis CI job. Each contender is a real
/// process; the winner deliberately exits without committing its claim.
#[test]
#[ignore = "requires dedicated Redis with AOF always/noeviction"]
fn redis_multiprocess_claim_and_crash_remain_inconclusive() {
    const NAME: &str =
        "enterprise_runtime::tests::redis_multiprocess_claim_and_crash_remain_inconclusive";
    if let Ok(namespace) = std::env::var("NEXUS_TEST_CHILD_NAMESPACE") {
        let store = redis_fixture(&namespace, 8);
        match store.claim(&fixture_call("crash-key")) {
            Ok(Claim::Leader(_)) => {
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(std::env::var_os("NEXUS_TEST_WINNER").unwrap())
                    .unwrap();
                std::process::exit(0);
            }
            Err(IpcError::Inconclusive) => return,
            _ => panic!("unexpected claim outcome"),
        }
    }
    let namespace = format!("test-{}", uuid::Uuid::new_v4());
    let store = redis_fixture(&namespace, 8);
    store.provision().unwrap();
    let winner = std::env::temp_dir().join(format!("nexus-winner-{}", uuid::Uuid::new_v4()));
    let mut children = (0..8)
        .map(|_| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--ignored", "--nocapture"])
                .env("NEXUS_TEST_CHILD_NAMESPACE", &namespace)
                .env("NEXUS_TEST_WINNER", &winner)
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    assert!(
        winner.is_file(),
        "one and only one process acquired leadership"
    );
    assert!(matches!(
        redis_fixture(&namespace, 8).claim(&fixture_call("crash-key")),
        Err(IpcError::Inconclusive)
    ));
    std::fs::remove_file(winner).unwrap();
    let mut connection = store.connection().unwrap();
    let _: usize = redis::cmd("DEL")
        .arg(&store.key)
        .query(&mut connection)
        .unwrap();
    assert!(store.health().is_err());
    assert!(matches!(
        store.claim(&fixture_call("new-key")),
        Err(IpcError::IdempotencyUnavailable)
    ));
}

#[test]
#[ignore = "requires dedicated Redis with AOF always/noeviction"]
fn redis_fencing_cache_partial_conflict_capacity_and_quarantine() {
    let namespace = format!("test-{}", uuid::Uuid::new_v4());
    let store = redis_fixture(&namespace, 2);
    store.provision().unwrap();
    assert!(store.provision().is_err());
    let call = fixture_call("one");
    let Claim::Leader(fence) = store.claim(&call).unwrap() else {
        panic!("leader")
    };
    let receipt = TransactionReceipt {
        target_endpoint: call.endpoint.clone(),
        payload_hash: call.hash.clone(),
        binding_digest_hex: "ab".repeat(32),
        transport_status: 204,
        seal_report: SealReport::Partial,
        idempotency_key: call.store_id.clone(),
    };
    assert!(store.finish(&call, "wrong-fence", Some(&receipt)).is_err());
    store.finish(&call, &fence, Some(&receipt)).unwrap();
    let Claim::Cached(cached) = redis_fixture(&namespace, 2).claim(&call).unwrap() else {
        panic!("cached")
    };
    assert_eq!(cached, receipt);
    let mut conflict = fixture_call("one");
    conflict.fingerprint = "different".into();
    assert!(matches!(
        store.claim(&conflict),
        Err(IpcError::IdempotencyConflict)
    ));
    let second = fixture_call("two");
    let Claim::Leader(fence) = store.claim(&second).unwrap() else {
        panic!("leader")
    };
    store.finish(&second, &fence, None).unwrap();
    assert!(matches!(store.claim(&second), Err(IpcError::Inconclusive)));
    assert!(matches!(
        store.claim(&fixture_call("three")),
        Err(IpcError::IdempotencyUnavailable)
    ));
    store.quarantine_for_rotation().unwrap();
    assert!(store.claim(&call).is_err());
    let mut connection = store.connection().unwrap();
    let _: usize = redis::cmd("DEL")
        .arg(&store.key)
        .query(&mut connection)
        .unwrap();
}

#[test]
#[ignore = "requires dedicated Redis with AOF always/noeviction"]
fn redis_completion_audit_failure_is_cached_partial_and_closes_admission() {
    let _guard = crate::apoptosis::test_serial();
    crate::apoptosis::reset_coordinator_for_tests();
    struct Sink(bool);
    impl CheckpointSink for Sink {
        fn store(&self, checkpoint: &AuditCheckpoint, _: &str) -> Result<(), IpcError> {
            if self.0 && checkpoint.records == 2 {
                Err(IpcError::Protocol("injected checkpoint failure"))
            } else {
                Ok(())
            }
        }
    }
    let namespace = format!("test-{}", uuid::Uuid::new_v4());
    let store = Arc::new(redis_fixture(&namespace, 8));
    store.provision().unwrap();
    let endpoint = "https://provider.example/charge";
    let directory = TenantDirectory::try_new(vec![crate::enterprise::ServiceAccount {
        id: "billing".into(),
        roles: vec!["charge".into()],
        attributes: vec![],
        allowlist: vec![endpoint.into()],
        role_endpoints: Default::default(),
        role_params: std::collections::BTreeMap::from([("charge".into(), vec!["amount".into()])]),
    }])
    .unwrap();
    let authority = TenantAuthority::new(directory.clone(), b"public-fixture").unwrap();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let proof = TenantCredential {
        account: "billing".into(),
        token: authority
            .issue_token("billing", "charge", now + 60_000, now)
            .unwrap(),
    };
    let admission = Arc::new(
        EnterpriseAdmission::new(authority, Arc::clone(&store), Arc::new(Sink(true))).unwrap(),
    );
    let body = br#"{"tool":"charge","params":{"amount":7}}"#;
    let hash = hex(&Sha256::digest(body));
    let Admission::Execute(operation) = admission
        .begin(&proof, endpoint, body, &hash, "key")
        .unwrap()
    else {
        panic!("execute")
    };
    let receipt = TransactionReceipt {
        target_endpoint: endpoint.into(),
        payload_hash: hash.clone(),
        binding_digest_hex: "ab".repeat(32),
        transport_status: 204,
        seal_report: SealReport::Retained,
        idempotency_key: operation.provider_key().into(),
    };
    assert!(
        matches!(operation.finish(Ok(receipt)),Err(IpcError::CleanupIncomplete(receipt)) if receipt.seal_report==SealReport::Partial)
    );
    assert!(matches!(
        admission.begin(&proof, endpoint, body, &hash, "other"),
        Err(IpcError::TargetDenied)
    ));
    let standby = Arc::new(
        EnterpriseAdmission::new(
            TenantAuthority::new(directory, b"public-fixture").unwrap(),
            Arc::clone(&store),
            Arc::new(Sink(false)),
        )
        .unwrap(),
    );
    assert!(
        matches!(standby.begin(&proof,endpoint,body,&hash,"key"),Err(IpcError::CleanupIncomplete(receipt)) if receipt.seal_report==SealReport::Partial)
    );
    let mut connection = store.connection().unwrap();
    let _: usize = redis::cmd("DEL")
        .arg(&store.key)
        .query(&mut connection)
        .unwrap();
}

#[test]
fn https_transport_sends_exact_body_and_preserves_real_failure_status() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = certificate.cert.der().to_vec();
    let key = tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    );
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let (socket,_) = tokio::time::timeout(Duration::from_secs(5),listener.accept()).await.unwrap().unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(socket).await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0;1024];
                let n = tokio::time::timeout(Duration::from_secs(5),tls.read(&mut chunk)).await.unwrap().unwrap();
                assert!(n>0); bytes.extend_from_slice(&chunk[..n]);
                assert!(bytes.len()<=8192);
                if bytes.ends_with(b"{\"amount\":7}") { break; }
            }
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.starts_with("POST /charge HTTP/1.1\r\n"));
            assert!(text.to_ascii_lowercase().contains("idempotency-key: scoped-key\r\n"));
            tls.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            tls.flush().await.unwrap();
        });
    });
    let endpoint = format!("https://localhost:{port}/charge");
    let payload = b"{\"amount\":7}";
    let hash = hex(&Sha256::digest(payload));
    let call = AuthorizedCall {
        target_endpoint: &endpoint,
        payload_hash: &hash,
        binding_digest_hex: "fixture",
        call_nonce: 1,
        issued_at_unix_ms: 1,
        idempotency_key: "scoped-key",
        nexus_signature: "public-fixture",
    };
    let mut transport = HttpPayloadTransport::new(Duration::from_secs(3))
        .unwrap()
        .with_ca_der(&der)
        .unwrap();
    assert!(transport.dispatch(&call).is_err());
    assert!(transport.dispatch_payload(&call, b"tampered").is_err());
    assert_eq!(
        transport.dispatch_payload(&call, payload).unwrap().status,
        503
    );
    worker.join().unwrap();
}
