//! Real daemon processes, real AOF Redis, verified TLS and exact payloads.
//! Explicitly required by the enterprise-redis CI job, not a simulated provider.
use nexus_ephemera::broker::SealReport;
use nexus_ephemera::crypto::verify_request_header;
use nexus_ephemera::enterprise::{ServiceAccount, TenantDirectory};
use nexus_ephemera::enterprise_runtime::{RedisIdempotency, TenantAuthority};
use nexus_ephemera::ipc::{IpcError, NexusClient};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

const KEY: &[u8] = b"public-enterprise-live-fixture";
const BODY: &[u8] = br#"{"params":{"amount":7},"tool":"charge"}"#;

#[tokio::test]
#[ignore = "requires dedicated AOF Redis; mandatory enterprise CI gate"]
async fn enterprise_two_daemons_forward_once_and_enforce_raw_ipc_policy() {
    let redis_url = std::env::var("NEXUS_TEST_REDIS_URL").expect("real Redis URL required");
    let id = uuid::Uuid::new_v4().simple().to_string();
    let directory_path = std::env::temp_dir().join(format!("nx-{}", &id[..12]));
    nexus_ephemera_ipc_os::create_private_directory(&directory_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca_path = directory_path.join("ca.der");
    std::fs::write(&ca_path, certificate.cert.der()).unwrap();
    nexus_ephemera_ipc_os::lock_file_to_current_user(&ca_path).unwrap();
    let private_key = tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    );
    let tls = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], private_key.into())
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}/charge",
        listener.local_addr().unwrap().port()
    );
    let expected_endpoint = endpoint.clone();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let provider = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let mut seen = std::collections::HashSet::new();
        let mut accepted_tx = Some(accepted_tx);
        for index in 0..3 {
            let (stream, _) = tokio::time::timeout(Duration::from_secs(60), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
                assert!(request.len() < 8192);
                if request.ends_with(BODY) {
                    break;
                }
            }
            let boundary = request.windows(4).position(|b| b == b"\r\n\r\n").unwrap();
            assert_eq!(&request[boundary + 4..], BODY);
            let headers = std::str::from_utf8(&request[..boundary]).unwrap();
            assert!(headers.starts_with("POST /charge HTTP/1.1\r\n"));
            let header = |name: &str| {
                headers
                    .lines()
                    .skip(1)
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case(name)
                            .then(|| value.trim().to_owned())
                    })
                    .unwrap()
            };
            let hash = Sha256::digest(BODY)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let scoped_key = header("Idempotency-Key");
            assert_ne!(scoped_key, "business-key");
            assert!(
                seen.insert(scoped_key.clone()),
                "a business key reached the provider twice"
            );
            let now = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap();
            assert!(
                verify_request_header(
                    KEY,
                    &header("X-Nexus-Signature"),
                    &scoped_key,
                    &hash,
                    &expected_endpoint,
                    now
                )
                .is_ok()
            );
            if index == 0 {
                stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
                stream.flush().await.unwrap();
            } else if index == 2 {
                accepted_tx.take().unwrap().send(()).unwrap();
                let mut probe = [0; 1];
                // The broker is killed after acceptance, before it can commit.
                let _ = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut probe))
                    .await
                    .unwrap();
            }
            // Index 1 deliberately drops an accepted request without a response.
        }
    });
    let account = ServiceAccount {
        id: "billing".into(),
        roles: vec!["charge".into()],
        attributes: vec![],
        allowlist: vec![endpoint.clone()],
        role_endpoints: Default::default(),
        role_params: std::collections::BTreeMap::from([("charge".into(), vec!["amount".into()])]),
    };
    let namespace = format!("live-{id}");
    let store = RedisIdempotency::new(&redis_url, &namespace, 32, Duration::from_secs(2)).unwrap();
    store.provision().unwrap();
    let authority = TenantAuthority::new(
        TenantDirectory::try_new(vec![account.clone()]).unwrap(),
        KEY,
    )
    .unwrap();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let token = authority
        .issue_token("billing", "charge", now + 60_000, now)
        .unwrap();
    let mut daemons = Vec::new();
    let mut clients = Vec::new();
    for index in 0..2 {
        #[cfg(unix)]
        let listen = directory_path
            .join(format!("d{index}.sock"))
            .to_string_lossy()
            .into_owned();
        #[cfg(windows)]
        let listen = format!(r"\\.\pipe\nexus-enterprise-{id}-{index}");
        let config_path = directory_path.join(format!("d{index}.json"));
        let config = serde_json::json!({"accounts":[{
            "id":account.id,"roles":account.roles,"attributes":account.attributes,
            "allowlist":account.allowlist,"role_params":account.role_params
        }],"redis_url":redis_url,"namespace":namespace,"capacity":32,
            "checkpoint_path":directory_path.join(format!("anchor{index}.json")),"provider_ca_der":ca_path});
        std::fs::write(&config_path, config.to_string()).unwrap();
        nexus_ephemera_ipc_os::lock_file_to_current_user(&config_path).unwrap();
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_nexus-daemon"))
            .args([
                "--listen",
                &listen,
                "--allow",
                &endpoint,
                "--enterprise-config",
            ])
            .arg(config_path)
            .args(["--timeout-ms", "5000"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(KEY).await.unwrap();
        }
        let mut ready = String::new();
        tokio::time::timeout(
            Duration::from_secs(20),
            tokio::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ready.trim(), "ready");
        clients.push(NexusClient::new(listen, Duration::from_secs(8), 65536).unwrap());
        daemons.push(child);
    }
    let first = clients[0]
        .execute_payload(&endpoint, BODY, "business-key", "billing", &token)
        .await
        .unwrap();
    assert_eq!(first.transport_status, 204);
    assert_eq!(first.seal_report, SealReport::Retained);
    let cached = clients[1]
        .execute_payload(&endpoint, BODY, "business-key", "billing", &token)
        .await
        .unwrap();
    assert_eq!(cached, first);
    assert!(matches!(
        clients[0]
            .execute_payload(&endpoint, BODY, "uncertain-key", "billing", &token)
            .await,
        Err(IpcError::Inconclusive)
    ));
    assert!(matches!(
        clients[1]
            .execute_payload(&endpoint, BODY, "uncertain-key", "billing", &token)
            .await,
        Err(IpcError::Inconclusive)
    ));
    assert!(matches!(
        clients[1]
            .execute_payload(
                &endpoint,
                br#"{"params":{"amount":8},"tool":"charge"}"#,
                "business-key",
                "billing",
                &token
            )
            .await,
        Err(IpcError::IdempotencyConflict)
    ));
    assert!(matches!(
        clients[1]
            .execute_payload(&endpoint, BODY, "forged-account", "foreign", &token)
            .await,
        Err(IpcError::TargetDenied)
    ));
    assert!(matches!(
        clients[1]
            .execute_payload(
                &endpoint,
                br#"{"params":{"amount":7},"tool":"read"}"#,
                "wrong-role",
                "billing",
                &token
            )
            .await,
        Err(IpcError::TargetDenied)
    ));
    assert!(matches!(
        clients[1]
            .execute_payload(
                &endpoint,
                br#"{"params":{"api_key":"canary"},"tool":"charge"}"#,
                "bad-param",
                "billing",
                &token
            )
            .await,
        Err(IpcError::Malformed) | Err(IpcError::TargetDenied)
    ));
    assert!(
        clients[1]
            .execute(&endpoint, "hash-only", "legacy-bypass")
            .await
            .is_err()
    );
    let pending = clients[0].execute_payload(&endpoint, BODY, "crash-key", "billing", &token);
    tokio::pin!(pending);
    tokio::select! {
        result = &mut pending => panic!("provider returned before crash: {result:?}"),
        accepted = tokio::time::timeout(Duration::from_secs(10),accepted_rx) => { accepted.unwrap().unwrap(); }
    }
    daemons[0].kill().await.unwrap();
    assert!(pending.await.is_err());
    assert!(matches!(
        clients[1]
            .execute_payload(&endpoint, BODY, "crash-key", "billing", &token)
            .await,
        Err(IpcError::Inconclusive)
    ));
    provider.await.unwrap();
    for child in &mut daemons {
        if child.try_wait().unwrap().is_none() {
            child.kill().await.unwrap();
        }
        child.wait().await.unwrap();
    }
    authority.close().unwrap();
    let mut connection = redis::Client::open(redis_url)
        .unwrap()
        .get_connection()
        .unwrap();
    let _: usize = redis::cmd("DEL")
        .arg(format!("nexus:enterprise:{{{namespace}}}"))
        .query(&mut connection)
        .unwrap();
    // Deliberately leave only public test fixtures on failure for diagnostics.
    for entry in std::fs::read_dir(&directory_path).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    let _ = std::fs::remove_dir(&directory_path);
}
