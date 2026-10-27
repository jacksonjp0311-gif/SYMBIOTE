//! Explicitly configured TLS 1.3 mutual-certificate sessions for agent API v2.
//!
//! The original loopback protocol remains independent and unchanged. This module
//! uses Rustls certificate/path/signature validation; there is no accept-all
//! verifier, custom TLS implementation, system-root discovery or plaintext
//! fallback. Pins bind authenticated certificate bytes to configured agent IDs.
//! Successful transport authentication does not establish knowledge truth.

use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const SECURE_PROTOCOL_VERSION: &str = "symbiote/2";
const ALPN: &[u8] = b"symbiote/2";
const MAX_FRAME: usize = 65_536;
const MAX_PEM_BYTES: usize = 65_536;
const MAX_KEY_BYTES: usize = 16_384;
const MAX_REQUESTS: u64 = 10_000;
const REVOKE_OPERATION: &str = "_session_revoke";

/// An OS-random 256-bit bearer capability, suitable for separate local process
/// channels. No capability is generated from clock time, PID or a fixed seed.
pub fn fresh_capability() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| "OS random source unavailable".to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Parsed credentials. Debug redacts private material; keys are never serialized.
pub struct TlsIdentity {
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    fingerprint: String,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsIdentity")
            .field("certificate_sha256", &self.fingerprint)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl TlsIdentity {
    pub fn from_pem(certificates: &[u8], private_key: &[u8]) -> Result<Self, String> {
        let certificates = parse_certificates(certificates)?;
        if private_key.is_empty() || private_key.len() > MAX_KEY_BYTES {
            return Err("private-key PEM exceeds its byte limit or is empty".into());
        }
        let mut key = None;
        for (kind, der) in parse_pem_sections(private_key)? {
            let candidate = PrivateKeyDer::from_pem(kind, der)
                .ok_or("private-key file contains an unsupported PEM section")?;
            if key.replace(candidate).is_some() {
                return Err("private-key file must contain exactly one key".into());
            }
        }
        let key = key.ok_or("private-key PEM contains no key")?;
        Ok(Self {
            fingerprint: fingerprint(&certificates[0]),
            certificates,
            key,
        })
    }

    pub fn from_pem_files(certificates: &Path, private_key: &Path) -> Result<Self, String> {
        Self::from_pem(
            &read_bounded_file(certificates, MAX_PEM_BYTES)?,
            &read_bounded_file(private_key, MAX_KEY_BYTES)?,
        )
    }

    pub fn certificate_sha256(&self) -> &str {
        &self.fingerprint
    }
}

#[derive(Clone, Debug)]
pub struct SecureLimits {
    /// Server-wide application request budget; reconnecting cannot reset it.
    pub max_requests: u64,
    /// Server-wide accepted-connection budget, including failed/unauthenticated
    /// TLS handshakes. Client-side copies do not override the server's limit.
    pub max_connections: u64,
    /// Includes the terminating newline, on both incoming and outgoing frames.
    pub max_frame_bytes: usize,
    /// Absolute deadline for each handshake, frame read and frame write.
    pub timeout: Duration,
}

impl Default for SecureLimits {
    fn default() -> Self {
        Self {
            max_requests: 256,
            max_connections: 64,
            max_frame_bytes: 16_384,
            timeout: Duration::from_secs(2),
        }
    }
}

impl SecureLimits {
    fn validate(&self) -> Result<(), String> {
        if self.max_requests == 0 || self.max_requests > MAX_REQUESTS {
            return Err("secure request budget must be in 1..=10000".into());
        }
        if self.max_connections == 0 || self.max_connections > MAX_REQUESTS {
            return Err("secure connection budget must be in 1..=10000".into());
        }
        if !(1024..=MAX_FRAME).contains(&self.max_frame_bytes) {
            return Err("secure frame budget must be in 1024..=65536".into());
        }
        if self.timeout < Duration::from_millis(1) || self.timeout > Duration::from_secs(30) {
            return Err("secure deadline must be between 1ms and 30s".into());
        }
        Ok(())
    }
}

/// A certificate pin grants explicit operations separately for each scope.
/// Identity text supplied by a peer cannot expand this operator-owned mapping.
#[derive(Clone, Debug)]
pub struct SecurePeerGrant {
    pub id: String,
    pub certificate_sha256: String,
    pub scopes: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct SecureEndpoint {
    pub server_id: String,
    pub address: SocketAddr,
    /// DNS name or IP SAN checked by Rustls against the server certificate.
    pub server_name: String,
    pub server_certificate_sha256: String,
    pub scope: String,
    pub operations: Vec<String>,
    pub limits: SecureLimits,
}

#[derive(Clone)]
pub struct TlsClientConfig {
    client_id: String,
    tls: Arc<rustls::ClientConfig>,
}

impl TlsClientConfig {
    pub fn new(
        client_id: String,
        identity: TlsIdentity,
        server_ca_pem: &[u8],
    ) -> Result<Self, String> {
        validate_label(&client_id)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "TLS 1.3 unavailable")?
            .with_root_certificates(root_store(server_ca_pem)?)
            .with_client_auth_cert(identity.certificates, identity.key)
            .map_err(|_| "invalid client certificate/key configuration")?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.enable_early_data = false;
        tls.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            client_id,
            tls: Arc::new(tls),
        })
    }
}

pub struct SecureServerConfig {
    bind_address: SocketAddr,
    server_id: String,
    fingerprint: String,
    tls: Arc<rustls::ServerConfig>,
    grants: BTreeMap<String, SecurePeerGrant>,
    limits: SecureLimits,
}

impl SecureServerConfig {
    pub fn new(
        bind_address: SocketAddr,
        server_id: String,
        identity: TlsIdentity,
        client_ca_pem: &[u8],
        grants: Vec<SecurePeerGrant>,
        limits: SecureLimits,
    ) -> Result<Self, String> {
        validate_label(&server_id)?;
        limits.validate()?;
        if bind_address.ip().is_multicast() || grants.is_empty() || grants.len() > 128 {
            return Err("invalid explicit bind address or peer-grant count".into());
        }
        let mut by_pin = BTreeMap::new();
        let mut identities = BTreeSet::new();
        for mut grant in grants {
            validate_label(&grant.id)?;
            validate_pin(&grant.certificate_sha256)?;
            grant.certificate_sha256.make_ascii_lowercase();
            if grant.scopes.is_empty() || grant.scopes.len() > 16 {
                return Err("peer must have 1..=16 explicit scopes".into());
            }
            for (scope, operations) in &grant.scopes {
                validate_scope(scope)?;
                validate_operations(operations)?;
            }
            if !identities.insert(grant.id.clone())
                || by_pin
                    .insert(grant.certificate_sha256.clone(), grant)
                    .is_some()
            {
                return Err("peer certificate pins and identities must be unique".into());
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store(client_ca_pem)?),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|_| "invalid mandatory client CA configuration")?;
        let fingerprint = identity.fingerprint;
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "TLS 1.3 unavailable")?
            .with_client_cert_verifier(verifier)
            .with_single_cert(identity.certificates, identity.key)
            .map_err(|_| "invalid server certificate/key configuration")?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        tls.send_tls13_tickets = 0;
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Self {
            bind_address,
            server_id,
            fingerprint,
            tls: Arc::new(tls),
            grants: by_pin,
            limits,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SecureSession {
    pub peer_id: String,
    pub certificate_sha256: String,
    pub scope: String,
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureAgreement {
    pub version: String,
    pub server_id: String,
    pub client_id: String,
    pub scope: String,
    pub format: String,
    pub operations: Vec<String>,
    pub max_requests: u64,
    pub max_frame_bytes: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: String,
    server_id: String,
    client_id: String,
    scope: String,
    format: String,
    operations: Vec<String>,
    max_requests: u64,
    max_frame_bytes: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: String,
    request_id: u64,
    scope: String,
    operation: String,
    payload: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: String,
    request_id: u64,
    scope: String,
    ok: bool,
    result: Value,
    error: Option<String>,
}

struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
    stopped: Arc<AtomicBool>,
}

impl DeadlineSocket {
    fn new(socket: TcpStream, timeout: Duration, stopped: Arc<AtomicBool>) -> Result<Self, String> {
        socket.set_nonblocking(false).map_err(io_error)?;
        socket.set_nodelay(true).map_err(io_error)?;
        Ok(Self {
            socket,
            deadline: Instant::now() + timeout,
            stopped,
        })
    }

    fn reset_deadline(&mut self, timeout: Duration) {
        self.deadline = Instant::now() + timeout;
    }

    fn remaining(&self) -> io::Result<Duration> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "session cancelled",
            ));
        }
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute TLS/frame deadline exceeded",
            ));
        }
        Ok(remaining)
    }
}

impl Read for DeadlineSocket {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        let received = self.socket.read(buffer)?;
        // Cancellation/deadline wins even if the OS returns buffered data while
        // a cloned socket is being shut down from another thread.
        self.remaining()?;
        Ok(received)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        let written = self.socket.write(buffer)?;
        self.remaining()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.flush()
    }
}

trait FramedTls: Read + Write {
    fn reset_deadline(&mut self, timeout: Duration);
}

impl FramedTls for StreamOwned<ClientConnection, DeadlineSocket> {
    fn reset_deadline(&mut self, timeout: Duration) {
        self.sock.reset_deadline(timeout);
    }
}

impl FramedTls for StreamOwned<ServerConnection, DeadlineSocket> {
    fn reset_deadline(&mut self, timeout: Duration) {
        self.sock.reset_deadline(timeout);
    }
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(
                "JSON frame exceeds negotiated byte budget",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_frame<S: FramedTls, T: Serialize>(
    stream: &mut S,
    value: &T,
    limit: usize,
    timeout: Duration,
) -> Result<(), String> {
    let mut buffer = LimitedBuffer {
        bytes: Vec::new(),
        limit: limit.saturating_sub(1),
    };
    serde_json::to_writer(&mut buffer, value).map_err(|error| error.to_string())?;
    buffer.bytes.push(b'\n');
    stream.reset_deadline(timeout);
    stream.write_all(&buffer.bytes).map_err(io_error)?;
    stream.flush().map_err(io_error)
}

fn read_frame<S: FramedTls, T: DeserializeOwned>(
    stream: &mut BufReader<S>,
    limit: usize,
    timeout: Duration,
) -> Result<T, String> {
    stream.get_mut().reset_deadline(timeout);
    let mut bytes = Vec::new();
    loop {
        let available = stream.fill_buf().map_err(io_error)?;
        if available.is_empty() {
            return Err("secure peer closed before a complete JSONL frame".into());
        }
        let (count, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index + 1, true),
            None => (available.len(), false),
        };
        if count > limit.saturating_sub(bytes.len()) {
            return Err("incoming JSON frame exceeds negotiated byte budget".into());
        }
        bytes.extend_from_slice(&available[..count]);
        stream.consume(count);
        if done {
            return serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid secure JSON frame: {error}"));
        }
    }
}

struct ActiveSocket {
    peer_id: Option<String>,
    socket: TcpStream,
}

struct ServerState {
    revoked: BTreeSet<String>,
    active: Option<ActiveSocket>,
}

pub struct SecureServerHandle {
    address: SocketAddr,
    server_id: String,
    fingerprint: String,
    known_peer_ids: BTreeSet<String>,
    stopped: Arc<AtomicBool>,
    state: Arc<Mutex<ServerState>>,
    requests: Arc<AtomicU64>,
    connections: Arc<AtomicU64>,
    session_failures: Arc<AtomicU64>,
    last_failure: Arc<Mutex<Option<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl SecureServerHandle {
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn certificate_sha256(&self) -> &str {
        &self.fingerprint
    }

    pub fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Acquire)
    }

    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::Acquire)
    }

    pub fn session_failures(&self) -> u64 {
        self.session_failures.load(Ordering::Acquire)
    }

    pub fn last_failure(&self) -> Option<String> {
        self.last_failure
            .lock()
            .ok()
            .and_then(|failure| failure.clone())
    }

    pub fn revoke_peer(&self, peer_id: &str) -> Result<(), String> {
        validate_label(peer_id)?;
        if !self.known_peer_ids.contains(peer_id) {
            return Err("peer identity has no configured secure grant".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "secure server state poisoned")?;
        state.revoked.insert(peer_id.into());
        if let Some(active) = &state.active {
            if active.peer_id.as_deref() == Some(peer_id) {
                let _ = active.socket.shutdown(Shutdown::Both);
            }
        }
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), String> {
        self.stopped.store(true, Ordering::Release);
        if let Some(active) = self
            .state
            .lock()
            .map_err(|_| "secure server state poisoned")?
            .active
            .as_ref()
        {
            let _ = active.socket.shutdown(Shutdown::Both);
        }
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "secure server thread panicked")?;
        }
        Ok(())
    }
}

impl Drop for SecureServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

pub fn spawn_secure_server<F>(
    config: SecureServerConfig,
    handler: F,
) -> Result<SecureServerHandle, String>
where
    F: Fn(&SecureSession, &str, Value) -> Result<Value, String> + Send + 'static,
{
    let listener = TcpListener::bind(config.bind_address).map_err(io_error)?;
    listener.set_nonblocking(true).map_err(io_error)?;
    let address = listener.local_addr().map_err(io_error)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(ServerState {
        revoked: BTreeSet::new(),
        active: None,
    }));
    let requests = Arc::new(AtomicU64::new(0));
    let connections = Arc::new(AtomicU64::new(0));
    let session_failures = Arc::new(AtomicU64::new(0));
    let last_failure = Arc::new(Mutex::new(None));
    let mut handle = SecureServerHandle {
        address,
        server_id: config.server_id.clone(),
        fingerprint: config.fingerprint.clone(),
        known_peer_ids: config
            .grants
            .values()
            .map(|grant| grant.id.clone())
            .collect(),
        stopped: Arc::clone(&stopped),
        state: Arc::clone(&state),
        requests: Arc::clone(&requests),
        connections: Arc::clone(&connections),
        session_failures: Arc::clone(&session_failures),
        last_failure: Arc::clone(&last_failure),
        thread: None,
    };
    handle.thread = Some(thread::spawn(move || {
        while !stopped.load(Ordering::Acquire) {
            if connections.load(Ordering::Acquire) >= config.limits.max_connections {
                if let Ok(mut last) = last_failure.lock() {
                    *last = Some("server-wide secure connection budget exhausted".into());
                }
                stopped.store(true, Ordering::Release);
                break;
            }
            match listener.accept() {
                Ok((socket, _)) => {
                    // Count before parsing TLS or authenticating a peer: invalid
                    // reconnects consume a real crypto/connection budget too.
                    connections.fetch_add(1, Ordering::AcqRel);
                    let result = (|| {
                        let cancellation_socket = socket.try_clone().map_err(io_error)?;
                        state
                            .lock()
                            .map_err(|_| "secure server state poisoned")?
                            .active = Some(ActiveSocket {
                            peer_id: None,
                            socket: cancellation_socket,
                        });
                        serve_session(socket, &config, &state, &stopped, &requests, &handler)
                    })();
                    if let Ok(mut state) = state.lock() {
                        state.active = None;
                    }
                    if let Err(error) = result {
                        session_failures.fetch_add(1, Ordering::AcqRel);
                        if let Ok(mut last) = last_failure.lock() {
                            *last = Some(error);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(error) => {
                    if let Ok(mut last) = last_failure.lock() {
                        *last = Some(io_error(error));
                    }
                    break;
                }
            }
        }
    }));
    Ok(handle)
}

fn serve_session<F>(
    socket: TcpStream,
    config: &SecureServerConfig,
    state: &Arc<Mutex<ServerState>>,
    stopped: &Arc<AtomicBool>,
    requests: &Arc<AtomicU64>,
    handler: &F,
) -> Result<(), String>
where
    F: Fn(&SecureSession, &str, Value) -> Result<Value, String>,
{
    let socket = DeadlineSocket::new(socket, config.limits.timeout, Arc::clone(stopped))?;
    let connection = ServerConnection::new(Arc::clone(&config.tls))
        .map_err(|_| "TLS server connection failed")?;
    let mut stream = StreamOwned::new(connection, socket);
    stream
        .conn
        .complete_io(&mut stream.sock)
        .map_err(io_error)?;
    check_negotiated_tls(stream.conn.protocol_version(), stream.conn.alpn_protocol())?;
    let peer_certificate = stream
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or("mandatory client certificate missing")?;
    let pin = fingerprint(peer_certificate);
    let grant = config
        .grants
        .get(&pin)
        .ok_or("client certificate has no operator-owned identity grant")?;
    {
        let mut state = state.lock().map_err(|_| "secure server state poisoned")?;
        if state.revoked.contains(&grant.id) {
            return Err("client authorization revoked".into());
        }
        if let Some(active) = &mut state.active {
            active.peer_id = Some(grant.id.clone());
        }
    }
    let mut stream = BufReader::new(stream);
    let hello: Hello = read_frame(
        &mut stream,
        config.limits.max_frame_bytes,
        config.limits.timeout,
    )?;
    if hello.version != SECURE_PROTOCOL_VERSION
        || hello.server_id != config.server_id
        || hello.client_id != grant.id
        || hello.format != "jsonl"
    {
        return Err("secure identity, version or format negotiation rejected".into());
    }
    validate_scope(&hello.scope)?;
    validate_operations(&hello.operations)?;
    if hello.max_requests == 0
        || hello.max_requests > MAX_REQUESTS
        || !(1024..=MAX_FRAME).contains(&hello.max_frame_bytes)
    {
        return Err("invalid secure client budget proposal".into());
    }
    let allowed = grant
        .scopes
        .get(&hello.scope)
        .ok_or("scope not authorized for this client certificate")?;
    let operations: Vec<_> = hello
        .operations
        .iter()
        .filter(|operation| allowed.contains(operation))
        .cloned()
        .collect();
    if operations.is_empty() {
        return Err("no mutually authorized secure operations".into());
    }
    let remaining = config
        .limits
        .max_requests
        .saturating_sub(requests.load(Ordering::Acquire));
    let agreement = SecureAgreement {
        version: SECURE_PROTOCOL_VERSION.into(),
        server_id: config.server_id.clone(),
        client_id: grant.id.clone(),
        scope: hello.scope.clone(),
        format: "jsonl".into(),
        operations: operations.clone(),
        max_requests: remaining.min(hello.max_requests),
        max_frame_bytes: config.limits.max_frame_bytes.min(hello.max_frame_bytes),
    };
    if agreement.max_requests == 0 {
        return Err("server-wide secure request budget exhausted".into());
    }
    write_frame(
        stream.get_mut(),
        &agreement,
        agreement.max_frame_bytes,
        config.limits.timeout,
    )?;
    let context = SecureSession {
        peer_id: grant.id.clone(),
        certificate_sha256: pin,
        scope: hello.scope,
        operations,
    };
    let mut expected_id = 1_u64;
    loop {
        let request: Request = read_frame(
            &mut stream,
            agreement.max_frame_bytes,
            config.limits.timeout,
        )?;
        if request.version != SECURE_PROTOCOL_VERSION
            || request.scope != context.scope
            || request.request_id != expected_id
        {
            return Err("secure request version, scope or sequence mismatch".into());
        }
        if stopped.load(Ordering::Acquire)
            || state
                .lock()
                .map_err(|_| "secure server state poisoned")?
                .revoked
                .contains(&context.peer_id)
        {
            return Err("secure session authorization revoked".into());
        }
        if request.operation == REVOKE_OPERATION {
            write_frame(
                stream.get_mut(),
                &Response {
                    version: SECURE_PROTOCOL_VERSION.into(),
                    request_id: request.request_id,
                    scope: context.scope.clone(),
                    ok: true,
                    result: json!({"revoked":true}),
                    error: None,
                },
                agreement.max_frame_bytes,
                config.limits.timeout,
            )?;
            return Ok(());
        }
        if !context.operations.contains(&request.operation) || expected_id > agreement.max_requests
        {
            return Err("secure operation or session budget rejected".into());
        }
        if requests
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < config.limits.max_requests).then_some(count + 1)
            })
            .is_err()
        {
            return Err("server-wide secure request budget exhausted".into());
        }
        let result = handler(&context, &request.operation, request.payload);
        let response = match result {
            Ok(result) => Response {
                version: SECURE_PROTOCOL_VERSION.into(),
                request_id: request.request_id,
                scope: context.scope.clone(),
                ok: true,
                result,
                error: None,
            },
            Err(error) => Response {
                version: SECURE_PROTOCOL_VERSION.into(),
                request_id: request.request_id,
                scope: context.scope.clone(),
                ok: false,
                result: Value::Null,
                error: Some(error),
            },
        };
        write_frame(
            stream.get_mut(),
            &response,
            agreement.max_frame_bytes,
            config.limits.timeout,
        )?;
        expected_id += 1;
    }
}

pub struct SecureCancellation {
    socket: TcpStream,
    stopped: Arc<AtomicBool>,
}

impl SecureCancellation {
    pub fn cancel(&self) -> Result<(), String> {
        self.stopped.store(true, Ordering::Release);
        self.socket.shutdown(Shutdown::Both).map_err(io_error)
    }
}

pub struct SecureClient {
    stream: BufReader<StreamOwned<ClientConnection, DeadlineSocket>>,
    agreement: SecureAgreement,
    timeout: Duration,
    next_request: u64,
    stopped: Arc<AtomicBool>,
}

impl SecureClient {
    pub fn connect(endpoint: &SecureEndpoint, config: &TlsClientConfig) -> Result<Self, String> {
        validate_label(&endpoint.server_id)?;
        validate_pin(&endpoint.server_certificate_sha256)?;
        validate_scope(&endpoint.scope)?;
        validate_operations(&endpoint.operations)?;
        endpoint.limits.validate()?;
        if endpoint.address.port() == 0
            || endpoint.address.ip().is_unspecified()
            || endpoint.address.ip().is_multicast()
        {
            return Err("secure endpoint requires an explicit unicast address and port".into());
        }
        let server_name = ServerName::try_from(endpoint.server_name.clone())
            .map_err(|_| "invalid TLS server name")?;
        let socket = TcpStream::connect_timeout(&endpoint.address, endpoint.limits.timeout)
            .map_err(io_error)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let socket = DeadlineSocket::new(socket, endpoint.limits.timeout, Arc::clone(&stopped))?;
        let connection = ClientConnection::new(Arc::clone(&config.tls), server_name)
            .map_err(|_| "TLS client connection failed")?;
        let mut stream = StreamOwned::new(connection, socket);
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(io_error)?;
        check_negotiated_tls(stream.conn.protocol_version(), stream.conn.alpn_protocol())?;
        let peer = stream
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or("server certificate missing")?;
        if !fingerprint(peer).eq_ignore_ascii_case(&endpoint.server_certificate_sha256) {
            return Err("server certificate does not match the explicitly pinned identity".into());
        }
        // No application data is sent until PKI, hostname, TLS, ALPN and pin checks pass.
        let hello = Hello {
            version: SECURE_PROTOCOL_VERSION.into(),
            server_id: endpoint.server_id.clone(),
            client_id: config.client_id.clone(),
            scope: endpoint.scope.clone(),
            format: "jsonl".into(),
            operations: endpoint.operations.clone(),
            max_requests: endpoint.limits.max_requests,
            max_frame_bytes: endpoint.limits.max_frame_bytes,
        };
        write_frame(
            &mut stream,
            &hello,
            endpoint.limits.max_frame_bytes,
            endpoint.limits.timeout,
        )?;
        let mut stream = BufReader::new(stream);
        let agreement: SecureAgreement = read_frame(
            &mut stream,
            endpoint.limits.max_frame_bytes,
            endpoint.limits.timeout,
        )?;
        if agreement.version != SECURE_PROTOCOL_VERSION
            || agreement.server_id != endpoint.server_id
            || agreement.client_id != config.client_id
            || agreement.scope != endpoint.scope
            || agreement.format != "jsonl"
            || agreement.operations.is_empty()
            || agreement
                .operations
                .iter()
                .any(|operation| !endpoint.operations.contains(operation))
            || agreement.max_requests == 0
            || agreement.max_requests > endpoint.limits.max_requests
            || agreement.max_frame_bytes > endpoint.limits.max_frame_bytes
            || agreement.max_frame_bytes < 1024
        {
            return Err(
                "server returned an agreement outside explicit client authorization".into(),
            );
        }
        validate_operations(&agreement.operations)?;
        Ok(Self {
            stream,
            agreement,
            timeout: endpoint.limits.timeout,
            next_request: 1,
            stopped,
        })
    }

    pub fn agreement(&self) -> &SecureAgreement {
        &self.agreement
    }

    pub fn cancellation_handle(&self) -> Result<SecureCancellation, String> {
        Ok(SecureCancellation {
            socket: self
                .stream
                .get_ref()
                .sock
                .socket
                .try_clone()
                .map_err(io_error)?,
            stopped: Arc::clone(&self.stopped),
        })
    }

    pub fn call(&mut self, operation: &str, payload: &Value) -> Result<Value, String> {
        if !self
            .agreement
            .operations
            .iter()
            .any(|allowed| allowed == operation)
        {
            return Err("operation is outside negotiated secure capabilities".into());
        }
        if self.next_request > self.agreement.max_requests {
            return Err("negotiated secure request budget exhausted".into());
        }
        self.transact(operation, payload)
    }

    fn transact(&mut self, operation: &str, payload: &Value) -> Result<Value, String> {
        if self.stopped.load(Ordering::Acquire) {
            return Err("secure session cancelled".into());
        }
        let request_id = self.next_request;
        self.next_request += 1;
        let result = (|| {
            write_frame(
                self.stream.get_mut(),
                &Request {
                    version: SECURE_PROTOCOL_VERSION.into(),
                    request_id,
                    scope: self.agreement.scope.clone(),
                    operation: operation.into(),
                    payload: payload.clone(),
                },
                self.agreement.max_frame_bytes,
                self.timeout,
            )?;
            let response: Response = read_frame(
                &mut self.stream,
                self.agreement.max_frame_bytes,
                self.timeout,
            )?;
            if self.stopped.load(Ordering::Acquire) {
                return Err("secure session cancelled".into());
            }
            if response.version != SECURE_PROTOCOL_VERSION
                || response.scope != self.agreement.scope
                || response.request_id != request_id
                || response.ok == response.error.is_some()
            {
                return Err("secure response version, scope, status or sequence mismatch".into());
            }
            if !response.ok {
                return Err(response
                    .error
                    .unwrap_or_else(|| "secure operation rejected".into()));
            }
            Ok(response.result)
        })();
        if result.is_err() {
            let _ = self.cancel();
        }
        result
    }

    pub fn revoke(&mut self) -> Result<(), String> {
        let result = self.transact(REVOKE_OPERATION, &Value::Null).map(|_| ());
        let _ = self.cancel();
        result
    }

    pub fn cancel(&mut self) -> Result<(), String> {
        self.stopped.store(true, Ordering::Release);
        self.stream
            .get_mut()
            .sock
            .socket
            .shutdown(Shutdown::Both)
            .map_err(io_error)
    }
}

impl Drop for SecureClient {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

fn parse_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    if bytes.is_empty() || bytes.len() > MAX_PEM_BYTES {
        return Err("certificate PEM exceeds its byte limit or is empty".into());
    }
    let mut certificates = Vec::new();
    for (kind, der) in parse_pem_sections(bytes)? {
        match kind {
            SectionKind::Certificate => certificates.push(CertificateDer::from(der)),
            _ => return Err("certificate file contains an unsupported PEM section".into()),
        }
        if certificates.len() > 8 {
            return Err("certificate chain exceeds eight certificates".into());
        }
    }
    if certificates.is_empty() {
        return Err("certificate PEM contains no certificates".into());
    }
    Ok(certificates)
}

fn parse_pem_sections(bytes: &[u8]) -> Result<Vec<(SectionKind, Vec<u8>)>, String> {
    // Typed PemObject iterators deliberately filter unrelated sections. Inspect
    // every recognized kind instead, and count boundaries so unknown labels or
    // nested sections cannot disappear silently. DER/base64 decoding remains
    // entirely in the maintained Rustls PKI parser.
    let mut starts = 0;
    let mut ends = 0;
    for line in bytes.split(|byte| matches!(*byte, b'\r' | b'\n')) {
        starts += usize::from(line.starts_with(b"-----BEGIN "));
        ends += usize::from(line.starts_with(b"-----END "));
    }
    if starts != ends {
        return Err("invalid PEM section boundaries".into());
    }
    let sections = <(SectionKind, Vec<u8>)>::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid PEM encoding".to_string())?;
    if sections.len() != starts {
        return Err("PEM contains an unsupported or nested section".into());
    }
    Ok(sections)
}

fn root_store(bytes: &[u8]) -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in parse_certificates(bytes)? {
        roots
            .add(certificate)
            .map_err(|_| "invalid configured trust anchor")?;
    }
    Ok(roots)
}

fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path)
        .map_err(|error| format!("TLS credential file {}: {error}", path.display()))?;
    if file.metadata().map_err(io_error)?.len() > limit as u64 {
        return Err("TLS credential file exceeds byte limit".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > limit {
        return Err("TLS credential file exceeds byte limit".into());
    }
    Ok(bytes)
}

fn fingerprint(certificate: &CertificateDer<'_>) -> String {
    format!("{:x}", Sha256::digest(certificate.as_ref()))
}

fn check_negotiated_tls(
    version: Option<rustls::ProtocolVersion>,
    alpn: Option<&[u8]>,
) -> Result<(), String> {
    if version != Some(rustls::ProtocolVersion::TLSv1_3) || alpn != Some(ALPN) {
        return Err("TLS 1.3 and symbiote/2 ALPN are mandatory".into());
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), String> {
    if label.is_empty()
        || label.len() > 128
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("identity or operation label is invalid".into());
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<(), String> {
    if scope.is_empty()
        || scope.len() > 256
        || !scope
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/:".contains(&byte))
    {
        return Err("secure scope label is invalid".into());
    }
    Ok(())
}

fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.len() != 64 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("certificate pin must be exactly 64 hexadecimal SHA256 characters".into());
    }
    Ok(())
}

fn validate_operations(operations: &[String]) -> Result<(), String> {
    if operations.is_empty() || operations.len() > 32 {
        return Err("secure capabilities must contain 1..=32 operations".into());
    }
    let mut unique = BTreeSet::new();
    for operation in operations {
        validate_label(operation)?;
        if operation == REVOKE_OPERATION || !unique.insert(operation) {
            return Err("duplicate or reserved secure capability".into());
        }
    }
    Ok(())
}

fn io_error(error: io::Error) -> String {
    format!("secure transport I/O: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use std::sync::mpsc;

    struct Fixtures {
        ca: CertifiedIssuer<'static, KeyPair>,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
        client_cert: Vec<u8>,
        client_key: Vec<u8>,
    }

    impl Fixtures {
        fn new() -> Self {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
            ];
            let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
            let (server_cert, server_key) =
                Self::leaf(&ca, "localhost", ExtendedKeyUsagePurpose::ServerAuth, false);
            let (client_cert, client_key) = Self::leaf(
                &ca,
                "client.test",
                ExtendedKeyUsagePurpose::ClientAuth,
                false,
            );
            Self {
                ca,
                server_cert,
                server_key,
                client_cert,
                client_key,
            }
        }

        fn leaf(
            ca: &CertifiedIssuer<'static, KeyPair>,
            name: &str,
            purpose: ExtendedKeyUsagePurpose,
            expired: bool,
        ) -> (Vec<u8>, Vec<u8>) {
            let mut params = CertificateParams::new(vec![name.into()]).unwrap();
            params.extended_key_usages = vec![purpose];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            if expired {
                params.not_before = rcgen::date_time_ymd(2019, 1, 1);
                params.not_after = rcgen::date_time_ymd(2020, 1, 1);
            }
            let key = KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, ca).unwrap();
            (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
        }

        fn client_config(&self) -> TlsClientConfig {
            TlsClientConfig::new(
                "client".into(),
                TlsIdentity::from_pem(&self.client_cert, &self.client_key).unwrap(),
                self.ca.pem().as_bytes(),
            )
            .unwrap()
        }

        fn grants(&self) -> Vec<SecurePeerGrant> {
            vec![SecurePeerGrant {
                id: "client".into(),
                certificate_sha256: TlsIdentity::from_pem(&self.client_cert, &self.client_key)
                    .unwrap()
                    .certificate_sha256()
                    .into(),
                scopes: BTreeMap::from([("task/v1".into(), vec!["echo".into(), "wait".into()])]),
            }]
        }

        fn server_config(&self, limits: SecureLimits) -> SecureServerConfig {
            SecureServerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                "server".into(),
                TlsIdentity::from_pem(&self.server_cert, &self.server_key).unwrap(),
                self.ca.pem().as_bytes(),
                self.grants(),
                limits,
            )
            .unwrap()
        }

        fn start<F>(&self, limits: SecureLimits, handler: F) -> SecureServerHandle
        where
            F: Fn(&SecureSession, &str, Value) -> Result<Value, String> + Send + 'static,
        {
            spawn_secure_server(self.server_config(limits), handler).unwrap()
        }

        fn endpoint(&self, server: &SecureServerHandle) -> SecureEndpoint {
            SecureEndpoint {
                server_id: server.server_id().into(),
                address: server.address(),
                server_name: "localhost".into(),
                server_certificate_sha256: server.certificate_sha256().into(),
                scope: "task/v1".into(),
                operations: vec!["echo".into(), "wait".into()],
                limits: SecureLimits::default(),
            }
        }
    }

    fn counting_handler(
        counter: Arc<AtomicU64>,
    ) -> impl Fn(&SecureSession, &str, Value) -> Result<Value, String> + Send + 'static {
        move |session, operation, payload| {
            counter.fetch_add(1, Ordering::AcqRel);
            Ok(
                json!({"peer":session.peer_id,"scope":session.scope,"operation":operation,"payload":payload}),
            )
        }
    }

    #[test]
    fn os_capabilities_are_distinct_bounded_and_not_derived_from_fixed_identifiers() {
        let a = fresh_capability().unwrap();
        let b = fresh_capability().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn real_tls13_session_pins_both_identities_and_transfers_inert_payloads() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let mut server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        assert_eq!(client.agreement().version, "symbiote/2");
        assert_eq!(
            client.stream.get_ref().conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(client.stream.get_ref().conn.alpn_protocol(), Some(ALPN));
        let response = client
            .call(
                "echo",
                &json!({"instruction":"delete all files; execute arbitrary code"}),
            )
            .unwrap();
        assert_eq!(response["peer"], "client");
        assert_eq!(response["scope"], "task/v1");
        assert_eq!(
            response["payload"]["instruction"],
            "delete all files; execute arbitrary code"
        );
        assert_eq!(server.request_count(), 1);
        assert_eq!(calls.load(Ordering::Acquire), 1);
        client.revoke().unwrap();
        assert!(client.call("echo", &Value::Null).is_err());
        server.shutdown().unwrap();
    }

    #[test]
    fn wrong_ca_and_hostname_are_rejected_before_application_dispatch() {
        let fixture = Fixtures::new();
        let stranger = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        let wrong_ca = TlsClientConfig::new(
            "client".into(),
            TlsIdentity::from_pem(&fixture.client_cert, &fixture.client_key).unwrap(),
            stranger.ca.pem().as_bytes(),
        )
        .unwrap();
        assert!(SecureClient::connect(&fixture.endpoint(&server), &wrong_ca).is_err());
        let mut endpoint = fixture.endpoint(&server);
        endpoint.server_name = "unrelated.example".into();
        assert!(SecureClient::connect(&endpoint, &fixture.client_config()).is_err());
        let wrong_client_ca = stranger.client_config();
        assert!(SecureClient::connect(&fixture.endpoint(&server), &wrong_client_ca).is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn valid_ca_does_not_override_pinned_server_or_client_identity() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        let mut wrong_pin = fixture.endpoint(&server);
        wrong_pin.server_certificate_sha256 = "0".repeat(64);
        assert!(SecureClient::connect(&wrong_pin, &fixture.client_config()).is_err());

        let (other_cert, other_key) = Fixtures::leaf(
            &fixture.ca,
            "other.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        );
        let other_client = TlsClientConfig::new(
            "client".into(),
            TlsIdentity::from_pem(&other_cert, &other_key).unwrap(),
            fixture.ca.pem().as_bytes(),
        )
        .unwrap();
        assert!(SecureClient::connect(&fixture.endpoint(&server), &other_client).is_err());

        let spoofed_id = TlsClientConfig::new(
            "admin".into(),
            TlsIdentity::from_pem(&fixture.client_cert, &fixture.client_key).unwrap(),
            fixture.ca.pem().as_bytes(),
        )
        .unwrap();
        assert!(SecureClient::connect(&fixture.endpoint(&server), &spoofed_id).is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn client_certificates_are_mandatory_and_server_eku_cannot_impersonate_client() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut unauthenticated = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(root_store(fixture.ca.pem().as_bytes()).unwrap())
            .with_no_client_auth();
        unauthenticated.alpn_protocols = vec![ALPN.to_vec()];
        let client = TlsClientConfig {
            client_id: "client".into(),
            tls: Arc::new(unauthenticated),
        };
        assert!(SecureClient::connect(&fixture.endpoint(&server), &client).is_err());

        let server_as_client = TlsClientConfig::new(
            "client".into(),
            TlsIdentity::from_pem(&fixture.server_cert, &fixture.server_key).unwrap(),
            fixture.ca.pem().as_bytes(),
        )
        .unwrap();
        assert!(SecureClient::connect(&fixture.endpoint(&server), &server_as_client).is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn expired_but_pinned_certificate_is_still_rejected_by_pki_validation() {
        let mut fixture = Fixtures::new();
        (fixture.server_cert, fixture.server_key) = Fixtures::leaf(
            &fixture.ca,
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            true,
        );
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        assert!(
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).is_err()
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn alpn_and_explicit_scope_negotiation_have_no_plaintext_or_v1_fallback() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        let mut config = fixture.client_config();
        let mut tls = (*config.tls).clone();
        tls.alpn_protocols = vec![b"symbiote/1".to_vec()];
        config.tls = Arc::new(tls);
        assert!(SecureClient::connect(&fixture.endpoint(&server), &config).is_err());
        let mut endpoint = fixture.endpoint(&server);
        endpoint.scope = "unapproved/v1".into();
        assert!(SecureClient::connect(&endpoint, &fixture.client_config()).is_err());
        endpoint.scope = "task/v1".into();
        endpoint.server_id = "different-server".into();
        assert!(SecureClient::connect(&endpoint, &fixture.client_config()).is_err());
        endpoint.server_id = "server".into();
        endpoint.operations = vec!["admin".into()];
        assert!(SecureClient::connect(&endpoint, &fixture.client_config()).is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn server_enforces_operations_sequences_scope_and_version_without_client_checks() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        for variant in ["operation", "sequence", "scope", "version"] {
            let mut client =
                SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config())
                    .unwrap();
            let mut request = Request {
                version: SECURE_PROTOCOL_VERSION.into(),
                request_id: 1,
                scope: "task/v1".into(),
                operation: "echo".into(),
                payload: Value::Null,
            };
            match variant {
                "operation" => request.operation = "admin".into(),
                "sequence" => request.request_id = 2,
                "scope" => request.scope = "other/v1".into(),
                _ => request.version = "symbiote/1".into(),
            }
            write_frame(
                client.stream.get_mut(),
                &request,
                client.agreement.max_frame_bytes,
                client.timeout,
            )
            .unwrap();
            assert!(read_frame::<_, Response>(
                &mut client.stream,
                client.agreement.max_frame_bytes,
                client.timeout
            )
            .is_err());
        }
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_eq!(server.request_count(), 0);
    }

    #[test]
    fn global_request_budget_cannot_be_reset_by_tls_reconnection() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits {
                max_requests: 1,
                ..SecureLimits::default()
            },
            counting_handler(Arc::clone(&calls)),
        );
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        assert_eq!(client.agreement().max_requests, 1);
        client.call("echo", &Value::Null).unwrap();
        assert!(client.call("echo", &Value::Null).is_err());
        client.revoke().unwrap();
        assert!(
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).is_err()
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }

    #[test]
    fn failed_and_unauthenticated_handshakes_consume_the_connection_budget() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits {
                max_connections: 2,
                timeout: Duration::from_millis(150),
                ..SecureLimits::default()
            },
            counting_handler(Arc::clone(&calls)),
        );
        let mut raw = TcpStream::connect(server.address()).unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut byte = [0];
        assert!(matches!(raw.read(&mut byte), Ok(0) | Err(_)));
        let stranger = Fixtures::new();
        let wrong_certificate = TlsClientConfig::new(
            "client".into(),
            TlsIdentity::from_pem(&stranger.client_cert, &stranger.client_key).unwrap(),
            fixture.ca.pem().as_bytes(),
        )
        .unwrap();
        assert!(SecureClient::connect(&fixture.endpoint(&server), &wrong_certificate).is_err());
        assert!(
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).is_err()
        );
        assert_eq!(server.connection_count(), 2);
        assert_eq!(server.request_count(), 0);
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn negotiated_frame_limits_reject_oversize_in_both_directions_and_recover() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits {
                max_frame_bytes: 1024,
                ..SecureLimits::default()
            },
            counting_handler(Arc::clone(&calls)),
        );
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        assert_eq!(client.agreement().max_frame_bytes, 1024);
        assert!(client
            .call("echo", &json!({"large":"x".repeat(2048)}))
            .is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        client
            .stream
            .get_mut()
            .sock
            .reset_deadline(Duration::from_secs(2));
        client
            .stream
            .get_mut()
            .write_all(format!("{}\n", "x".repeat(1025)).as_bytes())
            .unwrap();
        client.stream.get_mut().flush().unwrap();
        assert!(read_frame::<_, Response>(&mut client.stream, 1024, client.timeout).is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        client.call("echo", &json!({"small":true})).unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        client.revoke().unwrap();
    }

    #[test]
    fn oversized_application_response_is_never_written_as_a_partial_json_frame() {
        let fixture = Fixtures::new();
        let server = fixture.start(
            SecureLimits {
                max_frame_bytes: 1024,
                ..SecureLimits::default()
            },
            |_, _, payload| {
                if payload["large"] == true {
                    return Ok(json!({"data":"x".repeat(2048)}));
                }
                Ok(json!({"small":true}))
            },
        );
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        assert!(client.call("echo", &json!({"large":true})).is_err());
        assert_eq!(server.request_count(), 1);
        let mut recovered =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        assert_eq!(
            recovered.call("echo", &json!({"large":false})).unwrap()["small"],
            true
        );
        recovered.revoke().unwrap();
    }

    #[test]
    fn revoked_peer_is_disconnected_and_cannot_reconnect() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        server.revoke_peer("client").unwrap();
        assert!(client.call("echo", &Value::Null).is_err());
        assert!(
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).is_err()
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn unknown_revocations_cannot_expand_the_configured_peer_registry() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let mut server = fixture.start(
            SecureLimits::default(),
            counting_handler(Arc::clone(&calls)),
        );
        for index in 0..1024 {
            assert!(server.revoke_peer(&format!("unknown-{index}")).is_err());
        }
        assert_eq!(server.known_peer_ids.len(), 1);
        assert!(server.state.lock().unwrap().revoked.is_empty());
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        client.call("echo", &Value::Null).unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        server.revoke_peer("client").unwrap();
        server.revoke_peer("client").unwrap();
        assert_eq!(server.state.lock().unwrap().revoked.len(), 1);
        assert!(client.call("echo", &Value::Null).is_err());
        server.shutdown().unwrap();
    }

    #[test]
    fn revocation_blocks_next_requests_but_does_not_preempt_admitted_handlers() {
        let fixture = Fixtures::new();
        let mutations = Arc::new(AtomicU64::new(0));
        let handler_mutations = Arc::clone(&mutations);
        let (started, wait_for_start) = mpsc::channel();
        let (release, wait_for_release) = mpsc::channel();
        let (completed, wait_for_completion) = mpsc::channel();
        let mut server = fixture.start(SecureLimits::default(), move |_, _, _| {
            started.send(()).map_err(|error| error.to_string())?;
            wait_for_release
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| error.to_string())?;
            handler_mutations.fetch_add(1, Ordering::AcqRel);
            completed.send(()).map_err(|error| error.to_string())?;
            Ok(json!({"completed":true}))
        });
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        let worker = thread::spawn(move || {
            let in_flight = client.call("wait", &Value::Null);
            let next = client.call("echo", &Value::Null);
            (in_flight, next)
        });
        wait_for_start.recv_timeout(Duration::from_secs(2)).unwrap();
        server.revoke_peer("client").unwrap();
        assert_eq!(mutations.load(Ordering::Acquire), 0);
        // Already-admitted work remains native application authority even though
        // the transport has returned from revocation and closed the channel.
        release.send(()).unwrap();
        wait_for_completion
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let (in_flight, next) = worker.join().unwrap();
        assert!(in_flight.is_err());
        assert!(next.is_err());
        assert!(
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).is_err()
        );
        assert_eq!(mutations.load(Ordering::Acquire), 1);
        server.shutdown().unwrap();
    }

    #[test]
    fn cancellation_interrupts_an_inflight_tls_read() {
        let fixture = Fixtures::new();
        let (ready, receiving) = mpsc::channel();
        let mut server = fixture.start(SecureLimits::default(), move |_, _, _| {
            ready.send(()).map_err(|error| error.to_string())?;
            thread::sleep(Duration::from_millis(100));
            Ok(json!({"completed":true}))
        });
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        let cancellation = client.cancellation_handle().unwrap();
        let worker = thread::spawn(move || client.call("wait", &Value::Null));
        receiving.recv_timeout(Duration::from_secs(2)).unwrap();
        cancellation.cancel().unwrap();
        assert!(worker.join().unwrap().is_err());
        server.shutdown().unwrap();
    }

    #[test]
    fn unauthenticated_stall_and_partial_frame_use_absolute_deadlines() {
        let fixture = Fixtures::new();
        let calls = Arc::new(AtomicU64::new(0));
        let server = fixture.start(
            SecureLimits {
                timeout: Duration::from_millis(150),
                ..SecureLimits::default()
            },
            counting_handler(Arc::clone(&calls)),
        );
        let mut stalled = TcpStream::connect(server.address()).unwrap();
        stalled
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0];
        assert!(matches!(stalled.read(&mut byte), Ok(0) | Err(_)));
        let mut client =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        // Accepting the next TLS session happens after the prior failure has
        // been recorded; this avoids racing the listener thread's bookkeeping.
        assert!(server.session_failures() >= 1);
        client
            .stream
            .get_mut()
            .sock
            .reset_deadline(Duration::from_secs(2));
        let mut disconnected = false;
        for _ in 0..30 {
            if client
                .stream
                .get_mut()
                .write_all(b" ")
                .and_then(|_| client.stream.get_mut().flush())
                .is_err()
            {
                disconnected = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            disconnected,
            "partial bytes must not reset the absolute server frame deadline"
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        drop(client);
        let mut recovered =
            SecureClient::connect(&fixture.endpoint(&server), &fixture.client_config()).unwrap();
        recovered.call("echo", &Value::Null).unwrap();
        recovered.revoke().unwrap();
    }

    #[test]
    fn pem_credentials_reject_malformed_unknown_and_mixed_sections() {
        let fixture = Fixtures::new();
        let unknown = b"-----BEGIN UNRECOGNIZED KEY-----\nAA==\n-----END UNRECOGNIZED KEY-----\n";
        let public_key = b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n";
        let bad_base64 = b"-----BEGIN CERTIFICATE-----\n!!invalid!!\n-----END CERTIFICATE-----\n";
        let missing_end = b"-----BEGIN CERTIFICATE-----\nAA==\n";
        let nested = [
            b"-----BEGIN CERTIFICATE-----\n".as_slice(),
            fixture.server_cert.as_slice(),
            b"-----END CERTIFICATE-----\n".as_slice(),
        ]
        .concat();
        for invalid_certificates in [
            bad_base64.to_vec(),
            missing_end.to_vec(),
            nested,
            [fixture.server_cert.as_slice(), unknown].concat(),
            [fixture.server_cert.as_slice(), public_key].concat(),
            [
                fixture.server_cert.as_slice(),
                fixture.server_key.as_slice(),
            ]
            .concat(),
            [
                fixture.server_cert.as_slice(),
                b"-----END CERTIFICATE-----\n",
            ]
            .concat(),
        ] {
            assert!(TlsIdentity::from_pem(&invalid_certificates, &fixture.server_key).is_err());
        }
        for invalid_key in [
            b"-----BEGIN PRIVATE KEY-----\n!!invalid!!\n-----END PRIVATE KEY-----\n".to_vec(),
            b"-----BEGIN PRIVATE KEY-----\nAA==\n".to_vec(),
            [fixture.server_key.as_slice(), unknown].concat(),
            [fixture.server_key.as_slice(), public_key].concat(),
            [
                fixture.server_key.as_slice(),
                fixture.server_cert.as_slice(),
            ]
            .concat(),
        ] {
            assert!(TlsIdentity::from_pem(&fixture.server_cert, &invalid_key).is_err());
        }
    }

    #[test]
    fn pem_credentials_preserve_chain_and_key_count_limits() {
        let fixture = Fixtures::new();
        assert!(TlsIdentity::from_pem(&fixture.server_cert.repeat(8), &fixture.server_key).is_ok());
        assert!(
            TlsIdentity::from_pem(&fixture.server_cert.repeat(9), &fixture.server_key).is_err()
        );
        assert!(
            TlsIdentity::from_pem(&fixture.server_cert, &fixture.server_key.repeat(2)).is_err()
        );
        assert!(
            TlsIdentity::from_pem(&fixture.server_cert, &vec![b'x'; MAX_KEY_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn identity_pem_limits_and_explicit_configuration_fail_closed() {
        let fixture = Fixtures::new();
        let identity = TlsIdentity::from_pem(&fixture.server_cert, &fixture.server_key).unwrap();
        let debug = format!("{identity:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("PRIVATE KEY"));
        assert!(TlsIdentity::from_pem(&fixture.server_cert, &[]).is_err());
        assert!(
            TlsIdentity::from_pem(&vec![b'x'; MAX_PEM_BYTES + 1], &fixture.server_key).is_err()
        );
        let two_keys = [fixture.server_key.as_slice(), fixture.server_key.as_slice()].concat();
        assert!(TlsIdentity::from_pem(&fixture.server_cert, &two_keys).is_err());
        assert!(SecureLimits {
            max_requests: 0,
            ..SecureLimits::default()
        }
        .validate()
        .is_err());
        assert!(SecureLimits {
            max_connections: 0,
            ..SecureLimits::default()
        }
        .validate()
        .is_err());
        assert!(SecureLimits {
            max_frame_bytes: MAX_FRAME + 1,
            ..SecureLimits::default()
        }
        .validate()
        .is_err());
        assert!(SecureLimits {
            timeout: Duration::ZERO,
            ..SecureLimits::default()
        }
        .validate()
        .is_err());
        let duplicate = fixture.grants();
        let result = SecureServerConfig::new(
            "0.0.0.0:0".parse().unwrap(),
            "server".into(),
            identity,
            fixture.ca.pem().as_bytes(),
            vec![duplicate[0].clone(), duplicate[0].clone()],
            SecureLimits::default(),
        );
        assert!(result.is_err());
        // Explicit nonlocal binding is supported; it is never selected by default.
        assert!(SecureServerConfig::new(
            "0.0.0.0:0".parse().unwrap(),
            "server".into(),
            TlsIdentity::from_pem(&fixture.server_cert, &fixture.server_key).unwrap(),
            fixture.ca.pem().as_bytes(),
            fixture.grants(),
            SecureLimits::default(),
        )
        .is_ok());
    }
}
