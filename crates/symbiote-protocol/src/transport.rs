use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PROTOCOL_VERSION: &str = "symbiote/1";
pub const SCOPE: &str = "finite-boolean-v1";
const MAX_FRAME: usize = 65_536;
const MAX_REQUESTS: u64 = 10_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
static CHALLENGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Explicit local endpoint authorization. Debug output deliberately omits the token.
#[derive(Clone)]
pub struct Endpoint {
    pub id: String,
    pub address: SocketAddr,
    pub token: String,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("id", &self.id)
            .field("address", &self.address)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Shared capability tokens are restricted to a trusted local host in v0.1.
/// This protocol provides no TLS or defense against privileged local attackers.
pub struct ServerConfig {
    pub id: String,
    pub token: String,
    pub client_id: String,
    pub operations: Vec<String>,
    pub max_requests: u64,
    pub max_frame_bytes: usize,
    pub timeout: Duration,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: String,
    request_id: u64,
    operation: String,
    payload: Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: String,
    request_id: u64,
    ok: bool,
    result: Value,
    error: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    server_id: String,
    client_id: String,
    nonce: String,
    proof: String,
    operations: Vec<String>,
    scope: String,
    format: String,
    max_requests: u64,
    max_frame_bytes: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    version: String,
    server_id: String,
    client_nonce: String,
    nonce: String,
    proof: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Greeting {
    version: String,
    server_id: String,
    client_id: String,
    nonce: String,
}

fn fresh_nonce() -> Result<String, String> {
    let sequence = CHALLENGE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "invalid system clock".to_string())?
        .as_nanos();
    Ok(format!(
        "{:032x}{:016x}{:08x}",
        time,
        sequence,
        std::process::id()
    ))
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 56 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// Standard HMAC-SHA256 (RFC 2104). Domain separation prevents client/server proof reuse.
fn mac(token: &str, message: &[u8]) -> String {
    let mut key = [0_u8; 64];
    if token.len() > key.len() {
        key[..32].copy_from_slice(&Sha256::digest(token.as_bytes()));
    } else {
        key[..token.len()].copy_from_slice(token.as_bytes());
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for i in 0..64 {
        inner_pad[i] ^= key[i];
        outer_pad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn equal_proof(actual: &str, expected: &str) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn server_proof(
    token: &str,
    server_id: &str,
    client_id: &str,
    client_nonce: &str,
    nonce: &str,
) -> String {
    mac(
        token,
        format!("symbiote/1:server:{server_id}:{client_id}:{SCOPE}:{client_nonce}:{nonce}")
            .as_bytes(),
    )
}

fn client_proof(token: &str, hello: &Hello) -> Result<String, String> {
    let value = json!({"domain":"symbiote/1:client","server_id":hello.server_id,
        "client_id":hello.client_id,"nonce":hello.nonce,"operations":hello.operations,"scope":hello.scope,
        "format":hello.format,"max_requests":hello.max_requests,"max_frame_bytes":hello.max_frame_bytes});
    Ok(mac(
        token,
        &serde_json::to_vec(&value).map_err(|_| "cannot encode authorization".to_string())?,
    ))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Agreement {
    server_id: String,
    client_id: String,
    operations: Vec<String>,
    scope: String,
    format: String,
    max_requests: u64,
    max_frame_bytes: usize,
    timeout_ms: u64,
}

pub struct ServerHandle {
    endpoint: Endpoint,
    stop: Arc<AtomicBool>,
    revoked: Arc<AtomicBool>,
    active: Arc<Mutex<Option<TcpStream>>>,
    thread: Option<JoinHandle<()>>,
}

impl ServerHandle {
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Revocation is terminal for this server instance and all its sessions.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
        if let Ok(active) = self.active.lock() {
            if let Some(stream) = active.as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }

    pub fn shutdown(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(active) = self.active.lock() {
            if let Some(stream) = active.as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| "protocol server panicked".to_string())?;
        }
        Ok(())
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

fn validate_operations(operations: &[String]) -> bool {
    !operations.is_empty()
        && operations.len() <= 32
        && operations
            .iter()
            .all(|op| valid_label(op) && !op.starts_with('$'))
        && operations.iter().collect::<BTreeSet<_>>().len() == operations.len()
}

fn read_frame(
    reader: &mut BufReader<TcpStream>,
    limit: usize,
    timeout: Duration,
) -> Result<Value, String> {
    let deadline = Instant::now() + timeout;
    let mut frame = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "frame deadline exceeded".to_string())?;
        reader
            .get_ref()
            .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
            .map_err(|_| "cannot set read timeout".to_string())?;
        let available = reader
            .fill_buf()
            .map_err(|_| "frame read failed or timed out".to_string())?;
        if available.is_empty() {
            return Err("connection closed before complete frame".into());
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let length = newline.map_or(available.len(), |position| position + 1);
        if frame.len() + length > limit {
            return Err("frame byte budget exceeded".into());
        }
        frame.extend_from_slice(&available[..length]);
        reader.consume(length);
        if newline.is_some() {
            return serde_json::from_slice(&frame).map_err(|_| "invalid JSON frame".into());
        }
    }
}

fn write_frame(stream: &mut TcpStream, value: &impl Serialize, limit: usize) -> Result<(), String> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| "cannot encode JSON frame".to_string())?;
    bytes.push(b'\n');
    if bytes.len() > limit {
        return Err("frame byte budget exceeded".into());
    }
    stream
        .write_all(&bytes)
        .map_err(|_| "frame write failed or timed out".to_string())
}

fn reply(
    reader: &mut BufReader<TcpStream>,
    id: u64,
    result: Result<Value, String>,
    limit: usize,
) -> Result<(), String> {
    let response = match result {
        Ok(value) => Response {
            version: PROTOCOL_VERSION.into(),
            request_id: id,
            ok: true,
            result: value,
            error: None,
        },
        Err(error) => Response {
            version: PROTOCOL_VERSION.into(),
            request_id: id,
            ok: false,
            result: Value::Null,
            error: Some(error),
        },
    };
    write_frame(reader.get_mut(), &response, limit)
}

/// Starts a real TCP endpoint on an OS-selected loopback port.
/// Handlers are trusted local code and must terminate; socket deadlines do not preempt Rust code.
pub fn spawn_server<F>(config: ServerConfig, handler: F) -> Result<ServerHandle, String>
where
    F: Fn(&str, Value) -> Result<Value, String> + Send + 'static,
{
    if !valid_label(&config.id)
        || !valid_label(&config.client_id)
        || config.token.len() < 16
        || config.token.len() > 256
        || !validate_operations(&config.operations)
        || !(1..=MAX_REQUESTS).contains(&config.max_requests)
        || !(1024..=MAX_FRAME).contains(&config.max_frame_bytes)
        || config.timeout < Duration::from_millis(1)
        || config.timeout > Duration::from_secs(30)
    {
        return Err("invalid server identity, authorization, or budget configuration".into());
    }
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .map_err(|e| format!("loopback bind failed: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let endpoint = Endpoint {
        id: config.id.clone(),
        address: listener.local_addr().map_err(|e| e.to_string())?,
        token: config.token.clone(),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let revoked = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(None));
    let thread_stop = stop.clone();
    let thread_revoked = revoked.clone();
    let thread_active = active.clone();
    let thread = thread::spawn(move || {
        let used = AtomicU64::new(0);
        while !thread_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, address)) => {
                    if !address.ip().is_loopback() {
                        continue;
                    }
                    // Windows inherits the listener's nonblocking mode on accepted sockets.
                    // Per-frame deadlines below require blocking I/O with explicit timeouts.
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    if let Ok(mut slot) = thread_active.lock() {
                        *slot = stream.try_clone().ok();
                    }
                    let _ = stream.set_write_timeout(Some(config.timeout));
                    let _ = stream.set_nodelay(true);
                    let mut reader = BufReader::new(stream);
                    let _ = serve_session(
                        &mut reader,
                        &config,
                        &handler,
                        &thread_stop,
                        &thread_revoked,
                        &used,
                    );
                    if let Ok(mut slot) = thread_active.lock() {
                        *slot = None;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(_) => break,
            }
        }
    });
    Ok(ServerHandle {
        endpoint,
        stop,
        revoked,
        active,
        thread: Some(thread),
    })
}

fn serve_session<F>(
    reader: &mut BufReader<TcpStream>,
    config: &ServerConfig,
    handler: &F,
    stop: &AtomicBool,
    revoked: &AtomicBool,
    used: &AtomicU64,
) -> Result<(), String>
where
    F: Fn(&str, Value) -> Result<Value, String>,
{
    if stop.load(Ordering::SeqCst) || revoked.load(Ordering::SeqCst) {
        return Err("relationship revoked".into());
    }
    let greeting: Greeting =
        serde_json::from_value(read_frame(reader, config.max_frame_bytes, config.timeout)?)
            .map_err(|_| "invalid greeting".to_string())?;
    if greeting.version != PROTOCOL_VERSION
        || greeting.server_id != config.id
        || greeting.client_id != config.client_id
        || !valid_nonce(&greeting.nonce)
    {
        return Err("greeting authorization rejected".into());
    }
    let nonce = fresh_nonce()?;
    let challenge = Challenge {
        version: PROTOCOL_VERSION.into(),
        server_id: config.id.clone(),
        client_nonce: greeting.nonce.clone(),
        nonce: nonce.clone(),
        proof: server_proof(
            &config.token,
            &config.id,
            &config.client_id,
            &greeting.nonce,
            &nonce,
        ),
    };
    write_frame(reader.get_mut(), &challenge, config.max_frame_bytes)?;
    let first: Request =
        serde_json::from_value(read_frame(reader, config.max_frame_bytes, config.timeout)?)
            .map_err(|_| "invalid request schema".to_string())?;
    let authorization = (|| {
        if first.version != PROTOCOL_VERSION || first.operation != "$hello" || first.request_id != 0
        {
            return Err("unsupported protocol or missing hello".to_string());
        }
        let hello: Hello = serde_json::from_value(first.payload.clone())
            .map_err(|_| "invalid hello schema".to_string())?;
        if revoked.load(Ordering::SeqCst) || stop.load(Ordering::SeqCst) {
            return Err("relationship revoked".into());
        }
        if hello.server_id != config.id
            || hello.client_id != config.client_id
            || hello.nonce != nonce
            || !equal_proof(&hello.proof, &client_proof(&config.token, &hello)?)
        {
            return Err("authorization denied".into());
        }
        if hello.scope != SCOPE
            || hello.format != "jsonl"
            || !validate_operations(&hello.operations)
            || !(1..=MAX_REQUESTS).contains(&hello.max_requests)
            || !(1024..=MAX_FRAME).contains(&hello.max_frame_bytes)
        {
            return Err("incompatible capabilities or budgets".into());
        }
        let operations = hello
            .operations
            .into_iter()
            .filter(|op| config.operations.contains(op))
            .collect::<Vec<_>>();
        if operations.is_empty() {
            return Err("no mutually authorized operations".into());
        }
        let remaining = config
            .max_requests
            .saturating_sub(used.load(Ordering::SeqCst));
        if remaining == 0 {
            return Err("server request budget exhausted".into());
        }
        Ok(Agreement {
            server_id: config.id.clone(),
            client_id: config.client_id.clone(),
            operations,
            scope: SCOPE.into(),
            format: "jsonl".into(),
            max_requests: remaining.min(hello.max_requests),
            max_frame_bytes: config.max_frame_bytes.min(hello.max_frame_bytes),
            timeout_ms: config.timeout.as_millis() as u64,
        })
    })();
    let agreement = match authorization {
        Ok(agreement) => agreement,
        Err(error) => {
            reply(
                reader,
                first.request_id,
                Err(error.clone()),
                config.max_frame_bytes,
            )?;
            return Err(error);
        }
    };
    reply(
        reader,
        0,
        Ok(serde_json::to_value(&agreement).map_err(|e| e.to_string())?),
        agreement.max_frame_bytes,
    )?;
    let mut expected_id = 1;
    loop {
        let request: Request = serde_json::from_value(read_frame(
            reader,
            agreement.max_frame_bytes,
            config.timeout,
        )?)
        .map_err(|_| "invalid request schema".to_string())?;
        let mut terminal = false;
        let result = if stop.load(Ordering::SeqCst) || revoked.load(Ordering::SeqCst) {
            terminal = true;
            Err("relationship revoked".into())
        } else if request.version != PROTOCOL_VERSION || request.request_id != expected_id {
            terminal = true;
            Err("protocol version or request sequence mismatch".into())
        } else if request.operation == "$revoke" {
            terminal = true;
            Ok(json!({"revoked":true}))
        } else if expected_id > agreement.max_requests
            || used.load(Ordering::SeqCst) >= config.max_requests
        {
            terminal = true;
            Err("request budget exhausted".into())
        } else if !agreement.operations.contains(&request.operation) {
            terminal = true;
            Err("operation not authorized".into())
        } else {
            used.fetch_add(1, Ordering::SeqCst);
            // This is the only dispatch surface. JSON strings are never evaluated or executed.
            handler(&request.operation, request.payload)
                .map_err(|error| error.replace(&config.token, "[REDACTED]"))
        };
        reply(
            reader,
            request.request_id,
            result,
            agreement.max_frame_bytes,
        )?;
        if terminal {
            return Ok(());
        }
        expected_id += 1;
    }
}

pub struct Client {
    reader: BufReader<TcpStream>,
    agreement: Agreement,
    next_id: u64,
    closed: bool,
}

impl Client {
    pub fn connect(
        endpoint: &Endpoint,
        client_id: &str,
        allowed_operations: &[&str],
    ) -> Result<Self, String> {
        let operations = allowed_operations
            .iter()
            .map(|op| (*op).to_string())
            .collect::<Vec<_>>();
        if !endpoint.address.ip().is_loopback()
            || !valid_label(&endpoint.id)
            || !valid_label(client_id)
            || endpoint.token.len() < 16
            || endpoint.token.len() > 256
            || !validate_operations(&operations)
        {
            return Err("invalid or non-loopback endpoint authorization".into());
        }
        let mut stream = TcpStream::connect_timeout(&endpoint.address, CONNECT_TIMEOUT)
            .map_err(|_| "connection failed or timed out".to_string())?;
        stream
            .set_write_timeout(Some(CONNECT_TIMEOUT))
            .map_err(|e| e.to_string())?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        let client_nonce = fresh_nonce()?;
        write_frame(
            &mut stream,
            &Greeting {
                version: PROTOCOL_VERSION.into(),
                server_id: endpoint.id.clone(),
                client_id: client_id.into(),
                nonce: client_nonce.clone(),
            },
            MAX_FRAME,
        )?;
        let mut reader = BufReader::new(stream);
        let challenge: Challenge =
            serde_json::from_value(read_frame(&mut reader, MAX_FRAME, CONNECT_TIMEOUT)?)
                .map_err(|_| "invalid server challenge".to_string())?;
        if challenge.version != PROTOCOL_VERSION
            || challenge.server_id != endpoint.id
            || !valid_nonce(&challenge.nonce)
            || challenge.client_nonce != client_nonce
            || !equal_proof(
                &challenge.proof,
                &server_proof(
                    &endpoint.token,
                    &endpoint.id,
                    client_id,
                    &client_nonce,
                    &challenge.nonce,
                ),
            )
        {
            return Err("server identity proof rejected".into());
        }
        let mut hello = Hello {
            server_id: endpoint.id.clone(),
            client_id: client_id.into(),
            nonce: challenge.nonce,
            proof: String::new(),
            operations: operations.clone(),
            scope: SCOPE.into(),
            format: "jsonl".into(),
            max_requests: MAX_REQUESTS,
            max_frame_bytes: MAX_FRAME,
        };
        hello.proof = client_proof(&endpoint.token, &hello)?;
        write_frame(
            reader.get_mut(),
            &Request {
                version: PROTOCOL_VERSION.into(),
                request_id: 0,
                operation: "$hello".into(),
                payload: serde_json::to_value(hello).map_err(|e| e.to_string())?,
            },
            MAX_FRAME,
        )?;
        let response: Response =
            serde_json::from_value(read_frame(&mut reader, MAX_FRAME, CONNECT_TIMEOUT)?)
                .map_err(|_| "invalid response schema".to_string())?;
        if response.version != PROTOCOL_VERSION || response.request_id != 0 || !response.ok {
            return Err(response.error.unwrap_or_else(|| "hello rejected".into()));
        }
        let agreement: Agreement =
            serde_json::from_value(response.result).map_err(|_| "invalid agreement".to_string())?;
        if agreement.server_id != endpoint.id
            || agreement.client_id != client_id
            || agreement.scope != SCOPE
            || agreement.format != "jsonl"
            || !validate_operations(&agreement.operations)
            || agreement
                .operations
                .iter()
                .any(|op| !operations.contains(op))
            || !(1..=MAX_REQUESTS).contains(&agreement.max_requests)
            || !(1024..=MAX_FRAME).contains(&agreement.max_frame_bytes)
            || !(1..=30_000).contains(&agreement.timeout_ms)
        {
            return Err("agreement exceeds authorization or budgets".into());
        }
        reader
            .get_ref()
            .set_write_timeout(Some(Duration::from_millis(agreement.timeout_ms)))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            reader,
            agreement,
            next_id: 1,
            closed: false,
        })
    }

    pub fn operations(&self) -> &[String] {
        &self.agreement.operations
    }

    pub fn call(&mut self, operation: &str, payload: &Value) -> Result<Value, String> {
        if self.closed {
            return Err("connection is closed".into());
        }
        if !self.agreement.operations.iter().any(|op| op == operation) {
            return Err("operation not authorized".into());
        }
        if self.next_id > self.agreement.max_requests {
            return Err("request budget exhausted".into());
        }
        self.exchange(operation, payload)
    }

    fn exchange(&mut self, operation: &str, payload: &Value) -> Result<Value, String> {
        let id = self.next_id;
        let request = Request {
            version: PROTOCOL_VERSION.into(),
            request_id: id,
            operation: operation.into(),
            payload: payload.clone(),
        };
        let result = (|| {
            write_frame(
                self.reader.get_mut(),
                &request,
                self.agreement.max_frame_bytes,
            )?;
            let response: Response = serde_json::from_value(read_frame(
                &mut self.reader,
                self.agreement.max_frame_bytes,
                Duration::from_millis(self.agreement.timeout_ms),
            )?)
            .map_err(|_| "invalid response schema".to_string())?;
            if response.version != PROTOCOL_VERSION || response.request_id != id {
                return Err("response identity mismatch".into());
            }
            if !response.ok {
                return Err(response.error.unwrap_or_else(|| "request rejected".into()));
            }
            Ok(response.result)
        })();
        self.next_id += 1;
        if result.is_err() {
            self.cancel();
        }
        result
    }

    /// Revokes this negotiated session; the remote endpoint retains its independent state.
    pub fn revoke(&mut self) -> Result<(), String> {
        if self.closed {
            return Err("connection is closed".into());
        }
        let result = self.exchange("$revoke", &Value::Null).map(|_| ());
        self.cancel();
        result
    }

    /// Cooperative cancellation closes the socket immediately.
    pub fn cancel(&mut self) {
        self.closed = true;
        let _ = self.reader.get_mut().shutdown(Shutdown::Both);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ServerConfig {
        ServerConfig {
            id: "partner".into(),
            token: "test-only-capability-123".into(),
            client_id: "symbiote".into(),
            operations: vec!["observe".into(), "exchange".into()],
            max_requests: 8,
            max_frame_bytes: 4096,
            timeout: Duration::from_millis(250),
        }
    }
    #[test]
    fn real_tcp_negotiates_and_transfers_inert_data() {
        let server = spawn_server(config(), |_, payload| Ok(payload)).unwrap();
        let endpoint = server.endpoint();
        assert!(!format!("{endpoint:?}").contains(&endpoint.token));
        let mut client = Client::connect(&endpoint, "symbiote", &["observe", "forbidden"]).unwrap();
        assert_eq!(client.operations(), &["observe"]);
        let instruction = json!({"text":"delete all files; this remains inert data"});
        assert_eq!(client.call("observe", &instruction).unwrap(), instruction);
        assert!(client.call("forbidden", &Value::Null).is_err());
        client.revoke().unwrap();
        assert!(client.call("observe", &Value::Null).is_err());
    }
    #[test]
    fn denies_wrong_token_identity_and_missing_capabilities() {
        let server = spawn_server(config(), |_, payload| Ok(payload)).unwrap();
        let endpoint = server.endpoint();
        let mut wrong = endpoint.clone();
        wrong.token = "invalid-token-123456".into();
        assert!(Client::connect(&wrong, "symbiote", &["observe"]).is_err());
        assert!(Client::connect(&endpoint, "intruder", &["observe"]).is_err());
        wrong = endpoint.clone();
        wrong.id = "impostor".into();
        assert!(Client::connect(&wrong, "symbiote", &["observe"]).is_err());
        assert!(Client::connect(&endpoint, "symbiote", &["forbidden"]).is_err());
        assert!(Client::connect(&endpoint, "symbiote", &["observe"]).is_ok());
    }
    #[test]
    fn global_budget_cannot_be_reset_by_reconnecting() {
        let mut cfg = config();
        cfg.max_requests = 1;
        let server = spawn_server(cfg, |_, payload| Ok(payload)).unwrap();
        let mut client = Client::connect(&server.endpoint(), "symbiote", &["observe"]).unwrap();
        client.call("observe", &Value::Null).unwrap();
        assert!(client.call("observe", &Value::Null).is_err());
        drop(client);
        assert!(Client::connect(&server.endpoint(), "symbiote", &["observe"]).is_err());
    }
    #[test]
    fn oversized_frames_are_rejected_and_server_recovers() {
        let server = spawn_server(config(), |_, payload| Ok(payload)).unwrap();
        let mut client = Client::connect(&server.endpoint(), "symbiote", &["observe"]).unwrap();
        assert!(client.call("observe", &json!("x".repeat(5000))).is_err());
        let mut raw = TcpStream::connect(server.endpoint().address).unwrap();
        raw.write_all(&vec![b'x'; 5000]).unwrap();
        drop(raw);
        let mut recovered = Client::connect(&server.endpoint(), "symbiote", &["observe"]).unwrap();
        assert_eq!(recovered.call("observe", &json!(1)).unwrap(), json!(1));
    }
    #[test]
    fn unsupported_protocol_rejected_before_handler() {
        let server = spawn_server(config(), |_, _| panic!("unauthorized dispatch")).unwrap();
        let stream = TcpStream::connect(server.endpoint().address).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let greeting = Greeting {
            version: PROTOCOL_VERSION.into(),
            server_id: server.endpoint().id,
            client_id: "symbiote".into(),
            nonce: fresh_nonce().unwrap(),
        };
        write_frame(reader.get_mut(), &greeting, 4096).unwrap();
        let _: Challenge = serde_json::from_value(
            read_frame(&mut reader, 4096, Duration::from_millis(250)).unwrap(),
        )
        .unwrap();
        let request = Request {
            version: "symbiote/999".into(),
            request_id: 0,
            operation: "$hello".into(),
            payload: Value::Null,
        };
        write_frame(reader.get_mut(), &request, 4096).unwrap();
        let response: Response = serde_json::from_value(
            read_frame(&mut reader, 4096, Duration::from_millis(250)).unwrap(),
        )
        .unwrap();
        assert!(!response.ok);
    }
    #[test]
    fn revocation_and_cancel_terminate_active_sessions() {
        let server = spawn_server(config(), |_, payload| Ok(payload)).unwrap();
        let mut client = Client::connect(&server.endpoint(), "symbiote", &["observe"]).unwrap();
        server.revoke();
        assert!(client.call("observe", &Value::Null).is_err());
        drop(client);
        assert!(Client::connect(&server.endpoint(), "symbiote", &["observe"]).is_err());
    }
    #[test]
    fn operation_timeout_is_reported() {
        let mut cfg = config();
        cfg.timeout = Duration::from_millis(25);
        let server = spawn_server(cfg, |_, payload| {
            thread::sleep(Duration::from_millis(70));
            Ok(payload)
        })
        .unwrap();
        let mut client = Client::connect(&server.endpoint(), "symbiote", &["observe"]).unwrap();
        assert!(client.call("observe", &Value::Null).is_err());
        assert!(client.call("observe", &Value::Null).is_err());
    }
    #[test]
    fn invalid_configs_and_remote_endpoint_denied() {
        let mut cfg = config();
        cfg.token = "short".into();
        assert!(spawn_server(cfg, |_, payload| Ok(payload)).is_err());
        let endpoint = Endpoint {
            id: "partner".into(),
            address: "192.0.2.1:8080".parse().unwrap(),
            token: "test-capability-token".into(),
        };
        assert!(Client::connect(&endpoint, "symbiote", &["observe"]).is_err());
    }
    #[test]
    fn hmac_matches_standard_vector() {
        assert_eq!(
            mac("key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn server_enforces_operations_sequence_and_budget_without_client_checks() {
        let server = spawn_server(config(), |_, value| Ok(value)).unwrap();
        let mut client = Client::connect(&server.endpoint(), "symbiote", &["observe"]).unwrap();
        assert!(client.exchange("forbidden", &Value::Null).is_err());
        let mut client = Client::connect(&server.endpoint(), "symbiote", &["observe"]).unwrap();
        client.next_id = 2;
        assert!(client.exchange("observe", &Value::Null).is_err());

        let mut cfg = config();
        cfg.max_requests = 1;
        let limited = spawn_server(cfg, |_, value| Ok(value)).unwrap();
        let mut client = Client::connect(&limited.endpoint(), "symbiote", &["observe"]).unwrap();
        client.call("observe", &Value::Null).unwrap();
        client.agreement.max_requests = 100;
        assert!(client.call("observe", &Value::Null).is_err());
    }

    #[test]
    fn unauthenticated_stall_expires_then_next_client_can_connect() {
        let mut cfg = config();
        cfg.timeout = Duration::from_millis(50);
        let server = spawn_server(cfg, |_, value| Ok(value)).unwrap();
        let mut stalled = TcpStream::connect(server.endpoint().address).unwrap();
        stalled.write_all(b"{").unwrap();
        let mut client = Client::connect(&server.endpoint(), "symbiote", &["observe"]).unwrap();
        assert_eq!(client.call("observe", &json!(1)).unwrap(), json!(1));
    }

    #[test]
    fn stale_server_proof_rejected_before_client_authorization() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = Endpoint {
            id: "partner".into(),
            address: listener.local_addr().unwrap(),
            token: "test-only-capability-123".into(),
        };
        let remote = endpoint.clone();
        let fake = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_write_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let mut reader = BufReader::new(stream);
            let greeting = read_frame(&mut reader, 4096, Duration::from_millis(250)).unwrap();
            assert!(!greeting.to_string().contains(&remote.token));
            let stale_client_nonce = fresh_nonce().unwrap();
            let nonce = fresh_nonce().unwrap();
            let challenge = Challenge {
                version: PROTOCOL_VERSION.into(),
                server_id: remote.id.clone(),
                client_nonce: stale_client_nonce.clone(),
                nonce: nonce.clone(),
                proof: server_proof(
                    &remote.token,
                    &remote.id,
                    "symbiote",
                    &stale_client_nonce,
                    &nonce,
                ),
            };
            write_frame(reader.get_mut(), &challenge, 4096).unwrap();
            assert!(read_frame(&mut reader, 4096, Duration::from_millis(250)).is_err());
        });
        assert!(Client::connect(&endpoint, "symbiote", &["observe"]).is_err());
        fake.join().unwrap();
    }

    #[test]
    fn client_proof_binds_capabilities_and_cannot_be_replayed() {
        fn open(endpoint: &Endpoint) -> (BufReader<TcpStream>, Challenge) {
            let stream = TcpStream::connect(endpoint.address).unwrap();
            stream
                .set_write_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let mut reader = BufReader::new(stream);
            write_frame(
                reader.get_mut(),
                &Greeting {
                    version: PROTOCOL_VERSION.into(),
                    server_id: endpoint.id.clone(),
                    client_id: "symbiote".into(),
                    nonce: fresh_nonce().unwrap(),
                },
                4096,
            )
            .unwrap();
            let challenge = serde_json::from_value(
                read_frame(&mut reader, 4096, Duration::from_millis(250)).unwrap(),
            )
            .unwrap();
            (reader, challenge)
        }
        let server = spawn_server(config(), |_, value| Ok(value)).unwrap();
        let endpoint = server.endpoint();
        let (mut first, challenge) = open(&endpoint);
        let mut hello = Hello {
            server_id: endpoint.id.clone(),
            client_id: "symbiote".into(),
            nonce: challenge.nonce,
            proof: String::new(),
            operations: vec!["observe".into()],
            scope: SCOPE.into(),
            format: "jsonl".into(),
            max_requests: 8,
            max_frame_bytes: 4096,
        };
        hello.proof = client_proof(&endpoint.token, &hello).unwrap();
        // Mutating a signed proposal invalidates its proof.
        hello.operations.push("exchange".into());
        write_frame(
            first.get_mut(),
            &Request {
                version: PROTOCOL_VERSION.into(),
                request_id: 0,
                operation: "$hello".into(),
                payload: serde_json::to_value(&hello).unwrap(),
            },
            4096,
        )
        .unwrap();
        let rejected: Response = serde_json::from_value(
            read_frame(&mut first, 4096, Duration::from_millis(250)).unwrap(),
        )
        .unwrap();
        assert!(!rejected.ok);
        drop(first);
        let (mut second, _) = open(&endpoint);
        hello.operations.pop();
        // The original valid proof still cannot authenticate a new server challenge.
        write_frame(
            second.get_mut(),
            &Request {
                version: PROTOCOL_VERSION.into(),
                request_id: 0,
                operation: "$hello".into(),
                payload: serde_json::to_value(&hello).unwrap(),
            },
            4096,
        )
        .unwrap();
        let rejected: Response = serde_json::from_value(
            read_frame(&mut second, 4096, Duration::from_millis(250)).unwrap(),
        )
        .unwrap();
        assert!(!rejected.ok);
    }
}
