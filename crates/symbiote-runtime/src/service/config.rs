use super::{digest, label, OPERATIONS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use symbiote_protocol::{
    SecureEndpoint, SecureLimits, SecurePeerGrant, SecureServerConfig, TlsClientConfig, TlsIdentity,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub max_requests: u64,
    pub max_connections: u64,
    pub max_frame_bytes: usize,
    pub timeout_ms: u64,
    pub lifetime_ms: u64,
    pub per_peer_requests: u64,
    pub max_offers: usize,
    pub max_offer_bytes: usize,
    pub model_work: usize,
}
impl Limits {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=1024).contains(&self.max_requests)
            || !(1..=1024).contains(&self.max_connections)
            || !(1024..=65_536).contains(&self.max_frame_bytes)
            || !(50..=3000).contains(&self.timeout_ms)
            || !(1000..=600_000).contains(&self.lifetime_ms)
            || self.per_peer_requests == 0
            || self.per_peer_requests > self.max_requests
            || !(1..=64).contains(&self.max_offers)
            || !(1024..=32_768).contains(&self.max_offer_bytes)
            || self.max_offer_bytes + 1024 > self.max_frame_bytes
            || !(1024..=1_000_000).contains(&self.model_work)
        {
            return Err("configured service limits are outside supported finite bounds".into());
        }
        Ok(())
    }
    pub fn transport(&self) -> SecureLimits {
        SecureLimits {
            max_requests: self.max_requests,
            max_connections: self.max_connections,
            max_frame_bytes: self.max_frame_bytes,
            timeout: Duration::from_millis(self.timeout_ms),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Access {
    pub scope: String,
    pub operations: Vec<String>,
    pub artifacts: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Peer {
    pub alias: String,
    pub id: String,
    pub address: SocketAddr,
    pub server_name: String,
    pub certificate_sha256: String,
    pub access: Vec<Access>,
}
impl Peer {
    pub fn access(&self, scope: &str, operation: &str) -> Result<&Access, String> {
        self.access
            .iter()
            .find(|access| {
                access.scope == scope && access.operations.iter().any(|op| op == operation)
            })
            .ok_or_else(|| "peer operation is outside the configured context grant".into())
    }
}
impl Access {
    pub fn permits_artifact(&self, artifact: &str) -> bool {
        self.artifacts.iter().any(|id| id == "*" || id == artifact)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    pub scope: String,
    pub schema_fingerprint: String,
    pub truth_fixture: Option<PathBuf>,
    pub truth_sha256: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    state: PathBuf,
    identity: String,
    certificate: PathBuf,
    private_key: PathBuf,
    certificate_sha256: String,
    ca_certificate: PathBuf,
    bind_address: SocketAddr,
    peers: Vec<Peer>,
    contexts: Vec<Context>,
    limits: Limits,
}

pub(super) struct Config {
    pub state: PathBuf,
    pub identity: String,
    pub policy_digest: String,
    pub bind_address: SocketAddr,
    pub peers: Vec<Peer>,
    pub contexts: Vec<Context>,
    pub limits: Limits,
    certificate: Vec<u8>,
    key: Vec<u8>,
    ca: Vec<u8>,
    directory: PathBuf,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let manifest: Manifest = serde_json::from_slice(&read_bounded(path, 65_536)?)
            .map_err(|_| "service configuration rejected")?;
        if manifest.schema != "symbiote.service-config/1"
            || !label(&manifest.identity)
            || manifest.bind_address.ip().is_unspecified()
            || manifest.bind_address.ip().is_multicast()
            || manifest.peers.is_empty()
            || manifest.peers.len() > 32
            || manifest.contexts.is_empty()
            || manifest.contexts.len() > 8
        {
            return Err(
                "service identity, explicit unicast address or registry bounds rejected".into(),
            );
        }
        manifest.limits.validate()?;
        let mut scopes = BTreeSet::new();
        for context in &manifest.contexts {
            if !label(&context.scope)
                || !scopes.insert(&context.scope)
                || !sha(&context.schema_fingerprint)
                || context.truth_fixture.is_some() != context.truth_sha256.is_some()
                || context
                    .truth_sha256
                    .as_ref()
                    .is_some_and(|value| !sha(value))
            {
                return Err(
                    "service contexts need unique scopes and explicit schema/truth bindings".into(),
                );
            }
        }
        let mut ids = BTreeSet::from([manifest.identity.as_str()]);
        let mut aliases = BTreeSet::new();
        let mut pins = BTreeSet::from([manifest.certificate_sha256.to_ascii_lowercase()]);
        for peer in &manifest.peers {
            if !label(&peer.id)
                || !label(&peer.alias)
                || !ids.insert(&peer.id)
                || !aliases.insert(&peer.alias)
                || !sha(&peer.certificate_sha256)
                || !pins.insert(peer.certificate_sha256.to_ascii_lowercase())
                || peer.address.port() == 0
                || peer.address.ip().is_unspecified()
                || peer.address.ip().is_multicast()
                || peer.server_name.is_empty()
                || peer.server_name.len() > 253
                || !peer.server_name.is_ascii()
                || peer.access.is_empty()
                || peer.access.len() > 8
            {
                return Err("service registry requires distinct explicit bounded peer identities, aliases, pins and endpoints".into());
            }
            let mut peer_scopes = BTreeSet::new();
            for access in &peer.access {
                if !scopes.contains(&access.scope)
                    || !peer_scopes.insert(&access.scope)
                    || access.operations.is_empty()
                    || access.operations.len() > OPERATIONS.len()
                    || access
                        .operations
                        .iter()
                        .any(|operation| !OPERATIONS.contains(&operation.as_str()))
                    || access.operations.iter().collect::<BTreeSet<_>>().len()
                        != access.operations.len()
                    || access.artifacts.is_empty()
                    || access.artifacts.len() > 32
                    || access.artifacts.iter().any(|id| id != "*" && !label(id))
                {
                    return Err(
                        "service grant has an unsupported operation, context or artifact allowlist"
                            .into(),
                    );
                }
            }
        }
        let directory = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let certificate = read_bounded(&directory.join(&manifest.certificate), 65_536)?;
        let key = read_bounded(&directory.join(&manifest.private_key), 16_384)?;
        let ca = read_bounded(&directory.join(&manifest.ca_certificate), 65_536)?;
        let identity = TlsIdentity::from_pem(&certificate, &key)?;
        if !identity
            .certificate_sha256()
            .eq_ignore_ascii_case(&manifest.certificate_sha256)
        {
            return Err("service credential differs from the provisioned leaf pin".into());
        }
        TlsClientConfig::new(manifest.identity.clone(), identity, &ca)?;
        let policy_digest =
            digest(&serde_json::json!({"manifest":manifest,"ca_sha256":hash_bytes(&ca)}))?;
        Ok(Self {
            state: directory.join(manifest.state),
            identity: manifest.identity,
            policy_digest,
            bind_address: manifest.bind_address,
            peers: manifest.peers,
            contexts: manifest.contexts,
            limits: manifest.limits,
            certificate,
            key,
            ca,
            directory,
        })
    }
    pub fn context(&self, scope: &str) -> Result<&Context, String> {
        self.contexts
            .iter()
            .find(|context| context.scope == scope)
            .ok_or_else(|| "context is not configured".into())
    }
    pub fn peer(&self, id: &str) -> Result<&Peer, String> {
        self.peers
            .iter()
            .find(|peer| peer.id == id)
            .ok_or_else(|| "peer identity has no configured grant".into())
    }
    pub fn fixture(&self, context: &Context) -> Result<Vec<u8>, String> {
        let bytes = read_bounded(
            &self.directory.join(
                context
                    .truth_fixture
                    .as_ref()
                    .ok_or("context has no local truth fixture")?,
            ),
            65_536,
        )?;
        if Some(hash_bytes(&bytes)).as_ref() != context.truth_sha256.as_ref() {
            return Err("local truth fixture differs from its pinned bytes".into());
        }
        Ok(bytes)
    }
    pub fn client(&self) -> Result<TlsClientConfig, String> {
        TlsClientConfig::new(
            self.identity.clone(),
            TlsIdentity::from_pem(&self.certificate, &self.key)?,
            &self.ca,
        )
    }
    pub fn endpoint(&self, peer: &Peer, scope: &str, operation: &str) -> SecureEndpoint {
        SecureEndpoint {
            server_id: peer.id.clone(),
            address: peer.address,
            server_name: peer.server_name.clone(),
            server_certificate_sha256: peer.certificate_sha256.clone(),
            scope: scope.into(),
            operations: vec![operation.into()],
            limits: self.limits.transport(),
        }
    }
    pub fn server(&self, denied: &BTreeSet<String>) -> Result<SecureServerConfig, String> {
        let grants = self
            .peers
            .iter()
            .filter(|peer| !denied.contains(&peer.id))
            .map(|peer| SecurePeerGrant {
                id: peer.id.clone(),
                certificate_sha256: peer.certificate_sha256.clone(),
                scopes: peer
                    .access
                    .iter()
                    .map(|access| (access.scope.clone(), access.operations.clone()))
                    .collect::<BTreeMap<_, _>>(),
            })
            .collect();
        SecureServerConfig::new(
            self.bind_address,
            self.identity.clone(),
            TlsIdentity::from_pem(&self.certificate, &self.key)?,
            &self.ca,
            grants,
            self.limits.transport(),
        )
    }
}
pub(super) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|_| "cannot open configured service file")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect configured service file")?
        .is_file()
    {
        return Err("configured service input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read configured service file")?;
    if bytes.len() > limit {
        return Err("configured service file exceeds its byte budget".into());
    }
    Ok(bytes)
}
pub(super) fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
pub(super) fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
