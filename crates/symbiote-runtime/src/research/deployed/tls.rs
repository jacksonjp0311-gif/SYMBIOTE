//! Operator-provisioned credentials for the controlled native-process experiment.
//! Secret material is neither Debug nor included in errors or public receipts.
use super::{AGENT_OPS, ORACLE_OPS, SCOPE};
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

const MANIFEST_LIMIT: usize = 16_384;
const CERTIFICATE_LIMIT: usize = 65_536;
const KEY_LIMIT: usize = 16_384;
pub(super) const BOOTSTRAP_LIMIT: usize = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bounds {
    pub max_requests: u64,
    pub max_connections: u64,
    pub max_frame_bytes: usize,
    pub timeout_ms: u64,
}
impl Bounds {
    pub fn limits(&self) -> Result<SecureLimits, String> {
        if !(64..=512).contains(&self.max_requests)
            || !(32..=256).contains(&self.max_connections)
            || !(16_384..=65_536).contains(&self.max_frame_bytes)
            || !(50..=3000).contains(&self.timeout_ms)
        {
            return Err(
                "TLS deployment limits are outside the controlled experiment budget".into(),
            );
        }
        Ok(SecureLimits {
            max_requests: self.max_requests,
            max_connections: self.max_connections,
            max_frame_bytes: self.max_frame_bytes,
            timeout: Duration::from_millis(self.timeout_ms),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFiles {
    id: String,
    certificate: PathBuf,
    private_key: PathBuf,
    certificate_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceFiles {
    id: String,
    certificate: PathBuf,
    private_key: PathBuf,
    certificate_sha256: String,
    server_name: String,
    bind_address: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    scope: String,
    ca_certificate: PathBuf,
    controller: CredentialFiles,
    exact: ServiceFiles,
    linear: ServiceFiles,
    oracle_exact: ServiceFiles,
    oracle_linear: ServiceFiles,
    limits: Bounds,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Material {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub certificate_sha256: String,
}
impl Material {
    pub fn identity(&self) -> Result<TlsIdentity, String> {
        let identity = TlsIdentity::from_pem(
            self.certificate_pem.as_bytes(),
            self.private_key_pem.as_bytes(),
        )?;
        if !identity
            .certificate_sha256()
            .eq_ignore_ascii_case(&self.certificate_sha256)
        {
            return Err("provisioned TLS certificate does not match its explicit pin".into());
        }
        Ok(identity)
    }
}

pub(super) struct Service {
    pub id: String,
    pub material: Material,
    pub server_name: String,
    pub bind_address: SocketAddr,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bootstrap {
    pub material: Material,
    pub ca_pem: String,
    pub controller_pin: String,
    pub bind_address: SocketAddr,
    pub server_name: String,
    pub oracle_pin: String,
    pub oracle_server_name: String,
    pub limits: Bounds,
}
impl Bootstrap {
    pub fn validate(&self) -> Result<(), String> {
        self.limits.limits()?;
        loopback(self.bind_address)?;
        validate_name(&self.server_name)?;
        validate_name(&self.oracle_server_name)?;
        validate_pin(&self.controller_pin)?;
        validate_pin(&self.oracle_pin)?;
        if self.ca_pem.is_empty() || self.ca_pem.len() > CERTIFICATE_LIMIT {
            return Err("TLS bootstrap CA exceeds its byte limit or is empty".into());
        }
        self.material.identity()?;
        Ok(())
    }
    pub fn client(&self, id: &str) -> Result<TlsClientConfig, String> {
        TlsClientConfig::new(id.into(), self.material.identity()?, self.ca_pem.as_bytes())
    }
    pub fn server(&self, id: &str, controller: &str) -> Result<SecureServerConfig, String> {
        self.validate()?;
        SecureServerConfig::new(
            self.bind_address,
            id.into(),
            self.material.identity()?,
            self.ca_pem.as_bytes(),
            vec![grant(controller, &self.controller_pin, AGENT_OPS)],
            self.limits.limits()?,
        )
    }
    pub fn oracle_endpoint(&self, id: &str, address: SocketAddr) -> Result<SecureEndpoint, String> {
        Ok(endpoint(
            id,
            address,
            &self.oracle_server_name,
            &self.oracle_pin,
            ORACLE_OPS,
            self.limits.limits()?,
        ))
    }
}

pub(super) struct Deployment {
    pub controller_id: String,
    pub controller: TlsClientConfig,
    pub controller_pin: String,
    pub ca_pem: String,
    pub exact: Service,
    pub linear: Service,
    pub oracle_exact: Service,
    pub oracle_linear: Service,
    pub limits: Bounds,
}
impl Deployment {
    pub fn load(state: &Path, path: &Path) -> Result<Self, String> {
        let manifest: Manifest = serde_json::from_slice(&read_bounded(path, MANIFEST_LIMIT)?)
            .map_err(|_| "TLS deployment manifest rejected")?;
        if manifest.schema != "symbiote.tls-deployment/1" || manifest.scope != SCOPE {
            return Err("TLS deployment manifest version or scope rejected".into());
        }
        manifest.limits.limits()?;
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let ca_pem = read_text(&directory.join(&manifest.ca_certificate), CERTIFICATE_LIMIT)?;
        let controller_material = load_material(
            directory,
            &manifest.controller.certificate,
            &manifest.controller.private_key,
            &manifest.controller.certificate_sha256,
        )?;
        let exact = load_service(directory, manifest.exact)?;
        let linear = load_service(directory, manifest.linear)?;
        let oracle_exact = load_service(directory, manifest.oracle_exact)?;
        let oracle_linear = load_service(directory, manifest.oracle_linear)?;
        let mut ids = BTreeSet::new();
        let mut pins = BTreeSet::new();
        for (id, pin) in [
            (
                &manifest.controller.id,
                &controller_material.certificate_sha256,
            ),
            (&exact.id, &exact.material.certificate_sha256),
            (&linear.id, &linear.material.certificate_sha256),
            (&oracle_exact.id, &oracle_exact.material.certificate_sha256),
            (
                &oracle_linear.id,
                &oracle_linear.material.certificate_sha256,
            ),
        ] {
            if !ids.insert(id) || !pins.insert(pin.to_ascii_lowercase()) {
                return Err("TLS roles require distinct identities and certificate pins".into());
            }
        }
        for (directory, expected) in [
            (state.to_path_buf(), manifest.controller.id.as_str()),
            (state.join("network-tls/exact"), exact.id.as_str()),
            (state.join("network-tls/linear"), linear.id.as_str()),
        ] {
            let inspected = symbiote_memory::maintenance::inspect(&directory)?;
            if inspected.identity.as_deref() != Some(expected) {
                return Err("TLS role does not match its prepared persistent identity; run prepare-tls-state and provision the exact IDs".into());
            }
        }
        let controller = TlsClientConfig::new(
            manifest.controller.id.clone(),
            controller_material.identity()?,
            ca_pem.as_bytes(),
        )?;
        Ok(Self {
            controller_id: manifest.controller.id,
            controller,
            controller_pin: controller_material.certificate_sha256,
            ca_pem,
            exact,
            linear,
            oracle_exact,
            oracle_linear,
            limits: manifest.limits,
        })
    }
    pub fn bootstrap(&self, linear: bool) -> Bootstrap {
        let (agent, oracle) = if linear {
            (&self.linear, &self.oracle_linear)
        } else {
            (&self.exact, &self.oracle_exact)
        };
        Bootstrap {
            material: agent.material.clone(),
            ca_pem: self.ca_pem.clone(),
            controller_pin: self.controller_pin.clone(),
            bind_address: agent.bind_address,
            server_name: agent.server_name.clone(),
            oracle_pin: oracle.material.certificate_sha256.clone(),
            oracle_server_name: oracle.server_name.clone(),
            limits: self.limits.clone(),
        }
    }
    pub fn oracle_server(&self, linear: bool) -> Result<SecureServerConfig, String> {
        let (agent, oracle) = if linear {
            (&self.linear, &self.oracle_linear)
        } else {
            (&self.exact, &self.oracle_exact)
        };
        SecureServerConfig::new(
            oracle.bind_address,
            oracle.id.clone(),
            oracle.material.identity()?,
            self.ca_pem.as_bytes(),
            vec![grant(
                &agent.id,
                &agent.material.certificate_sha256,
                ORACLE_OPS,
            )],
            self.limits.limits()?,
        )
    }
    pub fn agent_endpoint(
        &self,
        linear: bool,
        address: SocketAddr,
    ) -> Result<SecureEndpoint, String> {
        let agent = if linear { &self.linear } else { &self.exact };
        Ok(endpoint(
            &agent.id,
            address,
            &agent.server_name,
            &agent.material.certificate_sha256,
            AGENT_OPS,
            self.limits.limits()?,
        ))
    }
}

fn grant(id: &str, pin: &str, operations: &[&str]) -> SecurePeerGrant {
    SecurePeerGrant {
        id: id.into(),
        certificate_sha256: pin.into(),
        scopes: BTreeMap::from([(
            SCOPE.into(),
            operations
                .iter()
                .map(|operation| (*operation).into())
                .collect(),
        )]),
    }
}
fn endpoint(
    id: &str,
    address: SocketAddr,
    name: &str,
    pin: &str,
    operations: &[&str],
    limits: SecureLimits,
) -> SecureEndpoint {
    SecureEndpoint {
        server_id: id.into(),
        address,
        server_name: name.into(),
        server_certificate_sha256: pin.into(),
        scope: SCOPE.into(),
        operations: operations
            .iter()
            .map(|operation| (*operation).into())
            .collect(),
        limits,
    }
}
fn load_service(directory: &Path, files: ServiceFiles) -> Result<Service, String> {
    loopback(files.bind_address)?;
    validate_name(&files.server_name)?;
    Ok(Service {
        id: files.id,
        material: load_material(
            directory,
            &files.certificate,
            &files.private_key,
            &files.certificate_sha256,
        )?,
        server_name: files.server_name,
        bind_address: files.bind_address,
    })
}
fn load_material(
    directory: &Path,
    certificate: &Path,
    key: &Path,
    pin: &str,
) -> Result<Material, String> {
    validate_pin(pin)?;
    let material = Material {
        certificate_pem: read_text(&directory.join(certificate), CERTIFICATE_LIMIT)?,
        private_key_pem: read_text(&directory.join(key), KEY_LIMIT)?,
        certificate_sha256: pin.to_ascii_lowercase(),
    };
    material.identity()?;
    Ok(material)
}
fn loopback(address: SocketAddr) -> Result<(), String> {
    if !address.ip().is_loopback() {
        return Err("supervised TLS experiment requires explicit loopback bind addresses".into());
    }
    Ok(())
}
fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err("TLS server name is invalid or unbounded".into());
    }
    Ok(())
}
fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.len() != 64 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("TLS certificate pin must contain 64 hexadecimal characters".into());
    }
    Ok(())
}
fn read_text(path: &Path, limit: usize) -> Result<String, String> {
    String::from_utf8(read_bounded(path, limit)?)
        .map_err(|_| "TLS credential file must use UTF-8 PEM".into())
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|_| "cannot open configured TLS file")?;
    if file
        .metadata()
        .map_err(|_| "cannot inspect configured TLS file")?
        .len()
        > limit as u64
    {
        return Err("configured TLS file exceeds its byte budget".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read configured TLS file")?;
    if bytes.len() > limit {
        return Err("configured TLS file exceeds its byte budget".into());
    }
    Ok(bytes)
}
