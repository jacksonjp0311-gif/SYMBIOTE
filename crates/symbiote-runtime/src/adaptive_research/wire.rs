//! Credentials are minted only for this process-owned loopback laboratory.
//! No secret material implements Debug or enters readiness, arguments or receipts.
use super::policy::Arm;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use symbiote_protocol::{
    SecureEndpoint, SecureLimits, SecurePeerGrant, SecureServerConfig, TlsClientConfig, TlsIdentity,
};

pub(super) const SCOPE: &str = "prospective-frontier-graph/v1";
pub(super) const NAME: &str = "owned-adaptive-lab.symbiote.test";
pub(super) const CONTROL_OPS: &[&str] = &[
    "configure",
    "begin",
    "warmup",
    "advance",
    "forecast",
    "export-page",
    "finish",
    "retained-page",
];
pub(super) const PEER_OPS: &[&str] = &["advertise", "request-edge"];
pub(super) const AUTHORITY_OPS: &[&str] = &["observe", "verify", "assess"];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Material {
    pub(super) certificate_pem: String,
    pub(super) private_key_pem: String,
    pub(super) pin: String,
}
impl Material {
    pub(super) fn identity(&self) -> Result<TlsIdentity, String> {
        let identity = TlsIdentity::from_pem(
            self.certificate_pem.as_bytes(),
            self.private_key_pem.as_bytes(),
        )?;
        if identity.certificate_sha256() != self.pin {
            return Err("owned laboratory certificate does not match its explicit pin".into());
        }
        Ok(identity)
    }
}
pub(super) struct LabCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
    pub(super) pem: String,
}
impl LabCa {
    pub(super) fn new() -> Result<Self, String> {
        let mut parameters = CertificateParams::new(Vec::<String>::new())
            .map_err(|_| "owned laboratory CA parameters failed")?;
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let issuer = CertifiedIssuer::self_signed(
            parameters,
            KeyPair::generate().map_err(|_| "owned laboratory CA key failed")?,
        )
        .map_err(|_| "owned laboratory CA creation failed")?;
        let pem = issuer.pem();
        Ok(Self { issuer, pem })
    }
    pub(super) fn leaf(&self) -> Result<Material, String> {
        let mut parameters = CertificateParams::new(vec![NAME.into()])
            .map_err(|_| "owned leaf parameters failed")?;
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let key = KeyPair::generate().map_err(|_| "owned leaf key failed")?;
        let certificate = parameters
            .signed_by(&key, &self.issuer)
            .map_err(|_| "owned leaf signing failed")?;
        let certificate_pem = certificate.pem();
        let private_key_pem = key.serialize_pem();
        let identity =
            TlsIdentity::from_pem(certificate_pem.as_bytes(), private_key_pem.as_bytes())?;
        Ok(Material {
            certificate_pem,
            private_key_pem,
            pin: identity.certificate_sha256().into(),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicEndpoint {
    pub(super) identity: String,
    pub(super) address: SocketAddr,
    pub(super) pin: String,
    pub(super) scope: String,
}
impl PublicEndpoint {
    pub(super) fn endpoint(&self, operation: &str, frame: usize) -> Result<SecureEndpoint, String> {
        if !self.address.ip().is_loopback()
            || self.pin.len() != 64
            || !self.pin.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !label(&self.identity)
        {
            return Err("owned loopback endpoint or explicit pin invalid".into());
        }
        Ok(SecureEndpoint {
            server_id: self.identity.clone(),
            address: self.address,
            server_name: NAME.into(),
            server_certificate_sha256: self.pin.clone(),
            scope: self.scope.clone(),
            operations: vec![operation.into()],
            limits: SecureLimits {
                max_requests: 1,
                max_connections: 1,
                max_frame_bytes: frame,
                timeout: Duration::from_secs(2),
            },
        })
    }
}
pub(super) fn label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 128
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Grant {
    pub(super) identity: String,
    pub(super) pin: String,
    pub(super) scope: String,
    pub(super) operations: Vec<String>,
}
impl Grant {
    pub(super) fn secure(&self) -> SecurePeerGrant {
        SecurePeerGrant {
            id: self.identity.clone(),
            certificate_sha256: self.pin.clone(),
            scopes: BTreeMap::from([(self.scope.clone(), self.operations.clone())]),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    pub(super) identity: String,
    pub(super) authorized: bool,
    pub(super) compatible: bool,
    pub(super) endpoint: Option<PublicEndpoint>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OfferMode {
    CurrentWarmup,
    PreviousContext,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Role {
    Learner {
        arm: Arm,
        observation_price: u64,
        offer_mode: OfferMode,
        inactive: bool,
    },
    Authority {
        worlds: Vec<AuthorityWorld>,
        allowed_observers: BTreeMap<String, Vec<String>>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityWorld {
    pub(super) context: String,
    pub(super) schema: symbiote_reasoning::planning::GraphSchema,
    pub(super) costs: Vec<u16>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bootstrap {
    pub(super) state: PathBuf,
    pub(super) expected_identity: String,
    pub(super) controller_identity: String,
    pub(super) material: Material,
    pub(super) ca_pem: String,
    pub(super) grants: Vec<Grant>,
    pub(super) role: Role,
    pub(super) protocol_sha256: String,
}
impl Bootstrap {
    pub(super) fn validate(&self) -> Result<(), String> {
        if !label(&self.expected_identity)
            || !label(&self.controller_identity)
            || self.expected_identity == self.controller_identity
            || self.ca_pem.len() > 16_384
            || self.material.certificate_pem.len() > 16_384
            || self.material.private_key_pem.len() > 8192
            || self.protocol_sha256.len() != 64
            || !self
                .protocol_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.grants.len() > 42
        {
            return Err("owned laboratory bootstrap bounds invalid".into());
        }
        self.material.identity()?;
        Ok(())
    }
    pub(super) fn client(&self) -> Result<TlsClientConfig, String> {
        TlsClientConfig::new(
            self.expected_identity.clone(),
            self.material.identity()?,
            self.ca_pem.as_bytes(),
        )
    }
    pub(super) fn server(&self, scope: &str) -> Result<SecureServerConfig, String> {
        self.validate()?;
        if !self
            .grants
            .iter()
            .any(|grant| grant.identity == self.controller_identity && grant.scope == scope)
        {
            return Err("owner control grant missing from laboratory bootstrap".into());
        }
        SecureServerConfig::new(
            "127.0.0.1:0"
                .parse()
                .map_err(|_| "owned loopback bind invalid")?,
            self.expected_identity.clone(),
            self.material.identity()?,
            self.ca_pem.as_bytes(),
            self.grants.iter().map(Grant::secure).collect(),
            SecureLimits {
                max_requests: 10_000,
                max_connections: 10_000,
                max_frame_bytes: 16_384,
                timeout: Duration::from_secs(2),
            },
        )
    }
}
