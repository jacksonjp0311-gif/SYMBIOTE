//! Explicitly authorized, bounded local exchanges. Wire payloads are inert JSON data.
//! AEFL-inspired buffering uses deterministic FIFO eviction and observed outcome drift;
//! scalar agreement never establishes truth or authorizes a connection.
pub mod secure;
mod telemetry;
mod transport;

pub use secure::{
    fresh_capability, spawn_secure_server, spawn_secure_server_metered, SecureAgreement,
    SecureCancellation, SecureClient, SecureEndpoint, SecureLimits, SecurePeerGrant,
    SecureServerConfig, SecureServerHandle, SecureSession, SecureTraffic, SecureTrafficSnapshot,
    TlsClientConfig, TlsIdentity, SECURE_PROTOCOL_VERSION,
};

pub use telemetry::{EchoBuffer, Sensor, Telemetry};
pub use transport::{
    spawn_scoped_server, spawn_server, Client, Endpoint, ServerConfig, ServerHandle,
    PROTOCOL_VERSION, SCOPE,
};
