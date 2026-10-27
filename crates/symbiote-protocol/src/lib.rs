//! Explicitly authorized, bounded local exchanges. Wire payloads are inert JSON data.
//! AEFL-inspired buffering uses deterministic FIFO eviction and observed outcome drift;
//! scalar agreement never establishes truth or authorizes a connection.
mod telemetry;
mod transport;

pub use telemetry::{EchoBuffer, Sensor, Telemetry};
pub use transport::{
    spawn_server, Client, Endpoint, ServerConfig, ServerHandle, PROTOCOL_VERSION, SCOPE,
};
