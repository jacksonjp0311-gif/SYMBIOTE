//! Supervised test fixture, excluded from the distributed SYMBIOTE runtime bundle.
//! It cannot terminate any process and refuses to start outside explicit test mode.
use std::path::PathBuf;
use symbiote_memory::{knowledge::KnowledgeStore, Store};

fn main() {
    if std::env::var("SYMBIOTE_CRASH_FIXTURE").as_deref() != Ok("owned-test-child") {
        eprintln!("This is a supervised crash-test fixture, not the SYMBIOTE runtime.");
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("fixture needs STATE READY MODE");
        std::process::exit(2);
    }
    let state = PathBuf::from(&args[0]);
    let ready = PathBuf::from(&args[1]);
    let mode = args[2].as_str();
    if !["both", "genesis", "knowledge", "staging"].contains(&mode) {
        eprintln!("invalid fixture mode");
        std::process::exit(2);
    }
    let original = Store::open(&state).expect("test fixture original store");
    let identity = original.identity().to_string();
    let mut held_original = Some(original);
    let _held_knowledge = if mode == "both" || mode == "knowledge" || mode == "staging" {
        Some(KnowledgeStore::open(&state, &identity).expect("test fixture structural store"))
    } else {
        None
    };
    if mode == "knowledge" {
        held_original.take();
    }
    if mode == "staging" {
        // Model the observable pre-commit crash boundary: an incomplete private
        // staging file exists, while the canonical atomic-commit targets do not change.
        std::fs::write(
            state.join(format!("ledger.{}.orphan.tmp", std::process::id())),
            b"incomplete staging bytes",
        )
        .expect("test fixture staging file");
    }
    std::fs::write(ready, format!("{}\n{}\n", std::process::id(), identity))
        .expect("test fixture readiness");
    loop {
        std::thread::park();
    }
}
