//! The host owns all grants and cancellation. No global stdin reader is created.
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        println!("Usage: cargo run -p symbiote-runtime --example cognitive -- CONFIG POLICY NEW_RECEIPTS_DIR");
        return Ok(());
    }
    // An embedding application's shutdown handler can retain a clone and set
    // this flag with Ordering::Release. The policy also bounds work and lifetime.
    let cancelled = Arc::new(AtomicBool::new(false));
    let report = symbiote_runtime::service::run_with_cancel(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
        cancelled,
    )?;
    println!("{report}");
    Ok(())
}
