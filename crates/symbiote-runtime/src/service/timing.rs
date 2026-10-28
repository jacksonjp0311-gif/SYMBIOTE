//! Bounded process diagnostics, separate from evidence, costs and rewards.
//!
//! Spans are inclusive and may overlap/nest across threads. They measure elapsed
//! call duration, not exclusive CPU or kernel time. SystemTime includes suspension
//! and clock adjustments; Instant has platform-specific suspension semantics.
//! Qualification uses its separate sleep detector. These counters never authorize
//! a promotion, select a peer or claim deterministic/hardware performance.
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LockResult, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const COUNT: usize = 6;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Stage {
    Compute,
    LockWait,
    Io,
    Evaluation,
    Replay,
    Shutdown,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Compute => "compute",
            Self::LockWait => "lock_wait",
            Self::Io => "io",
            Self::Evaluation => "evaluation",
            Self::Replay => "replay",
            Self::Shutdown => "shutdown",
        }
    }
}
const STAGES: [Stage; COUNT] = [
    Stage::Compute,
    Stage::LockWait,
    Stage::Io,
    Stage::Evaluation,
    Stage::Replay,
    Stage::Shutdown,
];

struct Counters {
    started: AtomicU64,
    completed: AtomicU64,
    monotonic_ns: AtomicU64,
    wall_elapsed_ns: AtomicU64,
    max_monotonic_ns: AtomicU64,
    first_wall_unix_ns: AtomicU64,
    last_wall_unix_ns: AtomicU64,
    wall_clock_regressions: AtomicU64,
    wall_clock_unavailable: AtomicU64,
    saturated: AtomicBool,
}
impl Counters {
    const fn new() -> Self {
        Self {
            started: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            monotonic_ns: AtomicU64::new(0),
            wall_elapsed_ns: AtomicU64::new(0),
            max_monotonic_ns: AtomicU64::new(0),
            first_wall_unix_ns: AtomicU64::new(0),
            last_wall_unix_ns: AtomicU64::new(0),
            wall_clock_regressions: AtomicU64::new(0),
            wall_clock_unavailable: AtomicU64::new(0),
            saturated: AtomicBool::new(false),
        }
    }
    fn add(&self, target: &AtomicU64, value: u64) {
        let _ = target.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            if current.checked_add(value).is_none() {
                self.saturated.store(true, Ordering::SeqCst);
            }
            Some(current.saturating_add(value))
        });
    }
}
static COUNTERS: [Counters; COUNT] = [const { Counters::new() }; COUNT];

fn nanos(value: u128, counters: &Counters) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => {
            counters.saturated.store(true, Ordering::SeqCst);
            u64::MAX
        }
    }
}
fn wall_now(counters: &Counters) -> Option<u64> {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => Some(nanos(value.as_nanos(), counters)),
        Err(_) => {
            counters.add(&counters.wall_clock_unavailable, 1);
            None
        }
    }
}

/// One actual completed span, recorded even when its body exits with an error.
/// Drop/finish updates only fixed process counters, never persistent state.
#[must_use = "keep the timer alive for the operation being measured"]
pub struct Timer {
    stage: Stage,
    started: Instant,
    wall_started: Option<u64>,
}
impl Timer {
    pub fn start(stage: Stage) -> Self {
        let counters = &COUNTERS[stage as usize];
        counters.add(&counters.started, 1);
        let started = Instant::now();
        let wall_started = wall_now(counters);
        if let Some(value) = wall_started {
            let _ = counters.first_wall_unix_ns.fetch_update(
                Ordering::SeqCst,
                Ordering::SeqCst,
                |previous| {
                    Some(if previous == 0 {
                        value
                    } else {
                        previous.min(value)
                    })
                },
            );
        }
        Self {
            stage,
            started,
            wall_started,
        }
    }
    pub fn finish(self) {
        drop(self);
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        let counters = &COUNTERS[self.stage as usize];
        let elapsed = nanos(self.started.elapsed().as_nanos(), counters);
        counters.add(&counters.monotonic_ns, elapsed);
        counters
            .max_monotonic_ns
            .fetch_max(elapsed, Ordering::SeqCst);
        if let Some(end) = wall_now(counters) {
            counters.last_wall_unix_ns.fetch_max(end, Ordering::SeqCst);
            if let Some(start) = self.wall_started {
                if let Some(duration) = end.checked_sub(start) {
                    counters.add(&counters.wall_elapsed_ns, duration);
                } else {
                    counters.add(&counters.wall_clock_regressions, 1);
                }
            }
        }
        counters.add(&counters.completed, 1);
    }
}

/// Measures acquisition only. Holding the returned guard does not inflate wait.
pub fn lock<T>(mutex: &Mutex<T>) -> LockResult<MutexGuard<'_, T>> {
    let _wait = Timer::start(Stage::LockWait);
    mutex.lock()
}

/// Inclusive duration of one persistence/transport call, including any parsing or
/// validation performed by that call. This is not exclusive kernel I/O duration.
pub fn io<T>(operation: impl FnOnce() -> T) -> T {
    let _io = Timer::start(Stage::Io);
    operation()
}

/// A concurrent diagnostic view: completed spans only, with in-flight counts.
/// Counters are individually atomic; the six-stage snapshot is not transactional.
pub fn snapshot() -> Value {
    let mut rows = Vec::with_capacity(COUNT);
    for stage in STAGES {
        let counters = &COUNTERS[stage as usize];
        let completed = counters.completed.load(Ordering::SeqCst);
        let started = counters.started.load(Ordering::SeqCst);
        let first = counters.first_wall_unix_ns.load(Ordering::SeqCst);
        let last = counters.last_wall_unix_ns.load(Ordering::SeqCst);
        rows.push(
            json!({"stage":stage.name(), "started":started,"completed":completed,
            "in_flight":started.saturating_sub(completed),
            "monotonic_elapsed_ns":counters.monotonic_ns.load(Ordering::SeqCst),
            "max_monotonic_elapsed_ns":counters.max_monotonic_ns.load(Ordering::SeqCst),
            "wall_elapsed_ns":counters.wall_elapsed_ns.load(Ordering::SeqCst),
            "min_started_wall_unix_ns":if first == 0 {None} else {Some(first)},
            "max_completed_wall_unix_ns":if last == 0 {None} else {Some(last)},
            "wall_clock_regressions":counters.wall_clock_regressions.load(Ordering::SeqCst),
            "wall_clock_unavailable":counters.wall_clock_unavailable.load(Ordering::SeqCst),
            "saturated":counters.saturated.load(Ordering::SeqCst)}),
        );
    }
    json!({"schema":"symbiote.stage-timing/1","pid":std::process::id(),"stages":rows,
        "inclusive_spans":true,"overlapping_totals_are_additive":false,
        "completed_spans_only":true,"snapshot_is_transactional":false,
        "logical_cost_or_reward_input":false,"deterministic_or_exclusive_cpu_time":false,
        "monotonic_basis":"std::time::Instant; suspension semantics depend on platform",
        "wall_basis":"SystemTime Unix nanoseconds; includes suspension and clock adjustments; regressions counted",
        "io_basis":"persistence/transport/stdIO call elapsed duration, including internal parsing/validation and waiting; not exclusive kernel time",
        "scope":"fixed current-process counters, including concurrent and failed operation spans"})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(value: &Value, stage: &str) -> Value {
        value["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["stage"] == stage)
            .unwrap()
            .clone()
    }
    #[test]
    fn failed_operations_still_record_completed_diagnostics_without_a_reward() {
        let before = row(&snapshot(), "evaluation")["completed"]
            .as_u64()
            .unwrap();
        let error: Result<(), &str> = {
            let _span = Timer::start(Stage::Evaluation);
            Err("controlled failure")
        };
        assert!(error.is_err());
        let report = snapshot();
        assert!(row(&report, "evaluation")["completed"].as_u64().unwrap() > before);
        assert!(
            row(&report, "evaluation")["monotonic_elapsed_ns"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(report["logical_cost_or_reward_input"], false);
        assert_eq!(report["overlapping_totals_are_additive"], false);
    }
    #[test]
    fn a_real_contended_mutex_records_acquisition_without_measuring_guard_lifetime() {
        let mutex = std::sync::Arc::new(Mutex::new(()));
        let holder = mutex.lock().unwrap();
        let shared = std::sync::Arc::clone(&mutex);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let before = row(&snapshot(), "lock_wait")["completed"].as_u64().unwrap();
        let waiter = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let _guard = lock(&shared).unwrap();
            acquired_tx.send(()).unwrap();
            release_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        drop(holder);
        acquired_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        // The worker still owns the mutex, yet acquisition timing is already
        // complete. Measuring the entire guard lifetime would fail this check.
        assert!(matches!(
            mutex.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        let acquired = row(&snapshot(), "lock_wait");
        assert!(acquired["completed"].as_u64().unwrap() > before);
        assert!(acquired["monotonic_elapsed_ns"].as_u64().unwrap() > 0);
        release_tx.send(()).unwrap();
        waiter.join().unwrap();
    }
    #[test]
    fn nested_real_compute_and_io_are_explicitly_inclusive_and_bounded() {
        let before = snapshot();
        {
            let _compute = Timer::start(Stage::Compute);
            io(|| {
                let data = b"bounded parser workload";
                assert_eq!(data.len(), 23);
            });
        }
        let after = snapshot();
        for stage in ["compute", "io"] {
            assert!(
                row(&after, stage)["completed"].as_u64().unwrap()
                    > row(&before, stage)["completed"].as_u64().unwrap()
            );
        }
        assert_eq!(after["stages"].as_array().unwrap().len(), COUNT);
        assert!(after.to_string().len() < 10000);
    }
}
