//! Shared controller-session admission. This schedules parent connection
//! attempts only; it neither retries connections nor paces nested learner RPCs.
//! Wait time is measured controller overhead, separate from participant costs.
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

const SPACING: Duration = Duration::from_millis(50);
const POLL: Duration = Duration::from_millis(10);
const WAIT_CAP: Duration = Duration::from_secs(5);

trait Clock: Send + Sync {
    fn now(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}
struct MonotonicClock {
    origin: Instant,
}
impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}
#[derive(Clone, Copy)]
enum Rejection {
    Cancelled,
    Deadline,
    WaitCap,
    Poisoned,
    ClockRange,
}
impl Rejection {
    fn message(self) -> &'static str {
        match self {
            Self::Cancelled => "parent session admission cancelled before connection attempt",
            Self::Deadline => {
                "parent session admission deadline exceeded before connection attempt"
            }
            Self::WaitCap => "parent session admission wait cap exceeded before connection attempt",
            Self::Poisoned => {
                "parent session admission state poisoned; no connection attempt admitted"
            }
            Self::ClockRange => "parent session admission monotonic clock range exhausted",
        }
    }
}
#[derive(Default)]
struct Counters {
    calls: AtomicU64,
    admitted: AtomicU64,
    cancelled: AtomicU64,
    deadline: AtomicU64,
    cap: AtomicU64,
    poisoned: AtomicU64,
    clock_range: AtomicU64,
    wait_ns: AtomicU64,
    max_wait_ns: AtomicU64,
}
fn add(counter: &AtomicU64, amount: u64) {
    let mut old = counter.load(Ordering::Acquire);
    loop {
        match counter.compare_exchange_weak(
            old,
            old.saturating_add(amount),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(current) => old = current,
        }
    }
}
fn maximum(counter: &AtomicU64, amount: u64) {
    let mut old = counter.load(Ordering::Acquire);
    while amount > old {
        match counter.compare_exchange_weak(old, amount, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(current) => old = current,
        }
    }
}
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

struct Limiter<C: Clock> {
    clock: C,
    last: Mutex<Option<Duration>>,
    counters: Counters,
}
impl<C: Clock> Limiter<C> {
    fn new(clock: C) -> Self {
        Self {
            clock,
            last: Mutex::new(None),
            counters: Counters::default(),
        }
    }
    fn check(
        &self,
        start: Duration,
        deadline: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Duration, Rejection> {
        let now = self.clock.now();
        if cancelled.load(Ordering::Acquire) {
            return Err(Rejection::Cancelled);
        }
        if now >= deadline {
            return Err(Rejection::Deadline);
        }
        if now.saturating_sub(start) >= WAIT_CAP {
            return Err(Rejection::WaitCap);
        }
        Ok(now)
    }
    fn sleep_bound(&self, now: Duration, start: Duration, deadline: Duration, wanted: Duration) {
        let remaining = deadline
            .saturating_sub(now)
            .min(WAIT_CAP.saturating_sub(now.saturating_sub(start)));
        self.clock.sleep(wanted.min(POLL).min(remaining));
    }
    fn finish(&self, start: Duration, result: Result<(), Rejection>) -> Result<(), String> {
        let elapsed = nanos(self.clock.now().saturating_sub(start));
        add(&self.counters.wait_ns, elapsed);
        maximum(&self.counters.max_wait_ns, elapsed);
        match result {
            Ok(()) => {
                add(&self.counters.admitted, 1);
                Ok(())
            }
            Err(reason) => {
                let counter = match reason {
                    Rejection::Cancelled => &self.counters.cancelled,
                    Rejection::Deadline => &self.counters.deadline,
                    Rejection::WaitCap => &self.counters.cap,
                    Rejection::Poisoned => &self.counters.poisoned,
                    Rejection::ClockRange => &self.counters.clock_range,
                };
                add(counter, 1);
                Err(reason.message().into())
            }
        }
    }
    fn admit(&self, deadline: Duration, cancelled: &AtomicBool) -> Result<(), String> {
        add(&self.counters.calls, 1);
        let start = self.clock.now();
        // try_lock keeps cancellation and deadlines effective even while a
        // different controller thread is waiting for its next admission slot.
        let mut last = loop {
            let now = match self.check(start, deadline, cancelled) {
                Ok(now) => now,
                Err(reason) => return self.finish(start, Err(reason)),
            };
            match self.last.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::Poisoned(_)) => {
                    return self.finish(start, Err(Rejection::Poisoned))
                }
                Err(TryLockError::WouldBlock) => self.sleep_bound(now, start, deadline, POLL),
            }
        };
        loop {
            let now = match self.check(start, deadline, cancelled) {
                Ok(now) => now,
                Err(reason) => return self.finish(start, Err(reason)),
            };
            let due = match *last {
                None => now,
                Some(previous) => match previous.checked_add(SPACING) {
                    Some(due) => due,
                    None => return self.finish(start, Err(Rejection::ClockRange)),
                },
            };
            if now >= due {
                // Set from actual monotonic admission time, never from an old
                // scheduled slot. Idle or delayed periods cannot bank a burst.
                *last = Some(now);
                return self.finish(start, Ok(()));
            }
            self.sleep_bound(now, start, deadline, due.saturating_sub(now));
        }
    }
    fn snapshot(&self) -> Value {
        let load = |value: &AtomicU64| value.load(Ordering::Acquire);
        let wait = load(&self.counters.wait_ns);
        let max_wait = load(&self.counters.max_wait_ns);
        json!({"schema":"symbiote.parent-session-admission/1","admission_calls":load(&self.counters.calls),"admitted":load(&self.counters.admitted),"cancelled":load(&self.counters.cancelled),"deadline_rejected":load(&self.counters.deadline),"wait_cap_rejected":load(&self.counters.cap),"poisoned_rejected":load(&self.counters.poisoned),"clock_range_rejected":load(&self.counters.clock_range),"wait_nanoseconds":wait,"wait_ms":wait/1_000_000,"max_wait_nanoseconds":max_wait,"max_wait_ms":max_wait/1_000_000,"minimum_spacing_ms":50,"max_rate_per_second":20,"max_admission_wait_ms":5000,"retry_policy":"none; a failed connection retains its consumed admission","scope":"parent/controller owner and judge session admissions only; nested learner RPCs separately bounded","wait_basis":"actual monotonic elapsed inside admit, including pacing and lock waits; excludes TCP/TLS","timing_limit":"10ms cancellation/deadline polling under a normally scheduled OS; measured descheduling overshoot is not clamped"})
    }
}

/// Create exactly one shared instance for all campaigns in a controller run.
pub(super) struct ParentAdmission {
    inner: Limiter<MonotonicClock>,
}
impl Default for ParentAdmission {
    fn default() -> Self {
        Self::new()
    }
}
impl ParentAdmission {
    pub(super) fn new() -> Self {
        Self {
            inner: Limiter::new(MonotonicClock {
                origin: Instant::now(),
            }),
        }
    }
    pub(super) fn admit(&self, deadline: Instant, cancelled: &AtomicBool) -> Result<(), String> {
        self.inner.admit(
            deadline.saturating_duration_since(self.inner.clock.origin),
            cancelled,
        )
    }
    /// Capture after all parent calls finish for a quiescent exact counter sum.
    pub(super) fn snapshot(&self) -> Value {
        self.inner.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[derive(Default)]
    struct FakeClock {
        time: Mutex<Duration>,
        sleep_calls: Mutex<Vec<Duration>>,
        cancel_on_sleep: Mutex<Option<Arc<AtomicBool>>>,
        oversleep: Mutex<Duration>,
    }
    impl FakeClock {
        fn advance(&self, time: Duration) {
            let mut now = self.time.lock().unwrap();
            *now = now.saturating_add(time);
        }
    }
    impl Clock for Arc<FakeClock> {
        fn now(&self) -> Duration {
            *self.time.lock().unwrap()
        }
        fn sleep(&self, duration: Duration) {
            self.sleep_calls.lock().unwrap().push(duration);
            self.advance(duration + *self.oversleep.lock().unwrap());
            if let Some(cancel) = self.cancel_on_sleep.lock().unwrap().as_ref() {
                cancel.store(true, Ordering::Release);
            }
        }
    }
    fn fixture() -> (Arc<FakeClock>, Limiter<Arc<FakeClock>>, AtomicBool) {
        let clock = Arc::new(FakeClock::default());
        let limiter = Limiter::new(Arc::clone(&clock));
        (clock, limiter, AtomicBool::new(false))
    }
    #[test]
    fn fake_clock_admissions_are_spaced_and_wait_is_accounted() {
        let (clock, limiter, cancel) = fixture();
        let deadline = Duration::from_secs(2);
        limiter.admit(deadline, &cancel).unwrap();
        assert_eq!(clock.now(), Duration::ZERO);
        limiter.admit(deadline, &cancel).unwrap();
        assert_eq!(clock.now(), SPACING);
        limiter.admit(deadline, &cancel).unwrap();
        assert_eq!(clock.now(), SPACING * 2);
        let snapshot = limiter.snapshot();
        assert_eq!(snapshot["admission_calls"], 3);
        assert_eq!(snapshot["admitted"], 3);
        assert_eq!(snapshot["wait_nanoseconds"], 100_000_000u64);
        assert_eq!(snapshot["max_wait_ms"], 50);
    }
    #[test]
    fn a_delayed_admission_does_not_create_catchup_or_refund_a_failed_connection() {
        let (clock, limiter, cancel) = fixture();
        let deadline = Duration::from_secs(4);
        limiter.admit(deadline, &cancel).unwrap();
        clock.advance(Duration::from_secs(1));
        limiter.admit(deadline, &cancel).unwrap();
        assert_eq!(clock.now(), Duration::from_secs(1));
        // The caller's connection can fail; there is no success/refund or retry
        // input to this limiter, so the next attempt still waits its full slot.
        limiter.admit(deadline, &cancel).unwrap();
        assert_eq!(clock.now(), Duration::from_millis(1050));
        assert_eq!(limiter.snapshot()["admitted"], 3);
    }
    #[test]
    fn cancellation_and_exact_deadline_reject_before_admission() {
        let (clock, limiter, cancel) = fixture();
        limiter.admit(Duration::from_secs(2), &cancel).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        *clock.cancel_on_sleep.lock().unwrap() = Some(Arc::clone(&cancelled));
        assert!(limiter
            .admit(Duration::from_secs(2), &cancelled)
            .unwrap_err()
            .contains("cancelled"));
        assert_eq!(clock.now(), POLL);
        assert_eq!(limiter.snapshot()["cancelled"], 1);
        assert_eq!(limiter.snapshot()["admitted"], 1);
        *clock.cancel_on_sleep.lock().unwrap() = None;
        assert!(limiter
            .admit(SPACING, &cancel)
            .unwrap_err()
            .contains("deadline"));
        assert_eq!(clock.now(), SPACING);
        assert_eq!(limiter.snapshot()["deadline_rejected"], 1);
        assert_eq!(limiter.snapshot()["admitted"], 1);
    }
    #[test]
    fn mutex_wait_is_cancellable_and_capped_without_lock_deadlock() {
        let (clock, limiter, cancel) = fixture();
        let guard = limiter.last.lock().unwrap();
        assert!(limiter
            .admit(Duration::from_millis(25), &cancel)
            .unwrap_err()
            .contains("deadline"));
        assert_eq!(clock.now(), Duration::from_millis(25));
        assert!(limiter
            .admit(Duration::from_secs(30), &cancel)
            .unwrap_err()
            .contains("wait cap"));
        assert_eq!(clock.now(), Duration::from_millis(5025));
        assert_eq!(limiter.snapshot()["admitted"], 0);
        assert_eq!(limiter.snapshot()["wait_cap_rejected"], 1);
        drop(guard);
    }
    #[test]
    fn scheduler_overshoot_is_measured_and_never_admitted_after_deadline() {
        let (clock, limiter, cancel) = fixture();
        limiter.admit(Duration::from_secs(2), &cancel).unwrap();
        *clock.oversleep.lock().unwrap() = Duration::from_millis(100);
        assert!(limiter.admit(Duration::from_millis(20), &cancel).is_err());
        assert_eq!(limiter.snapshot()["admitted"], 1);
        assert_eq!(limiter.snapshot()["max_wait_ms"], 110);
        assert_eq!(limiter.snapshot()["deadline_rejected"], 1);
    }
    #[test]
    fn manual_loopback_tcp_calibration_counts_failed_attempt_without_retry() {
        use std::net::{TcpListener, TcpStream};
        let limiter = ParentAdmission::new();
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(3);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut stamps = Vec::new();
        for _ in 0..3 {
            limiter.admit(deadline, &cancel).unwrap();
            stamps.push(limiter.inner.last.lock().unwrap().unwrap());
            let connected =
                TcpStream::connect_timeout(&address, Duration::from_millis(500)).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            drop(accepted);
            drop(connected);
        }
        for pair in stamps.windows(2) {
            assert!(pair[1] - pair[0] >= SPACING);
        }
        drop(listener);
        limiter.admit(deadline, &cancel).unwrap();
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
        assert_eq!(limiter.snapshot()["admission_calls"], 4);
        assert_eq!(limiter.snapshot()["admitted"], 4);
    }
}
