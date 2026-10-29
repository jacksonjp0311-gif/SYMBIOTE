//! Public local-engine lifecycle: exact transfer, actual restarted fresh use,
//! and live-ledger reconciliation. No producer internals or success setters.
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use symbiote_runtime::engine::{
    self, AffineQueryPolicy, Engine, EngineConfig, EpisodeOptions, ErrorKind, NoopSink,
    SourceDescriptor,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory {
    root: PathBuf,
    base: PathBuf,
}
impl Directory {
    fn new() -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let root = base.join(format!(
            "symbiote-engine-exchange-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self { root, base }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let Ok(path) = self.root.canonicalize() {
            if path.parent() == Some(self.base.as_path())
                && path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("symbiote-engine-exchange-test-")
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}
struct Source {
    descriptor: SourceDescriptor,
    mask: u16,
    calls: usize,
}
impl engine::ObservationSource for Source {
    fn descriptor(&self) -> SourceDescriptor {
        self.descriptor.clone()
    }
    fn observe(
        &mut self,
        r: engine::ObservationRequest<'_>,
    ) -> std::result::Result<engine::Observation, engine::SourceError> {
        self.calls += 1;
        Ok(engine::Observation {
            sequence: r.sequence,
            input: r.input,
            output: ((r.input & self.mask).count_ones() % 2) as u8,
        })
    }
}
fn descriptor(scope: &str, tag: &str) -> SourceDescriptor {
    SourceDescriptor {
        source_id: format!("unit-{scope}"),
        scope: scope.into(),
        epoch: "unit-1".into(),
        commitment: tag.repeat(64),
        width: 3,
    }
}
fn options(source: &SourceDescriptor) -> EpisodeOptions {
    let mut options = EpisodeOptions::bounded(source.clone());
    options.query_policy = AffineQueryPolicy::RankBasis;
    options
}
fn acquire(engine: &mut Engine, descriptor: &SourceDescriptor, mask: u16) -> engine::Artifact {
    let mut source = Source {
        descriptor: descriptor.clone(),
        mask,
        calls: 0,
    };
    let learned = engine
        .run_episode(&mut source, &options(descriptor), &mut NoopSink)
        .unwrap();
    assert_eq!(source.calls, 5);
    engine.export_artifact(&learned.artifact).unwrap()
}

#[test]
fn exact_bilateral_transfer_is_used_after_restart_and_reconciled_once() {
    let directory = Directory::new();
    let left = descriptor("unit-left/v1", "a");
    let right = descriptor("unit-right/v1", "b");
    let config = EngineConfig::new(vec![left.clone(), right.clone()]);
    let mut a = Engine::initialize(&directory.root.join("a"), config.clone()).unwrap();
    let mut b = Engine::initialize(&directory.root.join("b"), config.clone()).unwrap();
    let artifact_a = acquire(&mut a, &left, 3);
    let artifact_b = acquire(&mut b, &right, 5);
    let ga = a.authorize_local_exchange(&mut b, &artifact_a).unwrap();
    let ta = a.prepare_local_transfer(&mut b, &ga, &artifact_a).unwrap();
    let gb = b.authorize_local_exchange(&mut a, &artifact_b).unwrap();
    let tb = b.prepare_local_transfer(&mut a, &gb, &artifact_b).unwrap();
    let mut verify_a = Source {
        descriptor: left.clone(),
        mask: 3,
        calls: 0,
    };
    let received_b = b
        .accept_local_transfer(
            &ta,
            &artifact_a,
            &mut verify_a,
            &options(&left),
            &mut NoopSink,
        )
        .unwrap();
    let mut verify_b = Source {
        descriptor: right.clone(),
        mask: 5,
        calls: 0,
    };
    let received_a = a
        .accept_local_transfer(
            &tb,
            &artifact_b,
            &mut verify_b,
            &options(&right),
            &mut NoopSink,
        )
        .unwrap();
    assert_eq!(received_b.learning.record_sha256, artifact_a.record_sha256);
    assert_eq!(received_a.learning.record_sha256, artifact_b.record_sha256);
    assert_eq!(verify_a.calls, 5);
    assert_eq!(verify_b.calls, 5);
    let closed_a = a.close().unwrap();
    let closed_b = b.close().unwrap();
    let mut a = Engine::open(&closed_a.state, &closed_a.owner, config.clone()).unwrap();
    let mut b = Engine::open(&closed_b.state, &closed_b.owner, config.clone()).unwrap();
    // Five and six were absent from acquisition and validation at width three.
    for input in [5, 6] {
        assert_eq!(
            b.use_local_transfer(&ta, input).unwrap().answer,
            ((input & 3u16).count_ones() % 2) as u8
        );
        assert_eq!(
            a.use_local_transfer(&tb, input).unwrap().answer,
            ((input & 5u16).count_ones() % 2) as u8
        );
    }
    let ba = b.complete_local_transfer(&ta).unwrap();
    let ab = a.complete_local_transfer(&tb).unwrap();
    assert_eq!(ba.outcome.uses, 2);
    assert_eq!(ab.outcome.uses, 2);
    assert!(!ba.outcome.verified_benefit);
    assert!(ba.outcome.measured_net.is_none());
    assert!(
        a.reconcile_local_transfer(&b, &ta)
            .unwrap()
            .newly_reconciled
    );
    assert!(
        b.reconcile_local_transfer(&a, &tb)
            .unwrap()
            .newly_reconciled
    );
    let closed_a = a.close().unwrap();
    let closed_b = b.close().unwrap();
    let mut a = Engine::open(&closed_a.state, &closed_a.owner, config.clone()).unwrap();
    let mut b = Engine::open(&closed_b.state, &closed_b.owner, config).unwrap();
    let before_a = a.inspect().unwrap();
    let before_b = b.inspect().unwrap();
    assert!(
        !a.reconcile_local_transfer(&b, &ta)
            .unwrap()
            .newly_reconciled
    );
    assert!(
        !b.reconcile_local_transfer(&a, &tb)
            .unwrap()
            .newly_reconciled
    );
    assert_eq!(
        a.inspect().unwrap().operational_head_sha256,
        before_a.operational_head_sha256
    );
    assert_eq!(
        b.inspect().unwrap().operational_head_sha256,
        before_b.operational_head_sha256
    );
    assert_eq!(verify_a.calls, 5);
    assert_eq!(verify_b.calls, 5);
}

#[test]
fn swapped_fabricated_unused_and_revoked_transfers_cannot_gain_credit() {
    let directory = Directory::new();
    let left = descriptor("unit-left/v1", "c");
    let right = descriptor("unit-right/v1", "d");
    let config = EngineConfig::new(vec![left.clone(), right.clone()]);
    let mut a = Engine::initialize(&directory.root.join("a"), config.clone()).unwrap();
    let mut b = Engine::initialize(&directory.root.join("b"), config).unwrap();
    let artifact = acquire(&mut a, &left, 3);
    let grant = a.authorize_local_exchange(&mut b, &artifact).unwrap();
    let ticket = a.prepare_local_transfer(&mut b, &grant, &artifact).unwrap();
    let mut source = Source {
        descriptor: left.clone(),
        mask: 3,
        calls: 0,
    };
    b.accept_local_transfer(
        &ticket,
        &artifact,
        &mut source,
        &options(&left),
        &mut NoopSink,
    )
    .unwrap();
    let before = b.inspect().unwrap().operational_head_sha256;
    assert_eq!(
        b.complete_local_transfer(&ticket).unwrap_err().kind,
        ErrorKind::Uncertain
    );
    assert_eq!(b.inspect().unwrap().operational_head_sha256, before);
    let mut altered = ticket.clone();
    altered.exchange_id = "0".repeat(64);
    assert!(b.use_local_transfer(&altered, 6).is_err());
    assert!(a.reconcile_local_transfer(&b, &altered).is_err());
    assert_eq!(b.inspect().unwrap().operational_head_sha256, before);
    b.use_local_transfer(&ticket, 6).unwrap();
    b.complete_local_transfer(&ticket).unwrap();
    assert!(
        a.reconcile_local_transfer(&b, &ticket)
            .unwrap()
            .newly_reconciled
    );
    let historic = a.inspect().unwrap().operational_head_sha256;
    b.revoke(&artifact.record.id, "unit counterexample", &mut NoopSink)
        .unwrap();
    assert_eq!(
        b.use_local_transfer(&ticket, 5).unwrap_err().kind,
        ErrorKind::Revoked
    );
    assert_eq!(
        a.reconcile_local_transfer(&b, &ticket).unwrap_err().kind,
        ErrorKind::Revoked
    );
    assert_eq!(a.inspect().unwrap().operational_head_sha256, historic);
}
