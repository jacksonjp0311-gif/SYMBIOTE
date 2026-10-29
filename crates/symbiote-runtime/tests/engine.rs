//! Independent caller: only documented engine interfaces, no raw store access.
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use symbiote_runtime::engine::*;
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "symbiote-engine-consumer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Source {
    descriptor: SourceDescriptor,
    mask: u16,
    bias: u8,
    calls: usize,
    offline: bool,
    bad: Option<&'static str>,
}
impl Source {
    fn new(scope: &str, width: u8, mask: u16, bias: u8) -> Self {
        Self {
            descriptor: SourceDescriptor {
                source_id: format!("source-{scope}"),
                scope: scope.into(),
                epoch: "epoch-1".into(),
                commitment: format!("{mask:064x}"),
                width,
            },
            mask,
            bias,
            calls: 0,
            offline: false,
            bad: None,
        }
    }
}
impl ObservationSource for Source {
    fn descriptor(&self) -> SourceDescriptor {
        let mut d = self.descriptor.clone();
        if self.bad == Some("epoch") && self.calls > 0 {
            d.epoch = "changed".into();
        }
        d
    }
    fn observe(
        &mut self,
        r: ObservationRequest<'_>,
    ) -> std::result::Result<Observation, SourceError> {
        assert_eq!(r.source, &self.descriptor);
        assert_eq!(r.sequence, self.calls);
        if self.offline {
            return Err(SourceError::new(
                ErrorKind::Storage,
                "source deliberately offline",
            ));
        }
        self.calls += 1;
        if self.bad == Some("late") {
            std::thread::sleep(Duration::from_millis(8));
        }
        let answer = (((r.input & self.mask).count_ones() % 2) as u8) ^ self.bias;
        Ok(Observation {
            sequence: if self.bad == Some("sequence") {
                999
            } else {
                r.sequence
            },
            input: r.input,
            output: if self.bad == Some("binary") {
                2
            } else if self.bad == Some("contradiction")
                && self.calls > usize::from(self.descriptor.width) + 1
            {
                answer ^ 1
            } else {
                answer
            },
        })
    }
}
#[derive(Default)]
struct Sink(Vec<EngineEvent>);
impl EventSink for Sink {
    fn event(&mut self, e: &EngineEvent) -> std::result::Result<(), SinkError> {
        self.0.push(e.clone());
        Ok(())
    }
}
fn options(source: &Source) -> EpisodeOptions {
    let mut p = EpisodeOptions::bounded(source.descriptor.clone());
    p.query_policy = AffineQueryPolicy::RankBasis;
    p
}
fn config(source: &Source) -> EngineConfig {
    EngineConfig::new(vec![source.descriptor.clone()])
}
fn rehash_operations(path: &std::path::Path, mut mutate: impl FnMut(&mut serde_json::Value)) {
    use sha2::{Digest, Sha256};
    let mut rows = fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    for row in &mut rows {
        if let Some(decision) = row["payload"].get_mut("decision") {
            if decision["details"]["schema"] == "symbiote.embedding-engine/1" {
                mutate(&mut decision["details"]["event"]);
                decision["decision_id"] = serde_json::json!(format!(
                    "engine-{:x}",
                    Sha256::digest(serde_json::to_vec(&decision["details"]).unwrap())
                ));
            }
        }
    }
    let mut previous = "0".repeat(64);
    for (sequence, row) in rows.iter_mut().enumerate() {
        row["previous"] = serde_json::json!(previous);
        let hash = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&serde_json::json!([sequence, previous, row["payload"]]))
                    .unwrap()
            )
        );
        row["sha256"] = serde_json::json!(hash);
        previous = hash;
    }
    fs::write(
        path,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
}
#[test]
fn two_owners_decomposed_lifecycle_reopen_without_source_and_writer_exclusion() {
    let d = Directory::new();
    let cwd = std::env::current_dir().unwrap();
    let mut a_source = Source::new("a", 3, 5, 1);
    let mut b_source = Source::new("b", 3, 3, 0);
    let ac = config(&a_source);
    let bc = config(&b_source);
    let mut a = Engine::initialize(&d.0.join("a"), ac.clone()).unwrap();
    let mut b = Engine::initialize(&d.0.join("b"), bc.clone()).unwrap();
    let ai = a.identity().unwrap().to_string();
    let bi = b.identity().unwrap().to_string();
    assert_ne!(ai, bi);
    assert_eq!(
        Engine::initialize(&d.0.join("a"), ac.clone())
            .err()
            .unwrap()
            .kind,
        ErrorKind::AlreadyExists
    );
    assert!(matches!(
        Engine::open(&d.0.join("a"), &ai, ac.clone())
            .err()
            .unwrap()
            .kind,
        ErrorKind::Storage | ErrorKind::OwnerBusy
    ));
    let mut asink = Sink::default();
    let mut bsink = Sink::default();
    let candidate = a
        .observe_infer(
            &mut a_source,
            &options(&Source::new("a", 3, 5, 1)),
            &mut asink,
        )
        .unwrap();
    assert_eq!(a.inspect().unwrap().knowledge.records, 1);
    let evaluated = a.evaluate(candidate, &mut asink).unwrap();
    assert_eq!(a.inspect().unwrap().knowledge.records, 1);
    let ar = a.retain(evaluated, &mut asink).unwrap();
    let br = b
        .run_episode(
            &mut b_source,
            &options(&Source::new("b", 3, 3, 0)),
            &mut bsink,
        )
        .unwrap();
    assert_eq!((a_source.calls, b_source.calls), (5, 5));
    assert_ne!(ar.record_sha256, br.record_sha256);
    for input in 0..8 {
        let p = a.predict(&ar.artifact, input, &mut asink).unwrap();
        assert_eq!(
            p.answer,
            Some((((input & 5u16).count_ones() % 2) as u8) ^ 1)
        );
        assert_eq!(
            b.predict(&br.artifact, input, &mut bsink).unwrap().answer,
            Some(((input & 3u16).count_ones() % 2) as u8)
        );
    }
    assert_eq!(
        a.predict(&ar.artifact, 8, &mut asink).unwrap().basis,
        PredictionBasis::Abstained(Abstention::OutsideApplicability)
    );
    a.cancel();
    assert_eq!(
        a.run_episode(
            &mut a_source,
            &options(&Source::new("a", 3, 5, 1)),
            &mut asink
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Cancelled
    );
    assert!(!b.inspect().unwrap().cancelled);
    a.close().unwrap();
    b.close().unwrap();
    let mut reopened = Engine::open(&d.0.join("a"), &ai, ac).unwrap();
    a_source.offline = true;
    let reuse = reopened
        .run_episode(
            &mut a_source,
            &options(&Source::new("a", 3, 5, 1)),
            &mut asink,
        )
        .unwrap();
    assert!(reuse.reused);
    assert_eq!(reuse.usage.source_calls, 0);
    assert_eq!(a_source.calls, 5);
    assert_eq!(
        reopened
            .predict(&ar.artifact, 7, &mut asink)
            .unwrap()
            .answer,
        Some(1)
    );
    assert_eq!(reopened.historical_outcomes().unwrap().len(), 2);
    reopened.close().unwrap();
    assert_eq!(std::env::current_dir().unwrap(), cwd);
    assert!(!asink.0.is_empty() && !bsink.0.is_empty());
}
#[test]
fn malformed_contradictory_budget_late_and_changed_source_fail_typed_without_promotion() {
    for (case, kind) in [
        ("sequence", ErrorKind::Malformed),
        ("binary", ErrorKind::Malformed),
        ("contradiction", ErrorKind::Contradiction),
        ("late", ErrorKind::DeadlineExceeded),
        ("epoch", ErrorKind::Authorization),
        ("queries", ErrorKind::BudgetExhausted),
        ("work", ErrorKind::BudgetExhausted),
    ] {
        let d = Directory::new();
        let mut source = Source::new("test", 3, 5, 0);
        let cfg = config(&source);
        let mut opts = options(&source);
        if case == "queries" {
            opts.max_queries = 1;
        } else if case == "work" {
            opts.max_gf2_work = 1;
        } else {
            source.bad = Some(case);
        }
        if case == "late" {
            opts.duration = Duration::from_millis(3);
        }
        let mut e = Engine::initialize(&d.0.join("state"), cfg.clone()).unwrap();
        let owner = e.identity().unwrap().to_string();
        let error = e
            .run_episode(&mut source, &opts, &mut NoopSink)
            .err()
            .unwrap();
        assert_eq!(error.kind, kind, "{case}: {error}");
        assert_eq!(e.inspect().unwrap().knowledge.records, 1);
        assert!(e.inspect().unwrap().pending_episode.is_none());
        e.close().unwrap();
        Engine::open(&d.0.join("state"), &owner, cfg)
            .unwrap()
            .close()
            .unwrap();
    }
    let d = Directory::new();
    let mut s = Source::new("one", 1, 1, 0);
    let mut e = Engine::initialize(&d.0.join("state"), config(&s)).unwrap();
    assert_eq!(
        e.run_episode(
            &mut s,
            &options(&Source::new("one", 1, 1, 0)),
            &mut NoopSink
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Uncertain
    );
    assert_eq!(e.inspect().unwrap().knowledge.records, 1);
    e.close().unwrap();
}
struct FailingSink {
    after_commit: bool,
}
impl EventSink for FailingSink {
    fn event(&mut self, e: &EngineEvent) -> std::result::Result<(), SinkError> {
        if self.after_commit == matches!(e, EngineEvent::Retained { .. }) {
            Err(SinkError::new("explicit host sink failure"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn sink_failures_report_real_commit_and_incomplete_drop_never_resets() {
    for after_commit in [false, true] {
        let d = Directory::new();
        let mut source = Source::new("sink", 3, 5, 0);
        let cfg = config(&source);
        let mut e = Engine::initialize(&d.0.join("state"), cfg.clone()).unwrap();
        let owner = e.identity().unwrap().to_string();
        let error = e
            .run_episode(
                &mut source,
                &options(&Source::new("sink", 3, 5, 0)),
                &mut FailingSink { after_commit },
            )
            .err()
            .unwrap();
        assert_eq!(
            error.kind,
            if after_commit {
                ErrorKind::CommittedEventSink
            } else {
                ErrorKind::EventSink
            }
        );
        assert_eq!(error.committed.is_some(), after_commit);
        assert_eq!(
            e.inspect().unwrap().active_artifacts.len(),
            usize::from(after_commit)
        );
        e.close().unwrap();
        let reopened = Engine::open(&d.0.join("state"), &owner, cfg).unwrap();
        assert_eq!(
            reopened.inspect().unwrap().active_artifacts.len(),
            usize::from(after_commit)
        );
        reopened.close().unwrap();
    }
    let d = Directory::new();
    let mut source = Source::new("drop", 3, 5, 0);
    let cfg = config(&source);
    let mut e = Engine::initialize(&d.0.join("state"), cfg.clone()).unwrap();
    let owner = e.identity().unwrap().to_string();
    let _candidate = e
        .observe_infer(
            &mut source,
            &options(&Source::new("drop", 3, 5, 0)),
            &mut NoopSink,
        )
        .unwrap();
    drop(e);
    assert_eq!(
        Engine::open(&d.0.join("state"), &owner, cfg)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Hold
    );
}
#[test]
fn exact_artifact_independent_evaluation_revocation_and_stopped_checkpoint_restore() {
    let d = Directory::new();
    let mut source = Source::new("shared", 3, 5, 1);
    let cfg = config(&source);
    let opts = options(&source);
    let mut a = Engine::initialize(&d.0.join("a"), cfg.clone()).unwrap();
    let receipt = a.run_episode(&mut source, &opts, &mut NoopSink).unwrap();
    let artifact = a.export_artifact(&receipt.artifact).unwrap();
    let mut receiver_source = Source::new("shared", 3, 5, 1);
    let mut b = Engine::initialize(&d.0.join("b"), cfg.clone()).unwrap();
    let evaluated = b
        .evaluate_artifact(&artifact, &mut receiver_source, &opts, &mut NoopSink)
        .unwrap();
    assert_eq!(evaluated.record(), &artifact.record);
    let adopted = b.retain(evaluated, &mut NoopSink).unwrap();
    assert_eq!(adopted.record_sha256, artifact.record_sha256);
    assert_eq!(receiver_source.calls, 5);
    let bi = b.identity().unwrap().to_string();
    let closed = b.close().unwrap();
    let checkpoint = closed.checkpoint(&d.0.join("checkpoint")).unwrap();
    let mut original = Engine::open(&d.0.join("b"), &bi, cfg.clone()).unwrap();
    original
        .revoke(&adopted.artifact, "new counterexample", &mut NoopSink)
        .unwrap();
    assert_eq!(
        original
            .predict(&adopted.artifact, 7, &mut NoopSink)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Revoked
    );
    original.close().unwrap();
    let (mut restored, report) = Engine::restore(&checkpoint, &d.0.join("restored"), cfg).unwrap();
    assert!(report.rollback_discards_later_learning);
    assert!(!report.network_started);
    assert_eq!(restored.identity().unwrap(), bi);
    assert_eq!(
        restored
            .predict(&adopted.artifact, 7, &mut NoopSink)
            .unwrap()
            .answer,
        Some(1)
    );
    restored.close().unwrap();
    a.close().unwrap();
}

#[test]
fn foreign_candidate_cannot_abort_another_owner_and_untrusted_artifact_is_inert() {
    let d = Directory::new();
    let mut a_source = Source::new("scope", 3, 5, 0);
    let mut b_source = Source::new("scope", 3, 5, 0);
    let cfg = config(&a_source);
    let opts = options(&a_source);
    let mut a = Engine::initialize(&d.0.join("a"), cfg.clone()).unwrap();
    let mut b = Engine::initialize(&d.0.join("b"), cfg).unwrap();
    let ca = a
        .observe_infer(&mut a_source, &opts, &mut NoopSink)
        .unwrap();
    let cb = b
        .observe_infer(&mut b_source, &opts, &mut NoopSink)
        .unwrap();
    assert_eq!(
        b.evaluate(ca, &mut NoopSink).err().unwrap().kind,
        ErrorKind::Authorization
    );
    assert!(b.inspect().unwrap().pending_episode.is_some());
    let eb = b.evaluate(cb, &mut NoopSink).unwrap();
    let receipt = b.retain(eb, &mut NoopSink).unwrap();
    let mut artifact = b.export_artifact(&receipt.artifact).unwrap();
    assert!(Artifact::from_json(&artifact.to_json().unwrap()).is_ok());
    assert_eq!(
        Artifact::from_json(&vec![b' '; 16 * 1024 + 1])
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    artifact.training_inputs.push(999);
    assert_eq!(artifact.to_json().err().unwrap().kind, ErrorKind::Malformed);
    artifact.training_inputs.pop();
    artifact.record.payload = serde_json::json!({"kind":"instructions","code":"not executable"});
    assert_eq!(
        artifact.to_json().err().unwrap().kind,
        ErrorKind::IncompatibleSchema
    );
    assert_eq!(b.inspect().unwrap().knowledge.records, 2);
    a.close().unwrap();
    b.close().unwrap();
}
#[test]
fn internally_rehashed_audit_is_recomputed_and_changed_policy_cannot_open() {
    use sha2::{Digest, Sha256};
    let d = Directory::new();
    let mut source = Source::new("rehash", 3, 5, 0);
    let cfg = config(&source);
    let mut e = Engine::initialize(&d.0.join("state"), cfg.clone()).unwrap();
    let owner = e.identity().unwrap().to_string();
    e.run_episode(
        &mut source,
        &options(&Source::new("rehash", 3, 5, 0)),
        &mut NoopSink,
    )
    .unwrap();
    e.close().unwrap();
    let mut changed = cfg.clone();
    changed.authorized_sources[0].epoch = "changed".into();
    assert_eq!(
        Engine::open(&d.0.join("state"), &owner, changed)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Authorization
    );
    let path = d.0.join("state/operations.jsonl");
    let raw = fs::read_to_string(&path).unwrap();
    let mut rows = raw
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let mut changed = false;
    for row in &mut rows {
        if !row["payload"]["decision"].is_object() {
            continue;
        }
        let decision = &mut row["payload"]["decision"];
        if decision["details"]["event"]["phase"] == "inferred" {
            let count = decision["details"]["event"]["audit"]["snapshot"]["work_units"]
                .as_u64()
                .unwrap();
            decision["details"]["event"]["audit"]["snapshot"]["work_units"] =
                serde_json::json!(count + 1);
            decision["decision_id"] = serde_json::json!(format!(
                "engine-{:x}",
                Sha256::digest(serde_json::to_vec(&decision["details"]).unwrap())
            ));
            changed = true;
        }
    }
    assert!(changed);
    let mut previous = "0".repeat(64);
    for (sequence, row) in rows.iter_mut().enumerate() {
        row["previous"] = serde_json::json!(previous);
        let hash = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&serde_json::json!([sequence, previous, row["payload"]]))
                    .unwrap()
            )
        );
        row["sha256"] = serde_json::json!(hash);
        previous = hash;
    }
    let forged = rows
        .iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>();
    fs::write(&path, &forged).unwrap();
    let error = Engine::open(&d.0.join("state"), &owner, cfg).err().unwrap();
    assert_eq!(
        error.kind,
        ErrorKind::Malformed,
        "must pass generic receipt hashes and fail structural replay: {error}"
    );
    assert_eq!(fs::read_to_string(path).unwrap(), forged);
}

#[test]
fn rehashed_work_and_different_but_heldout_agreeing_model_are_not_saved_authority() {
    use symbiote_reasoning::structural::CompactAffineLearner;
    for alter_model in [false, true] {
        let d = Directory::new();
        let mut own = Source::new("foreign", 3, 5, 0);
        let cfg = config(&own);
        let opts = options(&own);
        let mut a = Engine::initialize(&d.0.join("a"), cfg.clone()).unwrap();
        let ar = a.run_episode(&mut own, &opts, &mut NoopSink).unwrap();
        let artifact = a.export_artifact(&ar.artifact).unwrap();
        let mut source = Source::new("foreign", 3, 5, 0);
        let mut b = Engine::initialize(&d.0.join("b"), cfg.clone()).unwrap();
        let owner = b.identity().unwrap().to_string();
        let evaluated = b
            .evaluate_artifact(&artifact, &mut source, &opts, &mut NoopSink)
            .unwrap();
        b.retain(evaluated, &mut NoopSink).unwrap();
        b.close().unwrap();
        let mut changed = false;
        let path = d.0.join("b/operations.jsonl");
        rehash_operations(&path, |event| {
            if !alter_model && event["phase"] == "finished" {
                let units = event["usage"]["gf2_work_units"].as_u64().unwrap();
                event["usage"]["gf2_work_units"] = serde_json::json!(units + 1);
                changed = true;
            } else if alter_model && event["phase"] == "inferred" {
                let audit = &mut event["audit"];
                let training = audit["training"].as_u64().unwrap() as usize;
                let budget = audit["snapshot"]["work_unit_budget"].as_u64().unwrap() as usize;
                let mut learner = CompactAffineLearner::new(3, budget).unwrap();
                for (sequence, q) in audit["queries"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .enumerate()
                {
                    let input = q["input"].as_u64().unwrap() as u16;
                    let answer = ((input & 6).count_ones() % 2) as u8;
                    if sequence < training {
                        assert_eq!(
                            learner
                                .choose_query_with_policy(AffineQueryPolicy::RankBasis)
                                .unwrap(),
                            Some(input)
                        );
                        q["output"] = serde_json::json!(answer);
                        learner.observe(input, answer).unwrap();
                    } else {
                        // The forged alternate model really agrees with the actual
                        // held-out case, so one-case evaluation cannot bind it.
                        assert_eq!(q["output"], serde_json::json!(answer));
                        assert_eq!(learner.forecast(input).unwrap().answer, Some(answer));
                    }
                }
                audit["snapshot"] = serde_json::to_value(learner.snapshot()).unwrap();
                changed = true;
            }
        });
        assert!(changed);
        let before = fs::read(&path).unwrap();
        assert_eq!(
            Engine::open(&d.0.join("b"), &owner, cfg)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Contradiction
        );
        assert_eq!(fs::read(path).unwrap(), before);
        a.close().unwrap();
    }
}

#[test]
fn retained_reconstruction_budget_and_panicking_callback_are_explicit() {
    let d = Directory::new();
    let mut source = Source::new("bounded", 3, 5, 0);
    let cfg = config(&source);
    let mut e = Engine::initialize(&d.0.join("state"), cfg.clone()).unwrap();
    let opts = options(&source);
    e.run_episode(&mut source, &opts, &mut NoopSink).unwrap();
    let mut narrow = opts;
    // First observe admits its 17-unit bound and performs 4 reduction checks,
    // 4 basis checks and one insertion. The second observe is not admitted.
    narrow.max_gf2_work = 17;
    let mut failures = Sink::default();
    assert_eq!(
        e.run_episode(&mut source, &narrow, &mut failures)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert!(failures.0.iter().any(|event| matches!(event,
        EngineEvent::Failed { kind: ErrorKind::BudgetExhausted, usage, .. }
            if usage.source_calls == 0 && usage.gf2_work_units == 9)));
    e.close().unwrap();
    struct Panics(SourceDescriptor);
    impl ObservationSource for Panics {
        fn descriptor(&self) -> SourceDescriptor {
            self.0.clone()
        }
        fn observe(
            &mut self,
            _: ObservationRequest<'_>,
        ) -> std::result::Result<Observation, SourceError> {
            panic!("host callback panic")
        }
    }
    let mut e = Engine::initialize(&d.0.join("panic"), cfg.clone()).unwrap();
    let owner = e.identity().unwrap().to_string();
    let mut source = Panics(narrow.source.clone());
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.observe_infer(
            &mut source,
            &EpisodeOptions::bounded(narrow.source.clone()),
            &mut NoopSink,
        )
    }));
    assert!(interrupted.is_err());
    assert_eq!(e.close().err().unwrap().kind, ErrorKind::Hold);
    assert_eq!(
        Engine::open(&d.0.join("panic"), &owner, cfg)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Hold
    );
}

#[test]
fn restore_preflights_metadata_policy_and_live_original_without_consuming_target() {
    let directory = Directory::new();
    let state = directory.0.join("owner");
    let mut source = Source::new("restore", 3, 5, 0);
    let cfg = config(&source);
    let mut engine = Engine::initialize(&state, cfg.clone()).unwrap();
    let owner = engine.identity().unwrap().to_string();
    let learned = engine
        .run_episode(
            &mut source,
            &options(&Source::new("restore", 3, 5, 0)),
            &mut NoopSink,
        )
        .unwrap();
    let checkpoint = engine
        .close()
        .unwrap()
        .checkpoint(&directory.0.join("backup"))
        .unwrap();
    for (case, mut bad, mut policy) in [
        ("owner", checkpoint.clone(), cfg.clone()),
        ("source", checkpoint.clone(), cfg.clone()),
        ("policy", checkpoint.clone(), cfg.clone()),
    ] {
        match case {
            "owner" => bad.owner = "different-owner".into(),
            "source" => bad.original_state = directory.0.join("different-source"),
            _ => policy.authorized_sources[0].epoch = "different-policy".into(),
        }
        let destination = directory.0.join(format!("rejected-{case}"));
        assert_eq!(
            Engine::restore(&bad, &destination, policy)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Authorization
        );
        assert!(
            !destination.exists(),
            "metadata/policy error must precede any destination creation"
        );
    }
    let live = Engine::open(&state, &owner, cfg.clone()).unwrap();
    let destination = directory.0.join("rejected-live");
    assert_eq!(
        Engine::restore(&checkpoint, &destination, cfg.clone())
            .err()
            .unwrap()
            .kind,
        ErrorKind::OwnerBusy
    );
    assert!(!destination.exists());
    live.close().unwrap();
    fs::rename(&state, directory.0.join("stopped-original-moved")).unwrap();
    let (mut restored, receipt) = Engine::restore(
        &checkpoint,
        &directory.0.join("accepted-missing-original"),
        cfg,
    )
    .unwrap();
    assert!(!receipt.network_started && receipt.rollback_discards_later_learning);
    assert_eq!(restored.identity().unwrap(), owner);
    assert_eq!(
        restored
            .predict(&learned.artifact, 6, &mut NoopSink)
            .unwrap()
            .answer,
        Some(1)
    );
    restored.close().unwrap();
}
