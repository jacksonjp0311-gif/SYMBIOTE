//! Manual released-shape fixtures only. This test never calls the frozen
//! prospective cohort generator, register(), or a registered target pilot.
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use symbiote_memory::{
    strategy::{StrategyLedger, StrategyRecord},
    Store,
};
use symbiote_reasoning::planning::{Edge, GraphSchema};
use symbiote_reasoning::query_strategy::{
    derive_policy, remap_task, run_trial, EdgeObservation, EdgeRole, GraphTask, SourceTrace,
    TrialLimits,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symbiote-transfer-manual-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let expected = std::fs::canonicalize(std::env::temp_dir()).ok();
        let actual = std::fs::canonicalize(&self.0).ok();
        if actual.as_ref().and_then(|p| p.parent()).map(PathBuf::from) == expected {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
fn manual(context: &str, layers: usize, goal: bool) -> GraphTask {
    let nodes = layers * 2;
    let end = nodes - 1;
    let a = std::iter::once(0)
        .chain(1..layers)
        .chain(std::iter::once(end))
        .collect::<Vec<_>>();
    let b = std::iter::once(0)
        .chain(layers..end)
        .chain(std::iter::once(end))
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    for path in [&a, &b] {
        for p in path.windows(2) {
            edges.push(Edge {
                from: p[0],
                to: p[1],
                lower: 1,
                upper: 9,
            });
        }
    }
    edges[layers].lower = 2;
    let mut costs = vec![1; edges.len()];
    costs[layers] = 2;
    costs[if goal { layers - 1 } else { 0 }] = 8;
    GraphTask {
        context: context.into(),
        schema: GraphSchema { nodes, edges },
        start: 0,
        goal: end,
        costs,
    }
}
fn offered(source: &str, goal: bool) -> StrategyRecord {
    let traces = (0..2)
        .map(|i| {
            let task = manual(&format!("manual-source-{source}-{i}"), 2, goal);
            SourceTrace {
                context: task.context,
                schema: task.schema,
                start: task.start,
                goal: task.goal,
                observations: task
                    .costs
                    .into_iter()
                    .enumerate()
                    .map(|(edge, cost)| EdgeObservation { edge, cost })
                    .collect(),
            }
        })
        .collect::<Vec<_>>();
    StrategyRecord{id:format!("{source}-query-policy"),revision:1,source:source.into(),
        policy:derive_policy(&traces,1000).unwrap().policy,training:traces,
        provenance:"Authorized manual structured observations, not executable instructions or universal transfer proof".into()}
}
fn calibration(owner: &str, phase: &str, goal: bool) -> Vec<GraphTask> {
    (0..2)
        .map(|i| manual(&format!("manual-cal-{owner}-{phase}-{i}"), 3, goal))
        .collect()
}
#[test]
fn two_way_manual_policy_exchange_changes_actual_future_queries_after_restart() {
    let root = Directory::new();
    let owners = [
        Arc::new(Store::open(&root.0.join("a")).unwrap()),
        Arc::new(Store::open(&root.0.join("b")).unwrap()),
    ];
    let ids = owners.each_ref().map(|o| o.identity().to_owned());
    assert_ne!(ids[0], ids[1]);
    let mut ledgers = owners
        .each_ref()
        .map(|o| StrategyLedger::open(Arc::clone(o)).unwrap());
    let offers = [offered(&ids[0], true), offered(&ids[1], false)];
    assert!(
        ledgers[0]
            .consider(offers[0].clone(), calibration(&ids[0], "own", true))
            .unwrap()
            .promoted
    );
    assert!(
        !ledgers[1]
            .consider(offers[1].clone(), calibration(&ids[1], "own", false))
            .unwrap()
            .promoted
    );
    let before = ledgers.each_ref().map(|l| l.selected().map(|r| r.policy));
    for i in 0..2 {
        let received: StrategyRecord =
            serde_json::from_slice(&serde_json::to_vec(&offers[1 - i]).unwrap()).unwrap();
        assert_eq!(received.source, ids[1 - i]);
        let decision = ledgers[i]
            .consider(received, calibration(&ids[i], "receiving", i == 1))
            .unwrap();
        assert!(decision.promoted && decision.active);
        assert!(!decision.replayed);
    }
    let heads = ledgers.each_ref().map(|l| l.head_sha256().to_owned());
    drop(ledgers);
    drop(owners);
    for i in 0..2 {
        let owner = Arc::new(Store::open(&root.0.join(if i == 0 { "a" } else { "b" })).unwrap());
        assert_eq!(owner.identity(), ids[i]);
        let ledger = StrategyLedger::open(owner).unwrap();
        assert_eq!(ledger.head_sha256(), heads[i]);
        let policy = ledger.selected().unwrap().policy;
        let task = manual(&format!("manual-new-schema-{i}"), 4, i == 1);
        let node_map = [4, 6, 1, 7, 0, 5, 3, 2];
        let edge_order = [6, 2, 7, 0, 4, 1, 3, 5];
        let remapped = remap_task(
            &task,
            &node_map,
            &edge_order,
            &format!("manual-remapped-target-{i}"),
        )
        .unwrap();
        let old = run_trial(&remapped, before[i].as_ref(), TrialLimits::default()).unwrap();
        let learned = run_trial(&remapped, Some(&policy), TrialLimits::default()).unwrap();
        assert!(old.certified_correctly() && learned.certified_correctly());
        assert!(learned.queried_edges.len() < old.queried_edges.len());
        let first = EdgeRole::of(
            &remapped.schema,
            remapped.start,
            remapped.goal,
            learned.queried_edges[0],
        )
        .unwrap();
        assert_eq!(
            first,
            if i == 0 {
                EdgeRole::FromStart
            } else {
                EdgeRole::ToGoal
            }
        );
        let fixed = symbiote_reasoning::query_strategy::QueryPolicy::ranked(if i == 0 {
            vec![EdgeRole::FromStart, EdgeRole::ToGoal]
        } else {
            vec![EdgeRole::ToGoal, EdgeRole::FromStart]
        })
        .unwrap();
        let matched = run_trial(&remapped, Some(&fixed), TrialLimits::default()).unwrap();
        assert_eq!(learned.queried_edges, matched.queried_edges); // Fixed controls remove a novelty/efficiency claim.
    }
}
#[test]
fn wrong_or_unpinned_registration_rejects_before_state_or_receipt_creation() {
    let root = Directory::new();
    let state = root.0.join("unopened");
    let output = root.0.join("never-written.json");
    assert!(
        symbiote_runtime::transfer::register(&state, &state.join("registration.json"))
            .unwrap_err()
            .contains("outside")
    );
    assert!(!state.exists());
    let registration = root.0.join("manual-bad-registration.json");
    std::fs::write(&registration, b"{}").unwrap();
    assert!(symbiote_runtime::transfer::run_registered(
        &state,
        &registration,
        "untrusted",
        &output
    )
    .is_err());
    let hash = format!("{:x}", Sha256::digest(b"{}"));
    assert!(
        symbiote_runtime::transfer::run_registered(&state, &registration, &hash, &output).is_err()
    );
    assert!(!state.exists() && !output.exists());
    assert_eq!(std::fs::read(&registration).unwrap(), b"{}");
}
