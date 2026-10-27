//! Offline owner-authorized policy lifecycle. One checked atomic journal batch
//! closes old candidates and changes policy; manifests and old receipts are never
//! overwritten. No network operation is admitted here.
use super::{config::Config, label, State};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use symbiote_memory::operational::{OperationalEvent, OperationalJournal, PolicyRelocation};

pub(super) fn initial_policy(
    current: &Config,
    journal: &OperationalJournal,
) -> Result<Config, String> {
    let snapshot = journal
        .events()
        .iter()
        .find_map(|event| match event {
            OperationalEvent::PolicyTransitioned {
                previous_policy, ..
            } => Some(previous_policy.clone()),
            _ => None,
        })
        .unwrap_or_else(|| current.public_snapshot());
    let policy = Config::historical(&snapshot)?;
    if policy.policy_digest != journal.genesis_policy_digest()
        || policy.identity != current.identity
    {
        return Err(
            "HOLD: original public policy does not match its immutable owner/genesis".into(),
        );
    }
    Ok(policy)
}

// A context label keeps its original meaning even after removal/readdition.
// Otherwise an old retained certificate could be exposed under a new truth.
pub(super) fn check_context_history(
    current: &Config,
    journal: &OperationalJournal,
    next: Option<&Config>,
) -> Result<(), String> {
    fn register(
        bindings: &mut BTreeMap<String, (String, Option<String>)>,
        policy: &Config,
    ) -> Result<(), String> {
        for context in &policy.contexts {
            let binding = (
                context.schema_fingerprint.clone(),
                context.truth_sha256.clone(),
            );
            if bindings
                .get(&context.scope)
                .is_some_and(|prior| prior != &binding)
            {
                return Err("context schema/truth meaning is immutable across policy history; use a new scope".into());
            }
            bindings.insert(context.scope.clone(), binding);
        }
        Ok(())
    }
    let mut bindings = BTreeMap::new();
    register(&mut bindings, current)?;
    for event in journal.events() {
        if let OperationalEvent::PolicyTransitioned {
            previous_policy,
            policy,
            ..
        } = event
        {
            register(&mut bindings, &Config::historical(previous_policy)?)?;
            register(&mut bindings, &Config::historical(policy)?)?;
        }
    }
    if let Some(next) = next {
        register(&mut bindings, next)?;
    }
    Ok(())
}

/// A changed certificate/CA/endpoint is explicit local rotation. Expanding
/// executable operations, artifacts, contexts/truth authority or any budget
/// additionally requires the reviewed permission-change flag.
pub(super) fn widened(old: &Config, new: &Config) -> Vec<String> {
    let mut changes = BTreeSet::new();
    let before = serde_json::to_value(&old.limits).expect("finite service limits serialize");
    let after = serde_json::to_value(&new.limits).expect("finite service limits serialize");
    for (name, value) in after.as_object().expect("limits are an object") {
        if value.as_u64() > before[name].as_u64() {
            changes.insert(format!("budget:{name}"));
        }
    }
    for context in &new.contexts {
        if match old.context(&context.scope) {
            Ok(prior) => {
                prior.schema_fingerprint != context.schema_fingerprint
                    || prior.truth_sha256 != context.truth_sha256
            }
            Err(_) => true,
        } {
            changes.insert(format!("context:{}", context.scope));
        }
    }
    for peer in &new.peers {
        let Ok(prior) = old.peer(&peer.id) else {
            changes.insert(format!("peer:{}", peer.id));
            continue;
        };
        for access in &peer.access {
            let Some(before) = prior
                .access
                .iter()
                .find(|entry| entry.scope == access.scope)
            else {
                changes.insert(format!("grant:{}:{}", peer.id, access.scope));
                continue;
            };
            if access
                .operations
                .iter()
                .any(|op| !before.operations.contains(op))
                || (!before.artifacts.iter().any(|id| id == "*")
                    && access
                        .artifacts
                        .iter()
                        .any(|id| !before.artifacts.contains(id)))
            {
                changes.insert(format!("grant:{}:{}", peer.id, access.scope));
            }
        }
    }
    changes.into_iter().collect()
}

fn reason(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 1024 {
        return Err("local policy lifecycle needs a nonempty reason of at most 1024 bytes".into());
    }
    Ok(())
}
fn check_anchor(state: &State, policy: &str, head: &str) -> Result<(), String> {
    if state.journal.policy_digest() != policy || state.journal.head_sha256() != head {
        return Err(
            "HOLD: stale or foreign expected policy/journal head; state was preserved".into(),
        );
    }
    Ok(())
}
fn settlements(state: &State, only_peer: Option<&str>) -> Result<Vec<OperationalEvent>, String> {
    let mut result = Vec::new();
    for event in state.journal.events() {
        let OperationalEvent::Quarantined {
            candidate_id, key, ..
        } = event
        else {
            continue;
        };
        if only_peer.is_some_and(|peer| peer != key.peer_id)
            || state.completed(candidate_id).is_some()
        {
            continue;
        }
        let prepared = state.journal.events().iter().find_map(|event| match event {
            OperationalEvent::EvaluationPrepared {
                candidate_id: id,
                record,
                response,
                ..
            } if id == candidate_id => Some((record, response)),
            _ => None,
        });
        if let Some((record, response)) = prepared {
            if state.knowledge.has_historical_promotion(record)? {
                result.push(OperationalEvent::EvaluationCompleted {
                    candidate_id: candidate_id.clone(),
                    record_sha256: record.digest()?,
                    response: response.clone(),
                });
                continue;
            }
        }
        result.push(OperationalEvent::EvaluationRejected { candidate_id: candidate_id.clone(),
            reason: "offline policy lifecycle canceled pending old-policy intent; no new learning promotion".into() });
    }
    Ok(result)
}

fn require_registered(config: &Config) -> Result<(), String> {
    for name in [
        "ledger.jsonl",
        "knowledge.jsonl",
        "operations.jsonl",
        "operations-owner.json",
    ] {
        if !config.state.join(name).is_file() {
            return Err("HOLD: offline lifecycle requires complete existing service state; no history was initialized".into());
        }
    }
    Ok(())
}

pub(super) struct RestoreInspection {
    pub(super) consumed: BTreeSet<String>,
    pub(super) pending: Vec<symbiote_memory::backup::RestoreMappingInfo>,
}

/// Restore metadata remains immutable evidence after activation; normal ledger
/// growth must not be compared with the old byte snapshot again. Every consumed
/// pin must still identify the same owner/path/head-bound historical mapping.
pub(super) fn restore_inspection(state: &State) -> Result<RestoreInspection, String> {
    let mappings =
        symbiote_memory::backup::restore_mappings(&state.config.state, &state.config.identity)?;
    let mut consumed = BTreeSet::new();
    for event in state.journal.events() {
        if let OperationalEvent::PolicyTransitioned {
            previous_policy_digest,
            expected_head,
            relocation: Some(proof),
            ..
        } = event
        {
            let mapping = mappings.iter().find(|mapping| mapping.sha256 == proof.restore_mapping_sha256)
                .ok_or("HOLD: consumed restore metadata is missing or changed; preserve and restore its original bytes")?;
            if symbiote_memory::backup::normalize_state_location(Path::new(&proof.prior_state))?
                != mapping.source_state
                || symbiote_memory::backup::normalize_state_location(Path::new(
                    &proof.restored_state,
                ))? != mapping.restored_state
                || mapping.operational_policy_sha256.as_deref()
                    != Some(previous_policy_digest.as_str())
                || mapping.operational_head_sha256.as_deref() != Some(expected_head.as_str())
                || !consumed.insert(mapping.sha256.clone())
            {
                return Err("HOLD: restore consumption does not bind its exact immutable path, policy and journal head".into());
            }
        }
    }
    let pending = mappings
        .into_iter()
        .filter(|mapping| !consumed.contains(&mapping.sha256))
        .collect();
    Ok(RestoreInspection { consumed, pending })
}

pub(crate) fn policy_status(path: &Path) -> Result<Value, String> {
    // Public-only loading works after a lost old private key. Inspection never
    // runs pending learning recovery.
    let config = Config::load_public(path)?;
    require_registered(&config)?;
    let state = State::load(config)?;
    let restored = restore_inspection(&state)?;
    let pending: Vec<_> = restored
        .pending
        .iter()
        .map(|mapping| {
            json!({"sha256":mapping.sha256,"source_state":mapping.source_state,
        "restored_state":mapping.restored_state,"destination_matches":mapping.destination_matches})
        })
        .collect();
    let denied: Vec<_> = state
        .journal
        .denied_peers()
        .into_iter()
        .map(|peer| {
            json!({
        "peer":peer,"denial_sha256":state.journal.latest_denial_sha256(&peer) })
        })
        .collect();
    Ok(
        json!({"schema":"symbiote.service-policy-status/1","identity":state.config.identity,
        "policy_sha256":state.journal.policy_digest(),"genesis_policy_sha256":state.journal.genesis_policy_digest(),
        "journal_head_sha256":state.journal.head_sha256(),"denied_peers":denied,
        "public_policy":state.config.public_snapshot(),"network_requests":0,"pending_recovery_performed":false,
        "activation_required":!pending.is_empty(),"unconsumed_restore_mappings":pending}),
    )
}

pub(crate) fn policy_transition(
    previous: &Path,
    next: &Path,
    expected_policy: &str,
    expected_head: &str,
    message: &str,
    reviewed: bool,
    review_relocation: bool,
) -> Result<Value, String> {
    reason(message)?;
    let mut old = Config::load_public(previous)?;
    let next = Config::load(next)?;
    if old.identity != next.identity {
        return Err("HOLD: policy transition cannot replace the persistent owner".into());
    }
    let relocation_paths = if review_relocation {
        let prior = old.state.clone();
        old.state.clone_from(&next.state); // effective I/O path only; exact public policy remains unchanged.
        Some(prior)
    } else {
        if std::fs::canonicalize(&old.state).map_err(|_| "old prepared state unavailable")?
            != std::fs::canonicalize(&next.state).map_err(|_| "new prepared state unavailable")?
        {
            return Err(
                "HOLD: state relocation needs --review-relocation and a verified restore mapping"
                    .into(),
            );
        }
        None
    };
    require_registered(&old)?;
    // load holds real owner/knowledge/journal writer guards, but never runs
    // recovery or initializes any history (required existing files above).
    // Verify restored bytes while those guards are held, before any append.
    let state = State::load(old)?;
    check_anchor(&state, expected_policy, expected_head)?;
    let inspection = restore_inspection(&state)?;
    let relocation = match relocation_paths {
        Some(prior) => {
            if inspection.pending.len() != 1 || !inspection.pending[0].destination_matches {
                return Err("HOLD: explicit restore review needs exactly one pending mapping at its verified destination; moved or nested unactivated restores must be restored cleanly".into());
            }
            let mapping = &inspection.pending[0];
            let verified = symbiote_memory::backup::validate_restore_mapping_excluding(
                &next.state,
                &prior,
                &next.identity,
                &inspection.consumed,
            )?;
            if verified != mapping.sha256 {
                return Err("HOLD: restore review selected a different mapping".into());
            }
            Some(PolicyRelocation {
                restore_mapping_sha256: verified,
                prior_state: mapping.source_state.clone(),
                restored_state: mapping.restored_state.clone(),
            })
        }
        None => {
            state.require_activated_restore()?;
            None
        }
    };
    check_context_history(&state.config, &state.journal, Some(&next))?;
    let changes = widened(&state.config, &next);
    if !changes.is_empty() && !reviewed {
        return Err("permission or budget expansion needs explicit --review-permission-change after local review".into());
    }
    let old_public = state.config.public_snapshot();
    let new_public = next.public_snapshot();
    Config::historical(&old_public)?;
    Config::historical(&new_public)?;
    if state.config.policy_digest == next.policy_digest && relocation.is_none() {
        return Err("policy transition must change the approved policy digest".into());
    }
    let mut events = settlements(&state, None)?;
    let canceled_or_acknowledged = events.len();
    events.push(OperationalEvent::PolicyTransitioned {
        previous_policy_digest: expected_policy.into(),
        policy_digest: next.policy_digest.clone(),
        expected_head: expected_head.into(),
        previous_policy: old_public,
        policy: new_public,
        reviewed_permission_change: reviewed,
        relocation: relocation.clone(),
        reason: message.into(),
    });
    let mut state = state;
    state.journal.append_checked_batch(expected_head, events)?;
    Ok(
        json!({"schema":"symbiote.service-policy-transition/1","status":"COMMITTED",
        "identity":state.config.identity,"previous_policy_sha256":expected_policy,"policy_sha256":next.policy_digest,
        "journal_head_sha256":state.journal.head_sha256(),"settled_candidates":canceled_or_acknowledged,
        "reviewed_permission_changes":changes,"denied_peers":state.journal.denied_peers(),
        "network_requests":0,"learning_promotions":0,"manifest_rewritten":false,"relocation":relocation}),
    )
}

pub(crate) fn peer_regrant(
    path: &Path,
    peer: &str,
    expected_policy: &str,
    expected_head: &str,
    message: &str,
    reviewed: bool,
) -> Result<Value, String> {
    reason(message)?;
    if !reviewed || !label(peer) {
        return Err(
            "peer regrant requires explicit --review-permission-change and a configured peer"
                .into(),
        );
    }
    let config = Config::load_public(path)?;
    require_registered(&config)?;
    let mut state = State::load(config)?;
    state.require_activated_restore()?;
    check_anchor(&state, expected_policy, expected_head)?;
    let id = state.config.resolve_peer(peer)?.id.clone();
    if !state.journal.denied_peers().contains(&id) {
        return Err("peer regrant requires an active durable denial".into());
    }
    let denial = state
        .journal
        .latest_denial_sha256(&id)
        .ok_or("denial anchor missing")?
        .to_string();
    let mut events = settlements(&state, Some(&id))?;
    events.push(OperationalEvent::PeerRestored {
        peer_id: id.clone(),
        denial_sha256: denial,
        reviewed_permission_change: true,
        policy_digest: expected_policy.into(),
        expected_head: expected_head.into(),
        reason: message.into(),
    });
    state.journal.append_checked_batch(expected_head, events)?;
    Ok(
        json!({"schema":"symbiote.service-peer-regrant/1","identity":state.config.identity,"peer":id,
        "denied":false,"persistent":true,"journal_head_sha256":state.journal.head_sha256(),
        "policy_sha256":expected_policy,"network_requests":0,"learning_promotions":0}),
    )
}
