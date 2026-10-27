//! Post-campaign audit of private decisions. This cannot influence learning or
//! select experiments; it only replays completed owner-bound operational records.
use super::cohort::World;
use super::policy::{Advertisement, Arm, Decision, Profile, Quota, Quote, RegistryPeer};
use super::wire::SCOPE;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use symbiote_memory::operational::{
    body_digest, OperationalEvent, OperationalJournal, PartnerInteractionOutcome,
};
use symbiote_memory::Store;

pub(super) fn inspect(
    state: &Path,
    identity: &str,
    arm: Arm,
    price: u64,
    registry: &[RegistryPeer],
    worlds: &[World],
    restart_after: usize,
) -> Result<Value, String> {
    if !state.join("operations.jsonl").is_file() {
        if state.join("operations-owner.json").exists()
            || std::fs::symlink_metadata(state.join("operations.jsonl")).is_ok()
        {
            return Err("HOLD: registered private operational journal is missing or not a regular file; history remains preserved".into());
        }
        return Ok(json!({"status":"NOT_INITIALIZED"}));
    }
    let owner = Arc::new(Store::open(state)?);
    if owner.identity() != identity {
        return Err("profile audit owner changed".into());
    }
    let policy = body_digest(
        &json!({"protocol":super::registration::PROTOCOL_SHA256,"arm":arm,"price":price,"family":"unrestricted-exact-DAG/common-ingestion/v1"}),
    )?;
    let journal = OperationalJournal::open(owner, identity, &policy)?;
    let mut prior = BTreeMap::<String, Profile>::new();
    let mut attempted = BTreeMap::<String, BTreeSet<String>>::new();
    let mut requests = 0;
    let mut successes = 0;
    let mut applicability = 0;
    let mut irrelevant = 0;
    let mut irrelevant_selections = 0;
    let mut post_use = 0;
    let mut post_action_change = 0;
    let mut prior_decisions = 0;
    for event in journal.events() {
        match event {
            OperationalEvent::PartnerDecisionRecorded { decision }
                if decision.details.get("choice").is_some() =>
            {
                let recorded: BTreeMap<String, Profile> =
                    serde_json::from_value(decision.details["profiles"].clone())
                        .map_err(|_| "recorded private profile map malformed")?;
                if recorded != prior {
                    return Err(
                        "profile decision used future, missing or cross-owner completed outcomes"
                            .into(),
                    );
                }
                if decision.details["choice"]["reason"] == "selected-offer-not-current-frontier" {
                    irrelevant_selections += 1;
                }
                if arm == Arm::Prospective {
                    let world = worlds
                        .iter()
                        .find(|world| world.context == decision.context)
                        .ok_or("profile decision applicability context missing")?;
                    let known: BTreeSet<usize> =
                        serde_json::from_value(decision.details["known_edges"].clone())
                            .map_err(|_| "profile decision known-edge witness missing")?;
                    let ads: Vec<Advertisement> =
                        serde_json::from_value(decision.details["advertisements"].clone())
                            .map_err(|_| "profile advertisement witness missing")?;
                    let quota: Quota =
                        serde_json::from_value(decision.details["remaining"].clone())
                            .map_err(|_| "profile reservation witness missing")?;
                    let frontier = decision
                        .frontier_edge
                        .ok_or("profile frontier witness missing")?;
                    let fingerprint =
                        symbiote_memory::knowledge::graph::graph_schema_fingerprint(&world.schema)?;
                    let peers = attempted.entry(decision.context.clone()).or_default();
                    let neutral = BTreeMap::new();
                    let base = Decision {
                        arm,
                        context: &decision.context,
                        schema_fingerprint: &fingerprint,
                        scope: SCOPE,
                        frontier,
                        known: &known,
                        registry,
                        advertisements: &ads,
                        profiles: &prior,
                        attempted_context_peers: peers,
                        fixed_peer: None,
                        uniform_index: None,
                        observation_price: price,
                        quota: &quota,
                        assessment_bound: 0,
                        quote: Quote {
                            receiver_max: 31,
                            contributor_max: 15,
                            pair_max: 46,
                            frame: 4096,
                            control_frame: 1024,
                        },
                    };
                    // The reserved work maximum is recoverable from the public
                    // algorithm recorded with the current native decision witness.
                    let bound = decision.details["assessment_work_bound"]
                        .as_u64()
                        .ok_or("profile assessment reservation witness missing")?
                        as usize;
                    let base = Decision {
                        assessment_bound: bound,
                        ..base
                    };
                    let actual = base.choose()?;
                    if serde_json::to_value(&actual).map_err(|e| e.to_string())?
                        != decision.details["choice"]
                    {
                        return Err(
                            "profile choice does not follow the frozen rational policy".into()
                        );
                    }
                    let cold = Decision {
                        profiles: &neutral,
                        ..base
                    }
                    .choose()?;
                    if !prior.is_empty() {
                        prior_decisions += 1;
                        if world.index > restart_after {
                            let score_changed = u128::from(actual.probability_numerator)
                                * u128::from(cold.probability_denominator)
                                != u128::from(cold.probability_numerator)
                                    * u128::from(actual.probability_denominator);
                            let action_changed =
                                actual.peer != cold.peer || actual.reason != cold.reason;
                            if score_changed || action_changed {
                                post_use += 1;
                            }
                            if action_changed {
                                post_action_change += 1;
                            }
                        }
                    }
                }
                if decision.details["choice"]["reason"] == "request-verified-frontier-offer" {
                    requests += 1;
                    if let Some(peer) = &decision.selected_peer {
                        attempted
                            .entry(decision.context.clone())
                            .or_default()
                            .insert(peer.clone());
                        let ads: Vec<Advertisement> =
                            serde_json::from_value(decision.details["advertisements"].clone())
                                .map_err(|_| "request applicability witness missing")?;
                        if !ads.iter().any(|ad| {
                            &ad.peer == peer && Some(ad.edge_id) == decision.frontier_edge
                        }) {
                            irrelevant += 1;
                        }
                    }
                }
            }
            OperationalEvent::PartnerInteractionCompleted { interaction } => {
                if interaction.outcome == PartnerInteractionOutcome::SkippedIrrelevant {
                    irrelevant_selections += 1;
                    continue;
                }
                let profile = prior.entry(interaction.peer_id.clone()).or_default();
                profile.attempts += 1;
                match interaction.outcome {
                    PartnerInteractionOutcome::VerifiedNovel => {
                        profile.verified_novel += 1;
                        successes += 1;
                    }
                    PartnerInteractionOutcome::VerificationFailed => {
                        profile.verification_failures += 1
                    }
                    PartnerInteractionOutcome::ApplicabilityFailed => {
                        profile.applicability_failures += 1;
                        applicability += 1;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(
        json!({"status":"VERIFIED","knowledge_requests":requests,"verified_novel_current_frontier":successes,"selection_precision":if requests>0{Some(successes as f64/requests as f64)}else{None},"false_applicability":applicability,"false_applicability_rate":if requests>0{Some(applicability as f64/requests as f64)}else{None},"irrelevant_requests":irrelevant,"irrelevant_selections":irrelevant_selections,"decisions_with_prior_completed_profiles":prior_decisions,"profile_changed_score_or_action_after_restart":post_use,"profile_changed_action_after_restart":post_action_change,"prior_profile_use_gate":if post_use>0{"DEMONSTRATED"}else{"NOT_DEMONSTRATED"},"profiles":prior,"meaning":"operational relationship adaptation; not an automatic knowledge promotion or performance proof"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registered_profile_loss_is_hold_and_never_recreates_history() {
        let root = std::env::temp_dir().join(format!(
            "symbiote-profile-audit-loss-{}",
            symbiote_protocol::fresh_capability().unwrap()
        ));
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(
            inspect(&root, "owner", Arm::Prospective, 100, &[], &[], 11).unwrap()["status"],
            "NOT_INITIALIZED"
        );
        let marker = b"retained-owner-proof";
        std::fs::write(root.join("operations-owner.json"), marker).unwrap();
        assert!(inspect(&root, "owner", Arm::Prospective, 100, &[], &[], 11).is_err());
        assert!(!root.join("operations.jsonl").exists());
        assert_eq!(
            std::fs::read(root.join("operations-owner.json")).unwrap(),
            marker
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
