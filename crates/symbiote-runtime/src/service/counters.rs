//! Role-aware run accounting. A SHA is a coordinate, never promotion authority.
//! Native store/journal witnesses decide counts; legacy summaries stay unchanged.
use super::*;
use symbiote_memory::knowledge::KnowledgeAnchor;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::service) enum Role {
    OrdinaryLearning,
    ReceiverRole,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::OrdinaryLearning => "ordinary_learning",
            Self::ReceiverRole => "receiver_role",
        }
    }
}
#[derive(Clone)]
pub(in crate::service) struct Boundary {
    knowledge: KnowledgeAnchor,
    events: usize,
    prefix: String,
}
pub(in crate::service) struct Counters {
    initial: Boundary,
    last: Boundary,
    promotions: BTreeMap<String, Role>,
    reused: BTreeMap<Role, BTreeSet<String>>,
}
fn boundary(owner: &State) -> Result<Boundary, String> {
    Ok(Boundary {
        knowledge: owner.knowledge.history_anchor(),
        events: owner.journal.events().len(),
        prefix: owner
            .journal
            .event_prefix_sha256(owner.journal.events().len())?,
    })
}
fn local_counts(ordinary: usize, receiver: usize, total_key: &str) -> Value {
    let mut value = json!({"ordinary_learning":ordinary,"receiver_role":receiver});
    value[total_key] = json!(ordinary + receiver);
    value
}
fn origin_counts(ordinary: usize, receiver: usize, partner: usize) -> Value {
    json!({"ordinary_learning":ordinary,"receiver_role":receiver,"partner_receiver":partner,"total":ordinary+receiver+partner})
}
fn matching_retained(
    owner: &State,
    at: &KnowledgeAnchor,
    offer: &KnowledgeRecord,
) -> Result<Option<String>, String> {
    owner
        .knowledge
        .active_at(at)?
        .into_iter()
        .find(|r| {
            r.scope == offer.scope
                && r.schema_fingerprint == offer.schema_fingerprint
                && r.payload == offer.payload
        })
        .map(|r| r.digest())
        .transpose()
}
/// Read only exact native prefixes. Every promotion is independently bound back
/// to the live store's original assessment, not accepted from the JSON row alone.
fn committed(
    owner: &State,
    from: &KnowledgeAnchor,
) -> Result<Vec<(String, KnowledgeRecord)>, String> {
    owner.knowledge.validate_anchor(from)?;
    let to = owner.knowledge.history_anchor();
    let bytes = config::read_bounded(
        &owner.knowledge.ledger_path(),
        symbiote_memory::MAX_LEDGER_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "counter knowledge UTF-8 rejected")?;
    if !text.ends_with('\n') {
        return Err("counter knowledge history is incomplete".into());
    }
    let rows: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).map_err(|_| "counter knowledge row rejected"))
        .collect::<Result<_, _>>()?;
    if rows.len() != to.records {
        return Err("counter disk/live knowledge lengths differ".into());
    }
    let at = |n: usize| -> Result<KnowledgeAnchor, String> {
        let a = KnowledgeAnchor {
            identity: to.identity.clone(),
            records: n,
            head_sha256: rows
                .get(n - 1)
                .and_then(|r| r["sha256"].as_str())
                .ok_or("counter knowledge SHA absent")?
                .into(),
        };
        owner.knowledge.validate_anchor(&a)?;
        Ok(a)
    };
    if at(to.records)? != to {
        return Err("counter final knowledge head differs".into());
    }
    let mut result = Vec::new();
    for (i, row) in rows.iter().enumerate().skip(from.records) {
        let before = at(i)?;
        let after = at(i + 1)?;
        match row["payload"]["event"].as_str() {
            Some("promote" | "promote_graph") => {
                let record: KnowledgeRecord =
                    serde_json::from_value(row["payload"]["record"].clone())
                        .map_err(|_| "counter promotion record rejected")?;
                let (sha, evidence) = owner
                    .knowledge
                    .promotion_evidence_between(&record, &before, &after)?;
                if row["sha256"] != sha || row["payload"]["assessment"]["evidence"] != evidence {
                    return Err("counter promotion is not the exact committed assessment".into());
                }
                result.push((sha, record));
            }
            Some("revoke") => {}
            _ => return Err("unsupported counter knowledge event".into()),
        }
    }
    Ok(result)
}
fn validate_operational_disk(owner: &State) -> Result<(), String> {
    let bytes = config::read_bounded(
        &owner.journal.ledger_path(),
        symbiote_memory::MAX_LEDGER_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "counter operational UTF-8 rejected")?;
    if !text.ends_with('\n') {
        return Err("counter operational ledger is truncated".into());
    }
    let rows: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).map_err(|_| "counter operational row rejected"))
        .collect::<Result<_, _>>()?;
    if rows.len() != owner.journal.events().len() + 1
        || rows.last().and_then(|r| r["sha256"].as_str()) != Some(owner.journal.head_sha256())
    {
        return Err("counter disk/live operational boundaries differ".into());
    }
    let mut previous = "0".repeat(64);
    for (i, row) in rows.iter().enumerate() {
        let keys = row
            .as_object()
            .ok_or("counter operational row is not an object")?;
        if keys.len() != 4
            || !keys
                .keys()
                .all(|k| matches!(k.as_str(), "sequence" | "previous" | "payload" | "sha256"))
            || row["sequence"].as_u64() != Some(i as u64)
            || row["previous"] != previous
            || row["sha256"] != digest(&(i, &previous, &row["payload"]))?
        {
            return Err("counter operational chain differs from committed history".into());
        }
        if i > 0
            && row["payload"]
                != serde_json::to_value(&owner.journal.events()[i - 1])
                    .map_err(|e| e.to_string())?
        {
            return Err("counter operational payload differs from validated live event".into());
        }
        previous = row["sha256"]
            .as_str()
            .ok_or("counter operational SHA absent")?
            .into();
    }
    Ok(())
}
impl Counters {
    pub(in crate::service) fn begin(owner: &State) -> Result<Self, String> {
        let at = boundary(owner)?;
        Ok(Self {
            initial: at.clone(),
            last: at,
            promotions: BTreeMap::new(),
            reused: BTreeMap::new(),
        })
    }
    pub(in crate::service) fn capture(&self, owner: &State) -> Result<Boundary, String> {
        if owner.knowledge.history_anchor() != self.last.knowledge {
            return Err("unattributed knowledge change before counter boundary".into());
        }
        boundary(owner)
    }
    pub(in crate::service) fn checkpoint(
        &mut self,
        owner: &State,
        before: &Boundary,
        role: Role,
        observation: Option<&Value>,
    ) -> Result<Value, String> {
        owner.knowledge.validate_anchor(&before.knowledge)?;
        if before.knowledge != self.last.knowledge
            || before.events > owner.journal.events().len()
            || owner.journal.event_prefix_sha256(before.events)? != before.prefix
        {
            return Err("counter action boundary is stale, foreign or reordered".into());
        }
        let changes = committed(owner, &before.knowledge)?;
        for (sha, _) in &changes {
            if self.promotions.insert(sha.clone(), role).is_some() {
                return Err("counter promotion was already attributed".into());
            }
        }
        if let Some(response) = observation {
            if response["status"] == "REUSED" {
                if role != Role::OrdinaryLearning
                    || owner.knowledge.history_anchor() != before.knowledge
                    || response["before"]
                        != serde_json::to_value(&before.knowledge).map_err(|e| e.to_string())?
                    || response["after"] != response["before"]
                    || response["queries_performed"] != 0
                {
                    return Err("observation reuse lacks an unchanged native boundary".into());
                }
                let sha = response["record_sha256"]
                    .as_str()
                    .ok_or("reuse record SHA absent")?;
                let record = owner
                    .knowledge
                    .active_at(&before.knowledge)?
                    .into_iter()
                    .find(|r| {
                        r.digest().ok().as_deref() == Some(sha)
                            && r.id == response["artifact"]
                            && r.scope == response["scope"]
                            && r.source == owner.config.identity
                    })
                    .ok_or("reuse names no actual active owned record")?;
                self.reused
                    .entry(role)
                    .or_default()
                    .insert(record.digest()?);
            }
        }
        // Reuse is recognized by an actual retained match at the saved decision head;
        // rejection/failure booleans or a same-looking digest confer no reuse credit.
        for (position, event) in owner
            .journal
            .events()
            .iter()
            .enumerate()
            .skip(self.last.events)
        {
            let decision = match event {
                OperationalEvent::PartnerInteractionCompleted { interaction }
                    if interaction.outcome == PartnerInteractionOutcome::SkippedIrrelevant =>
                {
                    owner.journal.events()[..position]
                        .iter()
                        .find_map(|e| match e {
                            OperationalEvent::PartnerDecisionRecorded { decision }
                                if decision.decision_id == interaction.decision_id
                                    && decision.details["schema"] == DETAILS
                                    && decision.details["phase"] == "learn" =>
                            {
                                Some((
                                    Role::OrdinaryLearning,
                                    decision.details["request"].clone(),
                                    decision.details["knowledge_before"].clone(),
                                ))
                            }
                            _ => None,
                        })
                }
                OperationalEvent::EvaluationRejected { candidate_id, .. } => owner.journal.events()
                    [..position]
                    .iter()
                    .find_map(|e| match e {
                        OperationalEvent::PartnerDecisionRecorded { decision }
                            if decision.details["schema"]
                                == "symbiote.receiver-evaluation-decision/1"
                                && decision.details["candidate_id"] == *candidate_id =>
                        {
                            Some((
                                Role::ReceiverRole,
                                decision.details["request"].clone(),
                                decision.details["knowledge_before"].clone(),
                            ))
                        }
                        _ => None,
                    }),
                _ => None,
            };
            if let Some((origin, request, at)) = decision {
                let request: Request =
                    serde_json::from_value(request).map_err(|_| "reuse request rejected")?;
                let at: KnowledgeAnchor =
                    serde_json::from_value(at).map_err(|_| "reuse anchor rejected")?;
                let Operation::Submit { offer } = request.body else {
                    return Err("reuse decision does not name an inert offer".into());
                };
                if let Some(sha) = matching_retained(owner, &at, &offer.record)? {
                    self.reused.entry(origin).or_default().insert(sha);
                }
            }
        }
        self.last = boundary(owner)?;
        Ok(
            json!({"schema":"symbiote.role-learning-checkpoint/1","role":role.name(),"before":before.knowledge,"after":self.last.knowledge,"journal_events":self.last.events,"journal_prefix_sha256":self.last.prefix,"new_promotions":changes.len(),"promotions":self.promotion_counts(),"reused_records":self.reuse_counts()}),
        )
    }
    fn promotion_counts(&self) -> Value {
        local_counts(
            self.promotions
                .values()
                .filter(|r| **r == Role::OrdinaryLearning)
                .count(),
            self.promotions
                .values()
                .filter(|r| **r == Role::ReceiverRole)
                .count(),
            "total_new",
        )
    }
    fn reuse_counts(&self) -> Value {
        local_counts(
            self.reused
                .get(&Role::OrdinaryLearning)
                .map_or(0, BTreeSet::len),
            self.reused
                .get(&Role::ReceiverRole)
                .map_or(0, BTreeSet::len),
            "total",
        )
    }
    pub(in crate::service) fn finish(&self, owner: &State) -> Result<Value, String> {
        validate_operational_disk(owner)?;
        if owner.knowledge.history_anchor() != self.last.knowledge {
            return Err("final knowledge contains unattributed commits".into());
        }
        if owner.journal.event_prefix_sha256(self.initial.events)? != self.initial.prefix {
            return Err("initial counter journal prefix changed".into());
        }
        let actual: BTreeSet<_> = committed(owner, &self.initial.knowledge)?
            .into_iter()
            .map(|(sha, _)| sha)
            .collect();
        if actual != self.promotions.keys().cloned().collect() {
            return Err("role counters do not reconcile with committed ledger suffix".into());
        }
        let index = feedback::replay_index(&owner.journal, &owner.knowledge)?;
        let mut completion_positions = BTreeMap::new();
        for (i, event) in owner.journal.events().iter().enumerate() {
            if let OperationalEvent::PartnerDecisionRecorded { decision } = event {
                let f = &decision.details["event"];
                if decision.details["schema"] == feedback::SCHEMA
                    && matches!(f["phase"].as_str(), Some("outcome" | "rejected"))
                {
                    feedback::validate_carrier(event)?;
                    let id = f["exchange_id"].as_str().ok_or("outcome exchange absent")?;
                    if completion_positions.insert(id.to_string(), i).is_some() {
                        return Err("duplicate completed outcome in counters".into());
                    }
                }
            }
        }
        let mut completed = [BTreeSet::new(), BTreeSet::new()];
        let mut capability = completed.clone();
        let mut benefits = completed.clone();
        let mut active = completed.clone();
        let mut active_cap = completed.clone();
        let mut active_benefits = completed.clone();
        let mut history = completed.clone();
        for experience in &index.experiences {
            let role = match experience.binding.origin {
                feedback::DecisionOrigin::NativeLearningIntent => 0,
                feedback::DecisionOrigin::ReceiverEvaluation => 1,
            };
            let id = &experience.binding.exchange_id;
            let position = *completion_positions
                .get(id)
                .ok_or("validated experience has no actual terminal ledger event")?;
            history[role].insert(id.clone());
            if position < self.initial.events {
                continue;
            }
            completed[role].insert(id.clone());
            let current = experience.currently_active
                && experience.binding.policy_sha256 == owner.config.policy_digest
                && owner
                    .config
                    .context(&experience.binding.scope)
                    .is_ok_and(|context| {
                        context.schema_fingerprint == experience.binding.schema_fingerprint
                            && context.truth_sha256.as_ref()
                                == Some(&experience.binding.fixture_sha256)
                            && owner.config.fixture(context).is_ok()
                    });
            if current {
                active[role].insert(id.clone());
            }
            if let feedback::ExperienceProof::Promotion {
                promotion_sha256, ..
            } = &experience.proof
            {
                let qualified = experience.outcome.quality == feedback::Quality::CapabilityExtended
                    && experience.outcome.uses > 0;
                if qualified {
                    capability[role].insert(promotion_sha256.clone());
                    if current {
                        active_cap[role].insert(promotion_sha256.clone());
                    }
                }
                if qualified
                    && experience.outcome.verified_benefit
                    && experience.outcome.measured_net.is_some_and(|net| net > 0)
                    && index.scoped_measurement_sha256(id)?.is_some()
                {
                    benefits[role].insert(promotion_sha256.clone());
                    if current {
                        active_benefits[role].insert(promotion_sha256.clone());
                    }
                }
            }
        }
        let remote = super::super::outcomes::counter_credits(owner, self.initial.events)?;
        Ok(
            json!({"schema":"symbiote.role-learning-counters/1","basis":"unique actual committed ledger events in this run; capability/benefit counts are outcome subsets, not additional promotions","initial_knowledge_anchor":self.initial.knowledge,"final_knowledge_anchor":self.last.knowledge,"initial_journal_events":self.initial.events,"initial_journal_prefix_sha256":self.initial.prefix,"final_journal_events":owner.journal.events().len(),"final_journal_prefix_sha256":owner.journal.event_prefix_sha256(owner.journal.events().len())?,"final_operational_head_sha256":owner.journal.head_sha256(),"promotions":self.promotion_counts(),"reused_records":self.reuse_counts(),"completed_outcomes":origin_counts(completed[0].len(),completed[1].len(),remote.new_completed),"capability_outcomes":origin_counts(capability[0].len(),capability[1].len(),remote.new_capability),"measured_benefits":origin_counts(benefits[0].len(),benefits[1].len(),remote.new_measured),"current_active_local":{"completed_outcomes":local_counts(active[0].len(),active[1].len(),"total"),"capability_outcomes":local_counts(active_cap[0].len(),active_cap[1].len(),"total"),"measured_benefits":local_counts(active_benefits[0].len(),active_benefits[1].len(),"total")},"durable_history_completed_outcomes":origin_counts(history[0].len(),history[1].len(),remote.history_completed),"partner_current_status":"unobservable after last authenticated response; partner counts preserve validated response snapshots","promotion_sha256_by_role":{"ordinary_learning":self.promotions.iter().filter(|(_,role)|**role==Role::OrdinaryLearning).map(|(sha,_)|sha).collect::<Vec<_>>(),"receiver_role":self.promotions.iter().filter(|(_,role)|**role==Role::ReceiverRole).map(|(sha,_)|sha).collect::<Vec<_>>()}}),
        )
    }
}
