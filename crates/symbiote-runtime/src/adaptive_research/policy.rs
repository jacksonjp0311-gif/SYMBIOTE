//! Request ranking only. No score authorizes a connection, validates a receipt,
//! or changes the receiver's exact hypothesis family.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Arm {
    Isolated,
    Fixed,
    Uniform,
    Prospective,
}
impl Arm {
    pub(super) const ALL: [Self; 4] = [
        Self::Isolated,
        Self::Fixed,
        Self::Uniform,
        Self::Prospective,
    ];
    pub(super) fn index(self) -> usize {
        match self {
            Self::Isolated => 0,
            Self::Fixed => 1,
            Self::Uniform => 2,
            Self::Prospective => 3,
        }
    }
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Fixed => "fixed-peer",
            Self::Uniform => "uniform-authorized",
            Self::Prospective => "prospective-frontier",
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Profile {
    pub(super) attempts: u64,
    pub(super) verified_novel: u64,
    pub(super) verification_failures: u64,
    pub(super) applicability_failures: u64,
}
impl Profile {
    pub(super) fn probability(&self) -> (u64, u64) {
        (self.verified_novel + 1, self.attempts + 2)
    }
    pub(super) fn quarantined(&self) -> bool {
        self.verification_failures + self.applicability_failures >= 2
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RegistryPeer {
    pub(super) identity: String,
    pub(super) authorized: bool,
    pub(super) compatible: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Advertisement {
    pub(super) peer: String,
    pub(super) context: String,
    pub(super) schema_fingerprint: String,
    pub(super) scope: String,
    pub(super) edge_id: usize,
    pub(super) offer_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Quota {
    pub(super) acquisitions: usize,
    pub(super) attempts: usize,
    pub(super) adopted_edges: usize,
    pub(super) model_work: usize,
    pub(super) requests: usize,
    pub(super) connections: usize,
    pub(super) traffic: usize,
}
impl Quota {
    #[cfg(test)]
    pub(super) fn fresh(edges: usize) -> Self {
        Self {
            acquisitions: edges,
            attempts: 3,
            adopted_edges: edges,
            model_work: 100_000,
            requests: 256,
            connections: 128,
            traffic: 1_048_576,
        }
    }
    pub(super) fn reserve_receiver(
        &self,
        assessment_work: usize,
        frame: usize,
        control_frame: usize,
    ) -> bool {
        self.acquisitions >= 1
            && self.attempts >= 1
            && self.adopted_edges >= 1
            && self.model_work > assessment_work
            && self.requests >= 3
            && self.connections >= 3
            && self.traffic >= 3 * (2 * frame + 2 * control_frame)
    }
    pub(super) fn reserve_contributor(&self, frame: usize, control_frame: usize) -> bool {
        self.requests >= 1 && self.connections >= 1 && self.traffic >= 2 * frame + 2 * control_frame
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(super) struct Quote {
    pub(super) receiver_max: u64,
    pub(super) contributor_max: u64,
    pub(super) pair_max: u64,
    pub(super) frame: usize,
    pub(super) control_frame: usize,
}
impl Quote {
    pub(super) fn validate(self) -> Result<(), String> {
        if self.receiver_max.checked_add(self.contributor_max) != Some(self.pair_max)
            || self.frame != 4096
            || self.control_frame != 1024
        {
            return Err(
                "HOLD: method-comparison quote does not match enforced operation bounds".into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct Choice {
    pub(super) peer: Option<String>,
    pub(super) offer_id: Option<String>,
    pub(super) probability_numerator: u64,
    pub(super) probability_denominator: u64,
    pub(super) reason: String,
    pub(super) frontier: usize,
    pub(super) observation_price: u64,
    pub(super) quote: Quote,
}
pub(super) struct Decision<'a> {
    pub(super) arm: Arm,
    pub(super) context: &'a str,
    pub(super) schema_fingerprint: &'a str,
    pub(super) scope: &'a str,
    pub(super) frontier: usize,
    pub(super) known: &'a BTreeSet<usize>,
    pub(super) registry: &'a [RegistryPeer],
    pub(super) advertisements: &'a [Advertisement],
    pub(super) profiles: &'a BTreeMap<String, Profile>,
    pub(super) attempted_context_peers: &'a BTreeSet<String>,
    pub(super) fixed_peer: Option<&'a str>,
    pub(super) uniform_index: Option<usize>,
    pub(super) observation_price: u64,
    pub(super) quota: &'a Quota,
    pub(super) assessment_bound: usize,
    pub(super) quote: Quote,
}
impl Decision<'_> {
    fn eligible(&self, ad: &Advertisement) -> bool {
        self.registry
            .iter()
            .any(|peer| peer.identity == ad.peer && peer.authorized && peer.compatible)
            && ad.context == self.context
            && ad.schema_fingerprint == self.schema_fingerprint
            && ad.scope == self.scope
    }
    fn relevant(&self, ad: &Advertisement) -> bool {
        ad.edge_id == self.frontier && !self.known.contains(&ad.edge_id)
    }
    pub(super) fn choose(&self) -> Result<Choice, String> {
        self.quote.validate()?;
        if self.profiles.values().any(|profile| {
            profile.attempts > 128
                || profile.verified_novel > profile.attempts
                || profile.verification_failures + profile.applicability_failures > profile.attempts
        }) {
            return Err(
                "audited relationship profile counters are inconsistent or exceed their cap".into(),
            );
        }
        let mut choice = Choice {
            peer: None,
            offer_id: None,
            probability_numerator: 0,
            probability_denominator: 1,
            reason: "local-observation".into(),
            frontier: self.frontier,
            observation_price: self.observation_price,
            quote: self.quote,
        };
        if self.arm == Arm::Isolated {
            choice.reason = "isolated-control".into();
            return Ok(choice);
        }
        let mut ads = self
            .advertisements
            .iter()
            .filter(|ad| self.eligible(ad))
            .collect::<Vec<_>>();
        ads.sort_by(|a, b| a.peer.cmp(&b.peer));
        if ads.windows(2).any(|pair| pair[0].peer == pair[1].peer) {
            return Err("duplicate registry advertisement identity".into());
        }
        let selected = match self.arm {
            Arm::Isolated => None,
            Arm::Fixed => self
                .fixed_peer
                .and_then(|identity| ads.iter().find(|ad| ad.peer == identity).copied()),
            Arm::Uniform => {
                if ads.is_empty() {
                    None
                } else {
                    let index = self
                        .uniform_index
                        .ok_or("uniform control lacks a bounded external draw")?;
                    Some(
                        *ads.get(index)
                            .ok_or("uniform draw outside candidate count")?,
                    )
                }
            }
            Arm::Prospective => {
                let mut candidates = ads
                    .into_iter()
                    .filter(|ad| {
                        self.relevant(ad)
                            && !self.attempted_context_peers.contains(&ad.peer)
                            && !self
                                .profiles
                                .get(&ad.peer)
                                .is_some_and(Profile::quarantined)
                    })
                    .collect::<Vec<_>>();
                candidates.sort_by(|a, b| {
                    let (an, ad) = self
                        .profiles
                        .get(&a.peer)
                        .cloned()
                        .unwrap_or_default()
                        .probability();
                    let (bn, bd) = self
                        .profiles
                        .get(&b.peer)
                        .cloned()
                        .unwrap_or_default()
                        .probability();
                    (u128::from(bn) * u128::from(ad))
                        .cmp(&(u128::from(an) * u128::from(bd)))
                        .then_with(|| a.peer.cmp(&b.peer))
                });
                candidates.first().copied()
            }
        };
        let Some(ad) = selected else {
            choice.reason = "no-eligible-offer".into();
            return Ok(choice);
        };
        choice.peer = Some(ad.peer.clone());
        choice.offer_id = Some(ad.offer_id.clone());
        if !self.relevant(ad) {
            choice.reason = "selected-offer-not-current-frontier".into();
            return Ok(choice);
        }
        if self.attempted_context_peers.contains(&ad.peer) {
            choice.reason = "peer-already-attempted-in-context".into();
            return Ok(choice);
        }
        let profile = self.profiles.get(&ad.peer).cloned().unwrap_or_default();
        if profile.quarantined() {
            choice.reason = "verification-quarantine".into();
            return Ok(choice);
        }
        let (numerator, denominator) = if self.arm == Arm::Prospective {
            profile.probability()
        } else {
            (1, 2)
        };
        choice.probability_numerator = numerator;
        choice.probability_denominator = denominator;
        if u128::from(self.quote.pair_max) * u128::from(denominator)
            >= u128::from(self.observation_price) * u128::from(numerator)
        {
            choice.reason = "conservative-exchange-price-not-lower".into();
            return Ok(choice);
        }
        if !self.quota.reserve_receiver(
            self.assessment_bound,
            self.quote.frame,
            self.quote.control_frame,
        ) {
            choice.reason = "fallback-and-common-work-reservation-unavailable".into();
            return Ok(choice);
        }
        choice.reason = "request-verified-frontier-offer".into();
        Ok(choice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn quote() -> Quote {
        Quote {
            receiver_max: 31,
            contributor_max: 15,
            pair_max: 46,
            frame: 4096,
            control_frame: 1024,
        }
    }
    #[test]
    fn exact_rational_gate_declines_cheap_observation_and_preserves_permission_boundary() {
        let registry = [
            RegistryPeer {
                identity: "valid".into(),
                authorized: true,
                compatible: true,
            },
            RegistryPeer {
                identity: "untrusted".into(),
                authorized: false,
                compatible: true,
            },
        ];
        let ads = [
            Advertisement {
                peer: "valid".into(),
                context: "opaque".into(),
                schema_fingerprint: "fingerprint".into(),
                scope: "scope".into(),
                edge_id: 1,
                offer_id: "offer".into(),
            },
            Advertisement {
                peer: "untrusted".into(),
                context: "opaque".into(),
                schema_fingerprint: "fingerprint".into(),
                scope: "scope".into(),
                edge_id: 1,
                offer_id: "spoofed".into(),
            },
        ];
        let profiles = BTreeMap::new();
        let known = BTreeSet::new();
        let attempted = BTreeSet::new();
        let quota = Quota::fresh(4);
        let mut decision = Decision {
            arm: Arm::Prospective,
            context: "opaque",
            schema_fingerprint: "fingerprint",
            scope: "scope",
            frontier: 1,
            known: &known,
            registry: &registry,
            advertisements: &ads,
            profiles: &profiles,
            attempted_context_peers: &attempted,
            fixed_peer: None,
            uniform_index: None,
            observation_price: 100,
            quota: &quota,
            assessment_bound: 16,
            quote: quote(),
        };
        let choice = decision.choose().unwrap();
        assert_eq!(choice.peer.as_deref(), Some("valid"));
        assert_eq!(choice.reason, "request-verified-frontier-offer");
        decision.observation_price = 1;
        assert_eq!(
            decision.choose().unwrap().reason,
            "conservative-exchange-price-not-lower"
        );
        assert_eq!(Arm::ALL.len(), 4);
        assert_eq!(Arm::Fixed.index(), 1);
        assert_eq!(Arm::Uniform.name(), "uniform-authorized");
        assert!(quota.reserve_contributor(4096, 1024));
    }
    #[test]
    fn two_actual_verification_failures_quarantine_but_transport_failures_do_not() {
        let profile = Profile {
            attempts: 4,
            verified_novel: 1,
            verification_failures: 1,
            applicability_failures: 1,
        };
        assert!(profile.quarantined());
        assert_eq!(profile.probability(), (2, 6));
        let transport_only = Profile {
            attempts: 4,
            ..Profile::default()
        };
        assert!(!transport_only.quarantined());
    }
}
