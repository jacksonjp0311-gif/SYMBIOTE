//! Development fixtures only. This file must not generate or inspect the
//! prospective evaluation cohort before source/environment registration.
#[path = "../src/adaptive_research/model.rs"]
mod model;
#[path = "../src/adaptive_research/policy.rs"]
mod policy;
// This development harness compiles the unopened primary entry points without
// executing them; process-only filters cannot mint an EvaluationPermit.
#[allow(dead_code)]
#[path = "../src/adaptive_research/actor.rs"]
mod actor;
#[allow(dead_code)]
#[path = "../src/adaptive_research/admission.rs"]
mod admission;
#[allow(dead_code)]
#[path = "../src/adaptive_research/authority.rs"]
mod authority;
#[allow(dead_code)]
#[path = "../src/adaptive_research/cohort.rs"]
mod cohort;
#[allow(dead_code)]
#[path = "../src/adaptive_research/controller.rs"]
mod controller;
#[allow(dead_code)]
#[path = "../src/adaptive_research/evidence.rs"]
mod evidence;
#[allow(dead_code)]
#[path = "../src/adaptive_research/meter.rs"]
mod meter;
#[allow(dead_code)]
#[path = "../src/adaptive_research/process.rs"]
mod process;
#[allow(dead_code)]
#[path = "../src/adaptive_research/profile_audit.rs"]
mod profile_audit;
#[allow(dead_code)]
#[path = "../src/adaptive_research/registration.rs"]
mod registration;
#[allow(dead_code)]
#[path = "../src/adaptive_research/replay_setup.rs"]
mod replay_setup;
#[allow(dead_code)]
#[path = "../src/adaptive_research/summary.rs"]
mod summary;
#[allow(dead_code)]
#[path = "../src/adaptive_research/wire.rs"]
mod wire;
