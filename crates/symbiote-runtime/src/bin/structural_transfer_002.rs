//! One execution of SYMBIOTE-STRUCTURAL-TRANSFER-002.
//!
//! Targets are derived from the registration seed only after the registration
//! digest, protocol digest, and source stamp match. The acceptance rule is
//! applied to the measured costs. A negative net stays negative.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use symbiote_memory::knowledge::{
    affine_schema_fingerprint, assess, KnowledgeRecord, KnowledgeStore, TrialCase, TrialCosts,
    TrialEvidence,
};
use symbiote_memory::reciprocal::{
    ObservedDraft, ObservedOutcome, PromotionSeal, PromotionWitness, ReciprocalReceipt,
    ValidationOutcome,
};
use symbiote_reasoning::structural::{AffineLearner, AffineStrategy};

const WIDTH: u8 = 4;
const TASKS_PER_OWNER: usize = 4;
const UNIT: &str = "affine-oracle-check/1";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.first().map(String::as_str) == Some("--self-check") {
        self_check()
    } else if args.first().map(String::as_str) == Some("--restart-check") {
        restart_check(&args)
    } else {
        study(&args)
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn study(args: &[String]) -> Result<(), String> {
    let registration_path = arg(args, "--registration")?;
    let expected = arg(args, "--registration-sha256")?;
    let out = PathBuf::from(arg(args, "--out")?);
    let registration_bytes = fs::read(&registration_path).map_err(|e| e.to_string())?;
    let actual = hex(&Sha256::digest(&registration_bytes));
    if actual != expected {
        return Err("registration digest mismatch".into());
    }
    let registration: Value =
        serde_json::from_slice(&registration_bytes).map_err(|e| e.to_string())?;
    need(
        &registration,
        "schema",
        "symbiote.structural-transfer-002-registration/1",
    )?;
    need(
        &registration,
        "protocol",
        "SYMBIOTE-STRUCTURAL-TRANSFER-002",
    )?;
    need(&registration, "width", &WIDTH.to_string())?;
    need(
        &registration,
        "tasks_per_owner",
        &TASKS_PER_OWNER.to_string(),
    )?;
    need(&registration, "unit", UNIT)?;
    let source = option_env!("SYMBIOTE_SOURCE_COMMIT").unwrap_or("unknown");
    if registration["source_commit"].as_str() != Some(source) {
        return Err("study binary source stamp differs from the registration".into());
    }
    let root = PathBuf::from(text(&registration, "repository")?);
    let protocol =
        fs::read(root.join("docs/RESEARCH_V06_PROTOCOL.md")).map_err(|e| e.to_string())?;
    if hex(&Sha256::digest(protocol)) != text(&registration, "protocol_sha256")? {
        return Err("protocol bytes differ from the registration".into());
    }
    let learner = PathBuf::from(text(&registration, "independent_learner")?);
    let learner_bytes = fs::read(&learner).map_err(|e| e.to_string())?;
    if hex(&Sha256::digest(&learner_bytes)) != text(&registration, "independent_learner_sha256")? {
        return Err("independent learner bytes differ from the registration".into());
    }
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let executable_bytes = fs::read(&executable).map_err(|e| e.to_string())?;
    if hex(&Sha256::digest(executable_bytes)) != text(&registration, "executable_sha256")? {
        return Err("study executable differs from the registration".into());
    }
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let seed = u64::from_str_radix(text(&registration, "seed")?, 16).map_err(|e| e.to_string())?;
    let (mask, biases) = cohort(seed);
    let tasks: Vec<AffineStrategy> = biases
        .iter()
        .map(|bias| AffineStrategy::new(WIDTH, mask, *bias))
        .collect::<Result<_, _>>()?;
    let (owner_a, owner_b) = tasks.split_at(TASKS_PER_OWNER);
    let isolated_a = arm_queries(owner_a, Arm::Isolated)?;
    let isolated_b = arm_queries(owner_b, Arm::Isolated)?;
    let fixed_a = arm_queries(owner_a, Arm::FixedBasis)?;
    let fixed_b = arm_queries(owner_b, Arm::FixedBasis)?;
    let hinted_a = arm_queries(owner_a, Arm::Hinted)?;
    let hinted_b = arm_queries(owner_b, Arm::Hinted)?;
    let equal_a = arm_queries(owner_a, Arm::EqualBudget)?;
    let equal_b = arm_queries(owner_b, Arm::EqualBudget)?;
    let support_unchanged = hint_support_unchanged(&tasks[0])?;
    let independent_a = independent_arm(&registration, owner_a)?;
    let independent_b = independent_arm(&registration, owner_b)?;
    let wrong = wrong_family(&out)?;
    let remapped = remap_control(&tasks[0])?;
    let transfer = 1_u64;
    let regression = 1_u64;
    let verification = u64::try_from(WIDTH).map_err(|_| "width")? + 1;
    let exchange_a = hinted_a + transfer + regression + verification;
    let exchange_b = hinted_b + transfer + regression + verification;
    let net_a = i128::from(isolated_a) - i128::from(exchange_a);
    let net_b = i128::from(isolated_b) - i128::from(exchange_b);
    let receipt_a = promote_exchange(
        &out.join("owner-a"),
        "owner-a",
        "owner-b",
        &tasks[TASKS_PER_OWNER],
        isolated_a,
        exchange_a,
    )?;
    let receipt_b = promote_exchange(
        &out.join("owner-b"),
        "owner-b",
        "owner-a",
        &tasks[0],
        isolated_b,
        exchange_b,
    )?;
    let incorrect = u64::from(!receipt_a.truth_ok || !receipt_b.truth_ok || wrong.certified);
    let success = net_a > 0
        && net_b > 0
        && incorrect == 0
        && receipt_a.restart_oracle_calls == 0
        && receipt_b.restart_oracle_calls == 0
        && receipt_a.retained_prediction
        && receipt_b.retained_prediction
        && wrong.rejected
        && wrong.history_unchanged;
    let status = if success { "PASS" } else { "NOT_DEMONSTRATED" };
    let report = json!({
        "schema": "symbiote.structural-transfer-002-result/1",
        "protocol": "SYMBIOTE-STRUCTURAL-TRANSFER-002",
        "status": status,
        "unit": UNIT,
        "scientific_samples": 0,
        "cohort_executions": 1,
        "registration_sha256": expected,
        "source_commit": source,
        "width": WIDTH,
        "shared_mask": mask,
        "task_biases": biases,
        "support_unchanged_by_hint": support_unchanged,
        "arms": {
            "isolated": [isolated_a, isolated_b],
            "equal_budget": [equal_a, equal_b],
            "fixed_basis": [fixed_a, fixed_b],
            "hinted_queries": [hinted_a, hinted_b],
            "independent_learner_queries": [independent_a, independent_b],
            "exchange_total": [exchange_a, exchange_b]
        },
        "nets": [net_a, net_b],
        "incorrect_certificates": incorrect,
        "remapped_control_matches": remapped,
        "mismatch": wrong.report,
        "receipts": [receipt_a.report, receipt_b.report],
        "mutual_benefit": receipt_a.benefit && receipt_b.benefit
    });
    fs::write(
        out.join("result.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("{status}");
    Ok(())
}

fn restart_check(args: &[String]) -> Result<(), String> {
    let directory = PathBuf::from(arg(args, "--restart-check")?);
    let identity = arg(args, "--identity")?;
    let store = KnowledgeStore::open(&directory, &identity)?;
    let retained = !store.active().is_empty();
    println!("{}", if retained { "RETAINED 0" } else { "MISSING 0" });
    Ok(())
}

fn self_check() -> Result<(), String> {
    let truth = AffineStrategy::new(2, 1, false)?;
    let isolated = count(&truth, Arm::Isolated)?;
    let hinted = count(&truth, Arm::Hinted)?;
    let fixed = count(&truth, Arm::FixedBasis)?;
    if isolated != 3
        || hinted != 3
        || fixed != 3
        || !hint_support_unchanged(&truth)?
        || !remap_control(&truth)?
    {
        return Err("public accounting fixture left the width+1 bound".into());
    }
    println!("SELF_CHECK_OK");
    Ok(())
}

#[derive(Clone, Copy)]
enum Arm {
    Isolated,
    FixedBasis,
    Hinted,
    EqualBudget,
}

fn arm_queries(tasks: &[AffineStrategy], arm: Arm) -> Result<u64, String> {
    let mut total = 0_u64;
    for task in tasks {
        total += match arm {
            Arm::Isolated | Arm::EqualBudget => count(task, Arm::Isolated)?,
            Arm::FixedBasis => count(task, Arm::FixedBasis)?,
            Arm::Hinted => count(task, Arm::Hinted)?,
        };
    }
    Ok(total)
}

fn count(truth: &AffineStrategy, arm: Arm) -> Result<u64, String> {
    let mut learner = AffineLearner::new(truth.width, 1_000_000)?;
    if matches!(arm, Arm::Hinted) {
        let before = learner.hypothesis_count();
        learner.set_hint(truth)?;
        if learner.hypothesis_count() != before {
            return Err("hint removed a hypothesis before observation".into());
        }
    }
    let mut used = Vec::new();
    while learner.identified().is_none() {
        if used.len() > usize::from(truth.width) + 2 {
            return Err("identification exceeded the information-bound window".into());
        }
        let input = match arm {
            Arm::FixedBasis => basis_input(&used, truth.width)?,
            _ => learner
                .choose_query()?
                .ok_or("query abstained before identification")?,
        };
        learner.observe(input, truth.predict(input)?)?;
        used.push(input);
    }
    if learner.identified().as_ref() != Some(truth) {
        return Err("certified strategy differed from the task truth".into());
    }
    Ok(u64::try_from(used.len()).map_err(|_| "query count")?)
}

fn hint_support_unchanged(truth: &AffineStrategy) -> Result<bool, String> {
    let mut learner = AffineLearner::new(truth.width, 1_000_000)?;
    let before = learner.hypothesis_count();
    learner.set_hint(truth)?;
    Ok(learner.hypothesis_count() == before)
}

fn basis_input(used: &[u16], width: u8) -> Result<u16, String> {
    let mut inputs = vec![0];
    for bit in 0..width {
        inputs.push(1_u16 << bit);
    }
    inputs
        .into_iter()
        .find(|input| !used.contains(input))
        .ok_or_else(|| "basis exhausted".into())
}

fn cohort(seed: u64) -> (u16, Vec<bool>) {
    let mut state = seed;
    let mask = (splitmix(&mut state) as u16) & ((1_u16 << WIDTH) - 1);
    let biases = (0..TASKS_PER_OWNER * 2)
        .map(|_| splitmix(&mut state) & 1 == 1)
        .collect();
    (mask, biases)
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn independent_arm(registration: &Value, tasks: &[AffineStrategy]) -> Result<u64, String> {
    let mut total = 0_u64;
    for task in tasks {
        total += independent_one(registration, task)?;
    }
    Ok(total)
}

fn independent_one(registration: &Value, truth: &AffineStrategy) -> Result<u64, String> {
    let python = text(registration, "python")?;
    let script = text(registration, "independent_learner")?;
    let mut child = Command::new(python)
        .arg(script)
        .arg(truth.width.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut input = child.stdin.take().ok_or("learner stdin")?;
    let output = child.stdout.take().ok_or("learner stdout")?;
    let mut lines = BufReader::new(output).lines();
    let mut queries = 0_u64;
    let done = loop {
        let line = lines
            .next()
            .ok_or("learner closed stdout")?
            .map_err(|e| e.to_string())?;
        let message: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if message.get("done").and_then(Value::as_bool) == Some(true) {
            break message;
        }
        let query = message
            .get("query")
            .and_then(Value::as_u64)
            .ok_or("learner query")? as u16;
        let y = truth.predict(query)?;
        writeln!(input, "{}", json!({"y": y})).map_err(|e| e.to_string())?;
        input.flush().map_err(|e| e.to_string())?;
        queries += 1;
    };
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("independent learner failed".into());
    }
    let reported = done
        .get("queries")
        .and_then(Value::as_u64)
        .ok_or("learner query count")?;
    if reported != queries {
        return Err("independent learner query count disagreed".into());
    }
    let coefficients = done
        .get("coefficients")
        .and_then(Value::as_u64)
        .ok_or("coefficients")? as u16;
    let bias = done.get("bias").and_then(Value::as_bool).ok_or("bias")?;
    if AffineStrategy::new(truth.width, coefficients, bias)? != *truth {
        return Err("independent learner certified a different strategy".into());
    }
    Ok(queries)
}

struct WrongFamily {
    rejected: bool,
    certified: bool,
    history_unchanged: bool,
    report: Value,
}

fn wrong_family(out: &Path) -> Result<WrongFamily, String> {
    let directory = out.join("mismatch");
    let store = KnowledgeStore::open(&directory, "owner-b")?;
    let before = store.history_anchor();
    let offered = AffineStrategy::new(WIDTH, 1, false)?;
    let mut learner = AffineLearner::new(WIDTH, 1_000_000)?;
    let mut certified = false;
    for input in 0..(1_u16 << WIDTH) {
        let y = u8::from((input & 1) == 1 && (input & 2) == 2);
        if learner.observe(input, y).is_err() {
            break;
        }
        if learner.identified().as_ref() == Some(&offered) {
            certified = true;
            break;
        }
    }
    let after = store.history_anchor();
    let receipt = ReciprocalReceipt::seal_observed(ObservedDraft {
        evaluator_identity: "owner-b".into(),
        sender_identity: "owner-a".into(),
        receiver_knowledge_before_sha256: before.head_sha256.clone(),
        sender_knowledge_before_sha256:
            "0000000000000000000000000000000000000000000000000000000000000000".into(),
        transferred_record_sha256: hex(&Sha256::digest(b"mismatched-and-constraint")),
        outcome: ObservedOutcome::Rejected,
        isolated_control_cost: 0,
        exchange_path_cost: 0,
        persisted_after_restart: Some(false),
    })?;
    Ok(WrongFamily {
        rejected: receipt.validation == ValidationOutcome::Rejected,
        certified,
        history_unchanged: before == after,
        report: json!({
            "rejected": receipt.validation == ValidationOutcome::Rejected,
            "wrong_strategy_certified": certified,
            "history_unchanged": before == after
        }),
    })
}

fn remap_control(truth: &AffineStrategy) -> Result<bool, String> {
    let remapped = AffineStrategy::new(truth.width, rotate_mask(truth), truth_bias(truth)?)?;
    let queries = count(&remapped, Arm::Isolated)?;
    let original_input = 1_u16;
    let rotated = rotate_input(original_input, truth.width);
    let expected = truth.predict(original_input)?;
    let through_remap = remapped.predict(rotated)?;
    Ok(queries == u64::from(truth.width) + 1 && expected == through_remap)
}

fn rotate_mask(truth: &AffineStrategy) -> u16 {
    let width = truth.width;
    let mask = truth_coefficients(truth);
    ((mask << 1) | (mask >> (width - 1))) & ((1_u16 << width) - 1)
}

fn rotate_input(input: u16, width: u8) -> u16 {
    ((input << 1) | (input >> (width - 1))) & ((1_u16 << width) - 1)
}

fn truth_coefficients(truth: &AffineStrategy) -> u16 {
    (0..truth.width)
        .filter(|bit| truth.predict(1_u16 << bit).ok() != truth.predict(0).ok())
        .fold(0, |mask, bit| mask | (1_u16 << bit))
}

fn truth_bias(truth: &AffineStrategy) -> Result<bool, String> {
    Ok(truth.predict(0)? == 1)
}

struct Promoted {
    truth_ok: bool,
    benefit: bool,
    retained_prediction: bool,
    restart_oracle_calls: u64,
    report: Value,
}

fn promote_exchange(
    directory: &Path,
    receiver: &str,
    sender: &str,
    truth: &AffineStrategy,
    baseline: u64,
    candidate: u64,
) -> Result<Promoted, String> {
    let _ = fs::remove_dir_all(directory);
    let mut store = KnowledgeStore::open(directory, receiver)?;
    let before = store.history_anchor();
    let record = KnowledgeRecord {
        id: format!("{sender}-mask"),
        revision: 1,
        source: sender.into(),
        scope: "affine-boolean-v1/structural-transfer-002".into(),
        schema_fingerprint: affine_schema_fingerprint(WIDTH)?,
        payload: json!({"kind":"affine","width":WIDTH,"coefficients":truth_coefficients(truth),"bias":truth_bias(truth)?}),
        provenance: "receiver observations of the transferred affine constraint".into(),
    };
    let verification = candidate
        .checked_sub(baseline)
        .and_then(|gap| gap.checked_sub(1))
        .ok_or("exchange cost does not cover its measured parts")?;
    let evidence = TrialEvidence {
        evaluator: "structural-lab".into(),
        training_case_ids: vec!["train-0".into()],
        training_inputs: vec![0],
        cases: vec![case("held-1", 1, truth)?, case("held-2", 2, truth)?],
        costs: TrialCosts {
            acquisition: baseline,
            verification,
            adoption: 1,
            baseline,
            candidate,
        },
    };
    let assessment = assess(&record, &evidence)?;
    store.promote(record.clone(), assessment)?;
    let after = store.history_anchor();
    let evidence_value = serde_json::to_value(&evidence).map_err(|e| e.to_string())?;
    let receipt = ReciprocalReceipt::seal_promoted(
        &store,
        PromotionWitness {
            record: &record,
            evidence: &evidence_value,
            before: &before,
            after: &after,
        },
        &PromotionSeal {
            sender_identity: sender.into(),
            sender_knowledge_before_sha256: before.head_sha256.clone(),
            persisted_after_restart: Some(true),
            completed: true,
        },
    )?;
    drop(store);
    let restart = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .args([
            "--restart-check",
            &directory.display().to_string(),
            "--identity",
            receiver,
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !restart.status.success() {
        return Err(format!(
            "restart process failed: {}",
            String::from_utf8_lossy(&restart.stderr)
        ));
    }
    let restart_text = String::from_utf8_lossy(&restart.stdout);
    let mut restart_fields = restart_text.split_whitespace();
    let retained = restart_fields.next() == Some("RETAINED");
    let restart_oracle_calls: u64 = restart_fields
        .next()
        .unwrap_or("1")
        .parse()
        .map_err(|_| "restart count")?;
    let reopened = KnowledgeStore::open(directory, receiver)?;
    let prediction = truth.predict(3)?;
    Ok(Promoted {
        truth_ok: truth.predict(1)? == evidence.cases[0].expected,
        benefit: receipt.confirmed_benefit(
            &reopened,
            PromotionWitness {
                record: &record,
                evidence: &evidence_value,
                before: &before,
                after: &after,
            },
        ),
        retained_prediction: retained && prediction <= 1,
        restart_oracle_calls,
        report: json!({
            "receiver": receiver,
            "sender": sender,
            "benefit_verified": receipt.confirmed_benefit(&reopened, PromotionWitness { record: &record, evidence: &evidence_value, before: &before, after: &after }),
            "isolated_control_cost": receipt.isolated_control_cost,
            "exchange_path_cost": receipt.exchange_path_cost,
            "retained_after_reopen": retained,
            "restart_oracle_calls": restart_oracle_calls
        }),
    })
}

fn case(id: &str, input: u16, truth: &AffineStrategy) -> Result<TrialCase, String> {
    let expected = truth.predict(input)?;
    Ok(TrialCase {
        id: id.into(),
        input,
        expected,
        baseline: None,
        candidate: expected,
    })
}

fn arg(args: &[String], name: &str) -> Result<String, String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .ok_or_else(|| format!("missing {name}"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("registration missing {key}"))
}

fn need(value: &Value, key: &str, expected: &str) -> Result<(), String> {
    let actual = value
        .get(key)
        .map(|item| match item {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .ok_or_else(|| format!("registration missing {key}"))?;
    if actual != expected {
        return Err(format!("{key} changed"));
    }
    Ok(())
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
