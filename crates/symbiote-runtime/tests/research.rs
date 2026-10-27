use serde_json::Value;
use std::fs;
use std::process::Command;

#[test]
fn research_models_retain_identity_predict_offline_and_keep_both_owners_separate() {
    let temp = std::env::temp_dir().join(format!(
        "symbiote-research-integration-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp).unwrap();
    let state = temp.join("state");
    let output = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["research", "--json", "--state"])
        .arg(&state)
        .arg("--receipts")
        .arg(temp.join("report.json"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["cases"], 24);
    assert_eq!(report["promoted"], 48);
    assert_ne!(report["identity"], report["partner_identity"]);
    assert_eq!(
        report["aggregate"]["correct"],
        report["aggregate"]["heldout_predictions"]
    );
    for case in report["participants"].as_array().unwrap() {
        assert_eq!(case["correct"], case["isolated_correct"]);
        assert!(case["exchange_cost"].as_u64().unwrap() < case["isolated_cost"].as_u64().unwrap());
        assert_eq!(
            case["own_oracle_queries"].as_u64().unwrap(),
            case["width"].as_u64().unwrap() + 1
        );
    }
    assert!(report["negative_controls"]
        .as_object()
        .unwrap()
        .values()
        .all(|x| x == true));
    let before = fs::read(state.join("knowledge.jsonl")).unwrap();
    let retained = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["predict", "--json", "--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(
        retained.status.success(),
        "{}",
        String::from_utf8_lossy(&retained.stderr)
    );
    let retained: Value = serde_json::from_slice(&retained.stdout).unwrap();
    assert_eq!(retained["identity"], report["identity"]);
    assert_eq!(retained["structural_artifacts"], 24);
    assert_eq!(retained["network_requests"], 0);
    assert_eq!(fs::read(state.join("knowledge.jsonl")).unwrap(), before);
    assert!(retained["structural_knowledge"]
        .as_array()
        .unwrap()
        .iter()
        .all(|x| x["source"] == "partner-linear"));
    let partner = Command::new(env!("CARGO_BIN_EXE_symbiote"))
        .args(["predict", "--json", "--state"])
        .arg(state.join("research-partner"))
        .output()
        .unwrap();
    assert!(partner.status.success());
    let partner: Value = serde_json::from_slice(&partner.stdout).unwrap();
    assert_eq!(partner["identity"], report["partner_identity"]);
    assert_eq!(partner["structural_artifacts"], 24);
    assert!(partner["structural_knowledge"]
        .as_array()
        .unwrap()
        .iter()
        .all(|x| x["source"] == "symbiote-exact"));
    fs::remove_dir_all(temp).unwrap();
}
