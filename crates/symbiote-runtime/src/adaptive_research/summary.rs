//! Derived comparisons only. Incomplete or ambiguous bills never become zero
//! cost samples; operational completion and positive utility are separate gates.
use serde_json::{json, Value};

const ACTIVE: [usize; 4] = [0, 1, 2, 4];
struct Metrics {
    cost: u64,
    correct: u64,
    total: u64,
    incorrect: u64,
}
fn metrics(case: &Value, role: usize) -> Result<Metrics, &'static str> {
    if case["status"] != "COMPLETED" {
        return Err("case not completed");
    }
    let rows = case["participants"]
        .as_array()
        .ok_or("participant list missing")?;
    let row = rows
        .iter()
        .find(|row| row["role"] == role)
        .ok_or("participant missing")?;
    if row["utility_evaluable"] != true {
        return Err("ambiguous source purchase or missing utility witness");
    }
    let read = |key: &str| {
        row[key]
            .as_u64()
            .ok_or("numeric participant metric missing")
    };
    let result = Metrics {
        cost: read("cost")?,
        correct: read("heldout_correct")?,
        total: read("heldout_total")?,
        incorrect: read("incorrect_certificates")?,
    };
    if result.correct > result.total
        || result.incorrect > result.total + 1
        || result.cost > 1_000_000_000
    {
        return Err("participant metric outside declared bounds");
    }
    Ok(result)
}
fn participant(base: &Metrics, next: &Metrics, role: usize) -> Value {
    let safe = base.incorrect == 0 && next.incorrect == 0;
    let benefit = safe
        && ((next.correct >= base.correct && next.cost < base.cost)
            || (next.correct > base.correct && next.cost <= base.cost));
    let class = if !safe {
        "incorrect-certificate"
    } else if next.correct < base.correct {
        "reduced-coverage"
    } else if benefit {
        "benefit"
    } else if next.correct > base.correct {
        "coverage-cost-tradeoff"
    } else if next.cost > base.cost {
        "higher-cost"
    } else {
        "equal"
    };
    json!({"role":role,"benefit":benefit,"class":class,"baseline_cost":base.cost,"candidate_cost":next.cost,"cost_difference":next.cost as i64-base.cost as i64,"baseline_correct":base.correct,"candidate_correct":next.correct,"heldout_total":base.total,"baseline_incorrect":base.incorrect,"candidate_incorrect":next.incorrect})
}
fn compare(cases: &[Value], worlds: usize, price: u64, baseline: &str, candidate: &str) -> Value {
    let mut pairs = Vec::new();
    let mut bilateral = 0;
    let mut evaluated = 0;
    let (mut base_cost, mut next_cost, mut base_coverage, mut next_coverage, mut wrong) =
        (0_u64, 0_u64, 0_u64, 0_u64, 0_u64);
    for world in 0..worlds {
        let locate = |arm: &str| {
            cases
                .iter()
                .filter(|case| {
                    case["world"] == world && case["price"] == price && case["arm"] == arm
                })
                .collect::<Vec<_>>()
        };
        let base = locate(baseline);
        let next = locate(candidate);
        if base.len() != 1 || next.len() != 1 {
            pairs.push(json!({"world":world,"status":"NOT_EVALUABLE","reason":"missing or repeated paired case"}));
            continue;
        }
        let mut rows = Vec::new();
        let mut complete = true;
        let mut both = true;
        for role in ACTIVE {
            match (metrics(base[0], role), metrics(next[0], role)) {
                (Ok(first), Ok(second)) if first.total == second.total => {
                    let result = participant(&first, &second, role);
                    if role <= 1 {
                        both &= result["benefit"] == true;
                    }
                    rows.push(result);
                }
                (first, second) => {
                    complete = false;
                    both = false;
                    rows.push(json!({"role":role,"class":"NOT_EVALUABLE","reason":first.err().or(second.err()).unwrap_or("held-out task counts differ")}));
                }
            }
        }
        if complete {
            evaluated += 1;
            bilateral += usize::from(both);
            for row in rows
                .iter()
                .filter(|row| row["role"].as_u64().is_some_and(|role| role <= 1))
            {
                base_cost += row["baseline_cost"].as_u64().expect("typed summary metric");
                next_cost += row["candidate_cost"]
                    .as_u64()
                    .expect("typed summary metric");
                base_coverage += row["baseline_correct"]
                    .as_u64()
                    .expect("typed summary metric");
                next_coverage += row["candidate_correct"]
                    .as_u64()
                    .expect("typed summary metric");
                wrong += row["baseline_incorrect"]
                    .as_u64()
                    .expect("typed summary metric")
                    + row["candidate_incorrect"]
                        .as_u64()
                        .expect("typed summary metric");
            }
        }
        pairs.push(json!({"world":world,"status":if complete{"EVALUATED"}else{"NOT_EVALUABLE"},"participants":rows,"bilateral_A_B1_benefit":both&&complete}));
    }
    let positive = evaluated == worlds
        && bilateral > 0
        && next_cost < base_cost
        && next_coverage >= base_coverage
        && wrong == 0;
    json!({"baseline_arm":baseline,"candidate_arm":candidate,"worlds_expected":worlds,"worlds_evaluable":evaluated,"bilateral_benefit_worlds":bilateral,"A_B1_baseline_cost":base_cost,"A_B1_candidate_cost":next_cost,"A_B1_baseline_correct":base_coverage,"A_B1_candidate_correct":next_coverage,"positive_utility_gate":if positive{"DEMONSTRATED"}else{"NOT_DEMONSTRATED"},"paired_worlds":pairs})
}
pub(super) fn summarize(cases: &[Value], worlds: usize) -> Value {
    let mut regimes = Vec::new();
    let mut primary = false;
    let mut broad = false;
    for price in [100, 1] {
        let mut comparisons = Vec::new();
        for baseline in ["isolated", "fixed-peer", "uniform-authorized"] {
            comparisons.push(compare(
                cases,
                worlds,
                price,
                baseline,
                "prospective-frontier",
            ));
        }
        if price == 100 {
            primary = comparisons[0]["positive_utility_gate"] == "DEMONSTRATED";
            broad = comparisons[1..]
                .iter()
                .all(|comparison| comparison["positive_utility_gate"] == "DEMONSTRATED");
        }
        let controls = ["fixed-peer", "uniform-authorized"]
            .into_iter()
            .map(|control| compare(cases, worlds, price, "isolated", control))
            .collect::<Vec<_>>();
        regimes.push(json!({"observation_price":price,"role":if price==100{"primary"}else{"negative-cost-control"},"prospective_vs_controls":comparisons,"relationship_controls_vs_isolated":controls}));
    }
    json!({"normal_policy_utility":if primary{"DEMONSTRATED"}else{"NOT_DEMONSTRATED"},"normal_better_partner_selection":if primary&&broad{"DEMONSTRATED"}else{"NOT_DEMONSTRATED"},"regimes":regimes,"meaning":"software completion does not imply a positive scientific utility result; all losses and incomplete pairs remain shown"})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn case(arm: &str, cost: u64, correct: u64) -> Value {
        json!({"status":"COMPLETED","world":0,"price":100,"arm":arm,"participants":ACTIVE.into_iter().map(|role|json!({"role":role,"utility_evaluable":true,"cost":cost,"heldout_correct":correct,"heldout_total":3,"incorrect_certificates":0})).collect::<Vec<_>>()})
    }
    #[test]
    fn every_loss_tradeoff_and_missing_pair_remains_visible() {
        let rows = vec![
            case("isolated", 100, 3),
            case("fixed-peer", 90, 3),
            case("uniform-authorized", 100, 3),
            case("prospective-frontier", 95, 3),
        ];
        let report = summarize(&rows, 1);
        assert_eq!(report["normal_policy_utility"], "DEMONSTRATED");
        assert_eq!(
            report["normal_better_partner_selection"],
            "NOT_DEMONSTRATED"
        );
        assert_eq!(
            report["regimes"][0]["prospective_vs_controls"][1]["paired_worlds"][0]["participants"]
                [0]["class"],
            "higher-cost"
        );
        let report = summarize(&rows[..3], 1);
        assert_eq!(report["normal_policy_utility"], "NOT_DEMONSTRATED");
        assert_eq!(
            report["regimes"][0]["prospective_vs_controls"][0]["worlds_evaluable"],
            0
        );
        let trade = participant(
            &Metrics {
                cost: 100,
                correct: 1,
                total: 3,
                incorrect: 0,
            },
            &Metrics {
                cost: 120,
                correct: 2,
                total: 3,
                incorrect: 0,
            },
            0,
        );
        assert_eq!(trade["class"], "coverage-cost-tradeoff");
        assert_eq!(trade["benefit"], false);
    }
}
