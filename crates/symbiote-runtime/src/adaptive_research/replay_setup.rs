//! Import only original empty identities and public opaque context labels.
//! No learned state, truth, credentials, or authority receipts enter a learner.
use super::cohort::World;
use super::policy::Arm;
use super::registration::{PROTOCOL_ID, PROTOCOL_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use symbiote_memory::knowledge::graph::graph_schema_fingerprint;
use symbiote_memory::Store;

const MAX_SETUP: usize = 131_072;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalPrimary {
    pub(super) run_id: String,
    pub(super) registration_sha256: String,
    pub(super) report_sha256: String,
    pub(super) frozen_environments_sha256: String,
    pub(super) candidate_source_commit: String,
    pub(super) candidate_binary_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetupBinding {
    pub(super) setup_sha256: String,
    pub(super) original_primary: OriginalPrimary,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Genesis {
    identity: String,
    genesis_jsonl: String,
}
impl Genesis {
    fn validate(&self) -> Result<(), String> {
        if Store::validate_empty_genesis(self.genesis_jsonl.as_bytes())? != self.identity {
            return Err("setup genesis does not belong to its declared identity".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Learner {
    role: usize,
    genesis: Genesis,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    arm: String,
    price: u64,
    authority: Genesis,
    roles: Vec<Learner>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalogue {
    schema: String,
    identity_count: usize,
    state_path_count: usize,
    counterfactual_learner_identities: usize,
    isolated_learner_profiles: usize,
    controller: Genesis,
    groups: Vec<Group>,
    contains_private_keys: bool,
    contains_learned_records: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorldContext {
    index: usize,
    context: String,
    schema_fingerprint: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreludeContext {
    arm: String,
    price: u64,
    context: String,
    schema_fingerprint: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    schema: String,
    protocol_id: String,
    protocol_sha256: String,
    original_primary: OriginalPrimary,
    genesis_catalogue: Catalogue,
    world_contexts: Vec<WorldContext>,
    prelude_contexts: Vec<PreludeContext>,
}
pub(super) struct LoadedSetup {
    setup: Setup,
    bytes: Vec<u8>,
    binding: SetupBinding,
}
fn hexadecimal(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn context(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| hexadecimal(suffix, 64))
}
fn expected_groups() -> BTreeSet<(u64, String)> {
    [100, 1]
        .into_iter()
        .flat_map(|price| Arm::ALL.map(|arm| (price, arm.name().into())))
        .collect()
}
fn reject_link(path: &Path) -> Result<(), String> {
    reject_link_with_temporary(path, &std::env::temp_dir())
}
fn reject_link_with_temporary(path: &Path, trusted_temporary: &Path) -> Result<(), String> {
    // macOS exposes its OS temporary directory through /var -> /private/var.
    // Resolve only that trusted prefix; canonicalizing the requested file
    // itself would erase evidence of user-created inner symlinks.
    let checked = match path.strip_prefix(trusted_temporary) {
        Ok(suffix) => fs::canonicalize(trusted_temporary)
            .map_err(|_| "trusted OS temporary directory unavailable")?
            .join(suffix),
        Err(_) => path.to_path_buf(),
    };
    for component in checked.ancestors() {
        let metadata =
            fs::symlink_metadata(component).map_err(|_| "setup path or ancestor is unavailable")?;
        #[cfg(windows)]
        let linked = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let linked = metadata.file_type().is_symlink();
        if linked {
            return Err("setup paths must not traverse symbolic links or reparse points".into());
        }
    }
    Ok(())
}
fn regular_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    reject_link(&absolute)?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|_| "setup file unavailable")?;
    if !metadata.is_file() || metadata.len() > MAX_SETUP as u64 {
        return Err("setup must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(&absolute)
        .map_err(|_| "setup file cannot be opened")?
        .take((MAX_SETUP + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "setup file read failed")?;
    if bytes.len() > MAX_SETUP {
        return Err("setup file exceeded its byte budget".into());
    }
    Ok(bytes)
}
impl LoadedSetup {
    pub(super) fn read(path: &Path, expected_sha256: &str) -> Result<Self, String> {
        Self::from_bytes(regular_bytes(path)?, expected_sha256)
    }
    fn from_bytes(bytes: Vec<u8>, expected_sha256: &str) -> Result<Self, String> {
        if !hexadecimal(expected_sha256, 64)
            || bytes.is_empty()
            || bytes.len() > MAX_SETUP
            || format!("{:x}", Sha256::digest(&bytes)) != expected_sha256
        {
            return Err("HOLD: setup bytes differ from the externally supplied SHA256".into());
        }
        let setup: Setup = serde_json::from_slice(&bytes).map_err(|_| {
            "setup schema rejected: only empty genesis and public contexts are allowed"
        })?;
        if setup.schema != "symbiote.reproduction-setup/1"
            || setup.protocol_id != PROTOCOL_ID
            || setup.protocol_sha256 != PROTOCOL_SHA256
            || setup.original_primary.run_id.is_empty()
            || setup.original_primary.run_id.len() > 128
            || !hexadecimal(&setup.original_primary.registration_sha256, 64)
            || !hexadecimal(&setup.original_primary.report_sha256, 64)
            || !hexadecimal(&setup.original_primary.frozen_environments_sha256, 64)
            || !hexadecimal(&setup.original_primary.candidate_source_commit, 40)
            || !hexadecimal(&setup.original_primary.candidate_binary_sha256, 64)
        {
            return Err("setup protocol or original evidence binding rejected".into());
        }
        let catalogue = &setup.genesis_catalogue;
        if catalogue.schema != "symbiote.simulation-genesis-catalogue/1"
            || catalogue.identity_count != 14
            || catalogue.state_path_count != 49
            || catalogue.counterfactual_learner_identities != 5
            || catalogue.isolated_learner_profiles != 40
            || catalogue.contains_private_keys
            || catalogue.contains_learned_records
            || catalogue.groups.len() != 8
        {
            return Err("setup must describe exactly the original empty paired simulation".into());
        }
        catalogue.controller.validate()?;
        let mut unique = BTreeSet::from([catalogue.controller.identity.clone()]);
        let mut groups = BTreeSet::new();
        let mut paired = BTreeMap::new();
        for group in &catalogue.groups {
            if !groups.insert((group.price, group.arm.clone())) || group.roles.len() != 5 {
                return Err("setup group or learner slot is duplicated or missing".into());
            }
            group.authority.validate()?;
            if !unique.insert(group.authority.identity.clone()) {
                return Err("setup authority aliases another identity".into());
            }
            let mut roles = BTreeSet::new();
            for learner in &group.roles {
                learner.genesis.validate()?;
                if learner.role >= 5 || !roles.insert(learner.role) {
                    return Err("setup requires each trusted learner role exactly once".into());
                }
                let entry = paired.entry(learner.role).or_insert_with(|| {
                    (
                        learner.genesis.identity.clone(),
                        learner.genesis.genesis_jsonl.clone(),
                    )
                });
                if entry
                    != &(
                        learner.genesis.identity.clone(),
                        learner.genesis.genesis_jsonl.clone(),
                    )
                {
                    return Err(
                        "paired learner genesis bytes differ across private profiles".into(),
                    );
                }
            }
        }
        if groups != expected_groups() || paired.len() != 5 {
            return Err("setup must enumerate the eight exact arm and price pairs".into());
        }
        for (identity, _) in paired.values() {
            if !unique.insert(identity.clone()) {
                return Err("setup paired role identities alias each other or an authority".into());
            }
        }
        if unique.len() != 14 || setup.world_contexts.is_empty() || setup.world_contexts.len() > 24
        {
            return Err("setup identity or world-context count rejected".into());
        }
        let mut labels = BTreeSet::new();
        for (index, world) in setup.world_contexts.iter().enumerate() {
            if world.index != index
                || !context(&world.context, "frontier-context-")
                || !hexadecimal(&world.schema_fingerprint, 64)
                || !labels.insert(world.context.clone())
            {
                return Err(
                    "setup world contexts must be unique and ordered by frozen index".into(),
                );
            }
        }
        let mut preludes = BTreeSet::new();
        for prelude in &setup.prelude_contexts {
            if !preludes.insert((prelude.price, prelude.arm.clone()))
                || !context(&prelude.context, "frontier-prelude-")
                || prelude.schema_fingerprint != setup.world_contexts[0].schema_fingerprint
                || !labels.insert(prelude.context.clone())
            {
                return Err(
                    "setup prelude contexts are duplicated or do not bind the first schema".into(),
                );
            }
        }
        if setup.prelude_contexts.len() != 8 || preludes != expected_groups() {
            return Err("setup must contain each original prelude context exactly once".into());
        }
        let binding = SetupBinding {
            setup_sha256: expected_sha256.into(),
            original_primary: setup.original_primary.clone(),
        };
        Ok(Self {
            setup,
            bytes,
            binding,
        })
    }
    pub(super) fn require_worlds(&self, count: usize) -> Result<(), String> {
        if self.setup.world_contexts.len() != count {
            return Err("setup context count differs from this declared experiment".into());
        }
        Ok(())
    }
    pub(super) fn apply_worlds(&self, worlds: &mut [World]) -> Result<(), String> {
        self.require_worlds(worlds.len())?;
        for (world, saved) in worlds.iter().zip(&self.setup.world_contexts) {
            if world.index != saved.index
                || graph_schema_fingerprint(&world.schema)? != saved.schema_fingerprint
            {
                return Err(
                    "HOLD: regenerated public graph differs from the setup schema binding".into(),
                );
            }
        }
        for (world, saved) in worlds.iter_mut().zip(&self.setup.world_contexts) {
            world.context.clone_from(&saved.context);
        }
        Ok(())
    }
    pub(super) fn binding(&self) -> SetupBinding {
        self.binding.clone()
    }
    pub(super) fn prelude(&self, price: u64, arm: Arm) -> Result<String, String> {
        self.setup
            .prelude_contexts
            .iter()
            .find(|item| item.price == price && item.arm == arm.name())
            .map(|item| item.context.clone())
            .ok_or_else(|| "setup prelude slot missing".into())
    }
    pub(super) fn copy_artifact(&self, artifacts: &Path) -> Result<(), String> {
        write_new(&artifacts.join("reproduction-setup.json"), &self.bytes)
    }
    fn slots(&self, state: &Path) -> Vec<(PathBuf, &Genesis)> {
        let mut result = vec![(
            state.to_path_buf(),
            &self.setup.genesis_catalogue.controller,
        )];
        for group in &self.setup.genesis_catalogue.groups {
            let root = state
                .join("campaigns")
                .join(if group.price == 100 {
                    "normal"
                } else {
                    "cheap"
                })
                .join(&group.arm);
            result.push((root.join("authority"), &group.authority));
            for role in &group.roles {
                result.push((
                    root.join(format!("participant-{}", role.role)),
                    &role.genesis,
                ));
            }
        }
        result
    }
    pub(super) fn install(&self, state: &Path) -> Result<Value, String> {
        reject_link(state)?;
        if !state.is_dir()
            || fs::read_dir(state)
                .map_err(|_| "setup destination unavailable")?
                .next()
                .is_some()
        {
            return Err("HOLD: setup destination must be a reserved empty state directory; existing state is preserved".into());
        }
        // Exclusive start marker prevents competing imports. An interrupted
        // import remains visibly nonempty and is never silently retried.
        write_new(
            &state.join("replay-setup.started.json"),
            &serde_json::to_vec(&self.binding).map_err(|e| e.to_string())?,
        )?;
        let slots = self.slots(state);
        for (path, genesis) in &slots {
            if path != state {
                fs::create_dir_all(path).map_err(|_| "setup slot directory creation failed")?;
            }
            reject_link(path)?;
            write_new(&path.join("ledger.jsonl"), genesis.genesis_jsonl.as_bytes())?;
        }
        for (path, genesis) in &slots {
            let bytes = fs::read(path.join("ledger.jsonl"))
                .map_err(|_| "restored genesis readback failed")?;
            if bytes != genesis.genesis_jsonl.as_bytes()
                || Store::validate_empty_genesis(&bytes)? != genesis.identity
            {
                return Err("HOLD: restored original genesis bytes failed readback".into());
            }
        }
        let receipt = json!({"schema":"symbiote.replay-setup-restored/1","setup_sha256":self.binding.setup_sha256,"state_paths":slots.len(),"logical_identities":14,"paired_learner_identities":5,"learner_private_profiles":40,"learned_records_imported":0,"private_keys_imported":0,"original_genesis_bytes_preserved":true});
        write_new(
            &state.join("replay-setup.complete.json"),
            &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
        )?;
        Ok(receipt)
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            "setup destination already exists or cannot be created; no overwrite performed"
        })?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "setup write could not be committed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbiote_protocol::fresh_capability;
    struct Temporary(PathBuf);
    impl Temporary {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "symbiote-replay-unit-{}",
                fresh_capability().unwrap()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            assert!(self.0.starts_with(std::env::temp_dir()));
            assert!(self
                .0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("symbiote-replay-unit-"));
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn empty(path: &Path) -> Genesis {
        let store = Store::open(path).unwrap();
        Genesis {
            identity: store.identity().into(),
            genesis_jsonl: fs::read_to_string(store.ledger_path()).unwrap(),
        }
    }
    fn manual_setup(root: &Path) -> Setup {
        let roles = (0..5)
            .map(|role| Learner {
                role,
                genesis: empty(&root.join(format!("role{role}"))),
            })
            .collect::<Vec<_>>();
        let groups = [100, 1]
            .into_iter()
            .flat_map(|price| Arm::ALL.map(move |arm| (price, arm)))
            .enumerate()
            .map(|(index, (price, arm))| Group {
                arm: arm.name().into(),
                price,
                roles: roles.clone(),
                authority: empty(&root.join(format!("auth{index}"))),
            })
            .collect();
        Setup {
            schema: "symbiote.reproduction-setup/1".into(),
            protocol_id: PROTOCOL_ID.into(),
            protocol_sha256: PROTOCOL_SHA256.into(),
            original_primary: OriginalPrimary {
                run_id: "manual-fixture-only".into(),
                registration_sha256: "a".repeat(64),
                report_sha256: "b".repeat(64),
                frozen_environments_sha256: "c".repeat(64),
                candidate_source_commit: "d".repeat(40),
                candidate_binary_sha256: "e".repeat(64),
            },
            genesis_catalogue: Catalogue {
                schema: "symbiote.simulation-genesis-catalogue/1".into(),
                identity_count: 14,
                state_path_count: 49,
                counterfactual_learner_identities: 5,
                isolated_learner_profiles: 40,
                controller: empty(&root.join("controller")),
                groups,
                contains_private_keys: false,
                contains_learned_records: false,
            },
            world_contexts: vec![WorldContext {
                index: 0,
                context: format!("frontier-context-{}", "a".repeat(64)),
                schema_fingerprint: "b".repeat(64),
            }],
            prelude_contexts: [100, 1]
                .into_iter()
                .flat_map(|price| Arm::ALL.map(move |arm| (price, arm)))
                .enumerate()
                .map(|(index, (price, arm))| PreludeContext {
                    arm: arm.name().into(),
                    price,
                    context: format!("frontier-prelude-{index:064x}"),
                    schema_fingerprint: "b".repeat(64),
                })
                .collect(),
        }
    }
    fn load(setup: &Setup) -> Result<LoadedSetup, String> {
        let bytes = serde_json::to_vec(setup).unwrap();
        let hash = format!("{:x}", Sha256::digest(&bytes));
        LoadedSetup::from_bytes(bytes, &hash)
    }
    #[test]
    fn original_genesis_restore_preserves_all_slots_without_sharing_private_files() {
        let temp = Temporary::new();
        let source = temp.0.join("source");
        fs::create_dir(&source).unwrap();
        let setup = manual_setup(&source);
        let loaded = load(&setup).unwrap();
        let destination = temp.0.join("state");
        fs::create_dir(&destination).unwrap();
        let receipt = loaded.install(&destination).unwrap();
        assert_eq!(receipt["state_paths"], 49);
        let first = destination.join("campaigns/normal/isolated/participant-0/ledger.jsonl");
        let paired = destination.join("campaigns/cheap/fixed-peer/participant-0/ledger.jsonl");
        let original = fs::read(&paired).unwrap();
        assert_eq!(fs::read(&first).unwrap(), original);
        fs::write(&first, b"changed only one file").unwrap();
        assert_eq!(fs::read(&paired).unwrap(), original);
        assert!(loaded.install(&destination).is_err());
        assert_eq!(fs::read(&first).unwrap(), b"changed only one file");
        assert!(!destination.join("knowledge.jsonl").exists());
    }
    #[test]
    fn foreign_genesis_unknown_keys_collisions_and_external_hash_tampering_are_rejected() {
        let temp = Temporary::new();
        let setup = manual_setup(&temp.0);
        let mut foreign = setup.clone();
        foreign.genesis_catalogue.controller.identity = foreign.genesis_catalogue.groups[0]
            .authority
            .identity
            .clone();
        assert!(load(&foreign).is_err());
        let mut history = setup.clone();
        history
            .genesis_catalogue
            .controller
            .genesis_jsonl
            .push_str("{}\n");
        assert!(load(&history).is_err());
        let mut collision = setup.clone();
        collision.genesis_catalogue.groups[0].authority =
            collision.genesis_catalogue.controller.clone();
        assert!(load(&collision).is_err());
        let mut value = serde_json::to_value(&setup).unwrap();
        value["models"] = json!([]);
        let bytes = serde_json::to_vec(&value).unwrap();
        let hash = format!("{:x}", Sha256::digest(&bytes));
        assert!(LoadedSetup::from_bytes(bytes, &hash).is_err());
        let original = serde_json::to_vec(&setup).unwrap();
        let hash = format!("{:x}", Sha256::digest(&original));
        let mut altered = setup.clone();
        altered.original_primary.run_id = "rehashed-but-not-externally-authorized".into();
        assert!(LoadedSetup::from_bytes(serde_json::to_vec(&altered).unwrap(), &hash).is_err());
        let mut wrong_slot = setup.clone();
        wrong_slot.genesis_catalogue.groups[0].arm = "../../elsewhere".into();
        assert!(load(&wrong_slot).is_err());
    }
    #[test]
    fn missing_slots_contexts_and_preexisting_destination_are_preserved() {
        let temp = Temporary::new();
        let setup = manual_setup(&temp.0);
        let mut missing = setup.clone();
        missing.genesis_catalogue.groups.pop();
        assert!(load(&missing).is_err());
        let mut duplicate = setup.clone();
        duplicate.prelude_contexts[1].context = duplicate.prelude_contexts[0].context.clone();
        assert!(load(&duplicate).is_err());
        let target = temp.0.join("occupied");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("sentinel"), b"preserve").unwrap();
        assert!(load(&setup).unwrap().install(&target).is_err());
        assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"preserve");
        assert!(!target.join("ledger.jsonl").exists());
        assert!(load(&setup).unwrap().require_worlds(24).is_err());
    }
    #[test]
    fn public_context_restore_checks_manual_schema_before_changing_any_label() {
        use symbiote_reasoning::planning::{Edge, GraphSchema};
        let temp = Temporary::new();
        let mut setup = manual_setup(&temp.0);
        let schema = GraphSchema {
            nodes: 4,
            edges: [(0, 1), (1, 3), (0, 2), (2, 3)]
                .into_iter()
                .map(|(from, to)| Edge {
                    from,
                    to,
                    lower: 1,
                    upper: 3,
                })
                .collect(),
        };
        let fingerprint = graph_schema_fingerprint(&schema).unwrap();
        setup.world_contexts[0]
            .schema_fingerprint
            .clone_from(&fingerprint);
        for prelude in &mut setup.prelude_contexts {
            prelude.schema_fingerprint.clone_from(&fingerprint);
        }
        let loaded = load(&setup).unwrap();
        let mut worlds = vec![World {
            index: 0,
            nodes: 4,
            seed: 17,
            seed_index: 0,
            counter: 0,
            canonical_adjacency: "released-manual-diamond".into(),
            context: "unrestored".into(),
            schema,
            costs: vec![1, 3, 2, 2],
        }];
        loaded.apply_worlds(&mut worlds).unwrap();
        assert_eq!(worlds[0].context, setup.world_contexts[0].context);
        worlds[0].schema.edges[0].upper = 4;
        worlds[0].context = "preserve-on-error".into();
        assert!(loaded.apply_worlds(&mut worlds).is_err());
        assert_eq!(worlds[0].context, "preserve-on-error");
    }
    #[cfg(unix)]
    #[test]
    fn trusted_os_temporary_alias_is_allowed_but_inner_links_remain_rejected() {
        use std::os::unix::fs::symlink;
        let temp = Temporary::new();
        let real = temp.0.join("physical-temporary");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("setup.json"), b"manual").unwrap();
        let alias = temp.0.join("os-temporary-alias");
        symlink(&real, &alias).unwrap();
        assert!(reject_link_with_temporary(&alias.join("setup.json"), &alias).is_ok());
        let outside = temp.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("setup.json"), b"preserve").unwrap();
        symlink(&outside, real.join("user-created-link")).unwrap();
        assert!(
            reject_link_with_temporary(&alias.join("user-created-link/setup.json"), &alias)
                .is_err()
        );
        symlink(real.join("setup.json"), real.join("leaf-link")).unwrap();
        assert!(reject_link_with_temporary(&alias.join("leaf-link"), &alias).is_err());
    }
}
