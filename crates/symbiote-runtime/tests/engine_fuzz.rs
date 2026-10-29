//! Fixed-budget adversarial input/property checks, without external fuzz engines.
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use symbiote_runtime::engine::*;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory {
    root: PathBuf,
    base: PathBuf,
}
impl Directory {
    fn new() -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let root = base.join(format!(
            "symbiote-engine-fuzz-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self { root, base }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let Ok(path) = self.root.canonicalize() {
            if path.parent() == Some(self.base.as_path())
                && path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("symbiote-engine-fuzz-")
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}
struct Source {
    description: SourceDescriptor,
    calls: usize,
}
impl ObservationSource for Source {
    fn descriptor(&self) -> SourceDescriptor {
        self.description.clone()
    }
    fn observe(
        &mut self,
        r: ObservationRequest<'_>,
    ) -> std::result::Result<Observation, SourceError> {
        self.calls += 1;
        Ok(Observation {
            sequence: r.sequence,
            input: r.input,
            output: ((r.input & 3).count_ones() % 2) as u8,
        })
    }
}
fn setup(directory: &Directory) -> (EngineConfig, Artifact) {
    let descriptor = SourceDescriptor {
        source_id: "unit-fuzz-source".into(),
        scope: "unit-fuzz/v1".into(),
        epoch: "unit-1".into(),
        commitment: "a".repeat(64),
        width: 3,
    };
    let config = EngineConfig::new(vec![descriptor.clone()]);
    let mut engine = Engine::initialize(&directory.root.join("teacher"), config.clone()).unwrap();
    let mut source = Source {
        description: descriptor.clone(),
        calls: 0,
    };
    let mut options = EpisodeOptions::bounded(descriptor);
    options.query_policy = AffineQueryPolicy::RankBasis;
    let retained = engine
        .run_episode(&mut source, &options, &mut NoopSink)
        .unwrap();
    let artifact = engine.export_artifact(&retained.artifact).unwrap();
    engine.close().unwrap();
    (config, artifact)
}

#[test]
fn fixed_256_byte_mutations_are_rejected_or_independently_correct() {
    let directory = Directory::new();
    let (config, artifact) = setup(&directory);
    let encoded = serde_json::to_vec(&artifact).unwrap();
    assert!(encoded.len() < 128 * 1024);
    let mut decoded = 0;
    for index in 0..256usize {
        let mut bytes = encoded.clone();
        let at = (index * 104729 + 17) % bytes.len();
        bytes[at] ^= 1u8 << (index % 8);
        let parsed = std::panic::catch_unwind(|| serde_json::from_slice::<Artifact>(&bytes));
        assert!(parsed.is_ok(), "bounded deserialization must not panic");
        if let Ok(changed) = parsed.unwrap() {
            decoded += 1;
            let mut receiver = Engine::initialize(
                &directory.root.join(format!("receiver-{index}")),
                config.clone(),
            )
            .unwrap();
            let before = receiver.inspect().unwrap().knowledge;
            let mut source = Source {
                description: artifact.source.clone(),
                calls: 0,
            };
            let mut options = EpisodeOptions::bounded(artifact.source.clone());
            options.query_policy = AffineQueryPolicy::RankBasis;
            let evaluated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                receiver.evaluate_artifact(&changed, &mut source, &options, &mut NoopSink)
            }));
            assert!(evaluated.is_ok(), "bounded engine admission must not panic");
            match evaluated.unwrap() {
                Ok(candidate) => {
                    let retained = receiver.retain(candidate, &mut NoopSink).unwrap();
                    for input in 0..8u16 {
                        assert_eq!(
                            receiver
                                .predict(&retained.artifact, input, &mut NoopSink)
                                .unwrap()
                                .answer,
                            Some(((input & 3).count_ones() % 2) as u8)
                        );
                    }
                }
                Err(error) => {
                    assert!(matches!(
                        error.kind,
                        ErrorKind::Malformed
                            | ErrorKind::Contradiction
                            | ErrorKind::Authorization
                            | ErrorKind::IncompatibleSchema
                    ));
                    assert_eq!(receiver.inspect().unwrap().knowledge, before);
                }
            }
            assert!(source.calls <= 5);
        }
    }
    assert!(
        decoded > 0,
        "fuzz set must exercise engine admission, not only JSON rejection"
    );
}

#[test]
fn internally_rehashed_wrong_affine_artifacts_never_promote() {
    let directory = Directory::new();
    let (config, original) = setup(&directory);
    let mut receiver = Engine::initialize(&directory.root.join("receiver"), config).unwrap();
    let before = receiver.inspect().unwrap().knowledge;
    for index in 0..64usize {
        let mut artifact = original.clone();
        artifact.record.payload["coefficients"] = serde_json::json!(3u16 ^ (1u16 << (index % 3)));
        artifact.record_sha256 = artifact.record.digest().unwrap();
        // The attacker can recompute ordinary hashes. It still has no observations,
        // evaluated token or authority to change the receiver's independent source.
        let mut source = Source {
            description: artifact.source.clone(),
            calls: 0,
        };
        let mut options = EpisodeOptions::bounded(artifact.source.clone());
        options.query_policy = AffineQueryPolicy::RankBasis;
        let result = receiver.evaluate_artifact(&artifact, &mut source, &options, &mut NoopSink);
        match result {
            Ok(_) => panic!("wrong model admitted at mutation {index}"),
            Err(error) => assert!(matches!(
                error.kind,
                ErrorKind::Malformed
                    | ErrorKind::Contradiction
                    | ErrorKind::Authorization
                    | ErrorKind::IncompatibleSchema
            )),
        }
        assert!(source.calls <= 5);
        assert_eq!(receiver.inspect().unwrap().knowledge, before);
    }
    assert!(receiver.inspect().unwrap().active_artifacts.is_empty());
}
