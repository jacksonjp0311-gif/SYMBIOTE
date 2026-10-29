// Minimal host importing only the documented engine API. The engine neither
// reads arguments nor prints; this standalone host owns those presentation acts.
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};
use symbiote_runtime::engine::*;

struct XorSource {
    description: SourceDescriptor,
    mask: u16,
    calls: usize,
    offline: bool,
}
impl ObservationSource for XorSource {
    fn descriptor(&self) -> SourceDescriptor {
        self.description.clone()
    }
    fn observe(
        &mut self,
        r: ObservationRequest<'_>,
    ) -> std::result::Result<Observation, SourceError> {
        if r.cancellation.is_cancelled() {
            return Err(SourceError::new(ErrorKind::Cancelled, "host cancellation"));
        }
        if self.offline {
            return Err(SourceError::new(
                ErrorKind::Storage,
                "source is deliberately unavailable",
            ));
        }
        if Instant::now() >= r.deadline {
            return Err(SourceError::new(
                ErrorKind::DeadlineExceeded,
                "host source deadline",
            ));
        }
        if r.sequence != self.calls || r.source != &self.description {
            return Err(SourceError::new(
                ErrorKind::Authorization,
                "host request binding differs",
            ));
        }
        self.calls += 1;
        Ok(Observation {
            sequence: r.sequence,
            input: r.input,
            output: ((r.input & self.mask).count_ones() % 2) as u8,
        })
    }
}
#[derive(Default)]
struct Events {
    calls: usize,
}
impl EventSink for Events {
    fn event(&mut self, _: &EngineEvent) -> std::result::Result<(), SinkError> {
        self.calls += 1;
        Ok(())
    }
}
fn source(scope: &str, mask: u16) -> XorSource {
    XorSource {
        description: SourceDescriptor {
            source_id: format!("host-{scope}"),
            scope: scope.into(),
            epoch: "host-epoch-1".into(),
            commitment: format!("{mask:064x}"),
            width: 3,
        },
        mask,
        calls: 0,
        offline: false,
    }
}
fn check(ok: bool, why: &str) -> std::io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::other(why))
    }
}
fn quoted(s: &str) -> String {
    let mut text = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => text.push_str("\\\""),
            '\\' => text.push_str("\\\\"),
            '\n' => text.push_str("\\n"),
            '\r' => text.push_str("\\r"),
            '\t' => text.push_str("\\t"),
            c if c.is_control() => {
                text.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => text.push(c),
        }
    }
    text.push('"');
    text
}
fn run(root: &Path) -> std::result::Result<String, Box<dyn std::error::Error>> {
    check(
        root.is_absolute(),
        "host output must be an absolute fresh directory",
    )?;
    fs::create_dir(root)?;
    let cwd = std::env::current_dir()?;
    let environment = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
    let mut a_source = source("consumer-a", 5);
    let mut b_source = source("consumer-b", 3);
    let ac = EngineConfig::new(vec![a_source.descriptor()]);
    let bc = EngineConfig::new(vec![b_source.descriptor()]);
    let mut a = Engine::initialize(&root.join("owner-a"), ac.clone())?;
    let mut b = Engine::initialize(&root.join("owner-b"), bc.clone())?;
    let ai = a.identity()?.to_string();
    let bi = b.identity()?.to_string();
    check(ai != bi, "owners must differ")?;
    check(
        Engine::open(&root.join("owner-a"), &ai, ac.clone()).is_err(),
        "same owner writer must be excluded",
    )?;
    let mut ae = Events::default();
    let mut be = Events::default();
    let mut ao = EpisodeOptions::bounded(a_source.descriptor());
    ao.query_policy = AffineQueryPolicy::RankBasis;
    let mut bo = EpisodeOptions::bounded(b_source.descriptor());
    bo.query_policy = AffineQueryPolicy::RankBasis;
    let candidate = a.observe_infer(&mut a_source, &ao, &mut ae)?;
    check(
        a.inspect()?.knowledge.records == 1,
        "observation must not promote",
    )?;
    let evaluated = a.evaluate(candidate, &mut ae)?;
    check(
        a.inspect()?.knowledge.records == 1,
        "evaluation must not promote",
    )?;
    let ar = a.retain(evaluated, &mut ae)?;
    let br = b.run_episode(&mut b_source, &bo, &mut be)?;
    check(
        a_source.calls == 5 && b_source.calls == 5,
        "bounded actual acquisition",
    )?;
    for input in 0..8 {
        check(
            a.predict(&ar.artifact, input, &mut ae)?.answer
                == Some(((input & 5u16).count_ones() % 2) as u8),
            "first owner exact answer",
        )?;
        check(
            b.predict(&br.artifact, input, &mut be)?.answer
                == Some(((input & 3u16).count_ones() % 2) as u8),
            "second owner exact answer",
        )?;
    }
    a.cancel();
    check(
        a.run_episode(&mut a_source, &ao, &mut ae)
            .err()
            .is_some_and(|e| e.kind == ErrorKind::Cancelled),
        "typed cancellation",
    )?;
    check(!b.inspect()?.cancelled, "cancellation cannot cross owners")?;
    a.close()?;
    let closed = b.close()?;
    let checkpoint = closed.checkpoint(&root.join("checkpoint"))?;
    let mut a = Engine::open(&root.join("owner-a"), &ai, ac)?;
    a_source.offline = true;
    let reused = a.run_episode(&mut a_source, &ao, &mut ae)?;
    check(
        reused.reused && reused.usage.source_calls == 0 && a_source.calls == 5,
        "retained reuse must not call unavailable source",
    )?;
    check(
        a.predict(&ar.artifact, 7, &mut ae)?.answer == Some(0),
        "reopened source-off answer",
    )?;
    let mut b = Engine::open(&root.join("owner-b"), &bi, bc.clone())?;
    b.revoke(&br.artifact, "host counterexample", &mut be)?;
    check(
        b.predict(&br.artifact, 7, &mut be)
            .err()
            .is_some_and(|e| e.kind == ErrorKind::Revoked),
        "revoked answer cannot remain available",
    )?;
    b.close()?;
    let (mut restored, restore) = Engine::restore(&checkpoint, &root.join("restored-owner-b"), bc)?;
    check(
        restore.rollback_discards_later_learning && !restore.network_started,
        "explicit stopped-owner rollback semantics",
    )?;
    check(
        restored.predict(&br.artifact, 7, &mut be)?.answer == Some(0),
        "verified restore exact answer",
    )?;
    check(ae.calls > 0 && be.calls > 0, "host-owned event sinks")?;
    check(
        std::env::current_dir()? == cwd,
        "engine must not change cwd",
    )?;
    check(
        std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>() == environment,
        "engine must not change the host environment",
    )?;
    restored.close()?;
    a.close()?;
    let v = version();
    let result=format!("{{\"schema\":\"symbiote.embedding-consumer/1\",\"status\":\"PASS\",\"engine_version\":{},\"build_source_commit\":{},\"owners\":[{},{}],\"source_calls\":[{},{}],\"retained_source_calls\":0,\"cancelled_typed\":true,\"writer_exclusion\":true,\"revoked_typed\":true,\"checkpoint_restore\":true,\"conditional\":true,\"economic_benefit_verified\":false,\"independent_scientific_samples\":0}}",quoted(v.version),quoted(v.build_source_commit),quoted(&ai),quoted(&bi),a_source.calls,b_source.calls);
    fs::write(root.join("acceptance.json"), result.as_bytes())?;
    Ok(result)
}
fn main() -> std::process::ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--version" {
        let v = version();
        println!("{{\"schema\":\"symbiote.embedding-consumer-version/1\",\"version\":{},\"build_source_commit\":{}}}",quoted(v.version),quoted(v.build_source_commit));
        return std::process::ExitCode::SUCCESS;
    }
    if args.len() != 2 || args[0] != "--out" {
        eprintln!("usage: embedding_consumer --out NEW_ABSOLUTE_DIRECTORY");
        return std::process::ExitCode::FAILURE;
    }
    match run(&PathBuf::from(&args[1])) {
        Ok(result) => {
            println!("{result}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("embedding consumer failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
