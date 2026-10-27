"""Bounded, once-only local software stability regression campaign.

No research cohort is launched. Registration pins the already-built native and
test executables, actual source tree, protocol, acceptance checks and budgets.
"""
import argparse
import ctypes
import hashlib
import json
import ntpath
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "SYMBIOTE-LOCAL-STABILITY-001"
PROTOCOL_FILE = "docs/STABILITY_CAMPAIGN_PROTOCOL.md"
BOUNDS = dict(campaign_seconds=600, command_seconds=30, network_seconds=45,
              cleanup_seconds=10, root_launches=96, preflight_launches=3,
              output_bytes_per_process=2 * 1024 * 1024, evidence_bytes=64 * 1024 * 1024,
              final_report_reserve_bytes=1024 * 1024, endurance_seconds=180,
              windows_active_processes_per_job=8, windows_job_memory_bytes=256 * 1024 * 1024)
CLI_CASES = (
    "retained_structural_models_are_read_and_used_without_ledger_mutation",
    "native_backup_cli_restores_identity_bytes_and_offline_predictions_without_activation",
    "native_backup_cli_rejects_live_writer_tampered_manifest_occupied_target_and_registry_pin",
)
SERVICE_CASES = (
    "configured_private_ip_service_quarantines_then_locally_evaluates_native_affine_and_graph",
    "lost_reply_and_actual_service_crash_preserve_one_idempotent_quarantine_receipt",
    "evaluation_intent_recovery_commits_once_and_retains_original_lost_ack_result",
    "offline_rotation_after_lost_private_key_preserves_identity_and_rejects_old_tls_pin",
    "rotation_retains_denial_and_reviewed_regrant_never_resurrects_old_candidates",
    "reviewed_verified_restore_relocation_uses_only_destination_when_source_and_old_key_are_gone",
    "restored_relative_manifest_requires_review_for_each_restore_even_when_policy_digest_is_unchanged",
    "moved_unreviewed_restore_cannot_activate_under_original_config_or_consume_foreign_destination",
    "consumed_restore_metadata_cannot_be_deleted_or_rehashed_into_different_paths",
    "nested_unactivated_restores_hold_without_implicitly_approving_ancestor_mappings",
    "unregistered_restored_owner_cannot_initialize_service_history_before_review",
    "maximum_service_manifest_rotates_maximum_public_snapshots_then_narrows_without_rewriting_history",
    "operator_peer_ids_win_alias_collisions_without_changing_authenticated_artifact_grants",
)
FAULTS = ("startup-timeout", "crash-after-ready", "crash-after-promotion")
ENDURANCE_CASE = "endurance::mixed_family_24_cycle_local_campaign"


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= BOUNDS["evidence_bytes"], "missing, linked or oversized JSON artifact")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, "non-finite JSON number"))


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, allow_nan=False, indent=2)
        stream.write("\n")


def source_files(root):
    root = Path(root)
    selected = (set(root.glob("crates/**/*.rs")) | set(root.glob("crates/**/Cargo.toml"))
                | set(root.glob("tools/*.py")) | set(root.glob("tools/*.ps1")) | set(root.glob("tools/*.sh"))
                | {root / "Cargo.toml", root / "Cargo.lock", root / PROTOCOL_FILE})
    require(all(path.is_file() and not path.is_symlink() for path in selected), "source file missing or linked")
    return {path.relative_to(root).as_posix(): sha(path) for path in sorted(selected)}


def evidence_size(root):
    total = 0
    for path in Path(root).rglob("*"):
        require(not path.is_symlink(), "campaign artifact tree contains a link")
        if path.is_file():
            total += path.stat().st_size
            require(total <= BOUNDS["evidence_bytes"], "campaign evidence byte budget exceeded")
    return total


class WindowsJob:
    """Assign a suspended owned process before ANY candidate instruction runs."""
    def __init__(self):
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", w.DWORD), ("minimum_ws", ctypes.c_size_t), ("maximum_ws", ctypes.c_size_t),
                        ("active_limit", w.DWORD), ("affinity", ctypes.c_size_t),
                        ("priority", w.DWORD), ("scheduling", w.DWORD)]
        class Io(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", Io), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_longlong) for name in ("user", "kernel", "period_user", "period_kernel")]
            _fields_ += [(name, w.DWORD) for name in ("faults", "total", "active", "terminated")]
        self.accounting = Accounting
        self.attached = False
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = arguments, result
        self.handle = self.kernel.CreateJobObjectW(None, None)
        require(bool(self.handle), "cannot create owned Windows Job Object")
        limits = Extended()
        limits.basic.flags = 0x2000 | 0x0008 | 0x0200  # kill-on-close, active count, job memory
        limits.basic.active_limit = BOUNDS["windows_active_processes_per_job"]
        limits.job_memory = BOUNDS["windows_job_memory_bytes"]
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise RuntimeError("cannot establish Windows process-tree limits")

    def attach_and_resume(self, process):
        from ctypes import wintypes as w
        require(self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)), "cannot contain suspended process in owned Job Object")
        self.attached = True
        class ThreadEntry(ctypes.Structure):
            _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("thread_id", w.DWORD),
                        ("owner_pid", w.DWORD), ("base_priority", w.LONG), ("delta_priority", w.LONG), ("flags", w.DWORD)]
        k = self.kernel
        for name, args, result in (
            ("CreateToolhelp32Snapshot", [w.DWORD, w.DWORD], w.HANDLE),
            ("Thread32First", [w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            ("Thread32Next", [w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            ("OpenThread", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            ("ResumeThread", [w.HANDLE], w.DWORD),
        ):
            function = getattr(k, name)
            function.argtypes, function.restype = args, result
        snapshot = k.CreateToolhelp32Snapshot(4, 0)
        require(snapshot not in (None, ctypes.c_void_p(-1).value), "cannot inspect suspended owned process thread")
        found = []
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            present = k.Thread32First(snapshot, ctypes.byref(entry))
            while present:
                if entry.owner_pid == process.pid:
                    found.append(entry.thread_id)
                present = k.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            k.CloseHandle(snapshot)
        require(len(found) == 1, "suspended child must have one primary thread before execution")
        thread = k.OpenThread(0x0002, False, found[0])
        require(bool(thread), "cannot open owned primary thread")
        try:
            require(k.ResumeThread(thread) == 1, "cannot resume exactly one owned suspension")
        finally:
            k.CloseHandle(thread)

    def active(self):
        info = self.accounting()
        require(self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None), "cannot inspect owned process-tree cleanup")
        return info.active

    def terminate(self):
        require(self.kernel.TerminateJobObject(self.handle, 125), "cannot terminate owned process tree")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def parse_darwin_group_census(raw, pid, sampler_pid):
    """Accept only a complete, clean native ps census with its own witness."""
    require(type(pid) is int and pid > 0 and type(sampler_pid) is int and sampler_pid > 0,
            "Darwin group census needs positive owned and sampler identities")
    require(raw and len(raw) <= 128 * 1024 and raw.endswith(b"\n"),
            "Darwin group census is empty, truncated or oversized")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise RuntimeError("Darwin group census encoding is unsupported") from error
    seen, members, sampler = set(), [], None
    for line in lines:
        fields = line.split()
        require(len(fields) == 3 and all(re.fullmatch(r"[0-9]+", field) for field in fields[:2])
                and re.fullmatch(r"[A-Za-z?][A-Za-z0-9<+>\-]*", fields[2]),
                "Darwin group census contains an unsupported row")
        row_pid, group = map(int, fields[:2])
        # ps -A may include kernel_task with PID/PGID zero.
        require(row_pid <= 2**31-1 and group <= 2**31-1 and row_pid not in seen,
                "Darwin group census contains duplicate or invalid identities")
        seen.add(row_pid)
        if row_pid == sampler_pid:
            sampler = (group, fields[2])
        if group == pid:
            members.append(dict(pid=row_pid, state=fields[2]))
    require(sampler is not None and sampler[0] != pid and sampler[1][0] != "Z",
            "Darwin group census lacks its own live sampler witness outside the owned group")
    return dict(basis="native-ps-complete-pid-pgid-stat-census", sampler_pid=sampler_pid,
                rows=len(seen), raw_bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(),
                # Apple's ps reports '?' for uninspectable Mach tasks. Such a
                # target remains active; only an explicit Z proves a zombie.
                members=members, active=any(row["state"][0] != "Z" for row in members))


def darwin_group_alive(pid, deadline=None, observation=None):
    """Bound native ps bytes/time inside the existing cleanup deadline."""
    start = time.monotonic()
    cutoff = min(start + 0.25, deadline if deadline is not None else start + 0.25)
    require(cutoff - start > 0.05, "Darwin group census cleanup deadline exhausted")
    selector = selectors.DefaultSelector()
    process = None
    raw = bytearray()
    try:
        process = subprocess.Popen(["/bin/ps", "-A", "-o", "pid=,pgid=,stat="],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=dict(os.environ, LC_ALL="C"))
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = cutoff - 0.025 - time.monotonic()
            require(remaining > 0, "Darwin group census timed out before complete EOF")
            for key, _ in selector.select(remaining):
                block = os.read(key.fileobj.fileno(), 4096)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                require(len(raw) + len(block) <= 128 * 1024, "Darwin group census byte budget exhausted")
                raw.extend(block)
        require(process.wait(timeout=max(0.001, cutoff-time.monotonic())) == 0,
                "Darwin native ps census failed")
        result = parse_darwin_group_census(bytes(raw), pid, process.pid)
        require(time.monotonic() <= cutoff, "Darwin group census deadline exhausted during parsing")
        if observation is not None:
            observation.clear()
            observation.update(result)
        return result["active"]
    finally:
        selector.close()
        if process is not None:
            process.stdout.close()
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=max(0.001, cutoff-time.monotonic()))


def group_alive(pid, deadline=None, observation=None):
    if sys.platform == "darwin":
        return darwin_group_alive(pid, deadline, observation)
    try:
        os.killpg(pid, 0)
        # A killed orphan can briefly remain a zombie under Linux's reaper.
        # A zombie cannot execute or retain a network listener. Do not call a
        # still-running child cleaned merely because the root exited.
        if Path("/proc").is_dir():
            found_zombie = False
            for entry in Path("/proc").iterdir():
                if not entry.name.isdecimal(): continue
                try:
                    fields = (entry/"stat").read_text().rsplit(")",1)[1].split()
                    if int(fields[2]) != pid: continue
                    if fields[0] != "Z": return True
                    found_zombie = True
                except (OSError,ValueError,IndexError): continue
            if found_zombie: return False
        return True
    except ProcessLookupError:
        return False


def signal_owned_group(pid, signum, deadline=None, observation=None):
    """An owned group can exit between a liveness probe and its signal."""
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        # Absence is idempotent; permission and other signalling errors remain
        # failures. The caller still verifies quiescence before accepting cleanup.
        pass
    except PermissionError:
        # XNU killpg excludes zombie members, so a zombie-only group can yield
        # EPERM. Only a fresh complete census can prove no executing member;
        # an active group, failed census or other platform retains the error.
        if sys.platform == "darwin" and not group_alive(pid, deadline, observation):
            return
        raise


def artifact_stem(label):
    """Encode only filesystem names; retain the exact label in the receipt."""
    require(isinstance(label,str) and bool(label),"process evidence needs a nonempty text label")
    readable=re.sub(r"[^A-Za-z0-9_-]+","-",label).strip("-_")[:12] or "label"
    return "p-"+readable+"-"+hashlib.sha256(label.encode("utf-8")).hexdigest()


def execute(argv, directory, label, *, timeout, cancelled=lambda: False, environment=None):
    """Bound captured bytes, terminate the owned tree, and preserve failures."""
    directory = Path(directory)
    stem=artifact_stem(label)
    stdout_path, stderr_path = directory / (stem + ".stdout"), directory / (stem + ".stderr")
    receipt_path=directory/(stem+".process.json")
    process, job, outcome, error = None, None, "completed", None
    start = time.monotonic()
    limit = BOUNDS["output_bytes_per_process"]
    output_budget = threading.Event()
    output_lock = threading.Lock()
    captured = [0]
    readers = []
    cleanup_verified = False
    cleanup_deadline = None
    group_observation = {}
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            options = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
            if environment: options["env"]=dict(os.environ,**environment)
            if os.name == "nt":
                job = WindowsJob()
                options["creationflags"] = 0x00000004 | 0x08000000 | 0x00000200  # suspended, hidden, new group
            else:
                options["start_new_session"] = True
            process = subprocess.Popen([str(value) for value in argv], **options)
            def drain(pipe, target):
                try:
                    while True:
                        block = pipe.read(65536)
                        if not block: break
                        with output_lock:
                            keep = min(len(block), max(0, limit-captured[0]))
                            target.write(block[:keep])
                            captured[0] += keep
                            if keep != len(block): output_budget.set()
                except (OSError,ValueError):
                    output_budget.set()
                finally:
                    pipe.close()
            for pipe,target in ((process.stdout,stdout),(process.stderr,stderr)):
                thread = threading.Thread(target=drain,args=(pipe,target),daemon=True)
                readers.append(thread)
                thread.start()
            if job:
                job.attach_and_resume(process)
            while process.poll() is None:
                if cancelled():
                    outcome = "cancelled"
                    break
                if time.monotonic() - start >= timeout:
                    outcome = "timeout"
                    break
                if output_budget.is_set():
                    outcome = "output-budget"
                    break
                time.sleep(0.02)
            cleanup_deadline=time.monotonic()+BOUNDS["cleanup_seconds"]
            if outcome != "completed":
                if job:
                    job.terminate()
                else:
                    signal_owned_group(process.pid, signal.SIGTERM, cleanup_deadline, group_observation)
            try:
                process.wait(timeout=max(0.001,min(BOUNDS["cleanup_seconds"]/2,cleanup_deadline-time.monotonic())))
            except subprocess.TimeoutExpired:
                if job:
                    job.terminate()
                else:
                    signal_owned_group(process.pid, signal.SIGKILL, cleanup_deadline, group_observation)
                process.wait(timeout=max(0.001,cleanup_deadline-time.monotonic()))
            # Job accounting can lag a signalled/reaped root by a scheduler
            # turn. Observe bounded quiescence before declaring a leaked child.
            settle_deadline = min(cleanup_deadline,time.monotonic()+0.25)
            while time.monotonic()<settle_deadline:
                active = job.active()!=0 if job else group_alive(process.pid, cleanup_deadline, group_observation)
                if not active: break
                time.sleep(0.01)
            if job:
                leaked = job.active() != 0
                if leaked:
                    job.terminate()
            else:
                leaked = group_alive(process.pid, cleanup_deadline, group_observation)
                if leaked:
                    signal_owned_group(process.pid, signal.SIGKILL, cleanup_deadline, group_observation)
            if leaked and outcome == "completed":
                outcome = "descendant-leak"
            while time.monotonic()<cleanup_deadline:
                cleanup_verified = job.active()==0 if job else not group_alive(process.pid, cleanup_deadline, group_observation)
                if cleanup_verified: break
                time.sleep(0.02)
        except BaseException as failure:
            outcome, error = "execution-error", str(failure)
            cleanup_deadline=cleanup_deadline or time.monotonic()+BOUNDS["cleanup_seconds"]
            try:
                if process is not None:
                    if job and job.attached: job.terminate()
                    elif job and process.poll() is None: process.kill()
                    # A failed liveness census must not prevent escalation of
                    # the session we already own. Verify quiescence afterwards.
                    elif not job: signal_owned_group(process.pid,signal.SIGKILL,cleanup_deadline,group_observation)
                    process.wait(timeout=max(0.001,cleanup_deadline-time.monotonic()))
                    cleanup_verified = job.active()==0 if job and job.attached else (not group_alive(process.pid, cleanup_deadline, group_observation) if not job else True)
            except BaseException as cleanup_failure:
                error += "; cleanup uncertain: "+str(cleanup_failure)
                outcome="cleanup-incomplete"
                cleanup_verified=False
        finally:
            cleanup_deadline=cleanup_deadline or time.monotonic()+BOUNDS["cleanup_seconds"]
            if job:
                try: job.close()
                except BaseException as cleanup_failure:
                    error=(error or "")+"; job close uncertain: "+str(cleanup_failure)
                    cleanup_verified=False
                    outcome="cleanup-incomplete"
            for thread in readers:
                thread.join(timeout=max(0,cleanup_deadline-time.monotonic()))
            if any(thread.is_alive() for thread in readers):
                cleanup_verified=False
                outcome="cleanup-incomplete"
    if output_budget.is_set() and outcome=="completed": outcome="output-budget"
    cleanup_elapsed=time.monotonic()-(cleanup_deadline-BOUNDS["cleanup_seconds"])
    if cleanup_elapsed>BOUNDS["cleanup_seconds"]:outcome="cleanup-time-budget"
    record = dict(label=label, argv=[str(x) for x in argv], pid=process.pid if process else None, exit_code=process.returncode if process else None,
                  outcome=outcome, elapsed_seconds=time.monotonic() - start,
                  error=error,cleanup_verified=cleanup_verified,output_truncated=output_budget.is_set(),
                  cleanup_elapsed_seconds=cleanup_elapsed,
                  containment="windows-job-suspended-before-execution" if os.name == "nt" else "owned-posix-session",
                  process_receipt=receipt_path.name,
                  stdout=stdout_path.name, stderr=stderr_path.name,
                  stdout_sha256=sha(stdout_path), stderr_sha256=sha(stderr_path),
                  stdout_bytes=stdout_path.stat().st_size, stderr_bytes=stderr_path.stat().st_size)
    if group_observation:
        record["posix_group_observation"] = group_observation
    if record["stdout_bytes"] + record["stderr_bytes"] > BOUNDS["output_bytes_per_process"]:
        record["outcome"] = "output-budget"
    write_new(receipt_path, record)
    return record


def output(record, directory):
    return (Path(directory) / record["stdout"]).read_text(encoding="utf-8")


def check_exit(record, expected=0):
    require(record["outcome"] == "completed" and record["exit_code"] == expected and record["cleanup_verified"] is True,
            record["label"] + " failed its declared exit/timeout/cleanup gate: "
            + str({key:record.get(key) for key in ("exit_code","outcome","cleanup_verified","error")}))


def check_native_test(text):
    require(re.search(r"test result: ok\. 1 passed; 0 failed;", text) is not None,
            "exact selected regression must execute one test, never zero or an entire suite")


def identity_chain(path):
    raw = Path(path).read_bytes()
    require(raw.endswith(b"\n"), "truncated identity ledger")
    previous, rows = "0" * 64, []
    for index, line in enumerate(raw.splitlines()):
        row = json.loads(line, object_pairs_hook=pairs)
        require(row["sequence"] == index and row["previous"] == previous, "identity ledger sequence/hash chain")
        value = {key:row[key] for key in ("sequence", "previous", "payload")}
        actual = hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        require(row["sha256"] == actual, "typed identity ledger integrity")
        rows.append(row)
        previous = actual
    require(rows and rows[0]["payload"]["event"] == "genesis" and rows[0]["payload"]["version"]==1,
            "supported identity genesis missing")
    return raw, rows


def knowledge_chain(path):
    raw=Path(path).read_bytes()
    require(raw.endswith(b"\n"),"truncated structural knowledge ledger")
    previous,rows="0"*64,[]
    for index,line in enumerate(raw.splitlines()):
        row=json.loads(line,object_pairs_hook=pairs)
        require(row["sequence"]==index and row["previous"]==previous,"structural sequence/hash chain")
        actual=hashlib.sha256(json.dumps([index,previous,row["payload"]],ensure_ascii=False,separators=(",",":")).encode()).hexdigest()
        require(row["sha256"]==actual,"typed structural receipt hash")
        rows.append(row);previous=actual
    require(rows and rows[0]["payload"]["event"]=="genesis","structural genesis missing")
    return raw,rows


def fault_evidence(fault,state,stderr):
    """A matching error alone is insufficient: require the actual durable stage."""
    require(fault in FAULTS and "SYMBIOTE failure:" in stderr,"fault must reach known native execution, not argument parsing")
    if fault=="startup-timeout":
        require("child readiness deadline exceeded" in stderr,"startup fault must reach the child readiness deadline")
    else:
        allowed=("connection closed before complete frame","frame read failed or timed out","frame write failed or timed out")
        if fault=="crash-after-ready":allowed+=("connection failed or timed out",)
        require(any(message in stderr for message in allowed),"crash must fail at the expected native transport stage")
    _,controller=identity_chain(Path(state)/"ledger.jsonl")
    controller_id=controller[0]["payload"]["identity"]
    owners={"controller":controller_id}
    models={}
    for role in ("exact","linear"):
        directory=Path(state)/"network"/role
        if not (directory/"ledger.jsonl").exists():continue
        _,identity=identity_chain(directory/"ledger.jsonl")
        raw,history=knowledge_chain(directory/"knowledge.jsonl")
        owners[role]=identity[0]["payload"]["identity"]
        require(history[0]["payload"]["identity"]==owners[role],"child structural owner binding")
        promotions=[row for row in history if row["payload"]["event"] in ("promote","promote_graph")]
        models[role]=dict(promotions=len(promotions),sha256=hashlib.sha256(raw).hexdigest())
        if promotions:
            require(len(promotions)==1 and promotions[0]["payload"]["record"]["payload"]["kind"]=="affine"
                    and promotions[0]["payload"]["record"]["payload"]["width"]==4,"post-commit crash must preserve exactly one actual four-bit model")
            models[role]["record"]=promotions[0]["payload"]["record"]
    expected_roles={"controller","exact"} if fault=="startup-timeout" else {"controller","exact","linear"}
    require(set(owners)==expected_roles and len(set(owners.values()))==len(owners),"fault must create the expected distinct native owners")
    require(models["exact"]["promotions"]==int(fault=="crash-after-promotion")
            and models.get("linear",{}).get("promotions",0)==0,"durable stage must match the specific injected crash")
    return dict(fault=fault,owners=owners,models=models,error_stage="child-readiness" if fault=="startup-timeout" else "native-transport-after-ready")


def assert_predictions(report, identity, count):
    require(report["identity"] == identity and type(report["network_requests"]) is int and report["network_requests"] == 0
            and type(report["active_artifacts"]) is int and report["active_artifacts"] == count, "actual offline identity/model/count checks")


def genesis_predictions(report,identity,revisions):
    assert_predictions(report,identity,len(revisions))
    require(report["schema"]=="symbiote.retained/1" and report["status"]=="PASS"
            and type(report["genesis_artifacts"]) is int and report["genesis_artifacts"]==len(revisions)
            and type(report["structural_artifacts"]) is int and report["structural_artifacts"]==0
            and report["structural_knowledge"]==[],"manual Genesis report family/counts")
    rows=prediction_revisions(report)
    require(set(rows)==set(revisions),"every expected manual artifact appears exactly once")
    truth={"alpha-table":("alpha",[0,1,1,0]),"beta-table":("beta",[0,1,0,1])}
    for artifact,revision in revisions.items():
        row=rows[artifact];partner,values=truth[artifact]
        require(row["partner"]==partner and row["scope"]=="finite-boolean-v1" and row["revision"]==revision,
                "manual artifact source/scope/revision binding")
        require(isinstance(row["predictions"],list) and len(row["predictions"])==4
                and all(type(value) is int and value in (0,1) for value in row["predictions"])
                and row["predictions"]==values,"actual complete finite prediction tables, never empty/vacuous rows")
    return rows


def final_acceptance(cancelled,elapsed,evidence_bytes,report_bytes):
    require(cancelled is False,"campaign cancelled during final verification")
    require(elapsed<=BOUNDS["campaign_seconds"],"campaign deadline exceeded during final verification")
    require(report_bytes<=BOUNDS["final_report_reserve_bytes"] and evidence_bytes+report_bytes<=BOUNDS["evidence_bytes"],
            "final report would exceed its reserved evidence budget")


def prediction_revisions(report):
    rows=report["predictions"]
    require(isinstance(rows,list) and all(isinstance(row.get("artifact"),str) and type(row.get("revision")) is int for row in rows),
            "native prediction rows use artifact and integer revision")
    require(len({row["artifact"] for row in rows})==len(rows),"duplicate retained artifact")
    return {row["artifact"]:row for row in rows}


def structural_affine_predictions(report,identity,record):
    assert_predictions(report,identity,1)
    require(report["genesis_artifacts"]==0 and report["predictions"]==[] and report["structural_artifacts"]==1,
            "post-commit output must contain the actual structural model")
    require(len(report["structural_knowledge"])==1,"one actual committed model expected")
    model=report["structural_knowledge"][0]
    for key in ("id","source","scope","revision","schema_fingerprint"):
        require(model[key]==record[key],"offline structural metadata differs from committed record")
    require(encode(model["model"])==encode(record["payload"]),"offline strategy differs from committed model")
    payload=record["payload"]
    require(payload["kind"]=="affine" and type(payload["width"]) is int and payload["width"]==4
            and type(payload["coefficients"]) is int and 0<=payload["coefficients"]<16 and type(payload["bias"]) is bool,
            "declared native affine schema")
    samples=model["sample_predictions"]
    require(len(samples)==8 and [row["input"] for row in samples]==list(range(8)),"offline sample inputs cover all eight displayed cases")
    for sample in samples:
        require(type(sample["input"]) is int and type(sample["output"]) is int,"offline affine samples must contain actual integer outputs")
        expected=((sample["input"] & payload["coefficients"]).bit_count()%2)^int(payload["bias"])
        require(sample["output"]==expected,"actual offline affine prediction matches committed strategy")


def record_digest(record):
    keys=("id","revision","source","scope","schema_fingerprint","payload","provenance")
    require(set(record)==set(keys),"strict inert native record fields")
    ordered={key:record[key] for key in keys}
    ordered["payload"]=json.loads(encode(record["payload"]))
    return hashlib.sha256(json.dumps(ordered,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()


def operational_chain(path,owner):
    raw=Path(path).read_bytes()
    require(raw.endswith(b"\n"),"operational history truncated")
    rows=[];previous="0"*64
    for index,line in enumerate(raw.splitlines()):
        row=json.loads(line,object_pairs_hook=pairs)
        require(row["sequence"]==index and row["previous"]==previous and row["sha256"]==digest([index,previous,row["payload"]]),"canonical operational sequence/content hash")
        previous=row["sha256"];rows.append(row)
    require(rows and rows[0]["payload"]["event"]=="genesis" and rows[0]["payload"]["version"]==1
            and rows[0]["payload"]["owner_identity"]==owner,"operational owner/version binding")
    marker=load(Path(path).parent/"operations-owner.json")
    require(marker["schema"]=="symbiote.operational-owner/1" and marker["owner_identity"]==owner
            and marker["genesis_sha256"]==rows[0]["sha256"] and marker["policy_digest"]==rows[0]["payload"]["policy_digest"],"immutable operational registration binding")
    return raw,rows


def artifact_file(root,relative):
    require(isinstance(relative,str) and not Path(relative).is_absolute() and ".." not in Path(relative).parts,"unsafe relative evidence reference")
    path=Path(root).joinpath(relative).resolve(strict=True)
    require(Path(root).resolve() in path.parents and path.is_file() and not path.is_symlink(),"evidence path leaves its owned directory")
    return path


def endurance_outputs(root,events):
    """Bind reported TLS values to exact preserved native command output."""
    native={};requests={};responses={}
    for event in events:
        data=event["data"];kind=event["kind"]
        if kind not in ("native-command","tls-request","tls-response"):continue
        target={"native-command":native,"tls-request":requests,"tls-response":responses}[kind]
        label=data["label"]
        require(isinstance(label,str) and label and label not in target,"duplicate or invalid native/TLS evidence label")
        target[label]=data
        if kind=="native-command":
            require(type(data["success"]) is bool and type(data["exit_code"]) is int,"actual native exit status is required")
            for stream in ("stdout","stderr"):
                require(sha(artifact_file(root,data[stream]))==data[stream+"_sha256"],"raw native command output integrity")
    require(set(requests)==set(responses) and set(requests)<=set(native),"each TLS request has exactly one raw native output and response")
    parsed={}
    for label,row in native.items():
        if row["success"]:
            require(row["exit_code"]==0,"native success must be exit zero")
            parsed[label]=load(artifact_file(root,row["stdout"]))
            require(isinstance(parsed[label],dict),"native output must be a JSON object")
    for label,row in responses.items():
        require(label in parsed and encode(row["response"])==encode(parsed[label]),"TLS response differs from actual native stdout")
        require(type(requests[label]["explicit_duplicate"]) is bool,"strict TLS duplicate marker")
    return native,parsed,requests,responses


def bound_native_receipt(parsed,label,receipt):
    require(label in parsed and encode(parsed[label])==encode(receipt),"report receipt differs from actual native stdout: "+label)


def bound_tls_pair(parsed,requests,responses,label,request,response,duplicate=False):
    require(label in requests and label in responses
            and requests[label]["explicit_duplicate"] is duplicate
            and encode(requests[label]["request"])==encode(request)
            and encode(responses[label]["response"])==encode(response),"report TLS pair differs from its actual event: "+label)
    bound_native_receipt(parsed,label,response)


def bound_quarantine(row,request,response,peer):
    body_sha256=digest(request)
    candidate=digest(dict(authenticated_sender=peer,canonical_body_sha256=body_sha256))
    require(request["body"]["operation"]=="candidate.submit"
            and row["key"]==dict(peer_id=peer,operation="candidate.submit",scope=request["scope"],request_id=request["request_id"])
            and row["body_sha256"]==body_sha256 and encode(row["body"])==encode(request)
            and row["candidate_id"]==candidate
            and encode(row["response"])==encode(response)
            and encode(response)==encode(dict(schema="symbiote.service-quarantine/1",status="QUARANTINED",candidate=candidate,promoted=False)),
            "actual quarantine key/body/hash/candidate/response binding")


POLICY_ACTIVATION_HOLD = "SYMBIOTE failure: HOLD: operational service/policy changed; preserve deny and idempotency history and use an explicit supported policy revision"
RESTORE_ACTIVATION_HOLD = "SYMBIOTE failure: HOLD: unreviewed restore cannot activate or mutate service state; inspect policy-status and explicitly review verified relocation"


def activation_guard_kind(blocked,stdout,stderr,policy_changed):
    """Classify only the two real guards, never an arbitrary failed command."""
    require(blocked["success"] is False and type(blocked["exit_code"]) is int and blocked["exit_code"]==1
            and stdout==b"" and type(policy_changed) is bool,"blocked activation needs an empty-output native exit one")
    expected=POLICY_ACTIVATION_HOLD if policy_changed else RESTORE_ACTIVATION_HOLD
    require(stderr in ((expected+"\n").encode(),(expected+"\r\n").encode()),
            "blocked activation did not reach the exact expected policy/restore guard")
    return "POLICY_CHANGE_HOLD" if policy_changed else "UNREVIEWED_RESTORE_HOLD"


def verify_midpoint_activation_guard(root,midpoint,owner):
    """Prove the fixed midpoint's owner/history and state-only policy change."""
    root=Path(root)
    blocked=midpoint["unreviewed_activation"]
    streams={name:artifact_file(root,blocked[name]).read_bytes() for name in ("stdout","stderr")}
    require(all(hashlib.sha256(data).hexdigest()==blocked[name+"_sha256"] for name,data in streams.items()),
            "blocked activation raw output differs from its preserved hashes")
    old=root/"owners/server-pre-restore";current=root/"owners/server-restored"
    old_identity,_=identity_chain(old/"ledger.jsonl")
    current_identity,current_rows=identity_chain(current/"ledger.jsonl")
    require(old_identity==current_identity and current_rows[0]["payload"]["identity"]==owner,
            "blocked activation must preserve the same real owner identity")
    old_knowledge,_=knowledge_chain(old/"knowledge.jsonl")
    current_knowledge,_=knowledge_chain(current/"knowledge.jsonl")
    require(old_knowledge==current_knowledge,"blocked activation cannot replace retained knowledge")
    before,prior=operational_chain(old/"operations.jsonl",owner)
    after,later=operational_chain(current/"operations.jsonl",owner)
    require(after.startswith(before),"restored operational history must retain its exact old prefix")
    backup=root/"midpoint-backup"
    manifest=load(backup/"backup-manifest.json")
    pin=sha(backup/"backup-manifest.json")
    require(manifest["schema"]=="symbiote.owner-backup/1" and manifest["identity"]==owner
            and all(midpoint[key]["identity"]==owner and midpoint[key]["manifest_sha256"]==pin for key in ("backup","verification","restore")),
            "blocked activation must concern the actual verified same-owner backup")
    for name in ("ledger.jsonl","knowledge.jsonl","operations.jsonl","operations-owner.json"):
        saved=artifact_file(root,"midpoint-backup/files/"+name).read_bytes()
        expected=artifact_file(root,"owners/server-pre-restore/"+name).read_bytes()
        require(saved==expected and manifest["files"][name]==dict(bytes=len(saved),sha256=hashlib.sha256(saved).hexdigest()),
                "backup and pre-restore owner/history bytes must agree")
    old_manifest=load(artifact_file(root,"public-policies/rotation-8-server.json"))
    new_manifest=load(artifact_file(root,"public-policies/midpoint-restored-server.json"))
    require(old_manifest["identity"]==new_manifest["identity"]==owner
            and old_manifest["schema"]==new_manifest["schema"]=="symbiote.service-config/1"
            and {k:v for k,v in old_manifest.items() if k!="state"}=={k:v for k,v in new_manifest.items() if k!="state"},
            "midpoint public policy may change only its state path")
    ca=sha(artifact_file(root,"public-certificates/ca.pem"))
    previous=dict(manifest=old_manifest,ca_sha256=ca);following=dict(manifest=new_manifest,ca_sha256=ca)
    old_policy=digest(previous);new_policy=digest(following)
    latest=next((row["payload"]["policy_digest"] for row in reversed(prior) if row["payload"]["event"]=="policy_transitioned"),prior[0]["payload"]["policy_digest"])
    require(old_policy==latest==manifest["operational_policy_sha256"]
            and prior[-1]["sha256"]==manifest["operational_head_sha256"],"copied old public policy must match the real backup epoch/head")
    activation=midpoint["activation"]
    require(activation["identity"]==owner and activation["previous_policy_sha256"]==old_policy
            and activation["policy_sha256"]==new_policy,"reviewed relocation must bind both recomputed public policy digests")
    mapping_pin=midpoint["restore"]["restore_mapping_sha256"]
    require(isinstance(mapping_pin,str) and re.fullmatch(r"[0-9a-f]{64}",mapping_pin) is not None,"bounded restore mapping digest")
    mapping_file=artifact_file(root,"owners/server-restored/restored-owner-"+mapping_pin+".json")
    mapping=load(mapping_file)
    require(sha(mapping_file)==mapping_pin and mapping["schema"]=="symbiote.restored-owner/1"
            and mapping["identity"]==owner and mapping["manifest_sha256"]==pin
            and mapping["manifest_json"].encode()==(backup/"backup-manifest.json").read_bytes(),"restore mapping binds the exact verified backup and owner")
    def location(value):
        require(isinstance(value,str) and bool(value),"public policy state path is required")
        if manifest["operating_system"]=="windows":return ntpath.normcase(ntpath.normpath(value.removeprefix("\\\\?\\")))
        return os.path.normpath(value)
    require(location(old_manifest["state"])==location(manifest["source_state"])==location(mapping["source_state"])==location(activation["relocation"]["prior_state"])
            and location(new_manifest["state"])==location(mapping["restored_state"])==location(activation["relocation"]["restored_state"])
            and activation["relocation"]["restore_mapping_sha256"]==mapping_pin,"copied policy paths must bind the actual source and reviewed restore mapping")
    transitions=[row["payload"] for row in later[len(prior):] if row["payload"]["event"]=="policy_transitioned"
                 and row["payload"]["relocation"] is not None]
    require(len(transitions)==1 and transitions[0]["previous_policy"]==previous and transitions[0]["policy"]==following
            and transitions[0]["previous_policy_digest"]==old_policy and transitions[0]["policy_digest"]==new_policy
            and transitions[0]["relocation"]==activation["relocation"],"actual policy transition must anchor the copied snapshots and relocation")
    return activation_guard_kind(blocked,streams["stdout"],streams["stderr"],old_policy!=new_policy)


def verify_endurance(root,binaries):
    """Independent fixed-fixture continuity checks on preserved native evidence."""
    root=Path(root).resolve(strict=True)
    report=load(root/"endurance-report.json")
    require(report["schema"]=="symbiote.local-endurance/1" and report["status"]=="PASS" and report["first_failure"] is None,"native continuity report completed without a hidden failure")
    for key,value in (("cycles_expected",24),("cycles_completed",24),("request_keys_expected",99),("request_keys_recorded",99),
                      ("service_starts_expected",26),("service_starts",26),("owned_stops",26),("models_retained",2)):
        require(type(report[key]) is int and report[key]==value,"actual continuity count "+key)
    require(report["native_binary_sha256"]==binaries["native"]["sha256"] and report["test_binary_sha256"]==binaries["service_tests"]["sha256"],"continuity uses exactly the registered native/test executables")
    require(report["current_server_state"]=="owners/server-restored" and report["client_state"]=="owners/client","declared final owner paths")
    owners=report["owner_identities"]
    require(len(owners)==2 and len(set(owners))==2,"two distinct persistent owner identities")
    server=root/report["current_server_state"];client=root/report["client_state"]
    owner_raw=[]
    for directory,owner in ((server,owners[0]),(client,owners[1])):
        raw,identity=identity_chain(directory/"ledger.jsonl")
        require(identity[0]["payload"]["identity"]==owner,"continuity identity equals actual owner genesis")
        owner_raw.append(raw)
    knowledge,rows=knowledge_chain(server/"knowledge.jsonl")
    require(rows[0]["payload"]["identity"]==owners[0],"actual retained knowledge owner")
    models=[row["payload"]["record"] for row in rows if row["payload"]["event"] in ("promote","promote_graph")]
    require(len(models)==2 and not any(row["payload"]["event"]=="revoke" for row in rows),"exactly two initial retained models, no hidden replacement")
    model_hashes={record_digest(record) for record in models}
    require(len(model_hashes)==2 and set(report["model_digests"])==model_hashes,"both actual complete model digests")
    by_scope={record["scope"]:record for record in models}
    require(set(by_scope)=={"affine-context/v1","graph-context/v1"} and all(record["source"]==owners[1] for record in models),"authenticated source and fixed two-context applicability")
    require(by_scope["affine-context/v1"]["payload"]==dict(kind="affine",width=3,coefficients=3,bias=False),"known manual affine strategy")
    graph=by_scope["graph-context/v1"]["payload"]
    expected_graph=dict(nodes=3,edges=[dict(zip(("from","to","lower","upper"),edge)) for edge in ((0,1,1,9),(1,2,1,9),(0,2,1,9))])
    require(graph==dict(kind="graph-map",schema=expected_graph,observations=[dict(edge_id=i,cost=cost) for i,cost in enumerate((1,2,5))]),"known complete manual graph observations")
    operations,ops=operational_chain(server/"operations.jsonl",owners[0])
    client_ops,client_rows=operational_chain(client/"operations.jsonl",owners[1])
    _,client_knowledge=knowledge_chain(client/"knowledge.jsonl")
    require(len(client_knowledge)==1 and client_knowledge[0]["payload"]["identity"]==owners[1],"client has its own unchanged nonlearning knowledge genesis")
    events=[json.loads(line,object_pairs_hook=pairs) for line in artifact_file(root,report["events_file"]).read_bytes().splitlines()]
    require(len(events)<10000 and [event["sequence"] for event in events]==list(range(len(events)))
            and sha(root/report["events_file"])==report["events_sha256"],"complete bounded event sequence and exact bytes")
    require([event["elapsed_ms"] for event in events]==sorted(event["elapsed_ms"] for event in events),"actual monotonic event order")
    native,parsed,requests,tls_responses=endurance_outputs(root,events)
    attempts=[];active={};ready_events={};stop_events={};starts=stops=killed=0
    for event in events:
        data=event["data"];kind=event["kind"]
        if kind=="tls-request":attempts.append((data["request"],data["explicit_duplicate"]))
        elif kind=="lost-reply-request":attempts.append((data,False))
        elif kind=="owned-listener-started":
            ready=data["ready"];pid=ready["pid"]
            require(ready["identity"]==owners[0] and type(pid) is int and pid>0 and pid not in active,"owned ready instance identity/PID timeline")
            starts+=1;require(data["spawn_ordinal"]==starts,"actual owned spawn ordinal")
            require(data["label"] not in ready_events,"duplicate listener start label")
            ready_events[data["label"]]=ready
            active[pid]=True
        elif kind in ("owned-listener-stopped","owned-listener-killed-and-joined"):
            pid=data["pid"];require(pid in active,"only a positively owned active listener can stop")
            del active[pid];stops+=1
            if kind=="owned-listener-killed-and-joined":killed+=1;require(data["joined"] is True and data["exit_code"]!=0,"real killed child was waited and unsuccessful")
            else:
                require(data["exit_code"]==0 and data["stop"]["identity"]==owners[0],"real graceful native shutdown")
                require(data["label"] not in stop_events,"duplicate listener stop label")
                stop_events[data["label"]]=data["stop"]
    require(starts==stops==26 and killed==1 and not active,"all 26 owned listeners stopped, one actual killed-service crash")
    keys={};duplicates=0
    for request,duplicate in attempts:
        key=(request["scope"],request["request_id"])
        if duplicate:
            require(key in keys and encode(request)==encode(keys[key]),"idempotent retry repeats the exact earlier wire request")
            duplicates+=1
        else:require(key not in keys,"fresh on-wire request key reused");keys[key]=request
    require(len(attempts)==100 and len(keys)==99 and duplicates==1
            and set(keys)=={(row["scope"],row["request_id"]) for row in report["request_keys"]},"99 unique wire keys and one exact retry; no 99-key durable-cache claim")
    cycles=report["cycles"]
    require(len(cycles)==24 and [row["cycle"] for row in cycles]==list(range(1,25)),"every fixed continuity cycle appears once")
    server_prefixes={};client_prefixes={}
    for raw,table in ((operations,server_prefixes),(client_ops,client_prefixes)):
        hasher=hashlib.sha256()
        for count,line in enumerate(raw.splitlines(keepends=True),1):
            hasher.update(line);table[hasher.hexdigest()]=count
    previous_server=previous_client=0
    for cycle in cycles:
        n=cycle["cycle"];responses=cycle["responses"]
        require(len(responses)==4 and cycle["ready"]["identity"]==cycle["stop"]["identity"]==owners[0],"four real replies and same owner each cycle")
        label=f"cycle-{n}-after-owned-crash" if n==10 else f"cycle-{n}"
        require(encode(cycle["ready"])==encode(ready_events.get(label))
                and encode(cycle["stop"])==encode(stop_events.get(f"cycle-{n}")),"cycle instance/stop bind actual owned process events")
        expected_ops=[]
        for scope in ("affine-context/v1","graph-context/v1"):
            expected_ops.extend((scope,operation) for operation in ("knowledge.read","knowledge.predict"))
        require([(row["request"]["scope"],row["request"]["body"]["operation"]) for row in responses]==expected_ops,"fixed manual read/predict operation order")
        for index,pair in enumerate(responses):
            request,reply=pair["request"],pair["response"];scope=request["scope"];record=by_scope[scope]
            label=f"cycle-{n}-{index//2}-{'read' if index%2==0 else 'predict'}"
            bound_tls_pair(parsed,requests,tls_responses,label,request,reply)
            require(encode(keys[(scope,request["request_id"])])==encode(request) and request["body"]["artifact"]==record["id"],"actual current model and unique wire request binding")
            if request["body"]["operation"]=="knowledge.read":
                require(reply["sender"]==owners[0] and reply["record_sha256"]==record_digest(reply["record"])==record_digest(record),"real read returns the unchanged retained record")
            else:
                query=(n-1)%8 if scope=="affine-context/v1" else (1,2,5)[(n-1)%3]
                expected=(query&3).bit_count()%2 if scope=="affine-context/v1" else {1:1,2:3,5:2}[query]
                require(request["body"]["input"]==query and reply["input"]==query and type(reply["prediction"]) is int
                        and reply["prediction"]==expected and reply["conditional"] is True and reply["physical_certificate_authorized"] is False
                        and reply["record_sha256"]==record_digest(record),"independently recomputed actual finite prediction")
                if scope=="graph-context/v1":
                    route=reply["route"];nodes,edges={1:([0,1],[0]),2:([0,1,2],[0,1]),5:([1,2],[1])}[query]
                    require(route["cost"]==expected and route["nodes"]==nodes and route["edges"]==edges and route["conditional"] is True,"actual exact shortest graph path certificate")
        witness=cycle["continuity"]
        require(witness["server_owner_sha256"]==hashlib.sha256(owner_raw[0]).hexdigest() and witness["client_owner_sha256"]==hashlib.sha256(owner_raw[1]).hexdigest()
                and witness["knowledge_sha256"]==hashlib.sha256(knowledge).hexdigest() and set(witness["model_digests"])==model_hashes and witness["models_retained"]==2,"nonvacuous owner/model continuity at every cycle")
        server_count=server_prefixes.get(witness["server_operations_sha256"],-1)
        client_count=client_prefixes.get(witness["client_operations_sha256"],-1)
        require(server_count>=previous_server and client_count>=previous_client
                and server_count==witness["server_operation_records"],"each cycle preserves an exact chronological prefix of actual operational history")
        previous_server,previous_client=server_count,client_count
    require([row["after_cycle"] for row in report["credential_rotations"]]==[4,8,16,20],"four explicitly scheduled leaf rotations")
    for row in report["credential_rotations"]:
        after=row["after_cycle"]
        bound_native_receipt(parsed,f"rotation-{after}-server",row["server_transition"])
        bound_native_receipt(parsed,f"rotation-{after}-client",row["client_transition"])
        require(row["previous_pin"]!=row["current_pin"] and row["stale_pin_rejection"]["application_mutation"] is False
                and row["stale_pin_rejection"]["error"] and row["stale_pin_rejection"]["before_cycle"]==row["after_cycle"]+1,"actual prior leaf pin rejection without application mutation")
    require([row["after_cycle"] for row in report["denials"]]==[6,18],"two scheduled denials/regrants")
    for row in report["denials"]:
        after=row["after_cycle"]
        for label,key in ((f"denial-{after}","denial"),(f"denied-serve-{after}","denied_service"),(f"regrant-{after}","regrant")):
            bound_native_receipt(parsed,label,row[key])
        stopped=row["denied_service"]
        require(row["denial"]["peer"]==row["regrant"]["peer"]==owners[1] and row["denial"]["denied"] is True and row["regrant"]["denied"] is False
                and stopped["schema"]=="symbiote.service-stop/1" and stopped["status"]=="STOPPED" and stopped["reason"]=="no-authorized-peers"
                and stopped["listener_opened"] is False and stopped["requests"]==stopped["connections"]==0,"denied serve opens no listener; generic success is insufficient")
    payloads=[row["payload"] for row in ops]
    require(sum(row["event"]=="policy_transitioned" for row in payloads)==5
            and sum(row["payload"]["event"]=="policy_transitioned" for row in client_rows)==4
            and sum(row["event"]=="peer_denied" for row in payloads)==sum(row["event"]=="peer_restored" for row in payloads)==2,
            "actual durable rotation/relocation/denial/regrant history")
    quarantined=[row for row in payloads if row["event"]=="quarantined"]
    require(len(quarantined)==3 and len({(row["key"]["peer_id"],row["key"]["operation"],row["key"]["scope"],row["key"]["request_id"]) for row in quarantined})==3,"only three durable candidate keys, not all read/predict requests")
    for label in ("submit-affine","submit-graph"):
        require(label in requests and label in tls_responses,"actual initial submission evidence")
        request=requests[label]["request"];response=tls_responses[label]["response"]
        matching=[row for row in quarantined if row["candidate_id"]==response["candidate"]]
        require(len(matching)==1,"initial submission has one actual quarantine")
        bound_quarantine(matching[0],request,response,owners[1])
    completed=[row for row in payloads if row["event"]=="evaluation_completed"]
    prepared_rows=[row for row in payloads if row["event"]=="evaluation_prepared"]
    prepared={row["candidate_id"]:row for row in prepared_rows}
    require(len(completed)==len(prepared_rows)==len(prepared)==2
            and all(row["record_sha256"]==record_digest(prepared[row["candidate_id"]]["record"]) and row["record_sha256"] in model_hashes
                    and encode(row["response"])==encode(prepared[row["candidate_id"]]["response"]) for row in completed),
            "exact completed operational history anchors both actual historical promotions and prepared receipts")
    for index,label in enumerate(("submit-affine","submit-graph")):
        candidate=tls_responses[label]["response"]["candidate"]
        matching=[row for row in completed if row["candidate_id"]==candidate]
        require(len(matching)==1,"initial candidate completed exactly once")
        bound_native_receipt(parsed,f"initial-evaluation-{index}",matching[0]["response"])
    lost=report["lost_reply"]
    matches=[row for row in quarantined if row["candidate_id"]==lost["candidate"]]
    require(lost["cycle"]==10 and lost["quarantine_rows"]==1 and len(matches)==1 and lost["candidate_evaluated"] is False
            and lost["committed_response"]["status"]=="QUARANTINED" and lost["committed_response"]["promoted"] is False
            and encode(lost["retry_response"])==encode(lost["committed_response"]) and lost["first_call_error"]
            and lost["owned_crash"]["joined"] is True and lost["owned_crash"]["exit_code"]!=0
            and lost["journal_sha256_before_crash"]==lost["journal_sha256_after_retry"],"genuine committed lost reply, one owned killed service, exact idempotent replay without mutation")
    bound_quarantine(matches[0],lost["request"],lost["committed_response"],owners[1])
    bound_tls_pair(parsed,requests,tls_responses,"lost-submit-exact-retry",lost["request"],lost["retry_response"],True)
    bound_native_receipt(parsed,"recover-owned-crash",lost["recovery"])
    require(lost["recovery"]["processes_terminated"]==0 and lost["recovery"]["ledgers_modified"] is False,"crash recovery removes only proven-dead locks without learning edits or killing other processes")
    require([event["data"] for event in events if event["kind"]=="lost-reply-request"]==[lost["request"]],"lost direct TLS request is the preserved exact quarantine request")
    crashes=[event["data"] for event in events if event["kind"]=="owned-listener-killed-and-joined"]
    require(len(crashes)==1 and all(crashes[0][key]==lost["owned_crash"][key] for key in ("pid","exit_code","joined"))
            and crashes[0]["cycle"]==10,"lost response references the actual killed and waited service")
    midpoint=report["midpoint_restore"]
    require(midpoint["after_cycle"]==12 and midpoint["old_source_absent"] is True and midpoint["new_learning_promotions"]==0
            and midpoint["pending_lost_candidate_rejected"]==lost["candidate"],"fixed midpoint relocation settles, never learns from, pending lost candidate")
    require(sum(row["event"]=="evaluation_rejected" and row["candidate_id"]==lost["candidate"] for row in payloads)==1,"pending quarantine rejected exactly once")
    require(midpoint["backup"]["manifest_sha256"]==midpoint["verification"]["manifest_sha256"]==midpoint["restore"]["manifest_sha256"]
            and midpoint["restore"]["network_started"] is False and midpoint["activation"]["relocation"]["restore_mapping_sha256"]==midpoint["restore"]["restore_mapping_sha256"],"verified backup and explicit restore-review mapping binding")
    for label,key in (("midpoint-backup","backup"),("midpoint-verify","verification"),("midpoint-restore","restore"),("midpoint-reviewed-relocation","activation")):
        bound_native_receipt(parsed,label,midpoint[key])
    blocked=midpoint["unreviewed_activation"]
    require(encode(native.get("midpoint-unreviewed-peers"))==encode(blocked),"unreviewed activation is the actual preserved failed native command")
    activation_guard=verify_midpoint_activation_guard(root,midpoint,owners[0])
    final=report["final_continuity"]
    require(encode(final)==encode(cycles[-1]["continuity"]) and report["identity_and_model_continuity"] is True
            and final["server_operations_sha256"]==hashlib.sha256(operations).hexdigest()
            and final["client_operations_sha256"]==hashlib.sha256(client_ops).hexdigest()
            and final["server_operation_records"]==len(ops),"final continuity binds actual surviving owner history")
    files=report["owner_files"];listed=set()
    for item in files:
        path=artifact_file(root,item["path"]);require(item["path"] not in listed,"duplicate preserved owner file")
        listed.add(item["path"])
        require(path.stat().st_size==item["bytes"] and sha(path)==item["sha256"],"exact preserved owner/backup bytes")
    actual={path.relative_to(root).as_posix() for prefix in ("owners","midpoint-backup") for path in (root/prefix).rglob("*") if path.is_file()}
    require(listed==actual,"no silent omission from final owner/backup inventory")
    for path in root.rglob("*"):
        require(not path.is_symlink(),"continuity evidence contains a link")
        if path.is_file():
            require(path.suffix.lower() not in (".key",".pfx",".p12"),"private credential file in continuity evidence")
            data=path.read_bytes()
            require(not any(marker in data for marker in (b"-----BEGIN PRIVATE KEY-----",b"-----BEGIN EC PRIVATE KEY-----",b"-----BEGIN RSA PRIVATE KEY-----")),"private key material in continuity evidence")
    return dict(status="PASS",classification="BOUNDED_LOCAL_CONTINUITY",cycles=24,owners=owners,wire_keys=99,durable_candidate_keys=3,
                service_starts=26,owned_stops=26,retained_models=2,model_digests=sorted(model_hashes),events_sha256=report["events_sha256"],
                independent_host_validation="OPEN_UNAVAILABLE",scientific_samples=0,report_sha256=sha(root/"endurance-report.json"),unreviewed_activation_guard=activation_guard)


def plan_descriptor():
    return dict(demo=["learn", "offline-predict", "reuse", "reject", "recover-reject", "drift", "recover-drift"],
                network=["single-width4-native-prototype", *FAULTS], backup=["snapshot", "verify", "restore", "predict", "occupied-reject", "tamper-reject"],
                cli_regressions=list(CLI_CASES), service_regressions=list(SERVICE_CASES),
                local_continuity=dict(test=ENDURANCE_CASE,cycles=24,unique_wire_request_keys=99,durable_submit_keys=3,rotations=4,denial_regrants=2,root_command_seconds=180),
                forbidden=["research", "graph-research", "adaptive-research", "benchmark cohorts"],
                host_scope="this PC only; same-host loopback/private-IP test fixtures; no external agent endpoints",
                two_host_validation="OPEN_UNAVAILABLE")


def register(binary, cli_tests, service_tests, artifacts, source_commit):
    require(re.fullmatch(r"[0-9a-f]{40}",source_commit) is not None,"registration needs the independently selected frozen source commit")
    artifacts = Path(artifacts).resolve()
    require(not artifacts.exists() and artifacts.parent.is_dir(), "registration requires a new artifact directory")
    require(Path(tempfile.gettempdir()).resolve() in artifacts.parents and ROOT not in artifacts.parents,
            "campaign requires its own new OS temporary artifact directory outside the checkout")
    artifacts.mkdir()
    before = source_files(ROOT)
    binaries = {name:dict(path=str(Path(path).resolve(strict=True)), sha256=sha(path))
                for name,path in (("native",binary),("cli_tests",cli_tests),("service_tests",service_tests))}
    native_dir = Path(binaries["native"]["path"]).parent
    require(Path(binaries["native"]["path"]).name==("symbiote.exe" if os.name=="nt" else "symbiote"),"candidate must use actual compiled CLI name")
    require(all(Path(binaries[name]["path"]).parent == native_dir / "deps" for name in ("cli_tests","service_tests")),
            "freshly built test harnesses must share the candidate build-profile deps directory; location alone does not authenticate their embedded native path")
    preflight = []
    for name,args in (("native",["version","--json"]),("cli_tests",["--list","--format","terse"]),("service_tests",["--list","--format","terse"])):
        record = execute([binaries[name]["path"],*args], artifacts, "preflight-"+name, timeout=30)
        check_exit(record)
        text = output(record,artifacts)
        if name != "native":
            listed = {line.removesuffix(": test") for line in text.splitlines() if line.endswith(": test")}
            required=set(CLI_CASES if name=="cli_tests" else (*SERVICE_CASES,ENDURANCE_CASE))
            require(required <= listed, "compiled regression/endurance case missing; rebuild before registration")
        else:
            version=json.loads(text, object_pairs_hook=pairs)
            workspace=(ROOT/"Cargo.toml").read_text(encoding="utf-8")
            expected=re.search(r'(?m)^version\s*=\s*"([^"]+)"',workspace).group(1)
            require(version["name"]=="SYMBIOTE" and version["version"]==expected
                    and version["build_source_commit"]==source_commit,"native version/source stamp differs from frozen candidate")
        preflight.append(record)
    require(source_files(ROOT) == before, "source changed during build preflight")
    registration = dict(schema="symbiote.stability-registration/1", protocol=PROTOCOL,
                        protocol_sha256=sha(ROOT/PROTOCOL_FILE), source_files=before, source_tree_sha256=digest(before),
                        source_commit=source_commit,
                        binaries=binaries, artifact_directory=str(artifacts.resolve()), bounds=BOUNDS,
                        plan=plan_descriptor(), preflight=preflight,
                        host=dict(os=platform.system(),architecture=platform.machine(),host_id_sha256=hashlib.sha256(platform.node().encode()).hexdigest()),
                        interpretation="local software regression campaign; no independent-host or scientific improvement claim")
    write_new(artifacts/"campaign-registration.json",registration)
    return dict(registration=str(artifacts/"campaign-registration.json"),registration_sha256=sha(artifacts/"campaign-registration.json"),status="REGISTERED_NOT_RUN")


class Campaign:
    def __init__(self, registration):
        self.registration = registration
        self.directory = Path(registration["artifact_directory"])
        self.binary = registration["binaries"]["native"]["path"]
        self.started = time.monotonic()
        self.records = []
        self.cancelled = False

    def unchanged(self):
        require(source_files(ROOT)==self.registration["source_files"], "source changed after registration")
        require(all(sha(value["path"])==value["sha256"] for value in self.registration["binaries"].values()), "registered executable changed")

    def call(self,label,args,expected=0,network=False,binary=None,endurance=False,environment=None):
        self.unchanged()
        require(len(self.records)<BOUNDS["root_launches"], "root process budget exhausted")
        remaining=BOUNDS["campaign_seconds"]-(time.monotonic()-self.started)
        require(remaining>0 and not self.cancelled, "campaign deadline/cancellation reached")
        require(evidence_size(self.directory)+BOUNDS["output_bytes_per_process"]+BOUNDS["final_report_reserve_bytes"]<=BOUNDS["evidence_bytes"],"reserve captured output and final receipt before another process")
        short=label if len(label)<=48 else label[:36]+"-"+hashlib.sha256(label.encode()).hexdigest()[:10]
        record=execute([binary or self.binary,*args],self.directory,f"{len(self.records):02d}-{short}",
                       timeout=min(remaining,BOUNDS["endurance_seconds"] if endurance else (BOUNDS["network_seconds"] if network else BOUNDS["command_seconds"])),cancelled=lambda:self.cancelled,environment=environment)
        self.records.append(record)
        with (self.directory/"process-receipts.jsonl").open("ab") as stream:stream.write(encode(record)+b"\n")
        evidence_size(self.directory)
        check_exit(record,expected)
        return record

    def native(self,label,command,state,*,fault=None,expected=0):
        args=[command,"--state",str(state),"--json"]
        receipt=self.directory/(label+".native.json")
        if command in ("demo","network-research"):
            args += ["--receipts",str(receipt)]
        if fault:args += ["--fault",fault]
        record=self.call(label,args,expected,network=command=="network-research")
        return load(receipt) if expected and receipt.exists() else (json.loads(output(record,self.directory),object_pairs_hook=pairs) if not expected else None)

    def snapshot(self,label,state):
        state=Path(state)
        target=self.directory/"state-snapshots"/label
        target.mkdir(parents=True,exist_ok=False)
        manifest={}
        if state.exists():
            for path in state.rglob("*"):
                require(not path.is_symlink(),"manual state snapshot contains a link")
                if not path.is_file(): continue
                require(path.stat().st_size<=4*1024*1024,"manual state file exceeds bound")
                require(evidence_size(self.directory)+path.stat().st_size+BOUNDS["final_report_reserve_bytes"]<=BOUNDS["evidence_bytes"],"state snapshot must leave room for final receipt")
                relative=path.relative_to(state)
                copied=target/relative
                copied.parent.mkdir(parents=True,exist_ok=True)
                with copied.open("xb") as stream:stream.write(path.read_bytes())
                manifest[relative.as_posix()]=sha(copied)
                evidence_size(self.directory)
        write_new(target/"snapshot-receipt.json",dict(source=str(state),files=manifest))

    def demo_and_backup(self):
        state=self.directory/"genesis"
        first=self.native("learn","demo",state)
        require(first["promoted"]==2 and first["reused"]==0, "first finite demo promotes exactly two artifacts")
        identity=first["identity"]
        before,rows=identity_chain(state/"ledger.jsonl")
        require(rows[0]["payload"]["identity"]==identity,"reported identity must equal the actual persisted genesis owner")
        self.snapshot("before-faults",state)
        prediction=self.native("predict","predict",state);genesis_predictions(prediction,identity,{"alpha-table":1,"beta-table":1})
        second=self.native("reuse","demo",state)
        require(second["identity"]==identity and second["promoted"]==0 and second["reused"]==2, "second process actually reuses both models")
        require((state/"ledger.jsonl").read_bytes()==before, "reuse cannot invent a new learning record")
        genesis_predictions(self.native("reuse-predict","predict",state),identity,{"alpha-table":1,"beta-table":1})
        wrong=self.directory/"wrong-artifact"
        rejection=self.native("reject","demo",wrong,fault="wrong-artifact",expected=1)
        require(rejection is not None and rejection["status"]=="REJECTED", "wrong artifact has an explicit preserved failure receipt")
        self.snapshot("rejected-candidate",wrong)
        rejected=self.native("rejected-predict","predict",wrong);genesis_predictions(rejected,rejection["identity"],{})
        recovered=self.native("recover-rejected","demo",wrong)
        require(recovered["identity"]==rejection["identity"] and recovered["promoted"]==2, "rejected candidate consumes no accepted revision")
        _,valid_history=identity_chain(wrong/"ledger.jsonl")
        require(valid_history[0]["payload"]["identity"]==rejection["identity"],"rejected-store recovery retains its actual genesis owner")
        promoted={row["payload"]["artifact"]["id"]:row["payload"]["artifact"] for row in valid_history if row["payload"]["event"]=="promote"}
        require(set(promoted)=={"alpha-table","beta-table"} and all(value["revision"]==1 for value in promoted.values()),"rejected offers cannot consume first accepted revisions")
        genesis_predictions(self.native("recovered-reject-predict","predict",wrong),rejection["identity"],{"alpha-table":1,"beta-table":1})
        drift=self.native("drift","demo",state,fault="drift",expected=1)
        require(drift["status"]=="REJECTED", "drift remains an explicit negative control")
        self.snapshot("after-drift-before-recovery",state)
        after=self.native("after-drift","predict",state);genesis_predictions(after,identity,{"beta-table":1})
        _,history=identity_chain(state/"ledger.jsonl")
        require(any(row["payload"]["event"]=="revoke" for row in history), "drift causes a durable revocation")
        repair=self.native("recover-drift","demo",state)
        require(repair["identity"]==identity and repair["promoted"]==repair["reused"]==1, "recovery retains identity and advances one revision")
        restored_prediction=self.native("recovered-predict","predict",state);genesis_predictions(restored_prediction,identity,{"alpha-table":2,"beta-table":1})
        by_id=prediction_revisions(restored_prediction)
        require(by_id["alpha-table"]["revision"]==2 and by_id["beta-table"]["revision"]==1, "old revoked alpha revision cannot reactivate")
        final_bytes,_=identity_chain(state/"ledger.jsonl")
        require(final_bytes.startswith(before), "original learning evidence remains an exact prefix")
        archive=self.directory/"backup"
        saved=json.loads(output(self.call("backup",["backup-state","--state",str(state),"--backup",str(archive),"--json"]),self.directory))
        pin=saved["manifest_sha256"]
        common=["--backup",str(archive),"--manifest-sha256",pin,"--json"]
        self.call("verify-backup",["verify-backup",*common])
        destination=self.directory/"restored"
        report=json.loads(output(self.call("restore",["restore-state",*common,"--state",str(destination)]),self.directory))
        require(report["identity"]==identity and report["network_started"] is False and report["requires_activation"] is True, "restoration retains owner without activation")
        require((destination/"ledger.jsonl").read_bytes()==final_bytes, "restore preserves complete history byte-for-byte")
        offline=self.native("restored-predict","predict",destination)
        require(offline==restored_prediction, "actual restored offline predictions equal original predictions")
        self.snapshot("after-restore",destination)
        self.call("occupied-restore",["restore-state",*common,"--state",str(destination)],expected=1)
        require("destination is occupied" in (self.directory/self.records[-1]["stderr"]).read_text(encoding="utf-8"),"occupied restore fails for the declared destination boundary")
        require((destination/"ledger.jsonl").read_bytes()==final_bytes, "occupied destination refusal preserves history")
        original_archive=(archive/"files/ledger.jsonl").read_bytes()
        (archive/"files/ledger.jsonl").write_bytes(original_archive.splitlines(keepends=True)[0])
        self.call("tampered-backup",["verify-backup",*common],expected=1)
        require("backup file set, bytes or owner differs from its manifest" in (self.directory/self.records[-1]["stderr"]).read_text(encoding="utf-8"),"valid-prefix archive rollback must fail its original manifest")
        require((state/"ledger.jsonl").read_bytes()==final_bytes, "negative archive never alters live source history")
        return dict(identity=identity,revisions={key:row["revision"] for key,row in by_id.items()},history_records=len(history),
                    preserved_history_sha256=sha(state/"ledger.jsonl"),rejected_transfer=True,drift_revocation=True,offline_restoration=True)

    def network(self):
        state=self.directory/"native-processes"
        report=self.native("native-processes","network-research",state)
        _,controller_history=identity_chain(state/"ledger.jsonl")
        require(controller_history[0]["payload"]["identity"]==report["identity"],"network controller identity binds actual genesis")
        for key in ("process_separation","private_identity_and_ledgers","forged_receipt_rejected","cross_domain_receipt_rejected","duplicate_receipt_rejected","restart_retained_predictions"):
            require(report[key] is True, "native prototype "+key)
        require(all(report[key]==0 for key in ("restart_acquisition_requests","restart_verification_requests","restart_assessment_requests")), "offline native restart makes zero oracle calls")
        for role,row in zip(("exact","linear"),report["participants"]):
            _,identity=identity_chain(state/"network"/role/"ledger.jsonl")
            _,knowledge=knowledge_chain(state/"network"/role/"knowledge.jsonl")
            require(identity[0]["payload"]["identity"]==knowledge[0]["payload"]["identity"]==row["identity"],"network participant identity binds both actual private genesis records")
            require(row["instance_nonce"]!=row["restart_instance_nonce"] and row["active_models"]>0, "real new native instance retains nonempty knowledge")
        for fault in FAULTS:
            path=self.directory/("network-"+fault)
            self.native(fault,"network-research",path,fault=fault,expected=1)
            stage=fault_evidence(fault,path,(self.directory/self.records[-1]["stderr"]).read_text(encoding="utf-8"))
            write_new(self.directory/(fault+".stage.json"),stage)
            self.snapshot("after-"+fault+"-before-lock-recovery",path)
            for candidate in (path,path/"network/exact",path/"network/linear"):
                if not (candidate/"ledger.jsonl").exists():continue
                before={name:(candidate/name).read_bytes() for name in ("ledger.jsonl","knowledge.jsonl") if (candidate/name).exists()}
                self.native(fault+"-inspect-"+candidate.name,"inspect-state",candidate)
                recovery=self.native(fault+"-recover-"+candidate.name,"recover",candidate)
                require(recovery["processes_terminated"]==0 and recovery["ledgers_modified"] is False,"recovery may remove verified-dead locks only")
                require(all((candidate/name).read_bytes()==raw for name,raw in before.items()), "recovery never rewrites identity or committed knowledge")
                check=self.native(fault+"-post-"+candidate.name,"inspect-state",candidate)
                require(all(lock["state"]=="absent" for lock in check["locks"]), "owned fault leaves no unrecovered writer")
            if fault=="crash-after-promotion":
                exact=path/"network/exact"
                committed=(exact/"knowledge.jsonl").read_bytes()
                offline=self.native("postcommit-offline","predict",exact)
                assert_predictions(offline,stage["owners"]["exact"],1)
                structural_affine_predictions(offline,stage["owners"]["exact"],stage["models"]["exact"]["record"])
                replay=self.native("postcommit-restart","network-research",path)
                require(replay["participants"][0]["identity"]==stage["owners"]["exact"]
                        and replay["participants"][0]["promotion"]["promoted"] is False
                        and replay["participants"][0]["promotion"]["already_retained"] is True,"post-commit restart must reuse the accepted model")
                require((exact/"knowledge.jsonl").read_bytes()==committed,"post-commit recovery cannot duplicate a promotion")
                require(self.native("postcommit-replay-predict","predict",exact)==offline,"actual post-commit predictions remain identical")
        return dict(scope="one four-bit native prototype, regression repetition only",restart_retained=True,negative_faults=list(FAULTS))

    def regressions(self):
        results=[]
        for name,cases in (("cli_tests",CLI_CASES),("service_tests",SERVICE_CASES)):
            for case in cases:
                record=self.call(case,[case,"--exact","--test-threads=1"],binary=self.registration["binaries"][name]["path"])
                check_native_test(output(record,self.directory))
                results.append(dict(name=case,status="PASS",classification="REGRESSION_REPEAT",process_receipt=record["process_receipt"]))
        return results

    def endurance(self):
        directory=(self.directory/"endurance").resolve()
        require(not directory.exists(),"continuity evidence must be fresh")
        record=self.call(ENDURANCE_CASE,[ENDURANCE_CASE,"--ignored","--exact","--test-threads=1"],
                         binary=self.registration["binaries"]["service_tests"]["path"],endurance=True,
                         environment={"SYMBIOTE_ENDURANCE_ARTIFACTS":str(directory)})
        check_native_test(output(record,self.directory))
        return verify_endurance(directory,self.registration["binaries"])


def run(registration_path,expected):
    path=Path(registration_path).resolve(strict=True)
    require(sha(path)==expected, "registration differs from externally retained SHA256")
    registration=load(path)
    require(registration["schema"]=="symbiote.stability-registration/1" and registration["protocol"]==PROTOCOL
            and registration["bounds"]==BOUNDS and registration["plan"]==plan_descriptor()
            and registration["protocol_sha256"]==sha(ROOT/PROTOCOL_FILE), "unsupported or changed frozen protocol/budgets/acceptance")
    require(path.parent==Path(registration["artifact_directory"]).resolve(), "registration artifact path changed")
    campaign=Campaign(registration)
    campaign.unchanged()
    write_new(path.parent/"campaign-started.json",dict(registration_sha256=expected,protocol=PROTOCOL))
    old_handlers={}
    for signum in (signal.SIGINT,signal.SIGTERM):
        old_handlers[signum]=signal.signal(signum,lambda *_:setattr(campaign,"cancelled",True))
    report=dict(schema="symbiote.local-stability/1",protocol=PROTOCOL,registration_sha256=expected,status="HOLD",
                independent_host_validation="OPEN_UNAVAILABLE",host_count=1,scientific_improvement_claim=False,
                stable_v1_qualification="OPEN; one local campaign cannot close independent-host or endurance gates")
    error=None
    try:
        report["demo_backup"]=campaign.demo_and_backup()
        report["native_processes"]=campaign.network()
        report["regressions"]=campaign.regressions()
        report["local_continuity"]=campaign.endurance()
        campaign.unchanged()
        final_acceptance(campaign.cancelled,time.monotonic()-campaign.started,evidence_size(path.parent),0)
        report["status"]="PASS"
    except Exception as failure:
        error=str(failure)
        report["failure"]=error
    finally:
        for signum,handler in old_handlers.items():signal.signal(signum,handler)
        report["root_processes"]=len(campaign.records)
        report["elapsed_seconds"]=time.monotonic()-campaign.started
        report["processes"]=campaign.records
        report["test_fixture_limit"]="selected integration tests own and may remove their temporary private fixtures; this campaign preserves their raw process outputs, not those removed directories"
        if report["status"]=="PASS":
            try:
                prospective=len(json.dumps(report,ensure_ascii=False,indent=2).encode())+1
                final_acceptance(campaign.cancelled,time.monotonic()-campaign.started,evidence_size(path.parent),prospective)
            except RuntimeError as failure:
                report["status"]="HOLD";report["failure"]=str(failure)
        write_new(path.parent/"campaign-report.json",report)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest="command",required=True)
    freeze=commands.add_parser("register")
    for name in ("binary","cli-tests","service-tests","artifacts"):freeze.add_argument("--"+name,type=Path,required=True)
    freeze.add_argument("--source-commit",required=True)
    start=commands.add_parser("run")
    start.add_argument("--registration",type=Path,required=True)
    start.add_argument("--registration-sha256",required=True)
    args=parser.parse_args()
    if args.command=="register":result=register(args.binary,args.cli_tests,args.service_tests,args.artifacts,args.source_commit)
    else:result=run(args.registration,args.registration_sha256)
    print(json.dumps(result,indent=2))
    return 0 if result.get("status") in ("PASS","REGISTERED_NOT_RUN") else 1


if __name__=="__main__":
    try:sys.exit(main())
    except (RuntimeError,ValueError,KeyError,OSError,subprocess.SubprocessError) as error:
        print(json.dumps(dict(schema="symbiote.local-stability/1",status="HOLD",failure=str(error))),file=sys.stderr)
        sys.exit(1)
