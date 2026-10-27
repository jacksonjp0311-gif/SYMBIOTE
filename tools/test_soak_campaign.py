"""Independent soak gate negatives. These tests never execute the hour."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import soak_campaign as soak


def timing_fixture(qualification):
    selected=soak.mode(qualification);origin=1000;events=[];cycles=[];gaps=[]
    points=sorted([*selected["rotations"],*selected["denials"],selected["lost"],selected["restore"]])
    def emit(kind,data,at):
        row=dict(sequence=len(events),kind=kind,data=data,elapsed_ms=at);events.append(row);return row
    pid=1001;ready_at=origin;cursor=origin
    emit("owned-listener-started",dict(label="main-initial",ready=dict(pid=pid)),origin)
    spans=[]
    for n in range(1,selected["cycles"]+1):
        first=origin+n*selected["spacing_ms"] if qualification else cursor+100
        times=list(range(cursor,first,1000))+[first]
        for at in times:emit("listener-alive",dict(cycle=n,pid=pid),at)
        for index,operation in ((0,"read"),(0,"predict"),(1,"read"),(1,"predict")):
            label=f"cycle-{n}-{index}-{operation}"
            for kind in ("tls-request","native-command","tls-response"):
                emit(kind,dict(label=label),first);first+=1
        finished=first-1
        cycles.append(dict(cycle=n,due_ms=n*selected["spacing_ms"],started_ms=times[-1]-origin,finished_ms=finished-origin,
                           idle_poll_count=len(times),max_idle_poll_gap_ms=100,ready=dict(pid=pid)))
        cursor=finished+1
        if n in points:
            span=cursor-ready_at;spans.append(span)
            kind="owned-listener-killed-and-joined" if n==selected["lost"] else "owned-listener-stopped"
            data=dict(pid=pid,main_listener=True,ready_to_wait_ms=span)
            data.update(dict(cycle=n) if kind.endswith("joined") else dict(label=f"maintenance-{n}"))
            emit(kind,data,cursor);cursor+=10;pid+=1;ready_at=cursor
            emit("owned-listener-started",dict(label=f"after-maintenance-{n}",ready=dict(pid=pid)),cursor)
            gaps.append(dict(after_cycle=n,elapsed_ms=10))
    spans.append(cursor-ready_at)
    emit("owned-listener-stopped",dict(label="measurement-final",pid=pid,main_listener=True,ready_to_wait_ms=spans[-1]),cursor)
    report=dict(mode=selected["name"],schedule=dict(spacing_ms=selected["spacing_ms"],window_ms=selected["window_ms"],
                rotations=selected["rotations"],denials=selected["denials"],lost_cycle=selected["lost"],restore_after=selected["restore"],late_limit_ms=5000,maintenance_gap_limit_ms=20000),
                cycles=cycles,maintenance_gaps=gaps,main_listener_span_ms=sum(spans),measurement_started_elapsed_ms=origin,
                max_idle_poll_gap_ms=100,idle_poll_count=sum(row["idle_poll_count"] for row in cycles),stale_tls_probe_attempts=4,measurement_elapsed_ms=cursor-origin,
                qualification="ONE_HOST_BOUNDED_HOUR" if qualification else "NOT_HOUR_QUALIFIED")
    return selected,report,events


class SoakGates(unittest.TestCase):
    def test_shifted_origin_and_inflated_spans_fail_even_with_new_json_digests(self):
        selected,report,events=timing_fixture(True)
        original=soak.digest(dict(report=report,events=events))
        for kind in ("origin","span"):
            changed=copy.deepcopy(report);trace=copy.deepcopy(events)
            if kind=="origin":
                changed["measurement_started_elapsed_ms"]-=100
                changed["measurement_elapsed_ms"]+=100
                for row in changed["cycles"]:row["started_ms"]+=100;row["finished_ms"]+=100
            else:
                stop=next(event for event in trace if event["kind"]=="owned-listener-stopped")
                stop["data"]["ready_to_wait_ms"]+=10000;changed["main_listener_span_ms"]+=10000
            self.assertNotEqual(soak.digest(dict(report=changed,events=trace)),original)
            with self.assertRaises(RuntimeError,msg=kind):soak.check_timing(changed,trace,selected)

    def test_actual_output_and_reply_events_cannot_slip_outside_the_slot(self):
        selected,report,events=timing_fixture(True)
        changed=copy.deepcopy(report);trace=copy.deepcopy(events)
        beginning=next(event["sequence"] for event in trace if event["kind"]=="native-command" and event["data"]["label"]=="cycle-1-0-predict")
        for event in trace[beginning:]:event["elapsed_ms"]+=40000
        first_stop=next(event for event in trace if event["kind"]=="owned-listener-stopped")
        first_stop["data"]["ready_to_wait_ms"]+=40000
        changed["main_listener_span_ms"]+=40000;changed["measurement_elapsed_ms"]+=40000
        changed["cycles"][0]["finished_ms"]+=40000
        self.assertEqual([event["elapsed_ms"] for event in trace],sorted(event["elapsed_ms"] for event in trace))
        soak.digest(dict(report=changed,events=trace))
        with self.assertRaisesRegex(RuntimeError,"outside scheduled cycle interval"):
            soak.check_timing(changed,trace,selected)

    def test_compressed_ordered_operations_plus_long_idle_cannot_manufacture_hour(self):
        selected,report,events=timing_fixture(True)
        trace=copy.deepcopy(events);changed=copy.deepcopy(report);origin=report["measurement_started_elapsed_ms"]
        # Keep the final actual stop at one hour, but move every application
        # attempt/liveness sample into an ordered compressed prefix.
        for event in trace[:-1]:event["elapsed_ms"]=origin+(event["elapsed_ms"]-origin)//1000
        active=None;total=0;last_end=None;gaps=[]
        for event in trace:
            data=event["data"]
            if event["kind"]=="owned-listener-started":
                if last_end is not None:gaps.append(dict(after_cycle=last_end["data"].get("cycle",int(last_end["data"].get("label","maintenance-0").removeprefix("maintenance-"))),elapsed_ms=event["elapsed_ms"]-last_end["elapsed_ms"]))
                active=event["elapsed_ms"]
            elif event["kind"] in ("owned-listener-stopped","owned-listener-killed-and-joined"):
                data["ready_to_wait_ms"]=event["elapsed_ms"]-active;total+=data["ready_to_wait_ms"];last_end=event
        changed["main_listener_span_ms"]=total;changed["maintenance_gaps"]=gaps
        for n,row in enumerate(changed["cycles"],1):
            row["started_ms"]=next(e["elapsed_ms"] for e in trace if e["kind"]=="tls-request" and e["data"]["label"]==f"cycle-{n}-0-read")-origin
            row["finished_ms"]=next(e["elapsed_ms"] for e in trace if e["kind"]=="tls-response" and e["data"]["label"]==f"cycle-{n}-1-predict")-origin
        self.assertEqual([e["elapsed_ms"] for e in trace],sorted(e["elapsed_ms"] for e in trace))
        self.assertGreaterEqual(total,3540000)
        soak.digest(dict(report=changed,events=trace))  # Rehashing is not acceptance.
        with self.assertRaises(RuntimeError):soak.check_timing(changed,trace,selected)

    def test_periodic_watch_checks_git_commit_even_when_content_pins_match(self):
        with mock.patch.object(soak,"pins_unchanged") as pins,mock.patch.object(soak,"git_unchanged",side_effect=RuntimeError("commit changed")) as git:
            with self.assertRaisesRegex(RuntimeError,"commit changed"):
                soak.live_candidate_check(Path("unused"),{}, {},True,"a"*40)
            pins.assert_called_once();git.assert_called_once_with("a"*40)

    def test_hour_requires_actual_full_hour_and_nonvacuous_live_listener_spans(self):
        selected,report,events=timing_fixture(True)
        soak.check_timing(report,events,selected)
        for elapsed in (0,3570000,3599999):
            changed=copy.deepcopy(report);changed["measurement_elapsed_ms"]=elapsed
            with self.assertRaises(RuntimeError):soak.check_timing(changed,events,selected)
        changed=copy.deepcopy(report);changed["main_listener_span_ms"]=0
        with self.assertRaises(RuntimeError):soak.check_timing(changed,events,selected)

    def test_missing_duplicate_late_and_burst_slots_cannot_pass(self):
        selected,report,events=timing_fixture(True)
        for kind in ("missing","duplicate","late","burst"):
            changed=copy.deepcopy(report)
            if kind=="missing":changed["cycles"].pop()
            elif kind=="duplicate":changed["cycles"][1]["cycle"]=1
            elif kind=="late":changed["cycles"][1]["started_ms"]+=5001;changed["cycles"][1]["finished_ms"]+=5001
            else:changed["cycles"][1]["started_ms"]=30000
            with self.assertRaises(RuntimeError,msg=kind):soak.check_timing(changed,events,selected)

    def test_fixture_is_explicitly_separate_and_cannot_be_relabelled_as_hour(self):
        selected,report,events=timing_fixture(False)
        soak.check_timing(report,events,selected)
        self.assertEqual(selected["keys"],51)
        with self.assertRaises(RuntimeError):soak.check_timing(report,events,soak.mode(True))
        report["qualification"]="ONE_HOST_BOUNDED_HOUR"
        with self.assertRaises(RuntimeError):soak.check_timing(report,events,selected)

    def test_maintenance_and_liveness_budgets_have_no_summary_only_escape(self):
        selected,report,events=timing_fixture(True)
        for kind in ("gap","missing","poll","span"):
            changed=copy.deepcopy(report);trace=copy.deepcopy(events)
            if kind=="gap":changed["maintenance_gaps"][0]["elapsed_ms"]=20001
            elif kind=="missing":changed["maintenance_gaps"].pop()
            elif kind=="poll":changed["cycles"][0]["max_idle_poll_gap_ms"]=5001
            else:next(event for event in trace if event["kind"]=="owned-listener-stopped")["data"]["ready_to_wait_ms"]-=1
            with self.assertRaises(RuntimeError,msg=kind):soak.check_timing(changed,trace,selected)

    def test_final_cancellation_time_and_bytes_never_become_pass(self):
        soak.final_checks(False,3601,True,0,1000)
        for args in ((True,3601,True,0,1000),(False,3901,True,0,1),(False,181,False,0,1),
                     (False,1,False,soak.BOUNDS["evidence_bytes"],1),(False,1,False,0,1024*1024+1)):
            with self.assertRaises(RuntimeError):soak.final_checks(*args)

    def test_source_binding_uses_versioned_exact_byte_utf8_manifest(self):
        observed=soak.source_files()
        manifest=observed["manifest"]
        self.assertEqual(manifest["schema"],"symbiote.source-manifest/2")
        names=[row["path"] for row in manifest["files"]]
        self.assertEqual(names,sorted(names,key=lambda value:value.encode("utf-8")))
        self.assertIn("tools/soak_campaign.py",names)
        self.assertEqual(observed["protocol_sha256"],soak.sha(soak.ROOT/soak.PROTOCOL_FILE))

    def test_executable_mutation_is_detected_without_any_native_execution(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-soak-pin-test-") as folder:
            path=Path(folder)/"fake.exe";path.write_bytes(b"first")
            sources=soak.source_files();pins=dict(native=dict(path=str(path),sha256=soak.sha(path)))
            soak.pins_unchanged(pins,sources);path.write_bytes(b"changed")
            with self.assertRaises(RuntimeError):soak.pins_unchanged(pins,sources)

    def test_once_started_marker_prevents_a_second_registered_launch(self):
        with tempfile.TemporaryDirectory(prefix="symbiote-soak-once-") as folder:
            root=Path(folder);manifest=soak.source_files()["manifest"]
            registration=dict(schema="symbiote.soak-registration/1",protocol=soak.PROTOCOL,protocol_sha256=soak.sha(soak.ROOT/soak.PROTOCOL_FILE),
                              source_order=soak.source_fingerprint.ALGORITHM,source_manifest=manifest,source_sha256=manifest["sha256"],source_commit="a"*40,
                              mode=soak.mode(True),bounds=soak.BOUNDS,artifact_directory=str(root),binaries={})
            path=root/"soak-registration.json";soak.write_new(path,registration)
            started=root/"soak-started.json";soak.write_new(started,dict(first=True));before=started.read_bytes()
            with mock.patch.object(soak,"pins_unchanged"),mock.patch.object(soak,"git_unchanged"),mock.patch.object(soak,"launch") as launch:
                with self.assertRaises(FileExistsError):soak.run(path,soak.sha(path))
                launch.assert_not_called()
            self.assertEqual(started.read_bytes(),before)

    def test_clean_committed_candidate_is_required(self):
        clean=mock.Mock(returncode=0,stdout="a"*40+"\n",stderr="")
        dirty=mock.Mock(returncode=0,stdout=" M tools/soak_campaign.py\n",stderr="")
        with mock.patch.object(soak.subprocess,"run",side_effect=[clean,dirty]):
            with self.assertRaises(RuntimeError):soak.git_unchanged("a"*40)


if __name__=="__main__":unittest.main()
