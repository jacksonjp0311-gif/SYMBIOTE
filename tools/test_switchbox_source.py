"""Process/authorization fixtures; never the registered fresh-task workload."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "adapters" / "switchbox_source.py"


class SourceProcessTests(unittest.TestCase):
    def test_owner_control_auth_sequence_and_no_private_wiring_export(self):
        with tempfile.TemporaryDirectory(prefix="switchbox-unit-") as directory:
            root = Path(directory).resolve()
            secret = "independent-unit-secret-01234567890123456789"
            (root / "token").write_text(secret, encoding="ascii")
            config = dict(source_id="source-unit", scope="unit-affine/v1", epoch="unit-epoch",
                          commitment="a" * 64, width=3, mask=3, bias=1, token_file="token",
                          max_queries=4, lifetime_ms=3000)
            (root / "private.json").write_text(json.dumps(config), encoding="utf-8")
            process = subprocess.Popen([sys.executable, "-B", str(SOURCE), "--config", str(root / "private.json"),
                                        "--transcript", str(root / "observations.jsonl")],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ready = json.loads(process.stdout.readline())
                self.assertEqual(ready["schema"], "symbiote.switchbox-ready/1")
                self.assertFalse({"mask", "bias", "token"} & ready.keys())
                host, port = ready["address"].split(":")

                def call(sequence, input_value, token=secret, extra=None):
                    body = dict(schema="symbiote.switchbox-request/1", source_id="source-unit",
                                scope="unit-affine/v1", epoch="unit-epoch", sequence=sequence,
                                input=input_value, token=token)
                    if extra:
                        body.update(extra)
                    with socket.create_connection((host, int(port)), timeout=1) as stream:
                        stream.sendall(json.dumps(body).encode() + b"\n")
                        return json.loads(stream.makefile("rb").readline(4097))

                self.assertEqual(call(0, 5, "wrong")["error"], "rejected")
                self.assertEqual(call(0, 5)["output"], 0)
                self.assertEqual(call(0, 5)["error"], "rejected")
                self.assertEqual(call(1, 0, extra={"command": "shutdown"})["error"], "rejected")
                self.assertEqual(call(1, 0)["output"], 1)
                process.stdin.write(b'{"command":"shutdown"}\n')
                process.stdin.flush()
                process.wait(timeout=3)
                summary = json.loads(process.stdout.read())
                self.assertEqual(process.returncode, 0, process.stderr.read().decode())
                self.assertEqual(summary["source_calls"], 2)
                self.assertEqual(summary["denied_requests"], 3)
                self.assertTrue(summary["owner_stopped"])
                raw = (root / "observations.jsonl").read_bytes()
                self.assertNotIn(secret.encode(), raw)
                self.assertNotIn(b'"mask"', raw)
                self.assertEqual(len(raw.splitlines()), 2)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()

    def test_invalid_configuration_does_not_echo_bearer_or_wiring(self):
        with tempfile.TemporaryDirectory(prefix="switchbox-unit-bad-") as directory:
            root = Path(directory).resolve()
            private = root / "private.json"
            private.write_text('{"token":"never-echo-this","mask":123456789}', encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", str(SOURCE), "--config", str(private),
                                     "--transcript", str(root / "new.jsonl")],
                                    capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"never-echo-this", result.stdout + result.stderr)
            self.assertFalse((root / "new.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
