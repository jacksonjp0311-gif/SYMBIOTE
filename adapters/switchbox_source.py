"""Owned loopback observation simulator, independent of the Rust reasoner.

Private wiring and bearer material are never returned. This development source
implements the documented affine family directly, one permitted query at a time;
it neither imports SYMBIOTE nor sends an answer table to the learner.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import socket
import sys
import threading
import time

MAX_FRAME = 4096
FAULTS = ("none", "wrong_sequence", "wrong_input", "nonbinary", "malformed",
          "oversized", "unavailable", "epoch", "contradiction", "late_final")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate source field")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "nonfinite source field"))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def output_bit(wiring, bias, width, input_value):
    """Independent gate simulation; no model enumeration or engine prediction."""
    value = bias
    for position in range(width):
        if wiring & (1 << position):
            value ^= (input_value >> position) & 1
    return value


def read_frame(stream, deadline, stop):
    raw = bytearray()
    while len(raw) <= MAX_FRAME:
        require(not stop.is_set() and time.monotonic() < deadline, "source frame deadline/cancellation")
        stream.settimeout(min(0.05, max(0.001, deadline-time.monotonic())))
        try:
            value = stream.recv(1)
        except socket.timeout:
            continue
        if not value:
            raise ValueError("incomplete source frame")
        raw.extend(value)
        if value == b"\n":
            require(len(raw) <= MAX_FRAME, "source frame budget")
            return decode(raw)
    raise ValueError("source frame budget")


def serve(config_path, transcript_path, fault="none"):
    config_path = Path(config_path).resolve(strict=True)
    require(config_path.stat().st_size <= 4096, "source config budget")
    config = decode(config_path.read_bytes())
    require(set(config) == {"source_id", "scope", "epoch", "commitment", "width",
                            "mask", "bias", "token_file", "max_queries", "lifetime_ms"},
            "source config fields")
    width = config["width"]
    require(type(width) is int and 2 <= width <= 8, "source width")
    require(type(config["mask"]) is int and 0 <= config["mask"] < (1 << width)
            and type(config["bias"]) is int and config["bias"] in (0, 1), "private wiring")
    require(type(config["max_queries"]) is int and 1 <= config["max_queries"] <= 256
            and type(config["lifetime_ms"]) is int and 1 <= config["lifetime_ms"] <= 600000,
            "source lifetime/query bounds")
    require(all(isinstance(config[key], str) and 0 < len(config[key]) <= 128
                for key in ("source_id", "scope", "epoch")), "source descriptor")
    require(isinstance(config["commitment"], str) and len(config["commitment"]) == 64
            and all(c in "0123456789abcdef" for c in config["commitment"]), "source commitment")
    token_path = config_path.parent / config["token_file"]
    require(token_path.is_file() and not token_path.is_symlink()
            and token_path.stat().st_size <= 256, "source token file")
    token = token_path.read_text(encoding="ascii").strip()
    require(1 <= len(token) <= 256 and all(32 <= ord(c) < 127 for c in token), "source token")
    require(fault in FAULTS, "source fault mode")
    transcript_path = Path(transcript_path).resolve()
    require(not transcript_path.exists(), "fresh source transcript required")
    stop = threading.Event()

    def owner():
        try:
            # Only the explicit owner pipe controls lifetime, never a query body.
            sys.stdin.buffer.readline(256)
        finally:
            stop.set()

    watcher = threading.Thread(target=owner, daemon=True)
    watcher.start()
    started = time.monotonic()
    calls = denied = 0
    previous = "0" * 64
    fields = {"schema", "source_id", "scope", "epoch", "sequence", "input", "token"}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, transcript_path.open("xb") as transcript:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(0.05)
        print(json.dumps(dict(schema="symbiote.switchbox-ready/1",
                              address="127.0.0.1:" + str(listener.getsockname()[1]),
                              **{key: config[key] for key in ("source_id", "scope", "epoch", "commitment", "width")})),
              flush=True)
        while not stop.is_set() and (time.monotonic() - started) * 1000 < config["lifetime_ms"]:
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(0.25)
                try:
                    request = read_frame(connection, min(started+config["lifetime_ms"]/1000,
                                                         time.monotonic()+0.25), stop)
                    require(isinstance(request, dict) and set(request) == fields, "request fields")
                    require(isinstance(request["token"], str)
                            and hmac.compare_digest(request["token"], token), "request authorization")
                    require(request["schema"] == "symbiote.switchbox-request/1"
                            and all(request[key] == config[key] for key in ("source_id", "scope", "epoch")),
                            "request descriptor")
                    require(type(request["sequence"]) is int and request["sequence"] == calls
                            and type(request["input"]) is int and 0 <= request["input"] < (1 << width)
                            and calls < config["max_queries"], "request sequence/input/budget")
                    value = output_bit(config["mask"], config["bias"], width, request["input"])
                    reply = dict(schema="symbiote.switchbox-response/1",
                                 **{key: config[key] for key in ("source_id", "scope", "epoch", "commitment", "width")},
                                 sequence=calls, input=request["input"], output=value)
                    row = dict(schema="symbiote.switchbox-observation/1", sequence=calls,
                               previous=previous, **{key: reply[key] for key in ("source_id", "scope", "epoch", "input", "output")})
                    calls += 1
                    if fault == "wrong_sequence": reply["sequence"] += 1
                    if fault == "wrong_input": reply["input"] ^= 1
                    if fault == "nonbinary": reply["output"] = 2
                    if fault == "epoch": reply["epoch"] += "-changed"
                    if fault == "contradiction" and calls == width + 2: reply["output"] ^= 1
                    if fault == "late_final" and calls == width + 2: time.sleep(0.3)
                    if fault == "unavailable":
                        row.update(response_frame_utf8="", response_bytes=0,
                                   response_sha256=hashlib.sha256(b"").hexdigest(), send_completed=False,
                                   output_is_oracle_value=True)
                        row["sha256"] = hashlib.sha256(canonical(row)).hexdigest()
                        transcript.write(canonical(row) + b"\n")
                        transcript.flush()
                        previous = row["sha256"]
                        continue
                    raw = canonical(reply) + b"\n"
                    if fault == "malformed": raw = b"{bad-json\n"
                    if fault == "oversized": raw = b"x" * (MAX_FRAME + 1) + b"\n"
                    sent = False
                    try:
                        connection.sendall(raw)
                        sent = True
                    finally:
                        row.update(response_frame_utf8=raw.decode("utf-8"), response_bytes=len(raw),
                                   response_sha256=hashlib.sha256(raw).hexdigest(), send_completed=sent,
                                   output_is_oracle_value=True)
                        row["sha256"] = hashlib.sha256(canonical(row)).hexdigest()
                        transcript.write(canonical(row) + b"\n")
                        transcript.flush()
                        previous = row["sha256"]
                except (ValueError, OSError, KeyError, TypeError, UnicodeError):
                    denied += 1
                    # No credential, private wiring, input or exception is echoed.
                    try: connection.sendall(b'{"schema":"symbiote.switchbox-error/1","error":"rejected"}\n')
                    except OSError: pass
        summary = dict(schema="symbiote.switchbox-summary/1", source_id=config["source_id"],
                       epoch=config["epoch"], source_calls=calls, denied_requests=denied,
                       transcript_head=previous, owner_stopped=stop.is_set(),
                       elapsed_seconds=time.monotonic() - started, private_wiring_exported=False,
                       fault=fault)
        print(json.dumps(summary), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--transcript", required=True, type=Path)
    parser.add_argument("--fault", choices=FAULTS, default="none")
    args = parser.parse_args()
    try:
        return serve(args.config, args.transcript, args.fault)
    except (ValueError, OSError, TypeError, KeyError, UnicodeError):
        print("source configuration or evidence rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
