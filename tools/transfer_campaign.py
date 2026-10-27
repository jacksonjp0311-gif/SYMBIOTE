"""Freeze and execute one native transfer study with exact build/source bindings."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading

import source_fingerprint
import stability_campaign as safety

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / 'docs/QUERY_TRANSFER_PROTOCOL.md'
SCHEMA = 'symbiote.transfer-campaign-registration/1'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 128*1024*1024,
            'bounded regular file required')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    require(Path(path).stat().st_size <= 1024*1024, 'bounded registration required')
    return json.loads(Path(path).read_bytes())


def write_new(path, value):
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write('\n')


def clean(commit):
    require(re.fullmatch('[0-9a-f]{40}', commit) is not None, 'full source commit required')
    for args, expected in ((['rev-parse', 'HEAD'], commit),
                           (['status', '--porcelain=v1', '--untracked-files=all'], '')):
        result = subprocess.run(['git', *args], cwd=ROOT, capture_output=True, timeout=10, check=False)
        require(result.returncode == 0 and len(result.stdout)+len(result.stderr) <= 2*1024*1024
                and result.stdout.decode('utf-8').strip() == expected,
                'candidate HEAD or clean working tree differs')


def preflight(registration):
    require(registration['schema'] == SCHEMA, 'unsupported campaign registration')
    clean(registration['source_commit'])
    source_fingerprint.verify(ROOT, registration['source_manifest'])
    require(sha(PROTOCOL) == registration['protocol_document_sha256'], 'protocol document changed')
    native = Path(registration['native'])
    require(sha(native) == registration['native_sha256'], 'native executable changed')
    native_reg = Path(registration['native_registration'])
    require(sha(native_reg) == registration['native_registration_sha256'], 'native registration changed')
    raw = load(native_reg)
    require(raw['native_sha256'] == registration['native_sha256']
            and raw['protocol_document_sha256'] == registration['protocol_document_sha256']
            and raw['source_commit'] == registration['source_commit']
            and Path(raw['state_directory']).resolve() == Path(registration['state']).resolve(),
            'native/outer source, executable, protocol or state bindings differ')
    return native, native_reg


def register(binary, state, artifacts, commit, cancelled=lambda: False):
    clean(commit)
    native = Path(binary).resolve(strict=True)
    state = Path(state).resolve()
    directory = Path(artifacts).resolve()
    require(not directory.exists() and not state.exists(), 'fresh campaign and state paths required')
    require(not directory.is_relative_to(ROOT) and not state.is_relative_to(ROOT),
            'registered artifacts and state must be outside frozen source checkout')
    require(not directory.is_relative_to(state) and not state.is_relative_to(directory),
            'state and artifact trees must be disjoint')
    before = source_fingerprint.manifest(ROOT)
    native_pin = sha(native)
    directory.mkdir(parents=True)
    version = safety.execute([native, '--version', '--json'], directory, 'version', timeout=10, cancelled=cancelled)
    safety.check_exit(version)
    value = json.loads(safety.output(version, directory))
    require(value['name'] == 'SYMBIOTE' and value['build_source_commit'] == commit,
            'compiled source stamp differs from clean candidate')
    native_reg = directory/'native-registration.json'
    process = safety.execute([native, 'transfer-register', '--state', state, '--receipts', native_reg,
                              '--json'], directory, 'register', timeout=10, cancelled=cancelled)
    safety.check_exit(process)
    registration = dict(schema=SCHEMA, source_commit=commit, source_manifest=before,
                        native=str(native), native_sha256=native_pin,
                        protocol_document_sha256=sha(PROTOCOL),
                        native_registration=str(native_reg), native_registration_sha256=sha(native_reg),
                        state=str(state), artifact_directory=str(directory), target_truth_opened=False,
                        native_version=value, register_process=process)
    preflight(registration)
    require(not cancelled(), 'registration cancelled')
    require(not state.exists(), 'registration opened prospective state')
    path = directory/'campaign-registration.json'
    write_new(path, registration)
    return dict(status='REGISTERED_NOT_RUN', registration=str(path), registration_sha256=sha(path))


def run(path, external_sha, cancelled=lambda: False):
    path = Path(path).resolve(strict=True)
    require(re.fullmatch('[0-9a-f]{64}', external_sha) is not None and sha(path) == external_sha,
            'campaign registration differs from external digest')
    registration = load(path)
    native, native_reg = preflight(registration)
    require(not cancelled(), 'campaign cancelled before admission')
    directory = Path(registration['artifact_directory'])
    require(directory.resolve() == path.parent and not Path(registration['state']).exists(),
            'registered locations changed or state already started')
    write_new(directory/'campaign-started.json', dict(registration_sha256=external_sha))
    report = dict(schema='symbiote.transfer-campaign/1', status='HOLD', registration_sha256=external_sha)
    try:
        output = directory/'transfer-report.json'
        process = safety.execute([native, 'transfer-research', '--state', registration['state'],
                                  '--registration', native_reg, '--registration-sha256',
                                  registration['native_registration_sha256'], '--receipts', output,
                                  ], directory, 'native-transfer', timeout=75, cancelled=cancelled)
        report['native_process'] = process
        safety.check_exit(process)
        verifier = safety.execute([sys.executable, ROOT/'tools/verify_transfer.py',
                                   '--registration', native_reg, '--registration-sha256',
                                   registration['native_registration_sha256'], '--source-commit',
                                   registration['source_commit'], '--native', native,
                                   '--report', output, '--output', directory/'independent-verification.json'],
                                  directory, 'independent-verifier', timeout=120, cancelled=cancelled)
        report['independent_process'] = verifier
        safety.check_exit(verifier)
        preflight(registration)
        require(not cancelled(), 'campaign cancelled before final receipt')
        result = load(directory/'independent-verification.json')
        require(result['status'] == 'PASS', 'independent verification did not pass')
        report.update(status='PASS', reciprocal_efficiency=result['reciprocal_efficiency'],
                      independent_verification_sha256=sha(directory/'independent-verification.json'),
                      source_sha256=registration['source_manifest']['sha256'])
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as failure:
        report['first_failure'] = str(failure)
    write_new(directory/'campaign-report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('register')
    for name in ('binary', 'state', 'artifacts'):
        setup.add_argument('--'+name, type=Path, required=True)
    setup.add_argument('--source-commit', required=True)
    execution = commands.add_parser('run')
    execution.add_argument('--registration', type=Path, required=True)
    execution.add_argument('--registration-sha256', required=True)
    args = parser.parse_args()
    cancelled = threading.Event()
    old = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            old[signum] = signal.signal(signum, lambda *_: cancelled.set())
        if args.command == 'register':
            result = register(args.binary, args.state, args.artifacts, args.source_commit, cancelled.is_set)
        else:
            result = run(args.registration, args.registration_sha256, cancelled.is_set)
    finally:
        for signum, handler in old.items():
            signal.signal(signum, handler)
    print(json.dumps(result, indent=2))
    return int(result['status'] == 'HOLD')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as failure:
        print(json.dumps(dict(status='HOLD', first_failure=str(failure))))
        raise SystemExit(1)
