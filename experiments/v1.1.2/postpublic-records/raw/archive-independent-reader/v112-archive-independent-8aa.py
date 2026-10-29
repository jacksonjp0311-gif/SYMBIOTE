"""Data-only independent final ZIP/tar/corpus audit; no producer imports/execution."""
import argparse
import hashlib
import json
import os
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

SOURCE = '8aa5f4c6ab26f7ccad53935a70414ae1765b57c6'
PLAN_SHA = '10d03b8c59c892178f7cc313f0e2d1c1bfa3c2a943f4efc6efe284be301fec4b'
CONFIG_SHA = '0a149930abe99da345d7056bc85813394ea31f7e6ad721f5cd2d155b5289afcd'
SELECTOR_SHA = '9b529e5cc1db05fd381cf8480b0ff8892b064e2353acaa88533e23a23447fe11'
ZIP_HELPER_SHA = '2a5a03909828247ef090bc7cc9e9cb23693aa98affcdb9478260cd2a54de95eb'
BASE_SHA = '9a2df3fc679ce154469013e02575551d9572e7cee4d2a0eca585e7fc3a780962'
DERIVED_CONFIG_SHA = '298c4d25d8c51f60960e1a63eaf25865ef0a567b19fea9d67d973e61753c994f'
QUALIFIED_MANIFEST_SHA = 'daafc48c29ffad69a9d0ec76209e523757d6446a4b7939b18a72d9fd25f6d069'
REQUIRED = {'staged-windows-native', 'hour-native', 'hour-service-driver', 'e3-primary-consumer', 'e3-reproduction-consumer'}
MAX_FILES = 20001
MAX_MEMBER = 256 << 20
MAX_TOTAL = 1 << 30
MAX_ZIP = 128 << 20


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite JSON'))


def safe(name):
    p = PurePosixPath(name)
    need(isinstance(name, str) and name and ':' not in name and '\\' not in name and p.as_posix() == name and not p.is_absolute() and not set(p.parts) & {'.', '..'}, 'unsafe member path')
    return p


def stream_hash(stream, expected_size):
    need(type(expected_size) is int and 0 <= expected_size <= MAX_MEMBER, 'member byte limit')
    h = hashlib.sha256()
    count = 0
    for block in iter(lambda: stream.read(1 << 20), b''):
        count += len(block)
        need(count <= expected_size, 'member stream exceeded declared bytes')
        h.update(block)
    need(count == expected_size, 'truncated member stream')
    return {'bytes': count, 'sha256': h.hexdigest()}


def physical(path, maximum=MAX_TOTAL):
    path = Path(path)
    for item in [path, *path.parents]:
        metadata = item.lstat()
        need(not stat.S_ISLNK(metadata.st_mode) and not getattr(metadata, 'st_file_attributes', 0) & 0x400, 'reparse input')
    before = path.stat()
    need(path.is_file() and before.st_size <= maximum, 'physical file limit/type')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'input changed while read')
    return {'bytes': before.st_size, 'sha256': h.hexdigest()}


def pinned_json(path, digest, maximum=32 << 20):
    row = physical(path, maximum)
    need(row['sha256'] == digest, 'external JSON pin mismatch: ' + str(path))
    raw = Path(path).read_bytes()
    need(sha(raw) == digest, 'JSON changed before parse')
    return raw, parse(raw)


def pointer(document, value):
    result = document
    need(value == '' or value.startswith('/'), 'invalid JSON pointer')
    if value:
        for part in value[1:].split('/'):
            part = part.replace('~1', '/').replace('~0', '~')
            result = result[int(part)] if isinstance(result, list) else result[part]
    return result


def run(args):
    need(not args.output.exists(), 'fresh audit output required')
    for value in (args.zip_sha256, args.tar_sha256, args.packaging_sha256, args.zip_receipt_sha256, args.manifest_sha256, args.derived_config_sha256):
        need(len(value) == 64 and value != '0' * 64 and all(c in '0123456789abcdef' for c in value), 'actual closed external nonplaceholder SHA required')
    need(args.extracted.resolve() not in args.output.resolve().parents and args.tar_extracted.resolve() not in args.output.resolve().parents, 'audit output outside closed extracted trees')
    need(args.derived_config_sha256 == DERIVED_CONFIG_SHA and args.manifest_sha256 == QUALIFIED_MANIFEST_SHA, 'not exact independently reviewed qualified plan')
    zipped = physical(args.zip, MAX_ZIP)
    need(zipped['sha256'] == args.zip_sha256, 'actual ZIP external pin mismatch')
    tar_row = physical(args.tar)
    need(tar_row['sha256'] == args.tar_sha256, 'actual tar external pin mismatch')
    _, packaging = pinned_json(args.packaging, args.packaging_sha256)
    _, zip_receipt = pinned_json(args.zip_receipt, args.zip_receipt_sha256)
    manifest_raw, manifest = pinned_json(args.extracted / 'MANIFEST.json', args.manifest_sha256, 16 << 20)
    _, derived = pinned_json(args.derived_config, args.derived_config_sha256)
    need(manifest['schema'] == 'symbiote.v1-evidence-manifest/2' and manifest['source_commit'] == SOURCE and manifest['packager_base']['sha256'] == BASE_SHA, 'qualified inner manifest binding')
    need(packaging['schema'] == 'symbiote.v1-evidence-packaging/4' and packaging['status'] == 'PASS' and packaging['archive_sha256'] == args.tar_sha256 and packaging['archive_bytes'] == tar_row['bytes'] and packaging['evidence_plan']['manifest_sha256'] == args.manifest_sha256, 'qualified tar receipt mismatch')
    need(all(packaging[k] is True for k in ('full_tree_membership_rechecked', 'final_archive_bytes_rechecked', 'final_hardlink_identity_rechecked')), 'tar verification incomplete')
    need(packaging['evidence_plan']['config_sha256'] == args.derived_config_sha256, 'derived config unbound to actual packaging')
    expected = {'MANIFEST.json': {'bytes': len(manifest_raw), 'sha256': args.manifest_sha256}}
    folded = {'manifest.json'}
    for entry in manifest['entries']:
        name = safe(entry['path']).as_posix()
        need(name.casefold() not in folded, 'duplicate/case-alias inner manifest member')
        folded.add(name.casefold())
        need(type(entry['bytes']) is int and 0 <= entry['bytes'] <= MAX_MEMBER, 'inner manifest member size')
        expected[name] = {'bytes': entry['bytes'], 'sha256': entry['sha256']}
    need(len(expected) <= MAX_FILES and sum(r['bytes'] for r in expected.values()) <= MAX_TOTAL, 'inner census bound')
    need(zip_receipt['schema'] == 'symbiote.evidence-zip-verification/1' and zip_receipt['status'] == 'PASS_BYTE_DERIVATION_ONLY' and zip_receipt['source_commit'] == SOURCE and zip_receipt['sha256'] == zipped['sha256'] and zip_receipt['bytes'] == zipped['bytes'] and zip_receipt['inner_manifest_sha256'] == args.manifest_sha256 and zip_receipt['original_tar'] == tar_row, 'ZIP receipt mismatch')

    with zipfile.ZipFile(args.zip) as archive:
        infos = archive.infolist()
        names = [i.filename for i in infos]
        need(len(names) == len(set(names)) == len({n.casefold() for n in names}) <= MAX_FILES + 1, 'duplicate/case-alias ZIP name')
        need(set(names) == {'DERIVATION.json'} | {'corpus/' + n for n in expected}, 'ZIP exact member set mismatch')
        derivation_raw = archive.read('DERIVATION.json')
        need(sha(derivation_raw) == zip_receipt['derivation_sha256'], 'derivation SHA mismatch')
        derivation = parse(derivation_raw)
        need(derivation['schema'] == 'symbiote.evidence-zip-derivation/1' and derivation['source_commit'] == SOURCE and derivation['original_tar'] == tar_row and derivation['original_manifest_sha256'] == args.manifest_sha256 and derivation['original_verification_sha256'] == args.packaging_sha256 and derivation['helper_sha256'] == ZIP_HELPER_SHA and derivation['inner_prefix'] == 'corpus/' and derivation['inner_members'] == expected, 'ZIP derivation binding mismatch')
        actual_zip = {}
        for info in infos:
            safe(info.filename)
            need(not info.is_dir() and not info.flag_bits & 1 and stat.S_IFMT(info.external_attr >> 16) == stat.S_IFREG, 'nonregular/encrypted ZIP member')
            with archive.open(info) as stream:
                actual_zip[info.filename] = stream_hash(stream, info.file_size)
        need({n.removeprefix('corpus/'): r for n, r in actual_zip.items() if n != 'DERIVATION.json'} == expected, 'actual ZIP bytes mismatch')
        need(archive.read('corpus/MANIFEST.json') == manifest_raw, 'ZIP inner manifest changed')
        collections = manifest['collections']
        need(len(collections) == 2 and [c['name'] for c in collections] == ['selection', 'operators'] and collections[0]['selection'] == 'tree' and collections[0]['files'] == [], 'not complete selection tree')
        prefix = safe(collections[0]['archive_prefix']).as_posix() + '/'

        def read_export(name):
            need(prefix + name in expected, 'export control missing from archive')
            return archive.read('corpus/' + prefix + name)

        plan_raw = read_export('selection-plan.json')
        config_raw = read_export('selector-config.json')
        selector_raw = read_export('selector.py')
        need(sha(plan_raw) == PLAN_SHA and sha(config_raw) == CONFIG_SHA and sha(selector_raw) == SELECTOR_SHA, 'original selected controls changed')
        plan = parse(plan_raw)
        config = parse(config_raw)
        selection = parse(read_export('selection.json'))
        original_v4 = parse(read_export('package-v4-config.json'))
        need(plan['config'] == config and plan['config_sha256'] == CONFIG_SHA and plan['source_commit'] == config['source_commit'] == selection['source_commit'] == SOURCE, 'selected plan/config source mismatch')
        need(selection['selection_plan_sha256'] == PLAN_SHA and selection['selector_sha256'] == SELECTOR_SHA and selection['sources'] == plan['sources'] and selection['payloads'] == plan['payloads'], 'selection export detached from plan')
        payloads = {row['path']: row for row in plan['payloads']}
        need(len(payloads) == 2526 and len(plan['sources']) == 14 and len(config['anchors']) == 52 and len(config['executables']) == 26, 'closed selection coverage mismatch')
        need({n[len(prefix):] for n in expected if n.startswith(prefix)} == set(payloads) | {'selection.json', 'selection-plan.json', 'selector-config.json', 'selector.py', 'package-v4-config.json'}, 'archive selection tree truncated/expanded')
        for path, row in payloads.items():
            need(expected[prefix + path] == {'bytes': row['bytes'], 'sha256': row['sha256']}, 'selected raw payload bytes changed')
        included = {(s['id'], row['path']): row for s in plan['sources'] for row in s['included']}
        source_map = {s['id']: s for s in plan['sources']}
        anchors = {}
        for anchor in config['anchors']:
            row = included[(anchor['source'], anchor['path'])]
            data = read_export(row['payload'])
            need(sha(data) == anchor['sha256'] == row['sha256'], 'archived raw anchor mismatch')
            document = parse(data)
            if anchor['source_commit_pointer'] is None:
                need(anchor['source_commit'] is None, 'unwitnessed anchor source label')
            else:
                need(pointer(document, anchor['source_commit_pointer']) == anchor['source_commit'], 'archived source relabel')
            for assertion in anchor['expect']:
                need(pointer(document, assertion['pointer']) == assertion['value'], 'archived anchor status changed')
            anchors[anchor['id']] = (anchor, document)
        role_checks = []
        for role in config['executables']:
            row = included[(role['source'], role['path'])]
            anchor, document = anchors[role['anchor']]
            need(row['sha256'] == role['sha256'] == pointer(document, role['digest_pointer']) and anchor['source_commit'] == source_map[role['source']]['source_commit'], 'archived image role/source binding')
            need(expected[prefix + row['payload']]['sha256'] == role['sha256'], 'archived image removed')
            role_checks.append({'role': role['role'], 'sha256': role['sha256'], 'source_commit': anchor['source_commit'], 'payload': row['payload']})
        subset = [r for r in original_v4['executables'] if r['role'] in REQUIRED]
        need(len(original_v4['executables']) == 26 and len(subset) == 5 and derived['executables'] == subset, 'direct alias subset changed raw role metadata')
        changed = {k for k in original_v4 if original_v4[k] != derived[k]}
        need(changed == {'anchors', 'archive', 'collections', 'executables', 'extract_to'}, 'derived V4 undeclared recipe change')
        need(derived['anchors'][:-2] == original_v4['anchors'] and [a['id'] for a in derived['anchors'][-2:]] == ['five-direct-note', 'exact-git-summary-note'], 'derived V4 raw anchor changed')
        need(derived['collections'][:1] == original_v4['collections'] and len(derived['collections']) == 2 and derived['collections'][1]['selection'] == 'tree' and derived['collections'][1]['files'] == [] and derived['history'] == original_v4['history'], 'original full tree/history changed')
        need(derived['format_classifications'] == original_v4['format_classifications'] and len(original_v4['format_classifications']) == 2 and all(x['format'] == 'cargo-json-stream/1' for x in original_v4['format_classifications']), 'exact unchanged two Cargo contracts changed')
        need(derived['archive'] == str(Path(os.environ['TEMP']) / 'vt112b/a.tar.gz') and derived['extract_to'] == str(Path(os.environ['TEMP']) / 've112b'), 'fresh corrected output coordinates changed')
        need(derived['receipts'] == derived['receipt_roots'] == [], 'unexpected separate receipts')
        operator_prefix = safe(collections[1]['archive_prefix']).as_posix() + '/'
        alias_note_raw = archive.read('corpus/' + operator_prefix + 'five-direct-note.json')
        git_note_raw = archive.read('corpus/' + operator_prefix + 'git-format-admission-note.json')
        need(sha(alias_note_raw) == 'de6376c6e4fba9e953f1915ef2ea162019fecf01b4f2c14bc3f8ae7a82df3cb2' and sha(git_note_raw) == '6ebdcab5a021637ab4b2029124d92994eed16d3ea076c7f68b26da5c3394ddea', 'actual reviewed explicit derivation notes changed')
        alias_note = parse(alias_note_raw)
        git_note = parse(git_note_raw)
        need(alias_note['schema'] == 'symbiote.v112-five-direct-derivation/1' and alias_note['status'] == 'DERIVED_CONFIG_ONLY_ALL_PAYLOADS_AND_LOGICAL_ROLES_PRESERVED' and alias_note['original_logical_executable_rows'] == original_v4['executables'] and alias_note['selected_direct_executable_rows'] == derived['executables'] and alias_note['all26logical_roles_retained_in_original_config_and_selection'] is True and alias_note['all_selected_payload_bytes_preserved'] is True and alias_note['physical_aliases'] == 4, 'archived alias note source bindings changed')
        need(git_note['schema'] == 'symbiote.v112-exact-git-format-admission/1' and git_note['status'] == 'DECLARED_EXACT_GIT_SUMMARY_DISPATCH_ONLY' and git_note['source_commit'] == SOURCE and git_note['base_format_classifications'] == 2 and git_note['base_format_rows'] == original_v4['format_classifications'], 'archived explicit Git note changed')
        extra = git_note['additional_exact_git_admission']
        need(extra['format'] == 'git-commit-summary/1' and extra['path'] == str(Path(derived['collections'][0]['path']) / 'p/02469/8.stdout') and extra['bytes'] == 177 and extra['sha256'] == '41bc1bb4e077def3cf33faaacc257bbe21bc433ffd0172d92b0cc0f0a062cfc0' and extra['source_commit'] == SOURCE and extra['selection_sha256'] == 'df529992e1b0e08619701c1514f01aee813ca42b64d79b01895807bf3708f261' and extra['copy_census_sha256'] == 'ad03f45cf2556e255dfe95222c78d2b670d4c08b37a333ad666530d1226c3def' and extra['original_origin'] == {'source': 'proofs', 'path': 'source-freeze/8.stdout'}, 'one exact Git admission source/origin changed')
        need(expected[prefix + 'p/02469/8.stdout'] == {'bytes': 177, 'sha256': extra['sha256']}, 'preserved original Git stdout changed')
        for key, pin in [('wrapper', '61c00fc358639cbf7e05dd63220ce8ace2b1cdb114938ce9c4ddfb5cb3756ec9'), ('tests', 'a60d8688f380e667f745ef3069fe08f21df561cb3fb6c1637228497f0c02b193'), ('independent_review', 'f6aab8a05eb33530fdac05617afdd88f3d112269087f32abb489c87745df96b4'), ('root_amendment', '5b03645073f0fe28ee81c9172b67c69915d659b7b96e02d5a2630c9563dcd721')]:
            coordinate = extra[key]
            rel = Path(coordinate['path']).relative_to(derived['collections'][1]['path']).as_posix()
            safe(rel)
            need(expected[operator_prefix + rel] == {'bytes': coordinate['bytes'], 'sha256': pin} and coordinate['sha256'] == pin, 'reviewed Git operator code/test/root/review missing')
        need(git_note['old_hold']['sha256'] == '90b201993e8bec2eea5a2aa101c31a5f7ddc0ce792dadf74685921fc5b72728f' and git_note['qualified_fingerprint_dispatch_has_one_addition'] is True and all(git_note[k] is True for k in ('qualified_adapter_source_unchanged', 'qualified_base_source_unchanged', 'raw_and_pem_primitives_unchanged', 'decoded_and_perline_scans_required', 'no_generic_json_or_text_bypass', 'no_input_rewrite')), 'Git disclosure/HOLD/scanner constraints changed')
        need(sha(archive.read('corpus/' + operator_prefix + 'prior-qualified-plan-HOLD.json')) == '90b201993e8bec2eea5a2aa101c31a5f7ddc0ce792dadf74685921fc5b72728f', 'prior actual packaging HOLD omitted')
        need(sha(archive.read('corpus/' + operator_prefix + 'parser-diagnostic.json')) == 'a548adb6ab3885c3b5cdc163b4d6617cc98dfc8edd6650b3a5f2ae693bd2622e', 'original parser diagnosis omitted')
        need(sha(archive.read('corpus/' + operator_prefix + 'package_v1_evidence_v4.py')) == '301bf6030271c38f43902631c35ac852c87455ab2f2bd3118a74c5b879a26ffc' and sha(archive.read('corpus/' + operator_prefix + 'package_stability_evidence_v4.py')) == BASE_SHA, 'original adapter/base source bytes changed')
        need(sha(archive.read('corpus/' + operator_prefix + 'selection-independent.json')) == 'e69ab73f3b99a0918ba81ed9c494411f7fcb15369658c5495be11b9f9a631551', 'original recursive container/alias/selection audit omitted')
        all_collections = {c['path']: c['archive_prefix'] + '/' for c in collections}
        for anchor in derived['anchors']:
            candidates = [(root, pre) for root, pre in all_collections.items() if Path(root) in Path(anchor['path']).parents]
            need(len(candidates) == 1, 'qualified anchor outside exact collection')
            root, pre = candidates[0]
            anchor_name = pre + Path(anchor['path']).relative_to(root).as_posix()
            anchor_raw = archive.read('corpus/' + anchor_name)
            need(sha(anchor_raw) == anchor['sha256'], 'qualified archived anchor bytes changed')
            document = parse(anchor_raw)
            for assertion in anchor['expect']:
                need(pointer(document, assertion['pointer']) == assertion['value'], 'qualified anchor assertion changed')
            if anchor['source_commit_pointer'] is not None:
                need(pointer(document, anchor['source_commit_pointer']) == anchor['source_commit'], 'qualified anchor source changed')
        need(len(manifest['registered_executables']) == 5 and {r['role'] for r in manifest['registered_executables']} == REQUIRED, 'qualified direct-role subset mismatch')
        direct_paths = set()
        for role in manifest['registered_executables']:
            need({k: v for k, v in role.items() if k != 'archive_path'} in subset, 'qualified role metadata changed')
            need(expected[role['archive_path']]['sha256'] == role['sha256'], 'direct alias actual bytes mismatch')
            direct_paths.add(role['archive_path'])
        need(len(direct_paths) == 4, 'qualified direct aliases not exact four unique')

    actual_tar = {}
    with tarfile.open(args.tar, 'r:gz') as archive:
        for item in archive:
            name = safe(item.name).as_posix()
            need(item.isfile() and name not in actual_tar and name in expected and item.size == expected[name]['bytes'], 'unexpected tar member')
            with archive.extractfile(item) as stream:
                actual_tar[name] = stream_hash(stream, item.size)
    need(actual_tar == expected, 'tar differs from ZIP/manifest')
    for extracted_root in (args.extracted, args.tar_extracted):
        extracted = {}
        for current, directories, files in os.walk(extracted_root, followlinks=False):
            for name in directories:
                p = Path(current) / name
                need(not p.is_symlink() and not p.is_junction(), 'extracted reparse directory')
            for name in files:
                p = Path(current) / name
                rel = p.relative_to(extracted_root).as_posix()
                safe(rel)
                need(rel in expected, 'extra extracted member')
                extracted[rel] = physical(p, MAX_MEMBER)
        need(extracted == expected, 'both ZIP and qualified tar extracted byte censuses must match')
    checksum = args.checksum.read_bytes()
    need(checksum == (zipped['sha256'] + '  EVIDENCE.zip\n').encode('ascii'), 'checksum must bind only actual EVIDENCE.zip')
    need(physical(args.zip, MAX_ZIP) == zipped and physical(args.tar) == tar_row, 'archive changed during independent read')
    need(physical(args.packaging)['sha256'] == args.packaging_sha256 and physical(args.zip_receipt)['sha256'] == args.zip_receipt_sha256, 'receipts changed during read')
    result = {
        'schema': 'symbiote.independent-v11-final-archive-audit/1',
        'status': 'PASS_DATA_ONLY_FINAL_ARCHIVE_BYTES',
        'source_commit': SOURCE, 'audit_script_sha256': physical(Path(__file__))['sha256'],
        'archive': zipped, 'tar': tar_row, 'manifest_sha256': args.manifest_sha256,
        'packaging_receipt_sha256': args.packaging_sha256, 'zip_receipt_sha256': args.zip_receipt_sha256,
        'derived_config_sha256': args.derived_config_sha256, 'selection_plan_sha256': PLAN_SHA,
        'zip_members': len(actual_zip), 'inner_members': len(expected),
        'actual_zip_equals_tar_equals_manifest_equals_extracted': True,
        'both_tar_and_zip_extracted_trees_checked': True,
        'additional_exact_git_format_wrapper_sha256': '61c00fc358639cbf7e05dd63220ce8ace2b1cdb114938ce9c4ddfb5cb3756ec9',
        'all_2526_selected_payloads_retained': True, 'all_26_role_image_bindings': role_checks,
        'five_direct_roles_four_unique_redundant_aliases': True,
        'immutable_original_26_role_controls_retained': True,
        'base_two_cargo_formats_and_additional_exact_git_note_retained': True,
        'physical_zip_within_128_mib': True, 'checksum_only_evidence_zip': True,
        'selection_independent_audit_sha256': 'e69ab73f3b99a0918ba81ed9c494411f7fcb15369658c5495be11b9f9a631551',
        'qualified_plan_delta_audit_sha256': 'd15369a767f047769d2bf909d499fdc2db3bd161102d956a608997ee4bf6c8b9',
        'native_executions': 0, 'independent_scientific_samples': 0,
        'limits': ['Data-only byte/semantic binding replay is not a fresh native, OS-fault, publication, cross-host or scientific experiment.', 'Historical source commits and HOLDs remain raw records; archive-top source never relabels original studies.'],
    }
    args.output.write_bytes((json.dumps(result, sort_keys=True, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({'path': str(args.output), 'sha256': physical(args.output)['sha256'], 'status': result['status'], 'bytes': zipped['bytes'], 'members': len(actual_zip)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('zip', 'tar', 'packaging', 'zip-receipt', 'extracted', 'tar-extracted', 'derived-config', 'checksum', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    for key in ('zip-sha256', 'tar-sha256', 'packaging-sha256', 'zip-receipt-sha256', 'manifest-sha256', 'derived-config-sha256'):
        parser.add_argument('--' + key, required=True)
    run(parser.parse_args())
