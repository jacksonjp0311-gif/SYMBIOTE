"""Version 2 source manifests: UTF-8 path order, exact bytes, explicit framing.

Old software-verification/1 receipts retain native Path ordering and their
declared LF normalization. This new format never silently reinterprets them.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat

ALGORITHM = 'symbiote.source-manifest/2'
MAX_FILES = 4096
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('utf-8')


def source_names(root):
    root = Path(root)
    selected = set(root.glob('crates/**/*.rs')) | set(root.glob('crates/**/Cargo.toml'))
    for pattern in ['tools/*.py', 'tools/*.ps1', 'tools/*.sh', '.github/workflows/*.yml']:
        selected.update(root.glob(pattern))
    selected.update({root/'Cargo.toml', root/'Cargo.lock', root/'SYMBIOTE-All-One.ps1'})
    if (root/'.gitattributes').exists():
        selected.add(root/'.gitattributes')
    return [path.relative_to(root).as_posix() for path in selected]


def manifest(root, names=None):
    root = Path(root).resolve(strict=True)
    selection = 'native-source-tree' if names is None else 'explicit-files'
    names = list(source_names(root) if names is None else names)
    if not names or len(names) > MAX_FILES or len(set(names)) != len(names):
        raise ValueError('Source manifest needs a bounded unique nonempty path set')
    rows = []
    total = 0
    portable_names = set()
    for name in sorted(names, key=lambda item: item.encode('utf-8')):
        path = PurePosixPath(name)
        if (path.is_absolute() or path.as_posix() != name or not path.parts
                or any(part in {'.','..'} or ':' in part or '\\' in part for part in path.parts)
                or len(name.encode('utf-8')) > 4096):
            raise ValueError('Unsafe or noncanonical relative source path')
        # A checkout with case aliases cannot be represented faithfully on Windows.
        if name.casefold() in portable_names:
            raise ValueError('Case-alias source paths are not portable')
        portable_names.add(name.casefold())
        current = root
        for part in path.parts:
            current = current/part
            details = current.lstat()
            if current.is_symlink() or getattr(details,'st_file_attributes',0) & getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0):
                raise ValueError('Linked or reparse source paths are forbidden')
        if not current.is_file() or current.stat().st_size > MAX_FILE_BYTES:
            raise ValueError('Missing, special or oversized source file')
        data = current.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            raise ValueError('Source changed beyond its size budget')
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('Source manifest aggregate byte budget exceeded')
        rows.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    body = {'schema':ALGORITHM,'selection':selection,'path_order':'relative POSIX path UTF-8 bytes',
            'content_policy':'exact bytes; no newline normalization',
            'files':rows,'total_bytes':total}
    return {**body,'sha256':hashlib.sha256(canonical(body)).hexdigest()}


def verify(root, expected):
    if expected.get('schema') != ALGORITHM:
        raise ValueError('Unsupported source manifest algorithm; old receipts remain separate')
    names = [row['path'] for row in expected.get('files',[])]
    if expected.get('selection') not in {'native-source-tree','explicit-files'}:
        raise ValueError('Unsupported source selection scope')
    observed = manifest(root,None if expected['selection']=='native-source-tree' else names)
    if observed != expected:
        raise ValueError('Source manifest bytes, path set, framing or digest changed')
    return observed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    report = manifest(args.root)
    with args.out.open('x',encoding='utf-8',newline='\n') as output:
        json.dump(report,output,indent=2,ensure_ascii=False)
        output.write('\n')
    print(json.dumps({'schema':ALGORITHM,'files':len(report['files']),'sha256':report['sha256']}))


if __name__ == '__main__':
    main()
