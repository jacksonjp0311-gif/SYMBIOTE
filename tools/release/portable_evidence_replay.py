"""Read-only replay of unchanged evidence through an externally pinned archive map.

Original absolute paths remain provenance strings. They are never opened or used
as fallback paths. Qualified consumer code and data bytes are not rewritten.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import ntpath
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import runpy
import sys


def need(value,message):
    if not value:raise RuntimeError(message)

def sha(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):result.update(block)
    return result.hexdigest()

def pairs(items):
    result={}
    for key,value in items:
        need(key not in result,'duplicate JSON key');result[key]=value
    return result

def load(path):
    need(Path(path).stat().st_size<=32*1024*1024,'bounded JSON required')
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,
                      parse_constant=lambda value:(_ for _ in ()).throw(RuntimeError('nonfinite JSON')))

def relative(value):
    need(isinstance(value,str) and '\\' not in value and ':' not in value,'canonical archive member required')
    path=PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix()==value and path.parts
         and all(part not in ('','.','..') for part in value.split('/')),'unsafe archive member')
    return path

def original_key(value):
    """Lexical cross-platform identity only; no original-host filesystem lookup."""
    need(isinstance(value,str) and value,'original provenance path required')
    if value.startswith('\\\\?\\UNC\\'):value='\\\\'+value[8:]
    elif value.startswith('\\\\?\\'):value=value[4:]
    need(not any(part in ('.','..') for part in re.split(r'[\\/]',value)),'escaped original provenance path')
    windows=PureWindowsPath(value)
    if windows.drive:
        need(windows.is_absolute(),'absolute original Windows path required')
        return 'windows:'+ntpath.normcase(ntpath.normpath(value)).replace('\\','/')
    posix=PurePosixPath(value)
    need(posix.is_absolute(),'absolute original path required')
    return 'posix:'+posix.as_posix()

def pointer(value,path):
    if path=='':return value
    need(isinstance(path,str) and path.startswith('/'),'JSON pointer required')
    for part in path[1:].split('/'):
        part=part.replace('~1','/').replace('~0','~')
        value=value[int(part)] if isinstance(value,list) else value[part]
    return value


class Archive:
    def __init__(self,root,manifest_sha256):
        self.root=Path(root).resolve(strict=True)
        need(re.fullmatch(r'[0-9a-f]{64}',manifest_sha256),'external MANIFEST SHA required')
        manifest=self.member('MANIFEST.json')
        need(sha(manifest)==manifest_sha256,'archive MANIFEST differs from external pin')
        self.manifest_sha256=manifest_sha256;self.document=load(manifest)
        need(self.document['schema']=='symbiote.v1-evidence-manifest/2','unsupported archive manifest')
        self.entries={};self.origins={};total=0
        for row in self.document['entries']:
            name=row['path'];relative(name);need(name not in self.entries,'duplicate archive member')
            path=self.member(name);size=path.stat().st_size
            need(type(row['bytes']) is int and size==row['bytes'] and size<=256*1024*1024,'archive member size differs')
            total+=size;need(len(self.entries)<20000 and total<=1024*1024*1024,'archive census budget exceeded')
            before=path.stat();need(sha(path)==row['sha256'],'archive member SHA differs');after=path.stat()
            need((before.st_size,before.st_mtime_ns,before.st_ino)==(after.st_size,after.st_mtime_ns,after.st_ino),'archive member changed while read')
            self.entries[name]=row
            for origin in row['sources']:self.origins.setdefault(original_key(origin),[]).append(name)
        actual=set()
        for directory,dirs,files in os.walk(self.root,followlinks=False):
            for name in dirs:self.member((Path(directory)/name).relative_to(self.root).as_posix(),directory=True)
            for name in files:actual.add((Path(directory)/name).relative_to(self.root).as_posix())
        need(actual==set(self.entries)|{'MANIFEST.json'},'complete extracted archive census differs')
        self.collections={}
        for row in self.document['collections']:
            need(row['name'] not in self.collections,'duplicate collection')
            self.member(row['archive_prefix'],directory=True);original_key(row['path']);self.collections[row['name']]=row

    def member(self,name,directory=False):
        cursor=self.root
        for part in relative(name).parts:
            cursor=cursor/part;info=cursor.lstat()
            need(not cursor.is_symlink() and not getattr(info,'st_file_attributes',0)&0x400,'linked archive member refused')
        need(cursor.is_dir() if directory else cursor.is_file(),'archive member type differs')
        return cursor

    def map_original(self,value):
        key=original_key(value);names=self.origins.get(key,[])
        need(names,'original provenance path is not selected in the pinned archive')
        # Prefer the declared collection view. Equal-byte aliases are permissible;
        # an ambiguous origin with different bytes is never resolved silently.
        need(len({self.entries[name]['sha256'] for name in names})==1,'ambiguous original path has conflicting bytes')
        matches=[]
        for row in self.collections.values():
            prefix=original_key(row['path'])+'/'
            if key.startswith(prefix):
                suffix=key[len(prefix):]
                for name in names:
                    if name.casefold()==(row['archive_prefix']+'/'+suffix).casefold():matches.append(name)
        name=sorted(matches or names)[0]
        return self.member(name)

    def anchor(self,identity):
        rows=[row for row in self.document['anchors'] if row['id']==identity]
        need(len(rows)==1,'one pinned provenance anchor required');row=rows[0]
        path=self.map_original(row['path']);need(sha(path)==row['sha256'],'anchor SHA differs')
        document=load(path)
        for assertion in row['expect']:need(pointer(document,assertion['pointer'])==assertion['value'],'anchor field assertion differs')
        if row['source_commit_pointer'] is not None:need(pointer(document,row['source_commit_pointer'])==row['source_commit'],'anchor source differs')
        return row,document

    def binding(self,role):
        rows=[row for row in self.document['registered_executables'] if row['role']==role]
        need(len(rows)==1,'one external executable role binding required');row=rows[0]
        anchor,document=self.anchor(row['anchor'])
        need(anchor['source_commit_pointer'] is not None,'executable has no source-bound anchor')
        need(pointer(document,row['digest_pointer'])==row['sha256'],'executable digest pointer differs')
        path=self.member(row['archive_path']);need(row['archive_path'] in self.entries and sha(path)==row['sha256'],'external executable bytes differ')
        return dict(path=str(path),sha256=row['sha256'],source_commit=anchor['source_commit'])

    def collection(self,name,subdir=''):
        row=self.collections[name];member=row['archive_prefix']
        if subdir:member+='/'+relative(subdir).as_posix()
        return self.member(member,directory=True)


MODULES=('source_fingerprint','stability_campaign','qualification_awake','transfer_campaign','reciprocal_engineering','soak_campaign')

@contextlib.contextmanager
def consumers(archive,tools_member,consumer_sha256,native,tests):
    directory=archive.member(tools_member,directory=True)
    need(sha(directory/'reciprocal_engineering.py')==consumer_sha256,'qualified consumer source pin differs')
    old={name:sys.modules.get(name) for name in MODULES};old_path=sys.path[:];old_bytecode=sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode=True
        sys.path.insert(0,str(directory))
        for name in MODULES:
            member=relative(tools_member+'/'+name+'.py').as_posix();need(member in archive.entries,'consumer dependency not in pinned census')
            path=archive.member(member)
            # Execute exactly the selected source bytes. SourceFileLoader may read
            # a timestamp-valid .pyc even when dont_write_bytecode is true.
            raw=path.read_bytes();need(len(raw)==archive.entries[member]['bytes'] and hashlib.sha256(raw).hexdigest()==archive.entries[member]['sha256'],'consumer dependency changed before execution')
            if name=='reciprocal_engineering':need(hashlib.sha256(raw).hexdigest()==consumer_sha256,'qualified consumer source pin differs')
            spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
            sys.modules[name]=module;exec(compile(raw,str(path),'exec'),module.__dict__)
        r=sys.modules['reciprocal_engineering'];original_manifest=r.verify_manifest
        expected={'native_binary':native['sha256'],'service_tests':tests['sha256']}
        def executable(root,manifest,selected,role,unused_original,expected_sha):
            need(expected_sha==expected[role] and manifest[role+'_sha256']==expected_sha,'role SHA is not independently source-bound')
            mapped=archive.map_original(manifest[role]);rel=mapped.relative_to(Path(root)).as_posix()
            names=('symbiote','symbiote.exe') if role=='native_binary' else ('service-tests','service-tests.exe')
            need(rel in selected and rel.split('/')[0]=='executables' and len(rel.split('/'))==2 and mapped.name in names,'strict snapshot role/member census differs')
            need(sha(mapped)==expected_sha,'snapshot differs from external executable SHA')
            return rel
        def manifest(root,unused_native,native_sha,service_tests=None):
            raw=load(archive.member(Path(root).relative_to(archive.root).as_posix()+'/artifact-manifest.json'))
            n=archive.map_original(raw['native_binary']);t=archive.map_original(raw['service_tests']) if service_tests is not None else None
            return original_manifest(root,n,native_sha,dict(path=str(t),sha256=service_tests['sha256']) if t is not None else None)
        r.verify_executable=executable;r.verify_manifest=manifest
        yield r,sys.modules['soak_campaign']
    finally:
        sys.dont_write_bytecode=old_bytecode
        sys.path[:]=old_path
        for name,value in old.items():
            if value is None:sys.modules.pop(name,None)
            else:sys.modules[name]=value


def replay(archive,kind,collection,tools_member,consumer_sha256,native_role='final-build-native',test_role='final-build-service-tests',
           registration_anchor=None,subdir=None,observation_helper=None,observation_helper_sha256=None,output=None):
    native=archive.binding(native_role);tests=archive.binding(test_role)
    root=archive.collection(collection,subdir if subdir is not None else ('native' if kind in ('cohort','hour') else ''))
    with consumers(archive,tools_member,consumer_sha256,native,tests) as (r,soak):
        if kind in ('cohort','hour'):
            _,registration=archive.anchor(registration_anchor)
            need(registration['source_commit']==native['source_commit']==tests['source_commit'],'registered source/executable role mismatch')
            for role,value in (('native',native),('service_tests',tests)):need(registration['binaries'][role]['sha256']==value['sha256'],'registration executable SHA differs')
            if kind=='cohort':
                need(registration['protocol_sha256']==r.PROTOCOL_SHA256 and registration['cohort']==r.COHORT and registration['bounds']==r.BOUNDS,'registered cohort/protocol changed')
                result=r.verify_cohort(root,registration)
            else:result=soak.verify_soak(root,registration['binaries'],registration['mode'])
        elif kind=='normal':result=r.verify_normal(root,native['path'],native['sha256'],tests)
        elif kind=='observation':
            need(observation_helper and observation_helper_sha256,'explicit trusted observation helper and SHA required')
            helper=archive.member(observation_helper);need(observation_helper in archive.entries and sha(helper)==observation_helper_sha256,'observation helper source pin differs')
            need(output is not None,'outside-corpus observation output required');target=Path(output).resolve()
            need(target!=archive.root and archive.root not in target.parents and not target.exists(),'fresh outside-corpus replay output required')
            old_argv=sys.argv[:]
            try:
                sys.argv=[str(helper),str(archive.member(tools_member,directory=True)),str(root),str(target)]
                runpy.run_path(str(helper),run_name='__main__')
            finally:sys.argv=old_argv
            result=load(target)
        else:raise RuntimeError('unsupported replay kind')
    return dict(schema='symbiote.portable-evidence-replay/1',status='PASS_DATA_REPLAY_ONLY',kind=kind,
                archive_manifest_sha256=archive.manifest_sha256,archive_source_commit=archive.document['source_commit'],
                source_bindings=dict(native=native,service_tests=tests),qualified_consumer_sha256=consumer_sha256,
                original_records_modified=False,original_host_path_fallback=False,native_or_registered_campaign_executed=False,
                original_absolute_paths='retained unchanged as provenance; mapped only through pinned MANIFEST entries/collections',result=result)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('kind',choices=('cohort','normal','observation','hour'))
    for key in ('archive-root','manifest-sha256','collection','tools-member','consumer-sha256','output'):p.add_argument('--'+key,required=True)
    p.add_argument('--native-role',default='final-build-native');p.add_argument('--test-role',default='final-build-service-tests')
    p.add_argument('--registration-anchor');p.add_argument('--artifact-subdir');p.add_argument('--observation-helper');p.add_argument('--observation-helper-sha256')
    args=p.parse_args();archive=Archive(args.archive_root,args.manifest_sha256)
    output=Path(args.output).resolve();need(archive.root not in output.parents and not output.exists(),'fresh outside-corpus output required')
    observation_output=output.with_name(output.stem+'.observation.json') if args.kind=='observation' else None
    result=replay(archive,args.kind,args.collection,args.tools_member,args.consumer_sha256,args.native_role,args.test_role,args.registration_anchor,
                  args.artifact_subdir,args.observation_helper,args.observation_helper_sha256,observation_output)
    with output.open('x',encoding='utf-8',newline='\n')as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(status=result['status'],kind=args.kind,output=str(output),sha256=sha(output))))

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,RuntimeError) as error:
        print(json.dumps(dict(status='HOLD',reason=str(error))),file=sys.stderr);raise SystemExit(1)
