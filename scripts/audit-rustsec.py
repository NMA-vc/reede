#!/usr/bin/env python3
"""Pinned RustSec package-version evidence, deliberately narrower than cargo-audit."""
from __future__ import annotations
import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import tomllib

CRATES_IO = 'registry+https://github.com/rust-lang/crates.io-index'
SEMVER_TOOL = 'reede-cargo-semver-query-v1 semver=1.0.28'


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()


def inventory(metadata: dict, lock: dict) -> list[dict]:
    packages = metadata.get('packages', [])
    locals_ = [p for p in packages if p.get('source') is None]
    if len(locals_) != 1 or locals_[0].get('name') != 'reede':
        raise ValueError('requires standalone Reede metadata, not the commercial workspace')
    identities = lambda ps: [(p['name'], p['version'], p.get('source')) for p in ps]
    actual, locked = identities(packages), identities(lock.get('package', []))
    if len(actual) != len(set(actual)) or len(locked) != len(set(locked)) or set(actual) != set(locked):
        raise ValueError('metadata and lockfile package identities/versions/sources differ')
    if len({p['id'] for p in packages}) != len(packages):
        raise ValueError('duplicate metadata package IDs')
    return sorted(packages, key=lambda p:(p['name'],p['version'],p.get('source') or ''))


def load_snapshot(directory: Path, names: set[str]) -> tuple[dict,list[dict]]:
    descriptor = json.loads((directory/'snapshot.json').read_text())
    if descriptor.get('schema') != 'reede-rustsec-snapshot-v1' or descriptor.get('repository') != 'https://github.com/RustSec/advisory-db':
        raise ValueError('unsupported snapshot origin/schema')
    if descriptor.get('tree_truncated') is not False:
        raise ValueError('truncated advisory index')
    if not names.issubset(set(descriptor['inventory_package_names'])):
        raise ValueError('snapshot inventory scope does not cover these package names')
    index = {entry['path']:entry for entry in descriptor['advisory_index']}
    if len(index) != len(descriptor['advisory_index']):
        raise ValueError('duplicate advisory index paths')
    required = {path:entry for path,entry in index.items() if path.split('/')[1] in names}
    supplied = {entry['path']:entry for entry in descriptor['included_files']}
    if not set(required).issubset(supplied):
        raise ValueError('snapshot omits matching advisory files')
    advisories = []
    for path, entry in sorted(required.items()):
        if not re.fullmatch(r'crates/[A-Za-z0-9_-]+/RUSTSEC-[0-9]{4}-[0-9]{4}\.md',path):
            raise ValueError('unsafe advisory path')
        file = directory/path
        if file.is_symlink() or not file.resolve().is_relative_to(directory.resolve()):
            raise ValueError('advisory path escapes snapshot')
        data = file.read_bytes()
        if len(data) != entry['size'] or blob_sha(data) != entry['sha'] or supplied[path]['sha'] != entry['sha']:
            raise ValueError(f'advisory blob integrity mismatch: {path}')
        text = data.decode('utf-8')
        match = re.match(r'\A```toml\n(.*?)\n```(?:\n|$)',text,re.S)
        if not match:
            raise ValueError(f'unsupported advisory encoding: {path}')
        parsed = tomllib.loads(match.group(1))
        if set(parsed)-{'advisory','versions','affected'}:
            raise ValueError(f'unsupported advisory tables: {path}')
        advisory, versions = parsed['advisory'], parsed['versions']
        if advisory['package'] != path.split('/')[1] or advisory['id']+'.md' != path.split('/')[-1]:
            raise ValueError('advisory identity/folder mismatch; aliases are not guessed')
        if set(versions)-{'patched','unaffected'} or 'patched' not in versions:
            raise ValueError('unsupported version metadata')
        for key in ['patched','unaffected']:
            requirements = versions.get(key,[])
            if not isinstance(requirements,list) or any(not isinstance(x,str) or '\n' in x or '\t' in x for x in requirements):
                raise ValueError('unsupported version requirement encoding')
        title = next((line[2:] for line in text.splitlines() if line.startswith('# ')), '')
        advisories.append({'path':path,'blob_sha':entry['sha'],'title':title,**parsed})
    return descriptor,advisories


def evaluate_queries(binary: Path, queries: set[tuple[str,str]]) -> tuple[dict,dict]:
    version = subprocess.run([str(binary),'--version'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    if version != SEMVER_TOOL:
        raise ValueError('unexpected semver evaluator provenance')
    queries = sorted(queries)
    if any('\n' in v or '\t' in v for query in queries for v in query):
        raise ValueError('unsupported query encoding')
    output = subprocess.run([str(binary)],input=''.join(v+'\t'+r+'\n' for v,r in queries),capture_output=True,text=True,check=True,timeout=30).stdout.splitlines()
    if len(output) != len(queries):
        raise ValueError('wrong number of semver answers')
    answers = {}
    for query,line in zip(queries,output):
        kind,_,value=line.partition('\t')
        if kind=='ok' and value in ('true','false'):
            answers[query]={'matches':value=='true'}
        elif kind=='error' and value in ('invalid_version','unsupported_requirement','unsupported_prerelease'):
            answers[query]={'not_evaluated':value}
        else:
            raise ValueError('malformed semver answer')
    return answers,{'implementation':version,'binary_sha256':digest(binary),'query_count':len(queries)}


def dependency_paths(metadata: dict) -> tuple[dict,dict]:
    packages={p['id']:p for p in metadata['packages']}
    nodes={p['id']:p for p in metadata.get('resolve',{}).get('nodes',[])}
    root=metadata.get('resolve',{}).get('root')
    paths={root:[]};queue=deque([root])
    while queue:
        current=queue.popleft()
        for dep in nodes.get(current,{}).get('deps',[]):
            target=dep['pkg']
            if target not in paths:
                paths[target]=paths[current]+[{'from':packages[current]['name']+'@'+packages[current]['version'],
                    'to':packages[target]['name']+'@'+packages[target]['version'],'dependency_name':dep['name'],
                    'kinds_and_targets':dep['dep_kinds']}]
                queue.append(target)
    return paths,nodes


def audit(metadata_path: Path, lock_path: Path, snapshot: Path, binary: Path) -> dict:
    metadata_bytes,lock_bytes=metadata_path.read_bytes(),lock_path.read_bytes()
    metadata=json.loads(metadata_bytes); lock=tomllib.loads(lock_bytes.decode('utf-8'))
    packages=inventory(metadata,lock)
    descriptor,advisories=load_snapshot(snapshot,{p['name'] for p in packages})
    queries={(p['version'],'*') for p in packages}
    for advisory in advisories:
        requirements=advisory['versions'].get('patched',[])+advisory['versions'].get('unaffected',[])
        for package in packages:
            if package['name']==advisory['advisory']['package'] and package.get('source')==CRATES_IO:
                queries.update((package['version'],r) for r in requirements)
    answers,matcher=evaluate_queries(binary,queries)
    paths,nodes=dependency_paths(metadata)
    root_id=metadata.get('resolve',{}).get('root')
    root_package=next(p for p in packages if p['id']==root_id)
    root_features=nodes.get(root_id,{}).get('features',[])
    evaluations=[]
    for advisory in advisories:
        entry=advisory['advisory']; versions=advisory['versions']
        for package in packages:
            if package['name']!=entry['package']:
                continue
            evidence={key:[] for key in ['patched','unaffected']}
            unsupported=[]
            if 'not_evaluated' in answers[package['version'],'*']:
                unsupported.append(answers[package['version'],'*']['not_evaluated'])
            for key in ['patched','unaffected']:
                for req in versions.get(key,[]):
                    answer=answers.get((package['version'],req),{'not_evaluated':'non_crates_io_source'})
                    evidence[key].append({'requirement':req,**answer})
                    if 'not_evaluated' in answer:
                        unsupported.append(answer['not_evaluated'])
            if entry.get('withdrawn'):
                status='withdrawn'
            elif package.get('source')!=CRATES_IO:
                status='not_evaluated_non_crates_io_source'
            elif unsupported:
                status='not_evaluated_unsupported_semver'
            elif any(x.get('matches') for x in evidence['patched']):
                status='patched_range_match'
            elif any(x.get('matches') for x in evidence['unaffected']):
                status='unaffected_range_match'
            else:
                status='informational_range_match' if entry.get('informational') else 'affected_version_range_match'
            evaluations.append({'advisory_id':entry['id'],'package':package['name'],'version':package['version'],
                'source':package.get('source'),'classification':status,'title':advisory['title'],
                'informational':entry.get('informational'),'withdrawn':entry.get('withdrawn'),
                'advisory_metadata':entry,'version_requirements':versions,'range_evidence':evidence,
                'affected_qualifiers':advisory.get('affected',{}),'platform_function_reachability':'not_evaluated',
                'enabled_metadata_features':nodes.get(package['id'],{}).get('features',[]),
                'one_resolved_dependency_path':paths.get(package['id']),
                'snapshot_path':advisory['path'],'blob_sha':advisory['blob_sha'],'unsupported':sorted(set(unsupported))})
    return {'schema':'reede-rustsec-evidence-v2','recorded_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        'metadata_sha256':hashlib.sha256(metadata_bytes).hexdigest(),'lockfile_sha256':hashlib.sha256(lock_bytes).hexdigest(),
        'inventory_packages':len(packages),'inventory_identity_match':True,
        'root_enabled_features':root_features,
        'all_declared_root_features_enabled':set(root_package.get('features',{})).issubset(root_features),
        'components':[{'name':p['name'],'version':p['version'],'source':p.get('source'),
            'advisory_files_at_snapshot':sum(a['advisory']['package']==p['name'] for a in advisories)} for p in packages],
        'scanner_source_sha256':digest(Path(__file__)),
        'rustsec_database':{key:descriptor[key] for key in ['repository','commit','commit_date','tree_sha','tree_truncated','commit_signature_verification']},
        'snapshot_descriptor_sha256':digest(snapshot/'snapshot.json'),'snapshot_advisories':len(advisories),
        'matcher':matcher,'summary':dict(sorted(Counter(x['classification'] for x in evaluations).items())),
        'evaluations':evaluations,'publication_ready':False,'cargo_audit':'not_run',
        'yanked_registry_status':'not_run','package_content_or_build_script_audit':'not_run',
        'limitations':['Filtered package-name snapshot of official advisory database; not cargo-audit or a general scanner.',
            'All-feature standalone metadata includes development and target-specific packages; range matches do not establish exploitability.',
            'Prerelease inventory versions are refused, not approximated. Stable versions and Cargo-compatible requirements (including prerelease bounds) use semver1.0.28 directly.',
            'Renamed dependency aliases resolve through canonical metadata package IDs; other registries/forks are not guessed.',
            'Platform/function/feature applicability is retained for manual review, not automatically dismissed.',
            'No registry yanked status, malicious crate detection, full license approval, independent security review or clean-release certification.',
            'scanner_source_sha256 identifies this Python scanner only; matcher.binary_sha256 and matcher.implementation identify the external semver evaluator, with no source-to-binary linkage asserted.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata',type=Path,required=True);parser.add_argument('--lockfile',type=Path,required=True)
    parser.add_argument('--snapshot',type=Path,default=Path(__file__).with_name('rustsec-snapshot'))
    parser.add_argument('--semver-bin',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('output exists; select a new evidence file')
    report=audit(args.metadata,args.lockfile,args.snapshot,args.semver_bin)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,default=str)+'\n')
    print(json.dumps({'summary':report['summary'],'publication_ready':False}))
    return int(any(x['classification'] in ('affected_version_range_match','informational_range_match') or x['classification'].startswith('not_evaluated') for x in report['evaluations']))


if __name__=='__main__':
    raise SystemExit(main())
