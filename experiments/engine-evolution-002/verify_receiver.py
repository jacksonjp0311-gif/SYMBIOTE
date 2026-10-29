# Data-only independent receiver audit. Never executes the producer or imports its code.
from pathlib import Path,PureWindowsPath,PurePosixPath
import json,hashlib,re,traceback,argparse,os,stat
# Set only by explicit CLI; absolute paths recorded inside evidence remain inert.
ROOT=DATA=REPO=OUT=None
LOCAL_BINDINGS=False
EXCLUDED_RECEIVER_EXECUTABLES={'symbiote-native.exe':'native','service-tests.exe':'service_test'}
ORIGINAL_ARTIFACT_ROOT=PureWindowsPath(r'C:\Users\jacks\AppData\Local\Temp\evo2-run-bb1b88e')
SOURCE='bb1b88eaa771be5e201ccfcfe93840c6750eb9d7'
PINS={'registration.json':'89241bf8b120508053a91966e57c02f70343a1f8a3e8aafe3d8a59ec1b385409','evolution-report.json':'a0dcb9752c578041e745489b80198f42011fd788e377eed674e84b7d45f1cf68','receiver-outcomes/outcome-artifacts.json':'a4c6bb7a804f1de3b42845e9347d409ec15d78ba2c8198e2f6c5700a909364fe'}
def need(ok,why):
 if not ok:raise ValueError(why)
def rawsha(b):return hashlib.sha256(b).hexdigest()
def sha(p):return rawsha(p.read_bytes())
def enc(v,sort=False):return json.dumps(v,ensure_ascii=False,separators=(',',':'),sort_keys=sort).encode('utf-8')
def dig(v):return rawsha(enc(v,True))
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def typed(v,fields):
 need(set(v)==set(fields),'typed fields '+str(fields))
 return {f:v[f] for f in fields}
def anchor(v):return typed(v,['identity','records','head_sha256'])
def record(v):
 o=typed(v,['id','revision','source','scope','schema_fingerprint','payload','provenance']);o['payload']=json.loads(enc(o['payload'],True));return o
def request(v):
 o=typed(v,['schema','scope','request_id','body']);b=typed(o['body'],['operation','offer']);off=typed(b['offer'],['record','training_inputs']);off['record']=record(off['record']);b['offer']=off;o['body']=b;return o
def baseline(v):return typed(v,['kind','reason'])
def costs(v):return typed(v,['unit_model','acquisition','validation','adoption','prediction','wire','replay'])
def feedback(decision):
 d=decision['details'];need(d['schema']=='symbiote.learning-feedback/1','feedback schema')
 f=d['event'];phase=f['phase'];fields={'decision':['phase','binding','before','baseline'],'promoted':['phase','exchange_id','record_sha256','before','after','evidence_sha256','promotion_sha256','costs','baseline'],'store_use':['phase','exchange_id','record_sha256','knowledge_at','input','output','model_work','sequence','basis'],'outcome':['phase','exchange_id','knowledge_at','outcome']}[phase]
 f=typed(f,fields)
 for key in ['before','after','knowledge_at']:
  if key in f:f[key]=anchor(f[key])
 if 'baseline'in f:f['baseline']=baseline(f['baseline'])
 if 'binding'in f:f['binding']=typed(f['binding'],['origin','exchange_id','decision_id','sender_id','receiver_id','scope','schema_fingerprint','request_sha256','candidate_id','offered_record_sha256','policy_sha256','fixture_sha256'])
 if 'costs'in f:f['costs']=costs(f['costs'])
 if 'basis'in f:f['basis']=typed(f['basis'],['kind','evidence_sha256'])
 if 'outcome'in f:
  o=typed(f['outcome'],['quality','baseline','candidate_cost','measured_net','verified_benefit','uses','unit_model']);o['baseline']=baseline(o['baseline']);f['outcome']=o
 e={'schema':d['schema'],'scope':d['scope'],'event':f}
 need(set(d)==set(e)and decision['context']==d['scope']and decision['decision_id']=='feedback-'+rawsha(enc(e)),'native typed feedback carrier hash')
 return f
def chain(text,identity,kind):
 need(text.endswith('\n'),'truncated ledger')
 rows=[json.loads(s)for s in text.splitlines()];previous='0'*64
 for i,row in enumerate(rows):
  need(set(row)=={'sequence','previous','payload','sha256'}and row['sequence']==i and row['previous']==previous,'ledger linkage')
  need(row['sha256']==rawsha(enc([i,previous,row['payload']])),'native receipt SHA')
  previous=row['sha256']
 g=rows[0]['payload'];need(g['event']=='genesis'and g.get('identity',g.get('owner_identity'))==identity,'ledger owner')
 if kind=='operations':need(g['service_id']=='configured-service/v1','native service lineage')
 return rows
def here_anchor(rows,identity,n=None):
 n=len(rows)if n is None else n
 return {'identity':identity,'records':n,'head_sha256':rows[n-1]['sha256']}
def rows(path):return[json.loads(s)for s in path.read_text(encoding='utf-8').splitlines()]
def channel(e):
 d=e.get('decision',{}).get('details',{})
 return d.get('event')if d.get('schema')=='symbiote.contribution-channel/1'else None

def mapped_artifact(original):
 """Map only the exact registered Windows artifact subtree; never try that host."""
 p=PureWindowsPath(original)
 need(p.is_absolute()and not any(x in['.','..']for x in p.parts),'absolute artifact provenance required')
 base=ORIGINAL_ARTIFACT_ROOT.parts
 need(len(p.parts)>=len(base)and [x.casefold()for x in p.parts[:len(base)]]==[x.casefold()for x in base],'artifact provenance outside registered root')
 rel=p.parts[len(base):]
 need(all(x and ':'not in x and '/'not in x and '\\'not in x for x in rel),'artifact path component rejected')
 return ROOT.joinpath(*rel)
def validate_tree():
 """Inspect each entry before descending; never follow symlinks or junctions."""
 pending=[ROOT];total=0;entries=0
 while pending:
  p=pending.pop();mode=p.lstat();entries+=1
  need(entries<=10000,'evidence entry count exceeds bounded reader envelope')
  if stat.S_ISREG(mode.st_mode):
   total+=mode.st_size;need(total<=134217728,'selected evidence bytes exceed workload envelope before reading')
  need(not stat.S_ISLNK(mode.st_mode)and not(getattr(mode,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',1024)),'linked evidence member rejected')
  need(stat.S_ISREG(mode.st_mode)or stat.S_ISDIR(mode.st_mode),'nonregular evidence member rejected')
  need(p.resolve().is_relative_to(ROOT),'evidence member escapes selected root')
  if stat.S_ISDIR(mode.st_mode):pending.extend(p.iterdir())
def audit():
 before={p.relative_to(ROOT).as_posix():sha(p)for p in ROOT.rglob('*')if p.is_file()}
 for name,pin in PINS.items():need(before[name]==pin,'external raw pin '+name)
 reg=load(ROOT/'registration.json');outer=load(ROOT/'evolution-report.json');art=load(DATA/'outcome-artifacts.json')
 need(mapped_artifact(reg['artifacts'])==ROOT,'registered original artifact root mapping')
 need(reg['source_commit']==outer['source_commit']==SOURCE and outer['registration_sha256']==PINS['registration.json'],'source/registration binding')
 need(outer['status']=='PASS_ENGINEERING_ONLY'and outer['scientific_samples']==0 and outer['broader_stable_qualification']=='HOLD'and not outer['automatic_retry'],'interpretation')
 need(reg['bounds']=={'seconds':600,'evidence_bytes':134217728}and 0<outer['elapsed_seconds']<=600,'whole bound')
 need(outer['awake']['released']and outer['awake']['max_observed_suspension_ms']<=1000,'awake closure')
 source_rehashed=0
 if REPO is not None:
  for item in reg['source_manifest']['files']:
   rel=PurePosixPath(item['path']);need(not rel.is_absolute()and '..'not in rel.parts and '\\'not in item['path']and ':'not in item['path'],'source member path')
   path=REPO.joinpath(*rel.parts);need(path.resolve().is_relative_to(REPO)and not path.is_symlink(),'source member containment')
   need(path.stat().st_size==item['bytes']and sha(path)==item['sha256'],'frozen source '+item['path']);source_rehashed+=1
 if LOCAL_BINDINGS:
  for name in['native','observer','memory_test','service_test']:need(sha(Path(reg[name]['path']))==reg[name]['sha256'],'explicit original-host binary '+name)
 need(reg['native']['sha256']==art['native_sha256']=='ef7cd032820653f36e7e141fecb85426d98349c1bfb96224713b989a0418fc66','declared actual native pin')
 need(reg['service_test']['sha256']==art['driver_sha256']=='42e745ff0763a9cd69affb948d4aff4af669ea70b4c0b50043babdf3b187278a','declared actual driver pin')
 actual={p.relative_to(DATA).as_posix()for p in DATA.rglob('*')if p.is_file()}-{'outcome-artifacts.json'}
 declared={f['path']for f in art['files']};need(len(declared)==len(art['files']),'duplicate artifact member')
 approved={name:next((f for f in art['files']if f['path']==name),None)for name in EXCLUDED_RECEIVER_EXECUTABLES}
 for name,role in EXCLUDED_RECEIVER_EXECUTABLES.items():need(approved[name]is not None and approved[name]['sha256']==reg[role]['sha256'],'excluded exact executable role pin '+name)
 missing=declared-actual
 need(missing<=set(EXCLUDED_RECEIVER_EXECUTABLES)and actual==declared-missing,'complete nonbinary copied corpus census')
 artifact_rehashed=0
 for f in art['files']:
  rel=PurePosixPath(f['path']);need(not rel.is_absolute()and '..'not in rel.parts and '\\'not in f['path']and ':'not in f['path'],'artifact member path')
  if f['path']in missing:continue
  p=DATA.joinpath(*rel.parts);need(p.is_relative_to(DATA)and p.stat().st_size==f['bytes']and sha(p)==f['sha256'],'artifact member '+f['path']);artifact_rehashed+=1
 secret=[]
 for p in ROOT.rglob('*'):
  if not p.is_file()or p.suffix.lower()=='.exe':continue
  b=p.read_bytes()
  if p.suffix.lower()=='.key'or re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|(?:ghp|github_pat)_[A-Za-z0-9_]{20,}|"(?:token|password|api_key|bearer)"\s*:\s*"[^"\s]+"',b,re.I):secret.append(p.relative_to(ROOT).as_posix())
 need(not secret,'private material scan '+str(secret))
 sc=load(DATA/'server.json');cc=load(DATA/'client.json');sp=load(DATA/'server-policy.json');cp=load(DATA/'client-policy.json')
 sid=cc['identity'];rid=sc['identity'];scope='affine-context/v1'
 need(len(sc['contexts'])==len(sc['peers'])==len(cc['contexts'])==len(cc['peers'])==1,'isolated stores')
 policy=lambda v:dig({'manifest':v,'ca_sha256':sha(DATA/v['ca_certificate'])})
 need(sp['service_policy_sha256']==policy(sc)and cp['service_policy_sha256']==policy(cc),'actual current policy hashes')
 for cfg in[sc,cc]:
  access=cfg['peers'][0]['access'][0];need(access['scope']==scope and access['artifacts']==['*']and {'outcome.read','candidate.submit'}<=set(access['operations']),'bilateral full-history permission')
  need(cfg['limits']['max_frame_bytes']==65536,'frame ceiling')
 recv=sp['outcomes']['receiver'];send=cp['outcomes']['sender'];need(send['receiver_policy_sha256']==policy(sc)and recv['fixture_sha256']==send['fixture_sha256']==sha(DATA/sc['contexts'][0]['truth_fixture']),'independent receiver fixture')
 need(recv['goal']==send['goal']==7 and recv['max_candidates_per_episode']<=sp['max_candidates_per_episode'],'local receiver goal')
 ops={role:chain((DATA/f'{role}-state/operations.jsonl').read_text(),identity,'operations')for role,identity in [('server',rid),('client',sid)]}
 know={role:chain((DATA/f'{role}-state/knowledge.jsonl').read_text(),identity,'knowledge')for role,identity in [('server',rid),('client',sid)]}
 for role,identity in [('server',rid),('client',sid)]:
  owner=load(DATA/f'{role}-state/operations-owner.json');g=ops[role][0];need(owner['owner_identity']==identity and owner['genesis_sha256']==g['sha256']and owner['policy_digest']==g['payload']['policy_digest'],'journal owner registration')
 summaries={tag:load(DATA/tag/'summary.json')for tag in ['sender-first','sender-restart','receiver-first','receiver-restart']}
 for key,tag in [('first','sender-first'),('restart','sender-restart'),('receiver_first','receiver-first'),('receiver_restart','receiver-restart')]:need(art[key]==summaries[tag],'summary copy '+key)
 ev={tag:rows(DATA/tag/'events.jsonl')for tag in summaries}
 pids=[]
 for tag,s in summaries.items():
  need(s['status']=='STOPPED'and s['partner_benefits_verified']==0,'no economic promotion '+tag)
  ready=next(e['details']for e in ev[tag]if e['phase']=='READY');need(ready['identity']==s['identity']and ready['service_policy_sha256']==policy(cc if tag.startswith('sender')else sc),'actual native readiness')
  need(ready['pid']==s['stage_timing']['pid'],'actual PID consistency');pids.append(ready['pid'])
  cfg=cc if tag.startswith('sender')else sc;pol=cp if tag.startswith('sender')else sp
  need(s['budget']['rpc_attempts']<=pol['max_rpc_attempts']<=cfg['limits']['max_requests']and s['budget']['model_work_reserved']<=pol['max_model_work']<=cfg['limits']['model_work'],'configured budgets')
  need(s['budget']['outbound_plaintext_reserved']+s['budget']['listener_plaintext_reserved']<=pol['max_plaintext_bytes'],'byte reservation budget')
 need(len(set(pids))==4 and set(pids)==set(art['pids']),'two actual process restarts')
 first=summaries['sender-first'];restart=summaries['sender-restart']
 need((first['fresh_promotions'],first['receiver_outcomes_verified'],first['receiver_capability_outcomes_verified'],first['quarantined_contributions'],first['observation_usage']['queries'])==(1,1,1,1,5),'first observed counters')
 need((restart['fresh_promotions'],restart['receiver_outcomes_verified'],restart['receiver_capability_outcomes_verified'],restart['quarantined_contributions'],restart['observation_usage']['queries'])==(0,0,0,0,0),'restart has no repeated learning/credit')
 for a,b in [('sender-first','sender-restart'),('receiver-first','receiver-restart')]:need(summaries[a]['final_knowledge_anchor']==summaries[b]['initial_knowledge_anchor']==summaries[b]['final_knowledge_anchor'],'knowledge retention '+a)
 need(not any(e['phase']in['CHANNEL_CONTRIBUTE','OUTCOME_RECEIVED','OUTCOME_RECONCILIATION']for e in ev['sender-restart']),'warm run does not send or repoll completed credit')
 wire=next(e for e in ev['sender-first']if e['phase']=='OUTCOME_RECEIVED'and e['details']['response']['status']=='USED');response=wire['details']['response'];proof=response['proof'];polls=[channel(r['payload'])for r in ops['client']if channel(r['payload'])and channel(r['payload'])['phase']=='poll'];need(len(polls)==1,'exact once bounded poll in actual run');poll=polls[0]
 need(proof['sender']==sid and proof['receiver']==rid and proof['scope']==scope and proof['challenge']==poll['challenge'],'proof peer/challenge')
 need(proof['policy']=={'manifest':sc,'ca_sha256':sha(DATA/sc['ca_certificate'])}and proof['fixture_sha256']==send['fixture_sha256'],'proof current authority')
 need(proof['ledgers']['knowledge']==(DATA/'server-state/knowledge.jsonl').read_text()and proof['ledgers']['operations']==(DATA/'server-state/operations.jsonl').read_text()and json.loads(proof['ledgers']['registration'])==load(DATA/'server-state/operations-owner.json'),'full original receiver history, retained at restart')
 k=know['server'];e=[r['payload']for r in ops['server'][1:]];need(len(k)==2 and len(e)==9,'actual receiver genesis plus one promotion')
 need(k[1]['payload']['event']=='promote'and proof['record']==k[1]['payload']['record']and proof['before']==here_anchor(k,rid,1)and proof['after']==proof['current']==here_anchor(k,rid),'one exact current adoption')
 need(not any(x['event']in['policy_transitioned','lifecycle_started','peer_denied','peer_restored']for x in e),'initial current epoch without prior relocation/denial')
 q=e[0];goal=e[1]['decision'];rd=e[2]['decision'];fd=feedback(e[3]['decision']);pr=e[4];co=e[5];prom=feedback(e[6]['decision']);use=feedback(e[7]['decision']);out=feedback(e[8]['decision'])
 need(q['event']=='quarantined'and pr['event']=='evaluation_prepared'and co['event']=='evaluation_completed','actual causal order')
 need(goal['details']['schema']=='symbiote.contribution-channel/1'and goal['details']['event']['phase']=='receiver_goal'and goal['details']['event']['goal']==7 and goal['decision_id']=='outcome-'+dig(goal['details']),'unique native prior goal')
 original=q['body'];offer=original['body']['offer'];offered=offer['record'];request_sha=dig(original);candidate=dig({'authenticated_sender':sid,'canonical_body_sha256':request_sha})
 need(candidate==q['candidate_id']==proof['candidate']==poll['candidate']and request_sha==q['body_sha256']==proof['request_sha256']==poll['request_sha256'],'exact original request/candidate')
 contributions=[x['payload']['decision']for x in ops['client']if x['payload'].get('decision',{}).get('details',{}).get('phase')=='contribute'];need(len(contributions)==1 and contributions[0]['decision_id']==poll['decision_id']and contributions[0]['details']['request']==original,'actual sender decision before exact transmitted artifact')
 source_record=know['client'][1]['payload']['record'];need(offered==source_record and source_record['source']==sid,'sender own retained observation record')
 audit=json.loads(source_record['provenance']);need([x['input']for x in audit['queries']]==offer['training_inputs']and len(audit['queries'])==5 and audit['fixture_sha256']==sha(DATA/'source.json'),'own observation audit and received training split')
 need(proof['record']['id']=='service-'+dig({'peer':sid,'scope':scope,'schema':offered['schema_fingerprint']})[:32]and proof['record']['source']==sid and proof['record']['payload']==offered['payload'],'localized artifact identity')
 saved=typed(rd['details'],['schema','phase','request','candidate_id','knowledge_before','service_policy_sha256','fixture_sha256']);saved['request']=request(saved['request']);saved['knowledge_before']=anchor(saved['knowledge_before'])
 need(rd['decision_id']=='receiver-evaluate-'+rawsha(enc(saved))and saved['request']==request(original)and saved['candidate_id']==candidate and saved['knowledge_before']==proof['before'],'native receiver decision hash/request/before')
 b=fd['binding'];exchange=dig({'decision':b['decision_id'],'sender':sid,'receiver':rid,'request':request_sha,'candidate':candidate,'scope':scope,'schema':offered['schema_fingerprint'],'policy':policy(sc),'fixture':send['fixture_sha256']})
 need(b==dict(origin='receiver_evaluation',exchange_id=exchange,decision_id=rd['decision_id'],sender_id=sid,receiver_id=rid,scope=scope,schema_fingerprint=offered['schema_fingerprint'],request_sha256=request_sha,candidate_id=candidate,offered_record_sha256=rawsha(enc(record(offered))),policy_sha256=policy(sc),fixture_sha256=send['fixture_sha256']),'complete causal binding')
 need(proof['exchange_id']==exchange and fd['before']==proof['before']and fd['baseline']['kind']=='unknown','exchange boundary')
 record_sha=rawsha(enc(record(proof['record'])));assessment=k[1]['payload']['assessment'];evidence=assessment['evidence'];evidence_sha=dig(evidence)
 need(pr['candidate_id']==co['candidate_id']==candidate and pr['record']==proof['record']and pr['fixture_sha256']==proof['fixture_sha256']and pr['response']==co['response']and co['record_sha256']==record_sha,'evaluation receipt binding')
 need(prom['exchange_id']==use['exchange_id']==out['exchange_id']==exchange and prom['record_sha256']==use['record_sha256']==record_sha and prom['before']==proof['before']and prom['after']==proof['after']and prom['promotion_sha256']==proof['promotion_sha256']==k[1]['sha256']and prom['evidence_sha256']==evidence_sha,'promotion/use exact anchors')
 truth=load(DATA/'affine-truth.json')['family'];payload=proof['record']['payload'];predict=lambda x:((x&payload['coefficients']).bit_count()%2)^int(payload['bias'])
 need(payload['kind']=='affine'and payload['width']==truth['width']==3 and all(predict(i)==y for i,y in enumerate(truth['outputs'])),'finite affine parity against independent fixture')
 need([x['input']for x in evidence['cases']]==[5,6,7]and not set(evidence['training_inputs'])&{5,6,7}and all(c['expected']==c['candidate']==predict(c['input'])for c in evidence['cases']),'distinct receiver validation cases')
 need(use['input']==7 and use['output']==predict(7)==0 and use['model_work']==1 and use['sequence']==0 and use['knowledge_at']==proof['after']and use['basis']==dict(kind='retained_evaluation',evidence_sha256=evidence_sha),'actual retained-case stored model use')
 pc=prom['costs'];ec=evidence['costs'];need((pc['acquisition'],pc['validation'],pc['adoption'],pc['prediction'],pc['wire'],pc['replay'])==(ec['acquisition'],ec['verification'],ec['adoption'],0,0,0),'actual stored component costs')
 subtotal=sum(pc[f]for f in['acquisition','validation','adoption','prediction','wire','replay']);o=out['outcome'];need(subtotal==ec['candidate']==9 and o['candidate_cost']==10 and o['quality']=='capability_extended'and o['baseline']==fd['baseline']==prom['baseline']and o['baseline']['kind']=='unknown'and o['uses']==1 and o['measured_net']is None and o['verified_benefit']is False,'unknown economics stay unknown')
 ces=[channel(r['payload'])for r in ops['client']if channel(r['payload'])];reconciled=[x for x in ces if x['phase']=='reconciled'];chunks=[x for x in ces if x['phase']=='witness_chunk'];need(len(reconciled)==1,'once-only reconciliation');rc=reconciled[0]
 need(rc['decision_id']==poll['decision_id']and rc['credit_key']==dig({'receiver':rid,'promotion':proof['promotion_sha256']})and rc['capability_verified']is True and rc['cost_benefit_verified']is False,'one exact promotion credit')
 need(len(chunks)==11 and [c['index']for c in chunks]==list(range(11))and all(c['total']==11 and c['decision_id']==poll['decision_id']and c['proof_sha256']==rc['proof_sha256']for c in chunks),'complete atomic witness chunks')
 raw=b''.join(bytes.fromhex(c['hex'])for c in chunks);need(rawsha(raw)==rc['proof_sha256']and json.loads(raw)==proof,'stored proof identical to actual API response')
 proof_bytes=len(raw);response_bytes=len(enc(response,True));need(proof_bytes<=56*1024 and response_bytes+1024<=65536 and len(k)<=4 and len(e)<=64,'proof envelope and transport bounds')
 for a,b in [('sender-first','receiver-first'),('sender-restart','receiver-restart')]:
  x=summaries[a]['outbound_plaintext_traffic'];y=summaries[b]['inbound_plaintext_traffic'];need(x['connection_attempts']==y['connection_attempts']and x['rpc_sent_bytes']==y['rpc_received_bytes']and x['rpc_received_bytes']==y['rpc_sent_bytes']and x['negotiation_sent_bytes']==y['negotiation_received_bytes']and x['negotiation_received_bytes']==y['negotiation_sent_bytes'],'bilateral metered plaintext')
 process=next(p for p in outer['process_calls']if p['label']=='receiver-outcomes');need(process['argv']==[reg['service_test']['path'],'outcomes::two_native_agents_reconcile_receiver_owned_outcome_and_restart','--exact','--nocapture','--test-threads=1']and process['exit_code']==0 and process['cleanup_verified']and not process['output_truncated']and process['outcome']=='completed','actual contained native proof process')
 receipt=load(ROOT/'processes'/process['process_receipt']);need(receipt==process,'outer process receipt copy')
 for field in['stdout','stderr']:need(sha(ROOT/'processes'/process[field])==process[field+'_sha256'],'process output '+field)
 need('1 passed; 0 failed' in (ROOT/'processes'/process['stdout']).read_text(),'actual native test completion')
 after={p.relative_to(ROOT).as_posix():sha(p)for p in ROOT.rglob('*')if p.is_file()};need(before==after,'raw corpus remained byte-identical throughout audit')
 total=sum(p.stat().st_size for p in ROOT.rglob('*')if p.is_file());original_total=total+sum(approved[n]['bytes']for n in missing);need(original_total<=134217728,'original whole evidence size including exact excluded executable roles')
 return dict(schema='symbiote.independent-receiver-audit/1',status='PASS_PORTABLE_DATA_ONLY_RECEIVER_LOOP',source_commit=SOURCE,registration_sha256=PINS['registration.json'],raw_pins={n:before[n]for n in sorted(before)if n.startswith('receiver-outcomes/')or n in PINS},whole_report_sha256=PINS['evolution-report.json'],whole_elapsed_seconds=outer['elapsed_seconds'],whole_evidence_bytes=original_total,selected_data_root_bytes=total,missing_original_executable_bytes=sum(approved[n]['bytes']for n in missing),component_process=process,source_files_rehashed=source_rehashed,source_manifest_rows=len(reg['source_manifest']['files']),source_byte_verification='PASS_SELECTED_REPOSITORY'if REPO is not None else 'NOT_REQUESTED_REGISTRATION_PINS_ONLY',local_binary_byte_verification='PASS_EXPLICIT_ORIGINAL_HOST_BINDINGS'if LOCAL_BINDINGS else 'NOT_REQUESTED_REGISTERED_PINS_ONLY',declared_artifact_members=len(art['files']),excluded_executable_members={n:approved[n]for n in sorted(missing)},artifact_members_rehashed=artifact_rehashed,receiver_operation_rows=len(ops['server']),sender_operation_rows=len(ops['client']),receiver_knowledge_rows=len(k),sender_knowledge_rows=len(know['client']),actual_receiver_promotions=1,actual_receiver_uses=1,sender_new_outcomes=1,sender_new_capability_outcomes=1,verified_economic_benefits=0,receiver_summary_fresh_promotions=0,receiver_summary_note='fresh_promotions is the normal learning-loop counter; receiver-role adoption is proven by its ledger and anchors, not added to this field',restart_new_outcomes=0,restart_new_capabilities=0,restart_source_queries=0,initial_source_queries=5,initial_gf2_work=first['observation_usage']['gf2_work_units'],restart_gf2_work=restart['observation_usage']['gf2_work_units'],actual_pids=art['pids'],goal_input=7,goal_output=0,validated_inputs=[5,6,7],stored_component_cost=9,stored_use_work=1,stored_outcome_cost=10,baseline_kind='unknown',measured_net=None,wire_response_bytes=response_bytes,stored_proof_bytes=proof_bytes,witness_chunks=len(chunks),transport_frame_ceiling=65536,proof_ceiling=57344,receiver_event_ceiling=64,knowledge_row_ceiling=4,first_sender_rpc_attempts=first['budget']['rpc_attempts'],restart_sender_rpc_attempts=restart['budget']['rpc_attempts'],plaintext_traffic={tag:summaries[tag]['outbound_plaintext_traffic']for tag in['sender-first','sender-restart']},budget_reservations={tag:s['budget']for tag,s in summaries.items()},private_material_scan='PASS_NO_PRIVATE_KEYS_OR_TOKEN_VALUES',raw_files_unchanged=True,scope='One authorized local native pair, exact affine width3 retained evaluation case; no fresh-task, remote honesty, full-cost efficiency, two-host, or generalized-intelligence claim')

def main(argv=None):
 global ROOT,DATA,REPO,OUT,LOCAL_BINDINGS
 parser=argparse.ArgumentParser(description='Independent data-only receiver evidence replay; never runs native code. Original-host bindings are optional and explicit.')
 parser.add_argument('--root',type=Path,required=True,help='Extracted run/ directory containing the original registration and receiver-outcomes/')
 parser.add_argument('--output',type=Path,required=True,help='New audit JSON outside the extracted run tree')
 parser.add_argument('--repository',type=Path,help='Optional caller-selected physical repository to rehash against the frozen manifest')
 parser.add_argument('--local-bindings',action='store_true',help='Explicitly read original physical binary paths in registration (original Windows host only)')
 args=parser.parse_args(argv)
 ROOT=args.root.resolve(strict=True);DATA=ROOT/'receiver-outcomes';OUT=args.output.absolute();LOCAL_BINDINGS=args.local_bindings
 REPO=args.repository.resolve(strict=True)if args.repository else None
 need(ROOT.is_dir(),'extracted run root must be a directory')
 need(not OUT.resolve(strict=False).is_relative_to(ROOT),'audit output must be outside evidence')
 need(not OUT.exists(),'audit output must be new')
 validate_tree()
 try:report=audit()
 except Exception as e:report=dict(schema='symbiote.independent-receiver-audit/1',status='HOLD',error=str(e),traceback=traceback.format_exc())
 report.update(audit_script_sha256=sha(Path(__file__)),selected_root=str(ROOT),optional_repository=str(REPO)if REPO else None,explicit_original_local_bindings=LOCAL_BINDINGS,path_mapping='lexical registered Windows artifact prefix to supplied extracted root; no fallback',replay_mode='data-only; native code and producer modules are never executed')
 with OUT.open('xb')as f:f.write(enc(report)+b'\n')
 print(json.dumps(dict(status=report['status'],receipt=str(OUT),sha256=sha(OUT),error=report.get('error'))))
 return 0 if report['status']=='PASS_PORTABLE_DATA_ONLY_RECEIVER_LOOP'else 1
if __name__=='__main__':raise SystemExit(main())
