"""Root acceptance of four actual first-public-run results; no remote mutation."""
import copy,hashlib,json
from pathlib import Path
T=Path(r'C:\Users\jacks\AppData\Local\Temp');OUT=T/'v112-root-public-accept-8aa'
def h(raw):return hashlib.sha256(raw).hexdigest()
def save(name,value):
    p=OUT/name;raw=json.dumps(value,indent=2,ensure_ascii=False,allow_nan=False).encode()+b'\n'
    with p.open('xb') as f:f.write(raw)
    return dict(path=str(p),bytes=len(raw),sha256=h(raw))
def main():
    p=T/'v112-public-assessment-8aa-002/reviewed-public-inputs.CAPTURED-REVIEW-REQUIRED.json';raw=p.read_bytes();assert h(raw)=='3b0b856645641ca5e1d9a8281b36f9dd71795247dfafdea0a5b29bbf13013c05';d=json.loads(raw)
    review=T/'v112-public-independent-review.json';assert h(review.read_bytes())=='4d9bf2387258ffc9e3a2bcc00154256f1b56cc9090e02975e93204af21a227d9'
    assert d['publication_plan']['sha256']=='e974dd7ecef3d2fc7356dfd090bdc32e086f00b4b51ae1efa7a823d474694b5d' and d['provisional_operation']['sha256']=='cfbb5d97e66644f50ddfb0d65298bfdf2801e02cee342b9a7276f98214a7e817'
    targets=['x86_64-pc-windows-msvc','x86_64-unknown-linux-gnu','aarch64-apple-darwin','x86_64-apple-darwin'];assert len(d['gates'])==4 and {g['role'] for g in d['gates']}=={'public-native:'+t for t in targets}
    evidence={}
    for gate in d['gates']:
        assert gate['review']['decision']=='REVIEW_REQUIRED' and 0<gate['started_unix_ns']<gate['finished_unix_ns']
        for item in gate['evidence']:
            data=Path(item['path']).read_bytes();assert h(data)==item['sha256'] and len(data)==item['bytes'];evidence[item['path']]=dict(sha256=h(data),bytes=len(data))
    accepted=copy.deepcopy(d)
    for gate in accepted['gates']:gate['review']['decision']='ACCEPT';gate['review']['reviewer']='Codex root: actual first-public-run receipts and independent source-bound data review'
    OUT.mkdir();inputs=save('reviewed-public-inputs.ACCEPTED.json',accepted)
    decision=save('decision.json',dict(schema='symbiote.v112-root-first-public-acceptance/1',status='ROOT_ACCEPTED_FOUR_ACTUAL_PUBLIC_PLATFORM_RESULTS',source_commit='8aa5f4c6ab26f7ccad53935a70414ae1765b57c6',public_run_id=40967471449,run_attempt=1,candidate_run_id=40945405929,release_id=428461777,publication_plan_sha256=d['publication_plan']['sha256'],asset_digest='cf8d5c03f1c8628ed4e9c5f4f0772dfce4be64bb10d5f7de5f33d54547eff9f2',original_request=dict(path=str(p),sha256=h(raw)),accepted_inputs=inputs,independent_review=dict(path=str(review),sha256=h(review.read_bytes())),checked_evidence=evidence,accepted_roles=[g['role'] for g in accepted['gates']],scope='Four first-attempt installed public CLI/embedding acceptances; 36 anonymous downloads of 33 distinct subjects; four conditional capability outcomes; zero measured benefits or duplicate restart credit. Bounded outcome polling preserved. No new scientific sample or two-host claim.',authorization='Assemble original formal public assessment once, then root may invoke original publisher finalize with mandatory fresh16 checks and actual latest verification.',stable='PENDING_ACTUAL_FINALIZATION',original_requests_mutated=False,operator_sha256=h(Path(__file__).read_bytes())))
    print(json.dumps(dict(decision=decision,accepted_inputs=inputs)))
if __name__=='__main__':main()
