import datetime,hashlib,json,pathlib,re,subprocess
p=pathlib.Path(__file__).resolve().parent
candidate=json.loads((p/'candidate.json').read_text())
required=['01-build','02-gettext','03-release-metadata','04-check','05b-distcheck-default','06-distcheck-shared','07-distcheck-static','08-native-consumers','10-go-consumers','11-build-pkgconfig']
records=[]
for name in required+['05-distcheck-default','09-binding-consumers']:
 r=json.loads((p/(name+'.json')).read_text())
 assert r['candidate_commit']==candidate['commit'] and r['candidate_tree']==candidate['tree']
 for key,hashkey in [('log','log_sha256'),('resource_log','resource_sha256')]:
  assert hashlib.sha256(pathlib.Path(r[key]).read_bytes()).hexdigest()==r[hashkey],name
 for f,h in r.get('input_sha256',{}).items(): assert hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()==h,(name,f)
 if name in required: assert r['result']=='PASS' and r['exit_status']==0 and r['identity_valid'],name
 records.append(r)
partial=next(r for r in records if r['gate']=='09-binding-consumers')
log=pathlib.Path(partial['log']).read_text()
for token in ['Python runtime:', 'Installed wheel runtime/version PASS', 'Verifying secdat-sdk v0.11.0', 'External Node tarball consumer/version/functions PASS','error obtaining VCS status']:
 assert token in log,token
assert partial['exit_status']==1 and partial['identity_valid']
# Ordered set-e script reaches Go only after successful Python/Rust/Node assertions.
assert log.index('Installed wheel runtime/version PASS')<log.index('Verifying secdat-sdk v0.11.0')<log.index('External Node tarball consumer/version/functions PASS')<log.index('error obtaining VCS status')
resources=[]
for r in records:
 t=pathlib.Path(r['resource_log']).read_text()
 def number(label):
  m=re.search(re.escape(label)+r':\s*([0-9.]+)',t); return float(m.group(1)) if m else None
 resources.append({'gate':r['gate'],'result':r['result'],'elapsed_seconds':r['elapsed_seconds'],'cpu_user_seconds':number('User time (seconds)'),'cpu_system_seconds':number('System time (seconds)'),'max_rss_kib':number('Maximum resident set size (kbytes)')})
artifacts={}
paths=[p/'secdat-0.11.0.tar.gz',p/'frozen-release-notes.md',p/'consumer-shared',p/'consumer-static',p/'installed-consumers-work/go-shared',p/'installed-consumers-work/go-static']
for pattern in ['installed-consumers-work/wheels/*.whl','installed-consumers-work/*.tgz','installed-consumers-work/rust-target/package/*.crate','prefix-*/lib/libsecdat.*','prefix-*/lib/pkgconfig/libsecdat.pc']:
 paths.extend(p.glob(pattern))
for f in paths:
 if f.is_file(): artifacts[str(f.relative_to(p))]={'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'size_bytes':f.stat().st_size}
summary={'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'candidate':candidate,'matrix_result':'COMPLETE with retained failed attempts and explicit successful-axis evidence','required_pass_receipts':required,'partial_binding_evidence':{'receipt':'09-binding-consumers.json','overall_result':'FAIL in later Go VCS stamping','accepted_completed_axes':['Python source wrapper runtime','Python wheel build and isolated installed runtime/version','Rust locked check and package verification','Node ci/build/dry-pack and external real-tarball load/version/functions'],'basis':'Ordered set -e script + explicit completion output before Go failure; exact checker and log hashes bound in receipt. Go shared/static completed separately in10.'},'failures':[{'receipt':'05-distcheck-default.json','disposition':'Parallel make query output contamination; documented serial05b passes, no source change; Issue248.'},{'receipt':'09-binding-consumers.json','disposition':'Archive consumer Go VCS auto-detection hit unrelated empty HOME/.git; command-local buildvcs=false in10, no global or product change.'}],'limits':['Known XFAIL221 same-protocol agent handover','Known242 orphan renamed-domain move failure remains unresolved','ADR0006 work166-169 not claimed complete','Mixed v1-parent/v2-child mask ambiguity guard retained; explicit migration/index/rebind required','Distcheck prefix skips installed-locale smoke;04 under/tmp covers installed Japanese locale','Static-only skips shared ABI and Python runtime; other profiles + isolated wheel cover those axes','Parallel distcheck harness issue248 remains open','Go archive-consumer VCS stamping explicitly disabled; source provenance separately verified','Rust manifest license metadata warning; package verification passed, registry publication not included','npm current-version configuration/install-script warnings recorded; external native addon consumer passed'],'resources':resources,'resource_totals_all_attempts':{'elapsed_gate_seconds':sum(x['elapsed_seconds'] for x in resources),'cpu_seconds':sum((x['cpu_user_seconds'] or 0)+(x['cpu_system_seconds'] or 0) for x in resources),'max_rss_kib':max(x['max_rss_kib'] or 0 for x in resources)},'artifacts':artifacts,'publication':'NOT PERFORMED; final owner decision required before main/tag/release writes'}
(p/'matrix-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({'matrix_result':summary['matrix_result'],'resource_totals_all_attempts':summary['resource_totals_all_attempts'],'artifact_count':len(artifacts)},indent=2))
