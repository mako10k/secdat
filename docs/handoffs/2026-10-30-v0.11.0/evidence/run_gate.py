#!/usr/bin/env python3
"""Record one serial release gate against a frozen source candidate."""
import datetime, hashlib, json, pathlib, subprocess, sys, time
root=pathlib.Path('/home/katsumata-m/secdat-release-0.11.0')
evidence=pathlib.Path(__file__).resolve().parent
name=sys.argv[1]; command=sys.argv[2:]
assert name and command
frozen=json.loads((evidence/'candidate.json').read_text())
def git(*args): return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
def identity():
 return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain','--untracked-files=normal')}
before=identity(); assert before['commit']==frozen['commit'] and before['tree']==frozen['tree'] and not before['status'],before
log=evidence/(name+'.log'); resource=evidence/(name+'.time'); receipt=evidence/(name+'.json')
assert not receipt.exists(), f'Receipt already exists: {receipt}; preserve prior attempts'
started=datetime.datetime.now(datetime.timezone.utc).isoformat(); begin=time.monotonic()
print(f'START {name}: {command}',flush=True)
with log.open('wb') as output:
 process=subprocess.run(['/usr/bin/time','-v','-o',str(resource),*command],cwd=root,stdout=output,stderr=subprocess.STDOUT)
after=identity(); elapsed=time.monotonic()-begin
valid=after['commit']==frozen['commit'] and after['tree']==frozen['tree'] and not after['status']
record={'gate':name,'candidate_commit':frozen['commit'],'candidate_tree':frozen['tree'],'command':command,'cwd':str(root),'configure':frozen['configure'],'environment_file':'environment.txt','start_utc':started,'finish_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'elapsed_seconds':elapsed,'exit_status':process.returncode,'result':'PASS' if process.returncode==0 and valid else 'FAIL','identity_before':before,'identity_after':after,'identity_valid':valid,'log':str(log),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'resource_log':str(resource),'resource_sha256':hashlib.sha256(resource.read_bytes()).hexdigest()}
receipt.write_text(json.dumps(record,indent=2)+'\n')
print(f"END {name}: {record['result']} rc={process.returncode} elapsed={elapsed:.2f}s identity={valid}",flush=True)
sys.exit(0 if record['result']=='PASS' else 1)
