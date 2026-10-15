from runlog import *
import shutil,struct,uuid
TASK='b06dd042-8638-4a47-937d-8ae644a205b9';ev=BASE/'evidence/acceptance';ev.mkdir(parents=True,exist_ok=True)
checks=[];batch=uuid.uuid4().hex[:8];created_jobs=[]
def check(name,ok,detail):
 checks.append(dict(name=name,passed=bool(ok),detail=detail))
 if not ok:raise AssertionError(name)
for job,kind,arch in [('owned-exe','PE','x86'),('owned-elf','ELF','arm')]:
 d=json.loads((BASE/'jobs'/job/'analysis.json').read_text());i=d['analysis']['info']
 check(job+'-fields',d['status']=='VERIFIED' and d['file_type']==kind and i['arch']==arch and i['bits']==64 and i['bintype']==kind.lower() and len(d['analysis']['sections'])>0,{'info':i,'sha256':d['sha256']})
elf=json.loads((BASE/'jobs/owned-elf/analysis.json').read_text())
check('elf-owned-symbol',any(x['name']=='owned_add' for x in elf['analysis']['symbols']),'owned_add')
apk=json.loads((BASE/'jobs/owned-apk/analysis.json').read_text());src=(BASE/'jobs/owned-apk/jadx/sources/owned/acceptance/OwnedArithmetic.java').read_text()
check('apk-real-manifest-dex-java',apk['status']=='VERIFIED' and 'owned.acceptance' in apk['manifest_tree'] and 'return i + i2;' in src,src)
managed=json.loads((BASE/'jobs/managed-pe/analysis.json').read_text())
check('managed-rea-original',managed['status']=='VERIFIED' and managed['rea_managed']['server']['version']=='6.3.0' and not managed['rea_managed']['rea_result'].get('isError'),str(managed['rea_managed']['rea_result'].keys()))
s=BASE/'samples';(s/'empty.bin').write_bytes(b'');(s/'unknown.bin').write_bytes(b'not executable');shutil.copy2(s/'owned.exe',s/'wrong-extension.txt')
with (s/'oversized.bin').open('wb') as f:f.truncate(64*1024*1024+1)
for name,expected in [('empty.bin',2),('unknown.bin',2),('oversized.bin',2),('wrong-extension.txt',0)]:
 job_name='test-'+name.replace('.','-')+'-'+batch
 r=run(name.replace('.','-'),['python','tools/rea/static.py','--task-id',TASK,'--input',s/name,'--job',job_name],ev,90)
 if (BASE/'jobs'/job_name/'analysis.json').is_file():created_jobs.append(job_name)
 check(name,r['exit_code']==expected,r)
r=run('outside-target',['python','tools/rea/static.py','--task-id',TASK,'--input',ROOT/'AGENTS.md','--job','outside-target'],ev)
check('outside-target-denied',r['exit_code']==2 and 'TARGET_DENIED' in (ROOT/r['stderr']).read_text(),r)
r=run('wrong-task',['python','tools/rea/static.py','--task-id','wrong','--input',s/'owned.exe','--job','wrong-task'],ev)
check('wrong-task-denied',r['exit_code']==2 and 'TASK_MISMATCH' in (ROOT/r['stderr']).read_text(),r)
# A local trusted timer fixture tests cancellation, not a target executable.
r=run('timeout-fixture',['python','-c','import os,time; print(os.getpid(),flush=True); time.sleep(30)'],ev,.2)
pid=int((ROOT/r['stdout']).read_text());alive=True
try:os.kill(pid,0)
except ProcessLookupError:alive=False
check('timeout-kill-reap',r['timed_out'] and r['exit_code']==-9 and not alive,{'pid':pid,'alive':alive,'record':r})
# Evidence output consistency and source samples unchanged by analysis.
for name in ['owned.exe','owned.elf','owned.apk']:
 old=json.loads((BASE/'evidence/build/samples.json').read_text())[name]['sha256']
 check('input-unchanged-'+name,sha(s/name)==old,old)
for job_name in ['owned-exe','owned-elf','owned-apk','managed-pe',*created_jobs]:
 p=BASE/'jobs'/job_name/'analysis.json';d=json.loads(p.read_text())
 for c in d['commands']:
  check('readback-'+p.parent.name+'-'+pathlib.Path(c['stdout']).stem,sha(ROOT/c['stdout'])==c['stdout_sha256'] and sha(ROOT/c['stderr'])==c['stderr_sha256'],c['exit_code'])
(ev/'results.json').write_text(json.dumps({'passed':len(checks),'failed':0,'checks':checks},ensure_ascii=False,indent=2));print('PASS',len(checks),'checks')
