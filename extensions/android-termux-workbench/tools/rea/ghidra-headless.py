#!/usr/bin/env python
"""Bounded standalone Ghidra headless adapter; not REA native provider integration."""
from runlog import *
from static import identify,TASK
import argparse,fcntl,re

def main():
 a=argparse.ArgumentParser(description='Termux ARM64 Ghidra12.1.4 自有小 ELF headless，输出真实 C 与汇编')
 a.add_argument('--task-id',required=True);a.add_argument('--input',required=True);a.add_argument('--job',required=True);args=a.parse_args()
 if args.task_id!=TASK:a.error('TASK_MISMATCH')
 if not re.fullmatch('[A-Za-z0-9_-]{1,64}',args.job):a.error('invalid job')
 p=pathlib.Path(args.input).resolve(strict=True)
 if not any(p.is_relative_to(BASE/d) for d in ('samples','inbox')) or not p.is_file():a.error('TARGET_DENIED')
 if p.stat().st_size>4*1024*1024:a.error('Ghidra minimal acceptance budget 4MiB')
 kind,_=identify(p)
 if kind!='ELF':a.error('本轮脚本只验收 ELF 中的 owned_add，PE完整反编译未验收')
 with (BASE/'analysis.lock').open('a') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:a.error('已有静态分析在运行')
  ps=subprocess.run(['ps','-eo','comm'],capture_output=True,text=True,check=True).stdout
  if any(pathlib.Path(x.strip()).name in ('sd-cli','paos-resume-decode') for x in ps.splitlines()):a.error('Z-Image活动，暂缓')
  c=BASE/'c1';g=ROOT/json.loads((c/'evidence/ghidra-install.json').read_text())['root']
  job=c/'jobs'/args.job
  if job.exists():a.error('JOB_EXISTS')
  job.mkdir(parents=True);(job/'project').mkdir();artifact=job/'ghidra-analysis.json'
  flags=[]
  for line in (g/'support/launch.properties').read_text().splitlines():
   if line.startswith(('VMARGS=','VMARGS_LINUX=')) and line.split('=',1)[1]:flags.append(line.split('=',1)[1])
  argv=['env',f'HOME={c}/home',f'TMPDIR={c}/tmp',f'XDG_CONFIG_HOME={c}/home/.config',f'XDG_CACHE_HOME={c}/home/.cache',JAVA,*flags,'-Xmx768m','-XX:ActiveProcessorCount=2','-XX:ParallelGCThreads=1','-XX:CICompilerCount=2','-Djava.awt.headless=true',f'-Duser.home={c}/home',f'-Djava.io.tmpdir={c}/tmp','-cp',g/'Ghidra/Framework/Utility/lib/Utility.jar','ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',job/'project','OwnedAnalysis','-import',p,'-max-cpu','1','-analysisTimeoutPerFile','60','-scriptPath',ROOT/'tools/rea/ghidra-scripts','-postScript','ReaOwnedExport.java',artifact,'-log',job/'application.log','-scriptlog',job/'script.log']
  digest=sha(p);r=run('headless',argv,job,120,cwd=g)
  result={'task_id':TASK,'status':'BLOCKED','backend':'standalone-ghidra-12.1.4','input':str(p.relative_to(ROOT)),'sha256':digest,'static_only':True,'command':r,'limitations':['仅自有小ELF owned_add函数验收','不是REA Ghidra桥完成','未执行目标，不保证恶意目标隔离','PE headless与其他架构未验收']}
  if artifact.is_file():
   data=json.loads(artifact.read_text());result['analysis']=data
   good=r['exit_code']==0 and data.get('sha256')==digest and data.get('decompile_completed') is True and bool(data.get('decompiled_c')) and bool(data.get('instructions')) and sha(p)==digest
   log=(job/'headless.stdout').read_text(errors='replace')+(job/'headless.stderr').read_text(errors='replace')
   good=good and 'REPORT: Analysis succeeded' in log and 'REPORT: Save succeeded' in log
   if good:result['status']='VERIFIED'
  (job/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
  lines=['# Ghidra headless 静态分析报告',f'结论：**{result["status"]}**',f'目标：`{result["input"]}`',f'SHA256：`{digest}`',f'实际命令 exit：{r["exit_code"]}，耗时{r["elapsed_s"]}秒，超时：{r["timed_out"]}']
  if result.get('analysis'):
   d=result['analysis'];lines.extend([f'语言：{d["language"]}；函数：{d["selected_function"]}',f'汇编指令：{len(d["instructions"])}条；native decompile：{d["decompile_completed"]}','## 真实反编译 C','```c',d.get('decompiled_c',''),'```'])
  lines+=['## 边界']+['- '+x for x in result['limitations']]
  (job/'报告.md').write_text('\n\n'.join(lines)+'\n')
  print(json.dumps({'status':result['status'],'result':str((job/'result.json').relative_to(ROOT)),'report':str((job/'报告.md').relative_to(ROOT))},ensure_ascii=False));return 0 if result['status']=='VERIFIED' else 2
if __name__=='__main__':raise SystemExit(main())
