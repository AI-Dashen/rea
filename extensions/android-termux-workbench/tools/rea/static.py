#!/usr/bin/env python
"""Offline static analysis only. Research adapter, not a registered capability."""
from runlog import *
from android_intelligence import build_android_intelligence
import argparse,struct,zipfile,fcntl,re,sys
TASK='b06dd042-8638-4a47-937d-8ae644a205b9'
def identify(p):
 b=p.read_bytes()
 if b.startswith(b'\x7fELF'):
  if len(b)<64 or b[4] not in (1,2) or b[5] not in (1,2):raise ValueError('损坏的 ELF 头')
  return 'ELF',{}
 if b.startswith(b'MZ'):
  if len(b)<64:raise ValueError('损坏的 PE DOS 头')
  offset=struct.unpack_from('<I',b,60)[0]
  if offset+24>len(b) or b[offset:offset+4]!=b'PE\0\0':raise ValueError('缺少有效 PE 签名')
  opt=offset+24;magic=struct.unpack_from('<H',b,opt)[0];dd=opt+(112 if magic==0x20b else 96)
  countpos=opt+(108 if magic==0x20b else 92)
  managed=False
  if magic in (0x10b,0x20b) and countpos+4<=len(b) and struct.unpack_from('<I',b,countpos)[0]>14 and dd+120<=len(b):
   managed=struct.unpack_from('<I',b,dd+112)[0]!=0
  return 'PE',{'managed_cli_directory':managed}
 if zipfile.is_zipfile(p):
  with zipfile.ZipFile(p) as z:
   infos=z.infolist()
   if len(infos)>10000 or sum(x.file_size for x in infos)>128*1024*1024:raise ValueError('ZIP 超过静态分析预算')
   if len({x.filename for x in infos})!=len(infos):raise ValueError('ZIP 重复文件名')
   for i in infos:
    if i.file_size>32*1024*1024 or (i.compress_size and i.file_size/i.compress_size>200):raise ValueError('ZIP 解压比例/单项预算超限')
    if i.filename.startswith('/') or '..' in pathlib.PurePosixPath(i.filename).parts:raise ValueError('ZIP 不安全路径')
   names=z.namelist()
   if 'AndroidManifest.xml' not in names or 'classes.dex' not in names:raise ValueError('不是完整 APK：缺少 Manifest 或 classes.dex')
   m=z.read('AndroidManifest.xml');dex=z.read('classes.dex')
   if not m.startswith(b'\x03\x00\x08\x00') or not dex.startswith(b'dex\n') or len(dex)<112:raise ValueError('无效 binary Manifest / DEX')
   return 'APK',{'zip_entries':names,'dex_header_bytes':len(dex),'signed':any(n.startswith('META-INF/') for n in names),'signature_validation':'NOT_PERFORMED'}
 return 'UNKNOWN',{}
def main():
 a=argparse.ArgumentParser(description='REA Termux 本地离线静态分析；仅 samples/inbox 内合法文件')
 a.add_argument('--task-id',required=True);a.add_argument('--input',required=True);a.add_argument('--job',required=True)
 a.add_argument('--backend',choices=['static','ghidra-headless'],default='static',help='默认已验收 PE/ELF/APK 静态路由；Ghidra 仅已验收含 owned_add 的小 ELF')
 args=a.parse_args()
 if args.task_id!=TASK:a.error('TASK_MISMATCH')
 if args.backend=='ghidra-headless':
  return subprocess.call([sys.executable,str(ROOT/'tools/rea/ghidra-headless.py'),'--task-id',args.task_id,'--input',args.input,'--job',args.job],env=env())
 if not re.fullmatch('[a-zA-Z0-9_-]{1,64}',args.job):a.error('invalid job')
 BASE.mkdir(exist_ok=True)
 with (BASE/'analysis.lock').open('a') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:a.error('已有静态分析在运行')
  p=pathlib.Path(args.input).resolve(strict=True)
  if not any(p.is_relative_to(BASE/d) for d in ('samples','inbox')) or not p.is_file():a.error('TARGET_DENIED；请先将合法文件放入隔离 inbox')
  if p.stat().st_size>64*1024*1024:a.error('超过 64MiB 预算')
  # Check tool process names, not arbitrary Android app data or secrets.
  ps=subprocess.run(['ps','-eo','comm'],capture_output=True,text=True,check=True).stdout
  if any(pathlib.Path(x.strip()).name in ('sd-cli','paos-resume-decode') for x in ps.splitlines()):a.error('Z-Image 活跃，暂缓分析')
  job=BASE/'jobs'/args.job
  if job.exists():a.error('JOB_EXISTS；保留原有成果')
  job.mkdir(parents=True)
  result={'schema_version':1,'task_id':TASK,'input':str(p.relative_to(ROOT)),'sha256':sha(p),'bytes':p.stat().st_size,'static_only':True,'status':'BLOCKED','commands':[],'limitations':['未执行、安装或加载目标程序','仅限受控本地静态分析；不是恶意样本安全隔离','不验证签名、运行行为或源代码等价性','REA Android Provider 已在自有小 APK 验证；大 APK、AAB、split APK 与混淆壳仍待验证']}
  def call(label,argv):
   r=run(label,argv,job);result['commands'].append(r)
   if r['exit_code']!=0:raise ValueError(f'{label} 失败，exit={r["exit_code"]}')
   return (ROOT/r['stdout']).read_text(errors='replace')
  try:
   kind,details=identify(p);result.update(file_type=kind,details=details)
   result['file_description']=call('file',['file','-b','--',p]).strip()
   if kind in ('PE','ELF'):
    text=call('rabin2',[LOCAL/'bin/rabin2','-j','-I','-S','-s','-i','-e',p]);data=json.loads(text)
    if not isinstance(data,dict) or not isinstance(data.get('info'),dict):raise ValueError('rabin2 未返回有效结构信息')
    info=data['info']
    if info.get('bintype')!=kind.lower() or info.get('bits') not in (32,64) or not isinstance(info.get('arch'),str) or not isinstance(data.get('sections'),list) or not data['sections']:raise ValueError('rabin2 格式/架构/节区校验失败')
    result['analysis']=data
    if kind=='ELF':result['elf_headers']=call('readelf',['llvm-readelf','-h','-l',p])
    if kind=='PE' and details['managed_cli_directory']:
     result['rea_managed']=json.loads(call('rea-managed',['node',ROOT/'tools/rea/managed-mcp.mjs',p]))
   elif kind=='APK':
    result['android_profile']=json.loads(call('android-profile',[sys.executable,ROOT/'tools/rea/android-package-profile.py',p]))['profile']
    result['manifest_tree']=call('manifest',['aapt','dump','xmltree',p,'AndroidManifest.xml'])
    result['rea_android']=json.loads(call('rea-android',['node',ROOT/'tools/rea/android-mcp.mjs',p]))
    normalized=result['rea_android']['package_evidence']['normalized_result']
    if normalized.get('class_count',0)<1:raise ValueError('REA Android Provider 未返回类')
    jar=ROOT/'run/rea-3a0be4d8/jadx-local/data/data/com.termux/files/usr/share/java/jadx-1.5.6-all.jar'
    call('jadx',[JAVA,'-Xmx384m','-cp',jar,'jadx.cli.JadxCLI','-j','1','--no-res','-d',job/'jadx',p])
    sources=list((job/'jadx/sources').rglob('*.java'))
    if not sources:raise ValueError('JADX 无 Java 输出')
    result['decompiled_files']=[{'path':str(x.relative_to(ROOT)),'sha256':sha(x),'bytes':x.stat().st_size} for x in sources]
    result['android_intelligence']=build_android_intelligence(p,job/'jadx/sources',normalized,result['android_profile'])
   else:raise ValueError('文件类型未支持')
   if sha(p)!=result['sha256']:raise ValueError('输入在分析期间变化')
   result['status']='VERIFIED'
  except (ValueError,OSError,struct.error,zipfile.BadZipFile,RuntimeError) as e:result['error']=str(e)
  (job/'analysis.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
  lines=['# 本地静态分析报告',f'任务：{TASK}',f'结论：**{result["status"]}**',f'文件：`{result["input"]}`',f'类型：{result.get("file_type","INVALID")}',f'SHA256：`{result["sha256"]}`',f'字节数：{result["bytes"]}','\n## 实际执行']
  lines.extend(f'- {pathlib.Path(r["argv"][0]).name}：exit {r["exit_code"]}，{r["elapsed_s"]} 秒；日志 `{r["stdout"]}`' for r in result['commands'])
  if result.get('error'):lines.append('阻塞：'+result['error'])
  data=result.get('analysis',{});info=data.get('info',{})
  if info:lines.extend(['\n## 静态结构',f'架构：{info.get("arch")}；位数：{info.get("bits")}；格式：{info.get("class")}',f'节区：{len(data.get("sections",[]))}；符号：{len(data.get("symbols",[]))}；导入：{len(data.get("imports",[]))}'])
  if result.get('decompiled_files'):lines.append(f'\nJava 文件回读：{len(result["decompiled_files"])} 份；Manifest 结构见 JSON。')
  if result.get('android_intelligence'):
   intel=result['android_intelligence'];verification=intel['verification']
   counts={name:value['count'] for name,value in intel['hotspots'].items() if value['count']}
   lines.extend(['\n## Android 架构与关键逻辑',f'证据图：{verification["graph_nodes"]} 节点 / {verification["graph_edges"]} 关系；扫描 {verification["source_files_scanned"]} 份源码。',f'关键逻辑线索：{json.dumps(counts,ensure_ascii=False)}',f'网络Origin：{", ".join(intel["network_origins"]) if intel["network_origins"] else "未发现"}',f'Native加载：{json.dumps(intel["native_links"]["load_libraries"],ensure_ascii=False)}',f'16KiB结构检查：{result["android_profile"]["native_16k_summary"]}。线索为启发式，须结合Evidence人工复核。'])
  lines.extend(['\n## 验证边界']+['- '+x for x in result['limitations']])
  (job/'报告.md').write_text('\n\n'.join(lines)+'\n');print(json.dumps({'status':result['status'],'json':str((job/'analysis.json').relative_to(ROOT)),'report':str((job/'报告.md').relative_to(ROOT))},ensure_ascii=False))
  return 0 if result['status']=='VERIFIED' else 2
if __name__=='__main__':raise SystemExit(main())
