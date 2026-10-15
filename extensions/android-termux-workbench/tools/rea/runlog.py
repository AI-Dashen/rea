"""Bounded sequential subprocess evidence; never invokes a shell."""
import os,subprocess,time,json,hashlib,signal,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
BASE=ROOT/'run/rea-b06dd042'
JAVA='/data/data/com.termux/files/usr/lib/jvm/java-21-openjdk/bin/java'
LOCAL=BASE/'local/data/data/com.termux/files/usr'
def env():
 (BASE/'home').mkdir(parents=True,exist_ok=True);(BASE/'tmp').mkdir(parents=True,exist_ok=True)
 e=os.environ.copy();e.update(HOME=str(BASE/'home'),TMPDIR=str(BASE/'tmp'),JAVA_HOME=str(pathlib.Path(JAVA).parents[1]),LD_LIBRARY_PATH=str(LOCAL/'lib'),R2_NOPLUGINS='1')
 e['PATH']=str(pathlib.Path(JAVA).parent)+':'+e['PATH'];return e
def sha(p):
 with open(p,'rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def run(label,argv,directory,timeout=60,cwd=ROOT):
 directory=pathlib.Path(directory);directory.mkdir(parents=True,exist_ok=True)
 out=directory/(label+'.stdout');err=directory/(label+'.stderr');t=time.time();expired=False;limited=False
 with out.open('wb') as o,err.open('wb') as e:
  try:
   p=subprocess.Popen(list(map(str,argv)),cwd=cwd,env=env(),stdin=subprocess.DEVNULL,stdout=o,stderr=e,start_new_session=True)
   while p.poll() is None:
    expired=time.time()-t>timeout;limited=out.stat().st_size+err.stat().st_size>16*1024*1024
    if expired or limited:
     os.killpg(p.pid,signal.SIGKILL);break
    time.sleep(.05)
   code=p.wait()
  except OSError as ex:e.write(str(ex).encode());code=127
 r=dict(argv=list(map(str,argv)),cwd=str(cwd),started_at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(t)),elapsed_s=round(time.time()-t,3),exit_code=code,timed_out=expired,output_limit=limited,stdout=str(out.relative_to(ROOT)),stderr=str(err.relative_to(ROOT)),stdout_sha256=sha(out),stderr_sha256=sha(err))
 (directory/(label+'.json')).write_text(json.dumps(r,ensure_ascii=False,indent=2));return r
