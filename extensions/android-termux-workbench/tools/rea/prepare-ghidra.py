"""Install verified official release into a new task-local tree, no system changes."""
from runlog import *
import zipfile,stat,shutil
c=BASE/'c1';ev=c/'evidence';meta=json.loads((ev/'ghidra-release.stdout').read_text());a=meta['assets'][0];archive=c/a['name']
assert archive.stat().st_size==a['size'] and sha(archive)==a['digest'].split(':')[1]
target=c/'ghidra-release';target.mkdir(exist_ok=False)
with zipfile.ZipFile(archive) as z:
 infos=z.infolist();total=sum(i.file_size for i in infos)
 assert len(infos)<100000 and total<2*1024**3
 roots=set()
 for i in infos:
  parts=pathlib.PurePosixPath(i.filename).parts
  assert not i.filename.startswith('/') and '..' not in parts and not stat.S_ISLNK(i.external_attr>>16)
  roots.add(parts[0])
 assert len(roots)==1
 z.extractall(target)
g=target/next(iter(roots));assert (g/'Ghidra/Framework/Utility/lib/Utility.jar').is_file()
record={'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'expected_sha256':a['digest'],'bytes':a['size'],'entries':len(infos),'expanded_bytes':total,'root':str(g.relative_to(ROOT)),'no_global_install':True}
(ev/'ghidra-install.json').write_text(json.dumps(record,indent=2))
probe=c/'PlatformProbe.java';probe.write_text('import ghidra.framework.Platform; public class PlatformProbe { public static void main(String[] a){ System.out.println("PLATFORM="+Platform.CURRENT_PLATFORM); System.out.println("OSDIR="+Platform.CURRENT_PLATFORM.getDirectoryName()); System.out.println("JAVA_OS="+System.getProperty("os.name")+"/"+System.getProperty("os.arch")); }}')
cp=':'.join(str(p) for p in g.rglob('*.jar'));(c/'probe-classes').mkdir(exist_ok=True)
r=run('platform-probe-compile',[pathlib.Path(JAVA).parent/'javac','-cp',cp,'-d',c/'probe-classes',probe],ev,30);assert r['exit_code']==0
r=run('platform-probe',[JAVA,'-Xmx128m','-Djava.awt.headless=true','-cp',str(c/'probe-classes')+':'+cp,'PlatformProbe'],ev,20);assert r['exit_code']==0
text=(ROOT/r['stdout']).read_text();assert 'OSDIR=linux_arm_64' in text and 'JAVA_OS=Linux/aarch64' in text
native=g/'Ghidra/Features/Decompiler/os/linux_arm_64/decompile';original={'path':str(native.relative_to(ROOT)),'sha256':sha(native) if native.is_file() else None}
if native.is_file():shutil.copy2(native,c/'release-native-ghidra-preserved')
source=ROOT/'run/rea-3a0be4d8/ghidra-source/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt';native.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,native);native.chmod(0o700)
(ev/'native-adaptation.json').write_text(json.dumps({'original_release_native':original,'source':str(source.relative_to(ROOT)),'target':str(native.relative_to(ROOT)),'source_sha256':sha(source),'target_sha256':sha(native),'matching_tag':'Ghidra_12.1.4_build','actual_platform_probe':text,'system_or_jvm_host_spoofing':False},indent=2))
print(json.dumps(record));print(text)
