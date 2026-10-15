#!/usr/bin/env python
"""Build small, owned fixtures used by the portable workbench tests."""

from runlog import *
import shutil, zipfile

s=BASE/'samples';s.mkdir(exist_ok=True)
ev=BASE/'evidence/build';ev.mkdir(parents=True,exist_ok=True)
(s/'owned.c').write_text('int owned_add(int a,int b){return a+b;} int main(void){return owned_add(2,3);}\n')
(s/'OwnedArithmetic.java').write_text('package owned.acceptance; public class OwnedArithmetic { public static int add(int a,int b){return a+b;} }\n')
(s/'AuditActivity.java').write_text('package owned.advanced; public class AuditActivity { public static String audit(String login){ String endpoint="https://api.example.test/v1/login?token=sample"; String signals="/system/bin/su isDebuggerConnected TracerPid AES MessageDigest"; return login+endpoint+signals; } }\n')
(s/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owned.acceptance"><application/></manifest>\n')
(s/'AndroidManifestAdvanced.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owned.advanced"><application/></manifest>\n')
for directory in ('classes','classes-advanced','dex','dex-advanced'):(s/directory).mkdir(exist_ok=True)
java=str(pathlib.Path(JAVA).parent/'javac')
d8=[JAVA,'-Xmx384m','-cp','/data/data/com.termux/files/usr/share/java/d8.jar','com.android.tools.r8.D8','--min-api','26']
steps=[
 ('elf',['clang','-O0','-g',s/'owned.c','-o',s/'owned.elf']),
 ('shared-elf',['clang','-shared','-fPIC','-O0','-g',s/'owned.c','-o',s/'libowned.so']),
 ('pe-object',['clang','--target=x86_64-pc-windows-msvc','-c',s/'owned.c','-o',s/'owned.obj']),
 ('pe-link',['lld-link','/entry:main','/subsystem:console','/nodefaultlib',f'/out:{s}/owned.exe',s/'owned.obj']),
 ('javac',[java,'--release','8','-d',s/'classes',s/'OwnedArithmetic.java']),
 ('d8',[*d8,'--output',s/'dex',s/'classes/owned/acceptance/OwnedArithmetic.class']),
 ('javac-advanced',[java,'--release','8','-d',s/'classes-advanced',s/'AuditActivity.java']),
 ('d8-advanced',[*d8,'--output',s/'dex-advanced',s/'classes-advanced/owned/advanced/AuditActivity.class']),
 ('apk-resources',['aapt','package','-f','-M',s/'AndroidManifest.xml','-F',s/'owned.apk']),
]
for label,argv in steps:
 r=run(label,argv,ev);print(label,r['exit_code'])
 if r['exit_code']!=0:raise SystemExit(1)
shutil.copy2(s/'owned.apk',s/'owned-advanced.apk')
with zipfile.ZipFile(s/'owned.apk','a') as z:z.write(s/'dex/classes.dex','classes.dex')
with zipfile.ZipFile(s/'owned-advanced.apk','a') as z:
 z.write(s/'dex-advanced/classes.dex','classes.dex');z.write(s/'libowned.so','lib/arm64-v8a/libowned.so')
shutil.copy2(s/'owned.apk',s/'owned-native-profile.apk')
with zipfile.ZipFile(s/'owned-native-profile.apk','a') as z:z.write(s/'owned.elf','lib/arm64-v8a/libjiagu.so')
(s/'malformed.exe').write_bytes(b'MZbroken')
with zipfile.ZipFile(s/'negative.apk','w') as z:z.writestr('AndroidManifest.xml','not binary XML')
manifest={p.name:{'bytes':p.stat().st_size,'sha256':sha(p)} for p in s.iterdir() if p.is_file()}
(ev/'samples.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(manifest,indent=2))
