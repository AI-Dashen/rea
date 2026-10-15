# Resume completed install/probe; no repeat extraction, download or compiler work.
from runlog import *
import shutil
c=BASE/'c1';ev=c/'evidence';record=json.loads((ev/'ghidra-install.json').read_text());g=ROOT/record['root']
text=(ev/'platform-probe.stdout').read_text()
assert 'OSDIR=linux_arm_64' in text and 'JAVA_OS=Linux/aarch64' in text
native=g/'Ghidra/Features/Decompiler/os/linux_arm_64/decompile';original={'path':str(native.relative_to(ROOT)),'sha256':sha(native) if native.is_file() else None}
backup=c/'release-native-ghidra-preserved'
if native.is_file():
 assert not backup.exists();shutil.copy2(native,backup)
source=ROOT/'run/rea-3a0be4d8/ghidra-source/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt';native.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,native);native.chmod(0o700)
(ev/'native-adaptation.json').write_text(json.dumps({'original_release_native':original,'source':str(source.relative_to(ROOT)),'target':str(native.relative_to(ROOT)),'source_sha256':sha(source),'target_sha256':sha(native),'matching_tag':'Ghidra_12.1.4_build','actual_platform_probe':text,'system_or_jvm_host_spoofing':False,'resume_reason':'first preparation checked enum toString against enum identifier; actual OSDIR and Java OS confirmed Linux/aarch64; no extraction/probe repeated'},indent=2))
print('matching Bionic decompiler placed in isolated release linux_arm_64')
