// Compatibility experiment: original Java metadata bridge only, NOT the REA JadxProvider.
import {Client} from '../../run/rea-3a0be4d8/released/node_modules/@modelcontextprotocol/client/dist/index.mjs';
import {StdioClientTransport} from '../../run/rea-3a0be4d8/released/node_modules/@modelcontextprotocol/client/dist/stdio.mjs';
import {inspectJadxAvailability} from '../../run/rea-3a0be4d8/released/node_modules/rea-agents/dist/android/JadxConfiguration.js';
import {writeFile,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
const root=path.resolve(new URL('../../',import.meta.url).pathname),base=root+'/run/rea-b06dd042',c=base+'/c1',ev=c+'/evidence';
const java='/data/data/com.termux/files/usr/lib/jvm/java-21-openjdk/bin/java',jar=c+'/jadx-headless-mcp-0.7.1-all.jar',bridge=root+'/run/rea-3a0be4d8/released/node_modules/rea-agents/bridge/android/ReaJadxBridge.java',apk=base+'/samples/owned.apk';
const hash=async p=>createHash('sha256').update(await readFile(p)).digest('hex');
if(await hash(jar)!=='6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75')throw Error('JAR_IDENTITY_MISMATCH');
const config={PATH:process.env.PATH,HOME:c+'/home',TMPDIR:c+'/tmp',JAVA_HOME:path.dirname(path.dirname(java)),REA_JADX_MCP_JAR:jar,REA_JADX_HEAP_MIB:'384',REA_JADX_ACTIVE_PROCESSOR_COUNT:'1'};
const availability=await inspectJadxAvailability(config);
await writeFile(ev+'/rea-apk-current-availability.json',JSON.stringify({platform:process.platform,arch:process.arch,configuration_supplied:true,availability},null,2));
const client=new Client({name:'termux-original-java-bridge-compatibility-probe',version:'1.0.0'},{capabilities:{}});
const transport=new StdioClientTransport({command:java,args:['-Xmx384m','-XX:ActiveProcessorCount=1','-Djava.awt.headless=true','-Duser.home='+c+'/home','-Djava.io.tmpdir='+c+'/tmp','--class-path',jar,bridge],cwd:c,env:config,stderr:'pipe',maxBufferSize:8*1024*1024});
transport.stderr?.on('data',b=>process.stderr.write(b));
const record={task_id:'b06dd042-8638-4a47-937d-8ae644a205b9',status:'BLOCKED',experiment:'unmodified-java-bridge-only-NOT-REA-PROVIDER',apk_sha256:await hash(apk),jar_sha256:await hash(jar),bridge_sha256:await hash(bridge),original_provider:availability,calls:[]};
try{
 await client.connect(transport,{timeout:30000});record.child_pid=transport.pid;record.server=client.getServerVersion();
 if(record.server?.name!=='rea-jadx-bridge'||record.server?.version!=='1')throw Error('BRIDGE_IDENTITY_MISMATCH');
 const catalog=await client.listTools();await writeFile(ev+'/jadx-bridge-tools.json',JSON.stringify(catalog,null,2));
 for(const [name,args] of [['rea_jvm_status',{}],['load_apk',{path:apk,threads:1,resources:'full'}],['get_app_info',{}],['get_android_manifest',{}],['list_classes',{offset:0,limit:20}],['get_class_summary',{class_name:'owned.acceptance.OwnedArithmetic'}],['get_method_body',{class_name:'owned.acceptance.OwnedArithmetic',method_name:'add',overload_index:0}]]){
  const result=await client.callTool({name,arguments:args},undefined,{timeout:30000});record.calls.push({name,arguments:args,result});
  if(result.isError)throw Error('BRIDGE_TOOL_ERROR '+name);
 }
 const get=n=>record.calls.find(x=>x.name===n).result.content.filter(x=>x.type==='text').map(x=>x.text).join('');
 const runtime=JSON.parse(get('rea_jvm_status')),classes=JSON.parse(get('list_classes')),method=JSON.parse(get('get_method_body'));
 if(runtime.engine_reported_version!=='0.7.1'||!classes.items.includes('owned.acceptance.OwnedArithmetic')||method.mode!=='java'||!method.body.includes('return'))throw Error('BRIDGE_RESULT_MISMATCH');
 record.runtime=runtime;record.method=method;record.status='VERIFIED';
}catch(e){record.error=String(e);process.exitCode=2;}
finally{
 await client.close();
 if(record.child_pid){try{process.kill(record.child_pid,0);record.child_alive_after_close=true;record.status='BLOCKED';record.error='child still alive after close';process.exitCode=2;}catch(e){record.child_alive_after_close=e.code!=='ESRCH';if(record.child_alive_after_close){record.status='BLOCKED';record.error='child exit unverified';process.exitCode=2;}}}
 await writeFile(ev+'/jadx-java-bridge-results.json',JSON.stringify(record,null,2));console.log(JSON.stringify({status:record.status,experiment:record.experiment,original_provider:availability.status,child_alive_after_close:record.child_alive_after_close}));
}
