// Original REA MCP, no host spoofing or import patch.
import {Client} from '../../run/rea-3a0be4d8/released/node_modules/@modelcontextprotocol/client/dist/index.mjs';
import {StdioClientTransport} from '../../run/rea-3a0be4d8/released/node_modules/@modelcontextprotocol/client/dist/stdio.mjs';
import {realpath} from 'node:fs/promises';
import path from 'node:path';
const root=path.resolve(new URL('../../',import.meta.url).pathname),base=root+'/run/rea-b06dd042';
const target=await realpath(process.argv[2]);
if(!target.startsWith(base+'/samples/')&&!target.startsWith(base+'/inbox/'))throw Error('TARGET_DENIED');
const client=new Client({name:'rea-termux-static-followup',version:'1.0.0'},{capabilities:{}});
const transport=new StdioClientTransport({command:process.execPath,args:[root+'/run/rea-3a0be4d8/released/node_modules/rea-agents/scripts/rea.mjs','mcp'],cwd:base,env:{PATH:process.env.PATH,HOME:base+'/home',TMPDIR:base+'/tmp',REA_MCP_INPUT_SCHEMA_PROFILE:'compact'},stderr:'pipe',maxBufferSize:16*1024*1024});
transport.stderr?.on('data',b=>process.stderr.write(b));
try{
 await client.connect(transport);
 const session=await client.callTool({name:'binary_session',arguments:{expected_package_version:'6.3.0'}},undefined,{timeout:45000});
 if(session.isError||client.getServerVersion()?.version!=='6.3.0')throw Error('SERVER_IDENTITY_MISMATCH');
 const result=await client.callTool({name:'inspect_managed_artifact',arguments:{path:target}},undefined,{timeout:45000});
 console.log(JSON.stringify({task_id:'b06dd042-8638-4a47-937d-8ae644a205b9',server:client.getServerVersion(),rea_result:result}));
 if(result.isError||!result.structuredContent)process.exitCode=1;
}finally{await client.close();}
