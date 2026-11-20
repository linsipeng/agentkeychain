import {rosterWitness} from '../../managed-cloud/shared/roster-witness.ts';
import {Database} from 'bun:sqlite';
import {readFileSync,readdirSync,readSync} from 'node:fs';
import sodium from 'libsodium-wrappers-sumo';
import worker from '../../managed-cloud/api-worker/index.ts';
import {deviceRepository} from '../../managed-cloud/api-worker/device-repository.ts';
import {digest} from '../../managed-cloud/shared/contracts.ts';
import {actionDigest} from '../../managed-cloud/shared/device-protocol.ts';
import {approvalRepository,decisionDigest} from '../../managed-cloud/api-worker/approval-repository.ts';
await sodium.ready;
let line='';const byte=Buffer.alloc(1);while(readSync(0,byte,0,1,null)){if(byte[0]===10)break;line+=byte.toString();}
const config=JSON.parse(line) as {db:string;token:string;checkpointPrivate:string;checkpointPublic:string};line='';
const sql=new Database(config.db);sql.exec('PRAGMA foreign_keys=ON;PRAGMA journal_mode=WAL;PRAGMA busy_timeout=5000;');
if(!sql.query("SELECT 1 FROM sqlite_master WHERE name='accounts'").get())for(const name of readdirSync('managed-cloud/api-worker/migrations').sort())sql.exec(readFileSync('managed-cloud/api-worker/migrations/'+name,'utf8'));
class Statement {
 constructor(readonly query:string,readonly values:unknown[]=[]){ }
 bind(...values:unknown[]){return new Statement(this.query,values);}
 execute(){const statement=sql.query(this.query),results=statement.all(...this.values as never[]);return {success:true,results,meta:{changes:sql.query('SELECT changes() AS n').get()?.n??0}};}
 async run(){return this.execute();}
 async all(){return this.execute();}
 async first(column?:string){const row=this.execute().results[0] as Record<string,unknown>|undefined;return column?row?.[column]??null:row??null;}
}
const db={prepare(query:string){return new Statement(query);},async batch(statements:Statement[]){return sql.transaction(()=>statements.map(s=>s.execute()))();}};
const witnessDB=new Database(config.db+'.witness');
if(!witnessDB.query("SELECT 1 FROM sqlite_master WHERE name='roster_witness'").get())witnessDB.exec(readFileSync('managed-cloud/recovery-worker/migrations/0004_roster_witness.sql','utf8'));
if(!(witnessDB.query('PRAGMA table_info(roster_witness)').all() as {name:string}[]).some(c=>c.name==='checkpoint_suffix'))witnessDB.exec(readFileSync('managed-cloud/recovery-worker/migrations/0007_witness_suffixes.sql','utf8'));
const witnessAdapter={prepare:(query:string)=>({bind:(...values:unknown[])=>({first:async()=>witnessDB.query(query).get(...values as never[])??null,run:async()=>witnessDB.query(query).run(...values as never[])})})};
const witnessKeys=sodium.crypto_sign_seed_keypair(sodium.crypto_generichash(32,Buffer.from('synthetic-witness:'+config.checkpointPrivate),null));
const witness=rosterWitness(witnessAdapter as never,{key:async()=>({keyId:'synthetic-witness',publicKey:Buffer.from(witnessKeys.publicKey).toString('base64')}),sign:async c=>Buffer.from(sodium.crypto_sign_detached(c,witnessKeys.privateKey)).toString('base64')},[{keyId:await digest(config.checkpointPublic),publicKey:config.checkpointPublic}],async()=>true);
const sessionDigest=await digest('synthetic-browser-session');
if(!sql.query("SELECT 1 FROM accounts WHERE id='account'").get()){
sql.run("INSERT OR IGNORE INTO accounts VALUES('account')");sql.run("INSERT OR IGNORE INTO tenants VALUES('tenant')");sql.run("INSERT OR IGNORE INTO memberships VALUES('tenant','account',1)");sql.run("INSERT OR IGNORE INTO vaults VALUES('tenant','vault',0)");
sql.run('INSERT OR IGNORE INTO browser_sessions(digest,csrf_digest,account_id,tenant_id,absolute_expires) VALUES(?,?,?,?,?)',[sessionDigest,await digest('synthetic-csrf'),'account','tenant',Math.floor(Date.now()/1000)+3600]);
}
const session={digest:sessionDigest,csrf_digest:await digest('synthetic-csrf'),account_id:'account',tenant_id:'tenant',absolute_expires:Math.floor(Date.now()/1000)+3600,step_up_digest:null,step_up_expires:null};
const repo=deviceRepository(db as never);let lose=false,offline=false,lossRoute='/sync/push';
const server=Bun.serve({hostname:'127.0.0.1',port:0,async fetch(request){
 const url=new URL(request.url);
 try{
  if(url.pathname.startsWith('/test/')){
   if(request.headers.get('authorization')!=='Bearer '+config.token)return new Response(null,{status:403});const input=await request.json() as Record<string,unknown>;
   if(url.pathname==='/test/browser'){
    const code=new URL(input.url as string).searchParams.get('code')!;
    const issuer=sql.query("SELECT id FROM devices WHERE active=1 ORDER BY rowid LIMIT 1").get() as {id:string}|null;
    const pair=await repo.pending(session,await digest(code),issuer?.id??null);
    if(!issuer){sql.run('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?',[await actionDigest('approve',pair.canonical),sessionDigest]);await repo.approve(session,pair.canonical,null);}
    return Response.json({requestId:pair.requestId,deviceId:pair.deviceId,requiresDevice:!!issuer});
   }
   if(url.pathname==='/test/deny-device'){sql.run('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?',[await actionDigest('deny',input.requestId as string),sessionDigest]);await repo.deny(session,input.requestId as string);return Response.json({denied:true});}
   if(url.pathname==='/test/approve-device'){
    const pairing=sql.query('SELECT canonical,signature FROM pairing_confirmations WHERE request_id=?').get(input.requestId as string) as {canonical:string;signature:string}|null;
    if(!pairing)return Response.json({pending:true});sql.run('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?',[await actionDigest('approve',pairing.canonical),sessionDigest]);await repo.approve(session,pairing.canonical,pairing.signature);return Response.json({approved:true});
   }
   if(url.pathname==='/test/approve'){
    const action=input.action==='deny'?'deny':input.action==='cancel'?'cancel':'approve';const ar=approvalRepository(db as never),detail=await ar.detail(session,input.requestId as string);sql.run('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?',[await decisionDigest(action,detail),sessionDigest]);await ar.decide(session,input.requestId as string,action);return Response.json({approved:true});
   }
   if(url.pathname==='/test/reset-rate'){sql.run('DELETE FROM auth_rate_windows');return Response.json({ok:true});}
   if(url.pathname==='/test/fault'){lose=input.lose===true;offline=input.offline===true;lossRoute=typeof input.lossRoute==='string'?input.lossRoute:'/sync/push';return Response.json({ok:true});}
   if(url.pathname==='/test/revoke'){const devices=await repo.list(session),device=devices.devices.find(d=>d.id===input.deviceId);if(!device)throw new Error();sql.run('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?',[device.revokeActionDigest,sessionDigest]);await repo.revoke(session,device.id);return Response.json({ok:true});}
   if(url.pathname==='/test/counts')return Response.json({versions:(sql.query('SELECT count(*) n FROM versions').get() as {n:number}).n,devices:(sql.query('SELECT count(*) n FROM devices').get() as {n:number}).n});
   return new Response(null,{status:404});
  }
  if(offline)return Response.json({error:{code:'internal_error'}},{status:503});
  const apiRequest=new Request('https://api.local.invalid'+url.pathname+url.search,{method:request.method,headers:request.headers,...(request.method==='GET'?{}:{body:await request.text()})});
  const response=await worker.fetch(apiRequest,{MAIN:db,RECOVERY:{witnessHead:async(t:string,v:string)=>{const h=await witness.head(t,v);return h?JSON.parse(h.receipt):null;},witness:(input:Parameters<typeof witness.accept>[0])=>witness.accept(input)},AUTH_ORIGIN:'https://local.invalid',DEVICE_API_ORIGIN:'https://api.local.invalid',TRUSTED_AUTH_SOURCE:{resolve:async()=> 'synthetic-'+(request.headers.get('x-test-source')??'loopback')},CHECKPOINT_SIGNER:{key:async()=>({keyId:await digest(config.checkpointPublic),publicKey:config.checkpointPublic}),sign:async(c:string)=>Buffer.from(sodium.crypto_sign_detached(c,Buffer.from(config.checkpointPrivate,'base64'))).toString('base64')}} as never);
  if(lose&&url.pathname.endsWith(lossRoute)&&response.ok){lose=false;return Response.json({error:{code:'internal_error'}},{status:503});}
  return response;
 }catch{return Response.json({error:{code:'test_service_failure'}},{status:500});}
}});
process.stdout.write(JSON.stringify({origin:`http://127.0.0.1:${server.port}`})+'\n');
process.on('SIGTERM',()=>{server.stop(true);sql.close();process.exit(0);});
