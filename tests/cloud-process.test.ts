/* eslint-disable no-unused-vars -- callback type */
import {URL,URLSearchParams} from 'node:url';
import {expect,test} from 'bun:test';
import {Database} from 'bun:sqlite';
import {spawn,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {mkdtempSync,mkdirSync,rmSync,readFileSync,existsSync,readdirSync,renameSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalManifest} from '../src/cloud/config.ts';
import {migrate} from '../src/db/migrate.ts';
import {initVault} from '../src/cli/init.ts';
const pause=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(fn:()=>boolean,ms=15000){const end=Date.now()+ms;while(!fn()){if(Date.now()>end)throw new Error('process_acceptance_timeout');await pause(30);}}
function child(cmd:string,args:string[],input:string){
 const p=spawn(cmd,args,{cwd:resolve('.'),env:{PATH:process.env.PATH!,TMPDIR:tmpdir()},stdio:['pipe','pipe','pipe']});let stdout='',stderr='';
 p.stdout.on('data',data=>{stdout+=data.toString();});p.stderr.on('data',data=>{stderr+=data.toString();});p.stdin.write(input);
 const done=new Promise<number>(resolve=>{p.on('exit',code=>resolve(code??-1));p.on('error',()=>resolve(-1));});
 return {p,done,out:()=>stdout,err:()=>stderr};
}
test('compiled CLI clients enroll via HTTP, compare SAS, capture, sync, retry and restart with persistent service',async()=>{
 await sodium.ready;const root=mkdtempSync(join(tmpdir(),'akc-phase45-process-')),a=join(root,'a'),b=join(root,'b');mkdirSync(a,{mode:0o700});mkdirSync(b,{mode:0o700});
 const binary=join(root,'client'),password=randomUUID()+randomUUID(),token=randomBytes(32).toString('base64url'),cp=sodium.crypto_sign_keypair(),b64=(v:Uint8Array)=>Buffer.from(v).toString('base64');
 const children:ChildProcessWithoutNullStreams[]=[];let stub:ReturnType<typeof Bun.serve>|undefined;
 try{
  for(const home of [a,b]){const db=new Database(join(home,'vault.db'));migrate(db);await initVault(db,password);db.close();}
  const build=child(process.execPath,['scripts/phase45/build-client.ts',binary],'');children.push(build.p);build.p.stdin.end();expect(await build.done).toBe(0);
  const service=child(process.execPath,['scripts/phase45/service.ts'],JSON.stringify({db:join(root,'service.db'),token,checkpointPrivate:b64(cp.privateKey),checkpointPublic:b64(cp.publicKey)})+'\n');children.push(service.p);
  await until(()=>service.out().includes('\n')||service.p.exitCode!==null);if(service.p.exitCode!==null)throw new Error('local_service_start_failed '+service.err());let origin=(JSON.parse(service.out().trim()) as {origin:string}).origin;
  const control=async(path:string,body:unknown)=>{const r=await fetch(origin+'/test/'+path,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token},body:JSON.stringify(body)});if(!r.ok)throw new Error('service_control_'+path+'_failed');return r.json() as Promise<Record<string,unknown>>;};
  const homes=[a,b];const secrets=new Map<string,string>(),phrases=new Map<string,{phrase:string;resolve:(v:Response)=>void}>();let secondRequest:string|null=null,secondDevice:string|null=null;
  stub=Bun.serve({hostname:'127.0.0.1',port:0,async fetch(request){
   if(request.headers.get('authorization')!=='Bearer '+token)return new Response(null,{status:403});
   const body=await request.json() as {home:string;value:unknown};if(!homes.includes(body.home))return new Response(null,{status:403});const path=new URL(request.url).pathname;
   if(path==='/get')return Response.json({value:secrets.get(body.home+':'+body.value)??null});
   if(path==='/put'){const v=body.value as {account:string;value:string};secrets.set(body.home+':'+v.account,v.value);return Response.json({ok:true});}
   if(path==='/remove'){secrets.delete(body.home+':'+body.value);return Response.json({ok:true});}
   if(path==='/browser'){const result=await control('browser',body.value);if(result.requiresDevice){secondRequest=result.requestId as string;secondDevice=result.deviceId as string;}return Response.json(result);}
   if(path==='/phrase')return new Promise<Response>(resolve=>{phrases.set(body.home,{phrase:(body.value as {phrase:string}).phrase,resolve});if(phrases.size===2){const confirmed=phrases.get(a)!.phrase===phrases.get(b)!.phrase;for(const p of phrases.values())p.resolve(Response.json({confirmed}));}});
   return new Response(null,{status:404});
  }});
  const canonical=canonicalManifest({witnessKeys:[{keyId:'synthetic-witness',publicKey:b64(sodium.crypto_sign_seed_keypair(sodium.crypto_generichash(32,Buffer.from('synthetic-witness:'+b64(cp.privateKey)),null)).publicKey)}],version:1,releaseId:'process-test',apiOrigin:'https://api.local.invalid',webOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[{keyId:createHash('sha256').update(b64(cp.publicKey)).digest('hex'),publicKey:b64(cp.publicKey)}]});
  const boot=(home:string,fault?:string)=>JSON.stringify({fault,clockOffset:fault==='issuer-expired'?601000:0,home,password,api:origin,secure:`http://127.0.0.1:${stub!.port}`,token,manifest:{canonical,signature:b64(sodium.crypto_sign_detached(canonical,cp.privateKey))},rootPublicKey:b64(cp.publicKey)})+'\n';
  const cli=(home:string,args:string[],fault?:string)=>{const p=child(binary,args,boot(home,fault));children.push(p.p);return p;};
  const syncMatrix=async(home:string,push=true)=>{
   const faults=push?['sync:after-lease','before:/v1/vaults/vault/sync/push','after:/v1/vaults/vault/sync/push','sync:receipt','sync:before-renew','before:/v1/vaults/vault/sync/pull','after:/v1/vaults/vault/sync/pull','sync:verified','sync:applied','sync:cursor']:['sync:after-lease','before:/v1/vaults/vault/sync/pull','after:/v1/vaults/vault/sync/pull','sync:verified','sync:applied','sync:cursor','sync:committed'];
   for(const fault of faults){await control('reset-rate',{});const crashed=cli(home,['cloud','sync-now'],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(fault.startsWith('sync:')?98:94);await pause(600);}
  };
  const legacyValue=randomUUID(),legacy=cli(a,['store','legacy','--scopes','test']);legacy.p.stdin.end(legacyValue+'\n');expect(await legacy.done,legacy.err()).toBe(0);
  const legacyDb=new Database(join(a,'vault.db'),{readonly:true});const oldRows=JSON.stringify(legacyDb.query('SELECT * FROM secrets').all());legacyDb.close();
  for(const slot of ['enrollment-intent','signing-private','wrapping-private','csk'])for(const timing of ['before','after']){
   const fault='secure:'+timing+':'+slot,crashed=cli(a,['cloud','login'],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(96);
  }
  const interrupted=cli(a,['cloud','login'],'enrollment-interrupt'),interruptedCode=await interrupted.done;if(interruptedCode!==92)throw new Error('enrollment-interrupt '+interruptedCode+' '+interrupted.err());
  for(const slot of ['enrollment-activation','roster-anchor','checkpoint-anchor'])for(const timing of ['before','after']){
   const fault='secure:'+timing+':'+slot,crashed=cli(a,['cloud','login'],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(96);await pause(600);
   const check=new Database(join(a,'vault.db'),{readonly:true});expect(JSON.stringify(check.query('SELECT * FROM secrets').all())).toBe(oldRows);check.close();
  }

  for(const fault of ['enrollment:before-sqlite','enrollment:after-sqlite','secure:before-remove:enrollment-intent','secure:after-remove:enrollment-intent']){
   const crashed=cli(a,['cloud','login'],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(96);await pause(600);
  }
  const loginA=cli(a,['cloud','login']);expect(await Promise.race([loginA.done,pause(15000).then(()=>{throw new Error('login_A_timeout '+loginA.err());})]),loginA.err()).toBe(0);
  const migratedDb=new Database(join(a,'vault.db'),{readonly:true});expect(JSON.stringify(migratedDb.query('SELECT * FROM secrets').all())).toBe(oldRows);migratedDb.close();
  const interruptedB=cli(b,['cloud','login'],'enrollment-interrupt');expect(await interruptedB.done).toBe(92);const deniedRequest=secondRequest!;
  const deniedIssuer=cli(a,['cloud','approve-device',deniedRequest],'before:/v1/devices/pairing-confirm');expect(await deniedIssuer.done,deniedIssuer.err()).toBe(94);await pause(600);
  await control('deny-device',{requestId:deniedRequest});const deniedTarget=cli(b,['cloud','login']);expect(await deniedTarget.done).toBe(1);expect(deniedTarget.err()).toContain('cloud_authorization_denied');
  const oldIssuer=cli(a,['cloud','approve-device',deniedRequest]);expect(await oldIssuer.done).toBe(1);expect(oldIssuer.err()).toContain('cloud_issuer_request_conflict');
  secondRequest=null;const loginB=cli(b,['cloud','login']);await until(()=>secondRequest!==null);expect(secondRequest).not.toBe(deniedRequest);

  for(const fault of ['before:/v1/devices/pairing-detail','after:/v1/devices/pairing-detail','issuer:before-journal','issuer:uncommitted-journal','before:/v1/devices/pairing-confirm']){
   const crashed=cli(a,['cloud','approve-device',secondRequest!],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(fault.startsWith('issuer:')?97:94);await pause(600);
  }
  const approve=cli(a,['cloud','approve-device',secondRequest!],'before:/v1/devices/trust-bundle');
  let approved=false;for(let i=0;i<100&&!approved;i++){approved=(await control('approve-device',{requestId:secondRequest})).approved===true;if(!approved)await pause(50);}expect(approved).toBe(true);
  expect(await approve.done,approve.err()).toBe(94);await pause(600);
  for(const fault of ['after:/v1/devices/trust-bundle','issuer:phrase-pending','issuer:phrase-confirmed','before:/v1/devices/enroll','after:/v1/devices/enroll','issuer:before-receipt','issuer:before-cleanup']){
   const crashed=cli(a,['cloud','approve-device',secondRequest!],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(fault.startsWith('issuer:')?97:94);await pause(600);
  }
  expect(await loginB.done,loginB.err()).toBe(0);expect(phrases.size).toBe(2);
  const resumedIssuer=cli(a,['cloud','approve-device',secondRequest!]);expect(await resumedIssuer.done,resumedIssuer.err()).toBe(0);
  const deliveredDb=new Database(join(root,'service.db'),{readonly:true}),canonicalDelivery=JSON.stringify(deliveredDb.query('SELECT * FROM trusted_enrollment_bundles').all()),canonicalPackages=JSON.stringify(deliveredDb.query('SELECT * FROM device_key_packages').all());deliveredDb.close();
  const concurrentIssuers=[cli(a,['cloud','approve-device',secondRequest!]),cli(a,['cloud','approve-device',secondRequest!])];
  const issuerResults=await Promise.all(concurrentIssuers.map(p=>p.done));expect(issuerResults.every(code=>code===0||code===1)).toBe(true);expect(issuerResults).toContain(0);
  for(let i=0;i<issuerResults.length;i++)if(issuerResults[i]===1)expect(concurrentIssuers[i]!.err()).toContain('cloud_sync_busy');
  const afterIssuers=new Database(join(root,'service.db'),{readonly:true});expect(JSON.stringify(afterIssuers.query('SELECT * FROM trusted_enrollment_bundles').all())).toBe(canonicalDelivery);expect(JSON.stringify(afterIssuers.query('SELECT * FROM device_key_packages').all())).toBe(canonicalPackages);afterIssuers.close();
  for(const fault of ['mutation:before','mutation:local','mutation:outbox']){
   const interrupted=cli(a,['store','interrupted-create','--scopes','test'],fault);interrupted.p.stdin.end(randomUUID()+'\n');expect(await interrupted.done,interrupted.err()).toBe(99);
   const db=new Database(join(a,'vault.db'),{readonly:true});expect(db.query("SELECT 1 FROM secrets WHERE name='interrupted-create'").get()).toBeNull();db.close();
  }
  let value=randomUUID()+randomUUID();const capture=cli(a,['capture','process-synthetic','--purpose','test credential','--no-open','--json']);
  await until(()=>capture.out().includes('\n'));
  const localUrl=(JSON.parse(capture.out().split('\n')[0]!) as {localUrl:string}).localUrl;
  expect((await fetch(localUrl,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({value})})).status).toBe(200);expect(await capture.done).toBe(0);
  for(const fault of ['sync:after-lease','before:/v1/vaults/vault/sync/push','after:/v1/vaults/vault/sync/push','sync:receipt','sync:before-renew','before:/v1/vaults/vault/sync/pull','after:/v1/vaults/vault/sync/pull','sync:verified','sync:applied','sync:cursor']){
   await control('reset-rate',{});const crashed=cli(a,['cloud','sync-now'],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(fault.startsWith('sync:')?98:94);await pause(600);
  }
  await control('fault',{lose:true});expect(await cli(a,['cloud','sync-now']).done).toBe(1);const committedCrash=cli(a,['cloud','sync-now'],'sync:committed');expect(await committedCrash.done,committedCrash.err()).toBe(98);await pause(600);const retried=cli(a,['cloud','sync-now']);expect(await retried.done,retried.err()+' '+service.err()).toBe(0);
  expect((await control('counts',{})).versions).toBe(2);
  const beforeCrashDb=new Database(join(b,'vault.db'),{readonly:true});const beforeCursor=JSON.stringify(beforeCrashDb.query("SELECT * FROM cloud_state WHERE id='cursor'").get());beforeCrashDb.close();
  expect(await cli(b,['cloud','sync-now'],'pull-crash').done).toBe(91);
  const afterCrashDb=new Database(join(b,'vault.db'),{readonly:true});expect(JSON.stringify(afterCrashDb.query("SELECT * FROM cloud_state WHERE id='cursor'").get())).toBe(beforeCursor);expect((afterCrashDb.query('SELECT count(*) n FROM cloud_history').get() as {n:number}).n).toBe(0);afterCrashDb.close();await pause(600);
  expect(await cli(b,['cloud','sync-now']).done).toBe(0);
  const get=cli(b,['get','process-synthetic']);expect(await get.done).toBe(0);expect(get.out().trim()===value).toBe(true);
  for(const home of [a,b])expect(readFileSync(join(home,'vault.db')).includes(Buffer.from(value))).toBe(false);
  const mcp=cli(b,['serve']);mcp.p.stdin.write(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'synthetic',version:'1'}}})+'\n');await until(()=>mcp.out().includes('"id":1'));
  mcp.p.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n'+JSON.stringify({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'akc_get',arguments:{name:'process-synthetic'}}})+'\n');await until(()=>mcp.out().includes('"id":2'));
  const result=mcp.out().split('\n').filter(Boolean).map(line=>JSON.parse(line) as {id:number;result?:unknown}).find(r=>r.id===2);expect(JSON.stringify(result?.result).includes(value)).toBe(true);mcp.p.kill('SIGTERM');
  const rotate=cli(a,['cloud','rotate','process-synthetic','--no-open','--json']);await until(()=>rotate.out().includes('\n'));
  const rotationUrl=(JSON.parse(rotate.out().split('\n')[0]!) as {localUrl:string}).localUrl,rotatedValue=randomUUID();
  expect((await fetch(rotationUrl,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({value:rotatedValue})})).status).toBe(200);expect(await rotate.done,rotate.err()).toBe(0);
  const rotationId=(JSON.parse(rotate.out().trim().split('\n').at(-1)!) as {requestId:string}).requestId;
  const unapproved=cli(a,['get','process-synthetic']);expect(await unapproved.done).toBe(0);expect(unapproved.out().trim()===value).toBe(true);
  await control('approve',{requestId:rotationId});await syncMatrix(a);expect(await cli(a,['cloud','sync-now']).done).toBe(0);await syncMatrix(b,false);expect(await cli(b,['cloud','sync-now']).done).toBe(0);value=rotatedValue;
  const rotatedGet=cli(b,['get','process-synthetic']);expect(await rotatedGet.done).toBe(0);expect(rotatedGet.out().trim()===value).toBe(true);
  const deletion=cli(a,['cloud','request-approval','delete','process-synthetic']);expect(await deletion.done,deletion.err()).toBe(0);
  const deletionRequest=JSON.parse(deletion.out()) as {requestId:string};await control('approve',{requestId:deletionRequest.requestId});await syncMatrix(a);expect(await cli(a,['cloud','sync-now']).done).toBe(0);expect(await cli(b,['cloud','sync-now']).done).toBe(0);
  expect(await cli(b,['get','process-synthetic']).done).not.toBe(0);
  const bypass=cli(a,['store','process-synthetic','--scopes','test']);bypass.p.stdin.end(randomUUID()+'\n');expect(await bypass.done).not.toBe(0);
  const restore=cli(a,['cloud','request-approval','restore','process-synthetic']);expect(await restore.done,restore.err()).toBe(0);await control('approve',{requestId:(JSON.parse(restore.out()) as {requestId:string}).requestId});await syncMatrix(a);expect(await cli(a,['cloud','sync-now']).done).toBe(0);expect(await cli(b,['cloud','sync-now']).done).toBe(0);
  const restored=cli(b,['get','process-synthetic']);expect(await restored.done).toBe(0);expect(restored.out().trim()===value).toBe(true);
  const scope=cli(a,['cloud','request-approval','scope','process-synthetic','test,synthetic']);expect(await scope.done,scope.err()).toBe(0);await control('approve',{requestId:(JSON.parse(scope.out()) as {requestId:string}).requestId});await syncMatrix(a);expect(await cli(a,['cloud','sync-now']).done).toBe(0);await syncMatrix(b,false);expect(await cli(b,['cloud','sync-now']).done).toBe(0);
  const exportPath=join(root,'approved.akcbundle');
  const blockedExport=cli(a,['export','--out',exportPath,'--yes']);expect(await blockedExport.done).toBe(1);expect(existsSync(exportPath)).toBe(false);
  const exportRequest=cli(a,['cloud','request-export',exportPath]);expect(await exportRequest.done,exportRequest.err()).toBe(0);
  const exportId=(JSON.parse(exportRequest.out()) as {requestId:string}).requestId;
  expect(await cli(a,['export','--out',exportPath,'--yes']).done).toBe(1);expect(existsSync(exportPath)).toBe(false);
  await control('approve',{requestId:exportId});await control('fault',{lose:true,lossRoute:'/export-consume'});expect(await cli(a,['export','--out',exportPath]).done).toBe(1);expect(existsSync(exportPath)).toBe(false);const exported=cli(a,['export','--out',exportPath]);expect(await exported.done,exported.err()).toBe(0);
  expect(readFileSync(exportPath).includes(Buffer.from(value))).toBe(false);expect(await cli(a,['export','--out',exportPath]).done).toBe(1);
  for(const stage of ['before-consume','after-consume','before-payload','before-journal','after-journal','after-create','after-staging-fsync','before-link','after-link','after-output-fsync','before-cleanup','before-complete']){
   await control('reset-rate',{});
   const path=join(root,'export-'+stage+'.akcbundle');
   const requested=cli(a,['cloud','request-export',path]);expect(await requested.done,requested.err()).toBe(0);
   await control('approve',{requestId:(JSON.parse(requested.out()) as {requestId:string}).requestId});
   const crashed=cli(a,['export','--out',path],'export:'+stage);expect(await crashed.done,stage+' '+crashed.err()).toBe(95);
   const before=existsSync(path)?readFileSync(path):null;
   const resumed=cli(a,['export','--out',path]);expect(await resumed.done,stage+' '+resumed.err()).toBe(0);
   const delivered=readFileSync(path);expect(delivered.includes(Buffer.from(value))).toBe(false);
   if(before)expect(delivered.equals(before)).toBe(true);
   expect(readdirSync(root).filter(name=>name.startsWith('.agentkeychain-export-'))).toHaveLength(0);
   expect(await cli(a,['export','--out',path]).done).toBe(1);
  }
  for(const mode of ['export-error','export-parent','export-symlink'])for(const stage of ['after-create','after-staging-fsync','before-link','after-link','after-output-fsync','before-cleanup','before-complete']){
   await control('reset-rate',{});
   const parent=join(root,mode+'-'+stage);mkdirSync(parent,{mode:0o700});const path=join(parent,'bundle');
   const requested=cli(a,['cloud','request-export',path]);expect(await requested.done,requested.err()).toBe(0);await control('approve',{requestId:(JSON.parse(requested.out()) as {requestId:string}).requestId});
   const failed=cli(a,['export','--out',path],mode+':'+stage);expect(await failed.done,failed.err()).toBe(1);
   if(mode==='export-parent'||mode==='export-symlink'){expect(readFileSync(join(parent,'unrelated'),'utf8')).toBe('preserve');expect(readdirSync(parent)).toEqual(['unrelated']);rmSync(parent,{recursive:true});renameSync(parent+'.moved',parent);}
   const before=existsSync(path)?readFileSync(path):null,resumed=cli(a,['export','--out',path]);expect(await resumed.done,resumed.err()).toBe(0);if(before)expect(readFileSync(path).equals(before)).toBe(true);
   expect(readFileSync(path).includes(Buffer.from(value))).toBe(false);expect(readdirSync(parent)).toEqual(['bundle']);
  }
  {
   await control('reset-rate',{});const path=join(root,'completed.bundle'),request=cli(a,['cloud','request-export',path]);expect(await request.done).toBe(0);await control('approve',{requestId:(JSON.parse(request.out()) as {requestId:string}).requestId});
   const crashed=cli(a,['export','--out',path],'export:after-complete');expect(await crashed.done,crashed.err()).toBe(95);const bytes=readFileSync(path);expect(await cli(a,['export','--out',path]).done).toBe(1);expect(readFileSync(path).equals(bytes)).toBe(true);
  }
  for(let fsync=1;fsync<=5;fsync++){
   await control('reset-rate',{});const path=join(root,'fsync-'+fsync+'.bundle'),request=cli(a,['cloud','request-export',path]);expect(await request.done,request.err()).toBe(0);await control('approve',{requestId:(JSON.parse(request.out()) as {requestId:string}).requestId});
   const failed=cli(a,['export','--out',path],'export-fsync:'+fsync);expect(await failed.done,failed.err()).toBe(1);const resumed=cli(a,['export','--out',path]);expect(await resumed.done,resumed.err()).toBe(0);expect(readFileSync(path).includes(Buffer.from(value))).toBe(false);
  }
  const legacyEdit=new Database(join(a,'vault.db'));legacyEdit.run("UPDATE secrets SET metadata='{\"legacy\":true}',version=version+1 WHERE name='process-synthetic'");legacyEdit.close();
  const reconcile=cli(a,['cloud','reconcile','process-synthetic']);expect(await reconcile.done,reconcile.err()).toBe(0);
  await control('approve',{requestId:(JSON.parse(reconcile.out()) as {requestId:string}).requestId});await syncMatrix(a);expect(await cli(a,['cloud','sync-now']).done).toBe(0);expect(await cli(b,['cloud','sync-now']).done).toBe(0);
  for(const action of ['deny','cancel','replace']){
   await control('reset-rate',{});
   const edit=new Database(join(a,'vault.db'));edit.run("UPDATE secrets SET version=version+1 WHERE name='process-synthetic'");edit.close();
   const first=cli(a,['cloud','reconcile','process-synthetic']);expect(await first.done,first.err()).toBe(0);
   const oldRequest=(JSON.parse(first.out()) as {requestId:string}).requestId;
   if(action==='replace'){
    const old=new Database(join(a,'vault.db'));old.run("UPDATE secrets SET version=version+1 WHERE name='process-synthetic'");old.close();
    await control('approve',{requestId:oldRequest});
   }else await control('approve',{requestId:oldRequest,action});
   for(const fault of ['reconcile:retired','reconcile:removed']){const crashed=cli(a,['cloud','sync-now'],fault);expect(await crashed.done,action+' '+fault+' '+crashed.err()).toBe(99);await pause(600);}
   expect(await cli(a,['cloud','sync-now']).done).toBe(0);
   const status=cli(a,['cloud','reconcile']);expect(await status.done).toBe(0);
   expect((JSON.parse(status.out()) as {state:string}[])[0]!.state).toBe(action==='replace'?'stale':action==='deny'?'denied':'cancelled');
   const replacement=cli(a,['cloud','reconcile','process-synthetic']);expect(await replacement.done,replacement.err()).toBe(0);
   const replacementId=(JSON.parse(replacement.out()) as {requestId:string}).requestId;expect(replacementId).not.toBe(oldRequest);
   await control('approve',{requestId:replacementId});expect(await cli(a,['cloud','sync-now']).done).toBe(0);expect(await cli(b,['cloud','sync-now']).done).toBe(0);
  }
  for(const fault of ['daemon:acquired','daemon:renewed','sync:committed']){
   const crashed=cli(a,['cloud','service','run'],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(fault.startsWith('daemon:')?100:98);await pause(600);
  }
  const daemonA=cli(a,['cloud','service','run']),daemonB=cli(b,['cloud','service','run']);await until(()=>existsSync(join(a,'cloud.sock'))&&existsSync(join(b,'cloud.sock')));
  const automaticValue=randomUUID(),automatic=cli(a,['store','automatic-synthetic','--scopes','test']);automatic.p.stdin.end(automaticValue+'\n');expect(await automatic.done).toBe(0);
  await until(()=>{const db=new Database(join(b,'vault.db'),{readonly:true});try{return !!db.query("SELECT 1 FROM secrets WHERE name='automatic-synthetic'").get();}finally{db.close();}});
  const automaticGet=cli(b,['get','automatic-synthetic']);expect(await automaticGet.done).toBe(0);expect(automaticGet.out().trim()===automaticValue).toBe(true);
  expect(await cli(a,['cloud','service','stop']).done).toBe(0);expect(await cli(b,['cloud','service','stop']).done).toBe(0);expect(await Promise.all([daemonA.done,daemonB.done])).toEqual([0,0]);
  await control('fault',{offline:true});const queued=cli(a,['store','offline-synthetic','--scopes','test']);queued.p.stdin.end(randomUUID()+'\n');expect(await queued.done).toBe(0);expect(await cli(a,['cloud','sync-now']).done).not.toBe(0);await control('fault',{});expect(await cli(a,['cloud','sync-now']).done).toBe(0);
  const before=(await control('counts',{})).versions;service.p.kill('SIGTERM');await service.done;
  const restarted=child(process.execPath,['scripts/phase45/service.ts'],JSON.stringify({db:join(root,'service.db'),token,checkpointPrivate:b64(cp.privateKey),checkpointPublic:b64(cp.publicKey)})+'\n');children.push(restarted.p);await until(()=>restarted.out().includes('\n'));origin=(JSON.parse(restarted.out().trim()) as {origin:string}).origin;
  expect((await control('counts',{})).versions).toBe(before);expect(await cli(b,['cloud','sync-now']).done).toBe(0);
  const devices=cli(b,['cloud','devices']);expect(await devices.done).toBe(0);const roster=JSON.parse(devices.out()) as {deviceId:string}[];
  expect(roster.some(d=>d.deviceId===secondDevice)).toBe(true);
  const historical=cli(b,['store','historical-b','--scopes','test']);historical.p.stdin.end(randomUUID()+'\n');expect(await historical.done).toBe(0);expect(await cli(b,['cloud','sync-now']).done).toBe(0);
  const bqueue=cli(b,['store','revoked-pending','--scopes','test']);bqueue.p.stdin.end(randomUUID()+'\n');expect(await bqueue.done).toBe(0);const beforeRevokeDb=new Database(join(b,'vault.db'),{readonly:true});const queueBytes=JSON.stringify(beforeRevokeDb.query('SELECT * FROM cloud_outbox').all());beforeRevokeDb.close();
  await control('revoke',{deviceId:secondDevice});
  for(const fault of ['secure:before:roster-anchor','secure:after:roster-anchor']){const crashed=cli(a,['cloud','sync-now'],fault);expect(await crashed.done,fault+' '+crashed.err()).toBe(96);await pause(600);}
  const propagate=cli(a,['cloud','sync-now']);expect(await propagate.done,propagate.err()).toBe(0);
  const signedDevices=cli(a,['cloud','devices']);expect(await signedDevices.done).toBe(0);expect((JSON.parse(signedDevices.out()) as {deviceId:string;revoked:boolean}[]).find(d=>d.deviceId===secondDevice)?.revoked).toBe(true);
  const revokedDaemon=cli(b,['cloud','service','run']);expect(await revokedDaemon.done,revokedDaemon.err()).toBe(0);
  const restartedB=cli(b,['cloud','sync-now']);expect(await restartedB.done).toBe(1);expect(restartedB.err()).toContain('revoked');
  const blockedWrite=cli(b,['store','after-revocation','--scopes','test']);blockedWrite.p.stdin.end(randomUUID()+'\n');expect(await blockedWrite.done).toBe(1);expect(blockedWrite.err()).toContain('revoked');
  expect(await cli(a,['cloud','sync-now']).done).toBe(0); // Historical B signatures remain verifiable after restart.
  const revokedDb=new Database(join(b,'vault.db'),{readonly:true});expect((revokedDb.query('SELECT count(*) n FROM cloud_outbox').get() as {n:number}).n).toBe(1);expect(JSON.stringify(revokedDb.query('SELECT * FROM cloud_outbox').all())).toBe(queueBytes);revokedDb.close();
  {
   const c=join(root,'expiry-target');mkdirSync(c,{mode:0o700});homes.push(c);const db=new Database(join(c,'vault.db'));migrate(db);await initVault(db,password);db.close();await control('reset-rate',{});
   const pending=cli(c,['cloud','login'],'enrollment-interrupt');expect(await pending.done,pending.err()).toBe(92);const expiredRequest=secondRequest!;
   const revokedIssuer=cli(b,['cloud','approve-device',expiredRequest]);expect(await revokedIssuer.done).toBe(1);
   const prepared=cli(a,['cloud','approve-device',expiredRequest],'before:/v1/devices/pairing-confirm');expect(await prepared.done,prepared.err()).toBe(94);await pause(600);
   const {CloudStore}=await import('../src/cloud/persistence.ts');const issuerDb=new Database(join(a,'vault.db')),issuerStore=new CloudStore(issuerDb,Buffer.from(secrets.get(a+':csk')!,'base64'));const original=issuerStore.get<{sealed:string;phrase:string}>('state','issuer:'+expiredRequest)!;
   const expired=cli(a,['cloud','approve-device',expiredRequest],'issuer-expired');expect(await expired.done,expired.err()).toBe(1);expect(expired.err()).toContain('cloud_authorization_expired');expect(issuerStore.get('state','issuer:'+expiredRequest)).toBeNull();
   const rejected=cli(a,['cloud','approve-device',expiredRequest]);expect(await rejected.done).toBe(1);expect(rejected.err()).toContain('cloud_issuer_request_conflict');
   const targetDb=new Database(join(c,'vault.db')),targetStore=new CloudStore(targetDb,Buffer.from(secrets.get(c+':csk')!,'base64'));const authorization=targetStore.get<Record<string,unknown>>('state','pending')!;targetStore.put('state','pending',{...authorization,deadline:0});targetStore.destroy();targetDb.close();
   const replacement=cli(c,['cloud','login'],'enrollment-interrupt');expect(await replacement.done,replacement.err()).toBe(92);const replacementRequest=secondRequest!;expect(replacementRequest).not.toBe(expiredRequest);
   const replacementIssuer=cli(a,['cloud','approve-device',replacementRequest],'before:/v1/devices/pairing-confirm');expect(await replacementIssuer.done,replacementIssuer.err()).toBe(94);await pause(600);const fresh=issuerStore.get<{sealed:string;phrase:string}>('state','issuer:'+replacementRequest)!;expect(fresh.sealed).not.toBe(original.sealed);expect(fresh.phrase).not.toBe(original.phrase);
   await control('deny-device',{requestId:replacementRequest});const cleanup=cli(c,['cloud','login']);expect(await cleanup.done).toBe(1);expect(cleanup.err()).toContain('cloud_authorization_denied');issuerStore.destroy();issuerDb.close();
  }
  const scan=(directory:string)=>{for(const entry of readdirSync(directory,{withFileTypes:true})){const path=join(directory,entry.name);if(entry.isDirectory())scan(path);else if(entry.isFile()){const bytes=readFileSync(path);for(const forbidden of [legacyValue,value,automaticValue])expect(bytes.includes(Buffer.from(forbidden))).toBe(false);}}};scan(root);
  const intact=new Database(join(a,'vault.db'),{readonly:true});const beforeMissingKey=JSON.stringify(intact.query('SELECT * FROM cloud_state ORDER BY id').all());intact.close();
  secrets.delete(a+':csk');const missingKey=cli(a,['cloud','login']);expect(await missingKey.done).toBe(1);expect(missingKey.err()).toContain('cloud_secure_store_locked');
  const preserved=new Database(join(a,'vault.db'),{readonly:true});expect(JSON.stringify(preserved.query('SELECT * FROM cloud_state ORDER BY id').all())).toBe(beforeMissingKey);preserved.close();
 }finally{for(const p of children)if(p.exitCode===null)p.kill('SIGKILL');stub?.stop(true);await pause(100);rmSync(root,{recursive:true,force:true});}
},600000);
