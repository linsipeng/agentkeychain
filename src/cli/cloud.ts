import {verifySyntheticContinuationRollout} from '../cloud/continuation-rollout.ts';
import {finalizeGenesisContinuation} from '../cloud/enrollment-intent.ts';
import {CloudStore} from '../cloud/persistence.ts';
import type {ManagedEndpointPolicy} from '../cloud/config.ts';
import type {SecureStore} from '../platform/secure-store.ts';
import type {SignedManagedOperation} from '../cloud/protocol.ts';
import {assertManagedPlatform} from '../platform/managed-support.ts';
import {activateRecovery} from '../cloud/recovery-activation.ts';
import {requestExport} from '../cloud/export.ts';
import {startSecureCapture} from '../capture/server.ts';
import {Database} from 'bun:sqlite';
import {existsSync,mkdirSync,writeFileSync,renameSync,unlinkSync} from 'node:fs';
import {join} from 'node:path';
import {homedir} from 'node:os';
import {spawn} from 'node:child_process';
import {productionPolicy} from '../cloud/config.ts';
import {openDb,vaultDir,dbPath,vaultExists} from '../vault.ts';
import {resolveVaultKek} from '../unlock.ts';
import {loginCloud,approveDevice,type LoginUI} from '../cloud/login.ts';
import {openCloudRuntime} from '../cloud/runtime.ts';
import {runCloudDaemon,serviceArtifact,wakeCloud,startCloudBackground} from '../cloud/daemon.ts';
import {readConfirm} from '../util/prompt.ts';
import {decrypt} from '../crypto/xchacha.ts';
const run=(command:string,args:string[])=>new Promise<void>((resolve,reject)=>{const child=spawn(command,args,{stdio:'ignore'});child.on('error',()=>reject(new Error('cloud_local_command_failed')));child.on('exit',code=>code===0?resolve():reject(new Error('cloud_local_command_failed')));});
const browser=async(url:string)=>{if(process.platform==='darwin')await run('/usr/bin/open',[url]);else if(process.platform==='linux')await run('xdg-open',[url]);else throw new Error('cloud_browser_unavailable');};
const ui:LoginUI={open:browser,showPhrase:phrase=>process.stdout.write(`Device pairing phrase: ${phrase}\n`),wait:ms=>new Promise(resolve=>setTimeout(resolve,ms)),confirmPhrase:async phrase=>{process.stdout.write(`Compare on both devices: ${phrase}\n`);return readConfirm('Do both devices show exactly the same phrase? [y/N] ');}};
export function cloudStatus(){
 try{const policy=productionPolicy();if(!existsSync(dbPath()))return {available:true,state:'not_enrolled',releaseId:policy.releaseId};const db=new Database(dbPath(),{readonly:true,create:false});try{const schema=db.query("SELECT 1 FROM sqlite_master WHERE name='cloud_schema'").get();if(!schema)return {available:true,state:'not_enrolled'};const version=db.query('SELECT version FROM cloud_schema WHERE id=1').get() as {version:number}|null;return {available:true,state:version?.version===1?'configured':'incompatible',schema:version?.version??null};}finally{db.close();}}
 catch(error){if(error instanceof Error&&error.message==='cloud_unavailable_not_provisioned')return {available:false,state:'cloud_unavailable_not_provisioned'};throw error;}
}
export async function requestCloudApproval(action:string,name:string,scopes?:string[]){
 if(!['delete','restore','scope'].includes(action)||!name||(action==='scope'&&(!scopes||!scopes.length||scopes.length>256||scopes.some(s=>typeof s!=='string'||!s.length||s.length>1024))))throw new Error('cloud_invalid_approval_request');
 productionPolicy();const db=openDb();let kek:Uint8Array|undefined;
 try{kek=await resolveVaultKek(db);const runtime=await openCloudRuntime(db,kek);try{
  const row=db.query('SELECT ciphertext,nonce,scopes,metadata,version FROM secrets WHERE name=?').get(name) as {ciphertext:Uint8Array;nonce:Uint8Array;scopes:string;metadata:string|null;version:number}|null;if(!row)throw new Error('not_found');
  const bytes=await decrypt(row.ciphertext,row.nonce,kek);
  try{const id=runtime.coordinator.requestApproval({name,value:new TextDecoder().decode(bytes),scopes:action==='scope'?scopes!:JSON.parse(row.scopes) as string[],metadata:row.metadata?JSON.parse(row.metadata) as Record<string,unknown>:null,localVersion:row.version+1},action==='scope'?'put':action as 'delete'|'restore',action==='scope'?'scope':undefined);
   try{await runtime.engine.sync();}catch(error){if(!(error instanceof Error)||error.message!=='approval_required')throw error;}
   await wakeCloud(vaultDir());return {state:'approval_required',requestId:id};
  }finally{bytes.fill(0);}
 }finally{runtime.close();}}finally{kek?.fill(0);db.close();}
}
// No shipping caller supplies fixture dependencies.
interface SyntheticContinuationGraph {
 policy:ManagedEndpointPolicy; secure:SecureStore;
 signed:Parameters<typeof verifySyntheticContinuationRollout>[1];
 open:()=>Database;
 // eslint-disable-next-line no-unused-vars -- private runtime transport contract
 obtain:(nonce:string)=>Promise<SignedManagedOperation>;
}
export async function runCloud(argv:string[],platform:string=process.platform,fixture?:SyntheticContinuationGraph):Promise<number>{
 assertManagedPlatform(platform);
 const command=argv[0]??'status';
 if(command==='continue-enrollment'){
  if(argv.length!==1||process.env.AKC_KEYCHAIN_TEST_MODE!=='1'||!fixture)throw new Error('cloud_continuation_not_provisioned');
  const {policy,secure}=fixture,permit=await verifySyntheticContinuationRollout(policy,fixture.signed);
  const csk=await secure.get('csk');if(!csk)throw new Error('cloud_secure_store_locked');
  let db:Database|undefined;
  try{
   db=fixture.open();const store=new CloudStore(db,csk);
   try{
    if(!await finalizeGenesisContinuation(secure,store,policy,fixture.obtain,permit))throw new Error('cloud_continuation_not_staged');
   }finally{store.destroy();}
  }finally{db?.close();csk.fill(0);}
  return 0;
 }
 if(argv.some(a=>a.startsWith('--')&&a!=='--json'&&!(['rotate','recover'].includes(command)&&a==='--no-open')&&!(command==='recover'&&a==='--restart')))throw new Error('cloud_unknown_option');
 if(command==='compatibility'){process.stdout.write(JSON.stringify({cloudSchema:1,protocolMin:2,protocolMax:2,localSchema:'v0.6.2',helperABI:1,helperVersion:'1',nativeHelper:process.platform==='darwin'?'required':'none'})+'\n');return 0;}
 if(command==='status'){process.stdout.write(JSON.stringify(cloudStatus())+'\n');return 0;}
 productionPolicy(); // All operational commands fail before opening Vault/Keychain when not provisioned.
 if(command==='request-approval'){process.stdout.write(JSON.stringify(await requestCloudApproval(argv[1]??'',argv[2]??'',argv[3]?.split(',')))+'\n');return 0;}
 if(command==='service'&&argv[1]!=='run'){
  const platform=process.platform;if(platform!=='darwin'&&platform!=='linux')throw new Error('cloud_service_unsupported');
  const artifact=serviceArtifact(platform,process.execPath,vaultDir());
  const directory=platform==='darwin'?join(homedir(),'Library','LaunchAgents'):join(homedir(),'.config','systemd','user'),path=join(directory,artifact.name),domain='gui/'+process.getuid!();
  switch(argv[1]){
   case 'install':mkdirSync(directory,{recursive:true,mode:0o700});writeFileSync(path+'.tmp',artifact.content,{mode:0o600,flag:'wx'});renameSync(path+'.tmp',path);break;
   case 'uninstall':await wakeCloud(vaultDir(),'stop');if(existsSync(path))unlinkSync(path);break;
   case 'start':await run(platform==='darwin'?'/bin/launchctl':'systemctl',platform==='darwin'?['bootstrap',domain,path]:['--user','start',artifact.name]);break;
   case 'stop':await wakeCloud(vaultDir(),'stop');if(!existsSync(path))break;await run(platform==='darwin'?'/bin/launchctl':'systemctl',platform==='darwin'?['bootout',domain+'/com.agentkeychain.cloud']:['--user','stop',artifact.name]);break;
   case 'status':process.stdout.write(JSON.stringify({installed:existsSync(path),running:await wakeCloud(vaultDir())})+'\n');break;
   default:throw new Error('cloud_invalid_service_command');
  }return 0;
 }
 if(!vaultExists())throw new Error('vault_not_initialized');const db=openDb();let kek:Uint8Array|undefined;
 try{
  if(command==='recover'){
   kek=await resolveVaultKek(db);
   await activateRecovery(db,kek,argv[1]?.startsWith('--')?undefined:argv[1],{open:async url=>{if(!argv.includes('--no-open'))await ui.open(url);},wait:ui.wait,status:(state,url)=>process.stdout.write(JSON.stringify({state,...(url?{verificationUrl:url}:{})})+'\n')},undefined,argv.includes('--restart'));return 0;
  }
  if(command==='login')await loginCloud(db,ui);
  kek=await resolveVaultKek(db);const runtime=await openCloudRuntime(db,kek);
  try{
   switch(command){
    case 'login':await runtime.http.session();runtime.store.put('state','health',{state:'idle'});await startCloudBackground(vaultDir());break;
    case 'rotate':{
     const name=argv[1]??'',row=db.query('SELECT scopes,metadata,version FROM secrets WHERE name=? AND deleted_at IS NULL').get(name) as {scopes:string;metadata:string|null;version:number}|null;
     if(!row)throw new Error('not_found');let requestId:string|undefined;
     const capture=await startSecureCapture({name,purpose:'Prepare a replacement; account approval is required before it takes effect.',scope:row.scopes,permission:'Existing permissions are retained',openBrowser:!argv.includes('--no-open'),successMessage:'Request prepared. Allow it once in your account to replace the saved credential.',onSubmit:async value=>{
      requestId=runtime.coordinator.requestApproval({name,value,scopes:JSON.parse(row.scopes) as string[],metadata:row.metadata?JSON.parse(row.metadata) as Record<string,unknown>:null,localVersion:row.version+1},'put','rotate');
      try{await runtime.engine.sync();}catch(error){if(!(error instanceof Error)||error.message!=='approval_required')throw error;}
     }});
     process.stdout.write(JSON.stringify({state:'waiting_for_local_input',...(argv.includes('--no-open')?{localUrl:capture.url}:{})})+'\n');
     try{if(await capture.done!=='stored')throw new Error('cloud_rotation_cancelled');process.stdout.write(JSON.stringify({state:'approval_required',requestId})+'\n');}finally{capture.close();}break;
    }
    case 'request-export':{if(!argv[1])throw new Error('cloud_export_output_required');const requestId=await requestExport(runtime,argv[1]);process.stdout.write(JSON.stringify({state:'approval_required',requestId})+'\n');break;}
    case 'reconcile':{
     runtime.coordinator.reconcile();
     if(argv[1]){const requestId=runtime.coordinator.approveLegacy(argv[1]);try{await runtime.engine.sync();}catch(error){if(!(error instanceof Error)||error.message!=='approval_required')throw error;}process.stdout.write(JSON.stringify({state:'approval_required',requestId})+'\n');}
     else process.stdout.write(JSON.stringify(runtime.coordinator.pendingLegacy())+'\n');break;
    }
    case 'sync-now':await runtime.engine.sync();break;
    case 'devices':process.stdout.write(JSON.stringify(runtime.enrollment.roster.map(d=>({deviceId:d.deviceId,revoked:d.revoked})))+'\n');break;
    case 'approve-device':await approveDevice(runtime,argv[1]??'',ui);break;
    case 'revoke-device':await browser(runtime.http.policy.webOrigin+'/app/devices/'+encodeURIComponent(argv[1]??''));break;
    case 'logout':runtime.http.logout();runtime.store.put('state','health',{state:'auth_required'});break;
    case 'service':{const controller=new globalThis.AbortController(),stop=()=>controller.abort();process.once('SIGINT',stop);process.once('SIGTERM',stop);try{await runCloudDaemon(runtime,vaultDir(),controller.signal);}finally{process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}break;}
    default:throw new Error('cloud_unknown_command');
   }
  }finally{runtime.close();}
 }finally{kek?.fill(0);db.close();}return 0;
}
