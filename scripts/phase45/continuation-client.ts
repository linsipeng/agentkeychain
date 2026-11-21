/** Test-only compiled entrypoint; no shipping CLI or native secure store. */
import {Database} from 'bun:sqlite';
import {realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,sep} from 'node:path';
import {CloudStore} from '../../src/cloud/persistence.ts';
import {verifyReleaseManifest} from '../../src/cloud/config.ts';
import {protectEnrollmentKeys,stageGenesisContinuation,finalizeGenesisContinuation} from '../../src/cloud/enrollment-intent.ts';
import {openCloudRuntime} from '../../src/cloud/runtime.ts';
import type {SecureAccount,SecureStore} from '../../src/platform/secure-store.ts';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {CloudKeys} from '../../src/cloud/crypto.ts';

const bootstrap=await Bun.stdin.json() as {
 home:string;endpoint:string;token:string;mode:'stage'|'finalize'|'ready';
 fault?:string; manifest:SignedManagedOperation; root:string;
 initialization?:{keys:Record<keyof CloudKeys,string>;nonce:string;evidence:Parameters<typeof stageGenesisContinuation>[4]};
};
const endpoint=new URL(bootstrap.endpoint),home=realpathSync(bootstrap.home);
if(process.env.AKC_KEYCHAIN_TEST_MODE!=='1'||!home.startsWith(realpathSync(tmpdir())+sep)||
 !home.split(sep).at(-1)?.startsWith('akc-continuation-process-')||
 process.env.HOME!==home||process.env.AGENTKEYCHAIN_HOME!==home||
 endpoint.protocol!=='http:'||endpoint.hostname!=='127.0.0.1'||!endpoint.port||endpoint.pathname!=='/'||
 endpoint.username||endpoint.password||endpoint.search||endpoint.hash)throw new Error('synthetic_bootstrap_required');
const control=async(path:string,value:unknown)=>{
 const response=await fetch(endpoint.origin+path,{method:'POST',redirect:'error',headers:{'content-type':'application/json',authorization:'Bearer '+bootstrap.token},body:JSON.stringify(value)});
 if(!response.ok)throw new Error('synthetic_transport_rejected');
 return response.json();
};
const secure:SecureStore={
 async get(account:SecureAccount){const result=await control('/secure/get',account) as {value:string|null};return result.value?Buffer.from(result.value,'base64'):null;},
 async put(account:SecureAccount,value:Uint8Array){
  await control('/secure/put',{account,value:Buffer.from(value).toString('base64')});
  if(bootstrap.fault==='after-checkpoint'&&account==='checkpoint-anchor')process.exit(77);
 },
 async remove(account:SecureAccount){
  if(bootstrap.fault==='before-cleanup'&&account==='enrollment-intent')process.exit(78);
  await control('/secure/remove',account);
 },
};
const policy=verifyReleaseManifest(bootstrap.manifest,Buffer.from(bootstrap.root,'base64'));
const db=new Database(join(home,'fixture.sqlite'));
try{
 if(bootstrap.mode==='stage'){
  const {keys:encoding,evidence,nonce}=bootstrap.initialization!;
  const keys=Object.fromEntries(Object.entries(encoding).map(([id,bytes])=>[id,Buffer.from(bytes,'base64')])) as unknown as CloudKeys;
  await protectEnrollmentKeys(secure,keys);
  const store=new CloudStore(db,keys.csk),{grant}=evidence;
  try{
   store.put('state','pending',{requestId:grant.requestId,deviceId:grant.deviceId});
   store.put('state','pending-approved',{requestId:grant.requestId,deviceId:grant.deviceId,vaultId:grant.vaultId});
   store.put('state','pending-self-roster',evidence.roster);store.put('state','pending-package',evidence.keyPackage);
   await stageGenesisContinuation(secure,store,policy,nonce,evidence);
  }finally{store.destroy();for(const key of Object.values(keys))key.fill(0);}
 }else if(bootstrap.mode==='ready'){
  const runtime=await openCloudRuntime(db,new Uint8Array(32),{policy,secure});runtime.close();
 }else{
  const csk=await secure.get('csk');if(!csk)throw new Error('synthetic_no_keys');
  const store=new CloudStore(db,csk);
  try{if(!await finalizeGenesisContinuation(secure,store,policy,async nonce=>await control('/custody/post',{nonce}) as SignedManagedOperation))throw new Error('synthetic_not_finalized');}
  finally{store.destroy();csk.fill(0);}
 }
 process.stdout.write('ok\n');
}catch(error){process.stderr.write(error instanceof Error?error.message:'synthetic_error');process.exitCode=1;}
finally{db.close();}
