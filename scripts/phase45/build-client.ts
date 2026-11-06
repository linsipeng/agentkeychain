import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
const bootstrap=resolve('scripts/phase45/bootstrap.ts');
const result=await Bun.build({entrypoints:['scripts/phase45/client.ts'],compile:{outfile:process.argv[2]!},plugins:[{name:'synthetic-client-composition',setup(build){
 build.onLoad({filter:/release\.generated\.ts$/},()=>({contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};export function releaseArtifact(){return {manifest:bootstrap.manifest,rootPublicKey:bootstrap.rootPublicKey};}`,loader:'ts'}));
 build.onLoad({filter:/src\/cloud\/runtime\.ts$/},async({path})=>({loader:'ts',contents:`import {testSecureStore,testNetwork} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace('secure:platformSecureStore(vaultDir())','secure:testSecureStore(),network:testNetwork')}));
 build.onLoad({filter:/src\/util\/keychain\.ts$/},async({path})=>({loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace('export async function resolvePassword(): Promise<string | null> {','export async function resolvePassword(): Promise<string | null> { return bootstrap.password;')}));
 build.onLoad({filter:/src\/cli\/cloud\.ts$/},async({path})=>({loader:'ts',contents:`import {testUI,bootstrap} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace(/const ui:LoginUI=.*?;\n/,'const ui:LoginUI=testUI;\n').replaceAll('await startCloudBackground(vaultDir());','').replaceAll('homedir()','bootstrap.home')}));
 build.onLoad({filter:/src\/cloud\/recovery-journal\.ts$/},async({path})=>({loader:'ts',contents:`import {bootstrap,nativeNow} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace('await this.write(stage,data);',"if(bootstrap.fault==='before:'+stage)process.exit(94);await this.write(stage,data);if(bootstrap.fault==='after:'+stage)process.exit(94);").replaceAll('Date.now()','nativeNow()').replaceAll('nativeNow()+30000','nativeNow()+500').replace('},10000);','},100);')}));
 build.onLoad({filter:/src\/cloud\/recovery\.ts$/},async({path})=>({loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace('custodian=await open',"if(bootstrap.fault==='after:api-share')process.exit(94);custodian=await open").replace('key=joinRecoveryKey',"if(bootstrap.fault==='after:custodian-share')process.exit(94);key=joinRecoveryKey").replace('return await unwrapVaultKey',"if(bootstrap.fault==='after:reconstruction')process.exit(94);return await unwrapVaultKey")}));
 build.onLoad({filter:/src\/cloud\/recovery-activation\.ts$/},async({path})=>({loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace("store.put('state','enrollment',enrollment);","if(bootstrap.fault==='before:sqlite-commit')process.exit(94);store.put('state','enrollment',enrollment);").replace("await journal.advance('local_committed');","if(bootstrap.fault==='after:sqlite-commit')process.exit(94);await journal.advance('local_committed');").replace("await journal.advance('active');","if(bootstrap.fault==='after:final-readback')process.exit(94);await journal.advance('active');")}));
 build.onLoad({filter:/src\/cloud\/export\.ts$/},async({path})=>{
  let contents=await readFile(path,'utf8');
  contents=contents.replace('closeSync,fsyncSync','closeSync,fsyncSync as nativeFsyncSync');
  contents="let exportFsync=0;function fsyncSync(fd:number){exportFsync++;if(bootstrap.fault==='export-fsync:'+exportFsync)throw new Error('synthetic_fsync_failure');nativeFsyncSync(fd); }\n"+contents;
  const points=[
   ['before-consume'," const accepted=await r.http.call"],
   ['after-consume'," if(!accepted.accepted"],
   ['before-journal',"    r.store.put('state',id,{...current,payload,payloadDigest"],
   ['after-journal',"   const bytes=current.payload!"],
   ['after-create',"      try{writeFileSync(fd,bytes);"],
   ['after-staging-fsync',"      fsyncSync(directory);stage="],
   ['before-link',"     sameParent();linkSync(temporary,target);"],
   ['after-link',"     final=inspect(target,bytes,false);"],
   ['after-output-fsync',"    fsyncSync(directory);sameParent();"],
   ['before-cleanup',"     unlinkSync(temporary);fsyncSync(directory);"],
   ['before-complete',"    sameParent();r.store.put('state',id,{intent:current.intent"],
  ];
  for(const [stage,needle] of points){if(!contents.includes(needle!))throw new Error('export_injection_missing_'+stage);contents=contents.replace(needle!,`if(bootstrap.fault==='export:${stage}')process.exit(95);if(bootstrap.fault==='export-error:${stage}')throw new Error('synthetic_export_io_failure');if(bootstrap.fault==='export-parent:${stage}'||bootstrap.fault==='export-symlink:${stage}'){renameSync(dirname(target),dirname(target)+'.moved');if(bootstrap.fault.startsWith('export-symlink:')){mkdirSync(dirname(target)+'.redirect');symlinkSync(dirname(target)+'.redirect',dirname(target));}else mkdirSync(dirname(target));writeFileSync(join(dirname(target),'unrelated'),'preserve',{mode:0o600});}`+needle);}
  contents=contents.replace('   }finally{closeSync(directory);}',"   }finally{closeSync(directory);}if(bootstrap.fault==='export:after-complete')process.exit(95);");
  return {loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};import {renameSync,mkdirSync,symlinkSync} from 'node:fs';\n`+contents};
 });
 build.onLoad({filter:/src\/transfer\.ts$/},async({path})=>({loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace('      const payload = [',"      if(bootstrap.fault==='export:before-payload')process.exit(95);const payload = [")}));
 build.onLoad({filter:/src\/cloud\/enrollment-intent\.ts$/},async({path})=>{
  let contents=await readFile(path,'utf8');
  const points=[['before-sqlite'," store.transaction(()=>{\n  store.put('state','enrollment',e);"],['after-sqlite'," await secure.remove('enrollment-intent');"]];
  for(const [stage,needle] of points){if(!contents.includes(needle!))throw new Error('enrollment_injection_missing_'+stage);contents=contents.replace(needle!,`if(bootstrap.fault==='enrollment:${stage}')process.exit(96);`+needle);}
  return {loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+contents};
 });
 build.onLoad({filter:/src\/cloud\/roster\.ts$/},async({path})=>({loader:'ts',contents:(await readFile(path,'utf8')).replaceAll('Date.now()+30000','Date.now()+500').replaceAll('Date.now()+6000','Date.now()')}));
 build.onLoad({filter:/src\/cloud\/login\.ts$/},async({path})=>{
  let contents=(await readFile(path,'utf8')).replace('},10000);','},100);');
  const points=[['phrase-pending','  if(!await ui.confirmPhrase(phrase))'],['phrase-confirmed'," while(Date.now()<grant.expiresAt*1000){\n  try{await runtime.http.call('/v1/devices/enroll'"],['before-receipt',"runtime.store.put('state','issuer-receipt:'+requestId,{requestId,canonical:delivery.canonical"],['before-cleanup',"runtime.store.remove('state','issuer:'+requestId);});return;"]];
  for(const [stage,needle] of points){if(!contents.includes(needle!))throw new Error('issuer_injection_missing_'+stage);contents=contents.replace(needle!,`if(bootstrap.fault==='issuer:${stage}')process.exit(97);`+needle);}
  return {loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+contents};
 });
 build.onLoad({filter:/src\/cloud\/issuer\.ts$/},async({path})=>({loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace("  store.put('state',id,delivery);return delivery;","  if(bootstrap.fault==='issuer:before-journal')process.exit(97);store.put('state',id,delivery);if(bootstrap.fault==='issuer:uncommitted-journal')process.exit(97);return delivery;")}));
 build.onLoad({filter:/src\/cloud\/persistence\.ts$/},async({path})=>({loader:'ts',contents:(await readFile(path,'utf8')).replace('ttl=30000,slot=1','ttl=500,slot=1')}));
 build.onLoad({filter:/src\/cloud\/durable\.ts$/},async({path})=>{
  let contents=await readFile(path,'utf8');
  const points=[['after-lease','  try{\n   if(this.rosterRuntime)'],['receipt','    const cp=await this.checkpoint(receipt.checkpoint);'],['before-renew',"    if(!this.store.acquireLease(owner))"],['verified','    this.revocationRoots([...anchors,...newAnchors]);'],['applied',"     this.store.put('state','cursor',next);"],['cursor',"this.store.put('state','checkpoint',page.pageCheckpoint);"],['committed','    await this.store.checkAnchor(this.secure,next,anchors);']];
  for(const [stage,needle] of points){if(!contents.includes(needle!))throw new Error('sync_injection_missing_'+stage);contents=contents.replace(needle!,`if(bootstrap.fault==='sync:${stage}')process.exit(98);`+needle);}
  contents=contents.replace("this.store.put('state','cursor',next);","if(bootstrap.fault==='pull-crash')process.exit(91);this.store.put('state','cursor',next);");
  return {loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+contents};
 });
 build.onLoad({filter:/src\/cloud\/coordinator\.ts$/},async({path})=>({loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace("this.writePayload(payload,false);this.store.put('outbox',op.operationId,{signed,approval:false});this.shadow(payload.name);","if(bootstrap.fault==='mutation:before')process.exit(99);this.writePayload(payload,false);if(bootstrap.fault==='mutation:local')process.exit(99);this.store.put('outbox',op.operationId,{signed,approval:false});if(bootstrap.fault==='mutation:outbox')process.exit(99);this.shadow(payload.name);").replace("this.store.put('state','retired:'+operationId,entry);this.store.remove('outbox',operationId);","this.store.put('state','retired:'+operationId,entry);if(bootstrap.fault==='reconcile:retired')process.exit(99);this.store.remove('outbox',operationId);if(bootstrap.fault==='reconcile:removed')process.exit(99);")}));
 build.onLoad({filter:/src\/cloud\/daemon\.ts$/},async({path})=>({loader:'ts',contents:`import {bootstrap} from ${JSON.stringify(bootstrap)};\n`+(await readFile(path,'utf8')).replace('let delay=30000','let delay=1000').replaceAll('Date.now(),30000,2','Date.now(),500,2').replace('},10000);','},100);').replace('acquired=true;',"acquired=true;if(bootstrap.fault==='daemon:acquired')process.exit(100);").replace('renewal=setInterval(()=>{',"renewal=setInterval(()=>{if(bootstrap.fault==='daemon:renewed')process.exit(100);")}));
}}]});
if(!result.success)throw new Error('test_client_build_failed');
