import {expect,test} from 'bun:test';
import {Database} from 'bun:sqlite';
import {migrate} from '../src/db/migrate.ts';
import {CloudStore} from '../src/cloud/persistence.ts';
import {createCloudKeys} from '../src/cloud/crypto.ts';
import {requestExport,acceptExport} from '../src/cloud/export.ts';
test('export binds encrypted snapshot and output; no local delivery before acceptance, reuse or changed content',async()=>{
 const {mkdtempSync,rmSync}=await import('node:fs'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
 const home=mkdtempSync(join(tmpdir(),'akc-export-approval-')),path=join(home,'export-test'),other=join(home,'other');
 const db=new Database(':memory:');migrate(db);const keys=await createCloudKeys(),store=new CloudStore(db,keys.csk);let approved=false,calls=0;
 const runtime={store,keys,enrollment:{accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d'},http:{async call(path:string){calls++;if(path.endsWith('consume')&&!approved)throw new Error('approval_required');return {accepted:true};}}};
 try{
  const id=await requestExport(runtime,path);expect(id.length).toBeGreaterThan(0);
  await expect(acceptExport(runtime,path)).rejects.toThrow('approval_required');
  approved=true;const permit=await acceptExport(runtime,path);expect(permit.requestId).toBe(id);
  await expect(acceptExport(runtime,other)).rejects.toThrow('approval_required');
  db.run("INSERT INTO secrets(name,ciphertext,nonce,scopes,created_at,updated_at,version) VALUES('changed',X'00',X'00','[]',1,1,1)");
  await expect(acceptExport(runtime,path)).rejects.toThrow('cloud_export_content_changed');expect(calls).toBe(3);
 }finally{db.close();rmSync(home,{recursive:true,force:true});}
});
test('concurrent export permits produce one immutable delivery and leave no plaintext',async()=>{
 const {mkdtempSync,readFileSync,rmSync}=await import('node:fs'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
 const home=mkdtempSync(join(tmpdir(),'akc-export-test-')),path=join(home,'export.akcbundle');
 const db=new Database(':memory:');migrate(db);const keys=await createCloudKeys(),store=new CloudStore(db,keys.csk);
 const runtime={store,keys,enrollment:{accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d'},http:{async call(){return {accepted:true};}}};
 try{await requestExport(runtime,path);const [a,b]=await Promise.all([acceptExport(runtime,path),acceptExport(runtime,path)]);const payload=[Buffer.alloc(24,1).toString('base64'),Buffer.alloc(16,2).toString('base64'),Buffer.alloc(32,3).toString('base64')].join(':')+'\n';a.write(payload);expect(readFileSync(path,'utf8')).toBe(payload);expect(()=>b.write('changed')).toThrow('approval_required');await expect(acceptExport(runtime,path)).rejects.toThrow('approval_required');}finally{db.close();rmSync(home,{recursive:true,force:true});}
});
test('export output intent follows the approved real directory and rejects a substituted symlink',async()=>{
 const {mkdtempSync,mkdirSync,symlinkSync,unlinkSync,rmSync}=await import('node:fs'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
 const home=mkdtempSync(join(tmpdir(),'akc-export-intent-'));mkdirSync(join(home,'first'));mkdirSync(join(home,'second'));symlinkSync(join(home,'first'),join(home,'destination'));
 const db=new Database(':memory:');migrate(db);const keys=await createCloudKeys(),store=new CloudStore(db,keys.csk);let calls=0;
 const runtime={store,keys,enrollment:{accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d'},http:{async call(){calls++;return {accepted:true};}}};
 try{const path=join(home,'destination','export');await requestExport(runtime,path);unlinkSync(join(home,'destination'));symlinkSync(join(home,'second'),join(home,'destination'));await expect(acceptExport(runtime,path)).rejects.toThrow('approval_required');expect(calls).toBe(1);}finally{db.close();rmSync(home,{recursive:true,force:true});}
});
test('prepared export survives expiry and resumes a linked staging file without another bundle',async()=>{
 const {mkdtempSync,readFileSync,writeFileSync,linkSync,existsSync,realpathSync,rmSync}=await import('node:fs'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
 const home=realpathSync(mkdtempSync(join(tmpdir(),'akc-export-resume-'))),path=join(home,'bundle');
 const db=new Database(':memory:');migrate(db);const keys=await createCloudKeys(),store=new CloudStore(db,keys.csk);
 const runtime={store,keys,enrollment:{accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d'},http:{async call(){return {accepted:true};}}};
 try{
  const requestId=await requestExport(runtime,path);await acceptExport(runtime,path);
  const row=store.all<{intent:{expiresAt:number;requestId:string};payload?:string;staging?:string;target?:string;payloadDigest?:string;accepted?:boolean}>('state').find(r=>r.id.startsWith('export:'))!;
  const payload=[Buffer.alloc(24,1).toString('base64'),Buffer.alloc(16,2).toString('base64'),Buffer.alloc(32,3).toString('base64')].join(':')+'\n';
  const {createHash}=await import('node:crypto');const digest=createHash('sha256').update(payload).digest('hex');
  const stage=join(home,'.agentkeychain-export-'+requestId+'-'+digest+'.tmp');
  store.put('state',row.id,{...row.value,intent:{...row.value.intent,expiresAt:1},accepted:true,payload,target:path,staging:stage,payloadDigest:digest});
  writeFileSync(stage,payload,{mode:0o600});linkSync(stage,path);
  expect(await requestExport(runtime,path)).toBe(requestId);
  const permit=await acceptExport(runtime,path);permit.write(payload);
  expect(readFileSync(path,'utf8')).toBe(payload);expect(existsSync(stage)).toBe(false);
 }finally{db.close();rmSync(home,{recursive:true,force:true});}
});
test('export refuses symlinks, foreign output hardlinks, unsafe modes and unencrypted payloads',async()=>{
 const {mkdtempSync,writeFileSync,symlinkSync,linkSync,readFileSync,rmSync}=await import('node:fs'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
 for(const kind of ['symlink','hardlink','mode','plaintext','samebytes']){
  const home=mkdtempSync(join(tmpdir(),'akc-export-race-')),path=join(home,'bundle'),other=join(home,'unrelated');
  const db=new Database(':memory:');migrate(db);const keys=await createCloudKeys(),store=new CloudStore(db,keys.csk);
  const runtime={store,keys,enrollment:{accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d'},http:{async call(){return {accepted:true};}}};
  const payload=[Buffer.alloc(24,1).toString('base64'),Buffer.alloc(16,2).toString('base64'),Buffer.alloc(32,3).toString('base64')].join(':')+'\n';
  try{
   await requestExport(runtime,path);const permit=await acceptExport(runtime,path);writeFileSync(other,payload,{mode:0o600});
   if(kind==='samebytes')writeFileSync(path,payload,{mode:0o600});if(kind==='symlink')symlinkSync(other,path);if(kind==='hardlink')linkSync(other,path);if(kind==='mode')writeFileSync(path,payload,{mode:0o644});
   expect(()=>permit.write(kind==='plaintext'?'plaintext':payload)).toThrow(kind==='plaintext'?'cloud_export_invalid_bundle':'cloud_export_output_conflict');
   expect(readFileSync(other,'utf8')).toBe(payload);
  }finally{db.close();rmSync(home,{recursive:true,force:true});}
 }
});
test('startup cleanup removes only journal-bound staging and preserves unrelated files',async()=>{
 const {cleanupExportStaging}=await import('../src/cloud/export.ts');
 const {mkdtempSync,realpathSync,writeFileSync,existsSync,rmSync}=await import('node:fs'),{tmpdir}=await import('node:os'),{join}=await import('node:path'),{createHash}=await import('node:crypto');
 const home=realpathSync(mkdtempSync(join(tmpdir(),'akc-export-cleanup-'))),target=join(home,'bundle');
 const db=new Database(':memory:');migrate(db);const keys=await createCloudKeys(),store=new CloudStore(db,keys.csk);
 const runtime={store,keys,enrollment:{accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d'},http:{async call(){return {accepted:true};}}};
 try{
  const requestId=await requestExport(runtime,target);await acceptExport(runtime,target);
  const row=store.all<{intent:unknown}>('state').find(r=>r.id.startsWith('export:'))!;
  const payload=[Buffer.alloc(24,1).toString('base64'),Buffer.alloc(16,2).toString('base64'),Buffer.alloc(32,3).toString('base64')].join(':')+'\n',payloadDigest=createHash('sha256').update(payload).digest('hex');
  const staging=join(home,'.agentkeychain-export-'+requestId+'-'+payloadDigest+'.tmp'),unrelated=join(home,'.agentkeychain-export-unrelated.tmp');
  store.put('state',row.id,{...row.value,accepted:true,payload,payloadDigest,target,staging});writeFileSync(staging,payload.slice(0,40),{mode:0o600});writeFileSync(unrelated,'unrelated',{mode:0o600});
  cleanupExportStaging(store);expect(existsSync(staging)).toBe(false);expect(existsSync(unrelated)).toBe(true);expect(existsSync(target)).toBe(false);
 }finally{db.close();rmSync(home,{recursive:true,force:true});}
});
