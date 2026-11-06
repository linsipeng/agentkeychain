import {RelativeDirectory} from '../platform/relative-directory.ts';
import sodium from 'libsodium-wrappers-sumo';
import {createHash,randomUUID} from 'node:crypto';
import {resolve,dirname,basename,join} from 'node:path';
import {readFileSync,writeFileSync,realpathSync,lstatSync,fstatSync,constants,openSync as openAbsolute,closeSync,fsyncSync} from 'node:fs';
import {canonicalExport,type ExportIntent} from '../../managed-cloud/shared/export.ts';
import type {CloudStore} from './persistence.ts';
import type {CloudKeys} from './crypto.ts';
import type {SignedManagedOperation} from './protocol.ts';
import type {SyncRemote} from './durable.ts';
interface ExportRuntime {store:CloudStore;keys:CloudKeys;enrollment:{accountId:string;tenantId:string;vaultId:string;deviceId:string};http:Pick<SyncRemote,'call'>}
interface ExportJournal {intent:ExportIntent;signed:SignedManagedOperation;completed:boolean;payload?:string;accepted?:boolean;target?:string;staging?:string;payloadDigest?:string;published?:{dev:number;ino:number}}
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
const destination=(path:string)=>join(realpathSync(dirname(resolve(path))),basename(path));
const output=(path:string)=>{const resolved=destination(path),parent=lstatSync(dirname(resolved));return hash(JSON.stringify(['AgentKeychain-export-output-v1',resolved,parent.dev,parent.ino,'agentkeychain-export',1]));};
export const exportSnapshot=(store:CloudStore)=>hash(JSON.stringify(store.db.query('SELECT * FROM secrets WHERE deleted_at IS NULL ORDER BY name').all()));
export async function requestExport(r:ExportRuntime,path:string){
 const id='export:'+output(path);
 const journal=r.store.transaction(()=>{
  const previous=r.store.get<ExportJournal>('state',id),content=exportSnapshot(r.store);
  if(previous&&!previous.completed&&(previous.accepted||previous.payload||previous.intent.expiresAt>Math.floor(Date.now()/1000))){
   if(previous.intent.contentDigest!==content)throw new Error('cloud_export_content_changed');return previous;
  }
  const intent:ExportIntent={version:1,action:'export',requestId:randomUUID(),...r.enrollment,contentDigest:content,outputDigest:output(path),expiresAt:Math.floor(Date.now()/1000)+900};
  // Only public identity fields belong in the signed network intent.
  const safe:ExportIntent={version:intent.version,action:intent.action,requestId:intent.requestId,accountId:intent.accountId,tenantId:intent.tenantId,vaultId:intent.vaultId,deviceId:intent.deviceId,contentDigest:intent.contentDigest,outputDigest:intent.outputDigest,expiresAt:intent.expiresAt};
  const canonical=canonicalExport(safe),next={intent:safe,signed:{canonical,signature:Buffer.from(sodium.crypto_sign_detached(canonical,r.keys.signingPrivate)).toString('base64')},completed:false};r.store.put('state',id,next);return next;
 });
 await r.http.call('/v1/devices/export-request',journal.signed);return journal.intent.requestId;
}
export async function acceptExport(r:ExportRuntime,path:string){
 const target=destination(path),id='export:'+output(path),journal=r.store.get<ExportJournal>('state',id);
 if(!journal||journal.completed)throw new Error('approval_required');
 const check=()=>{if(output(path)!==journal.intent.outputDigest)throw new Error('cloud_export_output_conflict');if(exportSnapshot(r.store)!==journal.intent.contentDigest)throw new Error('cloud_export_content_changed');};check();
 const accepted=await r.http.call('/v1/devices/export-consume',journal.signed) as {accepted:boolean;requestId?:string};
 if(!accepted.accepted||(accepted.requestId!==undefined&&accepted.requestId!==journal.intent.requestId))throw new Error('approval_required');
 check();
 r.store.transaction(()=>{const current=r.store.get<ExportJournal>('state',id)!;r.store.put('state',id,{...current,accepted:true});});
 return {requestId:journal.intent.requestId,write(payload:string){
  r.store.transaction(()=>{
   check();const current=r.store.get<ExportJournal>('state',id)!;if(current.completed)throw new Error('approval_required');
   if(!current.payload){
    encryptedPayload(payload);const payloadDigest=hash(payload);
    r.store.put('state',id,{...current,payload,payloadDigest,target,staging:join(dirname(target),'.agentkeychain-export-'+current.intent.requestId+'-'+payloadDigest+'.tmp')});
   }
  });
   check();let current=r.store.get<ExportJournal>('state',id)!;if(current.completed)throw new Error('approval_required');
   const bytes=current.payload!,temporary=current.staging;
   encryptedPayload(bytes);
   if(!temporary||current.target!==target||current.payloadDigest!==hash(bytes)||temporary!==join(dirname(target),'.agentkeychain-export-'+current.intent.requestId+'-'+hash(bytes)+'.tmp'))throw new Error('cloud_export_output_conflict');
   // Keep the descriptor open across publication; inspect names without following links.
   const directory=openAbsolute(dirname(target),constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
   const relative=new RelativeDirectory(directory,dirname(target));
   const openSync=relative.open,linkSync=relative.link,unlinkSync=relative.unlink;
   const inspect=(path:string,bytes:string,stage:boolean)=>inspectRelative(relative,path,bytes,stage);
   try{
    check();const parent=fstatSync(directory);if(hash(JSON.stringify(['AgentKeychain-export-output-v1',target,parent.dev,parent.ino,'agentkeychain-export',1]))!==current.intent.outputDigest)throw new Error('cloud_export_output_conflict');const sameParent=()=>{const now=lstatSync(dirname(target));if(now.dev!==parent.dev||now.ino!==parent.ino)throw new Error('cloud_export_output_conflict');check();};
    sameParent();
    r.store.transaction(()=>{
    current=r.store.get<ExportJournal>('state',id)!;if(current.completed)throw new Error('approval_required');
    let stage=inspect(temporary,bytes,true);
    let final=inspect(target,bytes,false);
    if(final&&!((stage&&final.nlink===2&&stage.nlink===2&&final.dev===stage.dev&&final.ino===stage.ino)||(!stage&&final.nlink===1&&current.published?.dev===final.dev&&current.published?.ino===final.ino)))throw new Error('cloud_export_output_conflict');
    if(!final){
     if(!stage){
      const fd=openSync(temporary,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
      try{writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}
      fsyncSync(directory);stage=inspect(temporary,bytes,true);
     }
     if(stage&&stage.size<Buffer.byteLength(bytes)){
      if(stage.nlink!==1)throw new Error('cloud_export_output_conflict');
      const fd=openSync(temporary,constants.O_WRONLY|constants.O_NOFOLLOW);
      try{const now=fstatSync(fd);if(now.dev!==stage.dev||now.ino!==stage.ino||now.nlink!==1)throw new Error('cloud_export_output_conflict');writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}
      stage=inspect(temporary,bytes,true);
     }
     if(stage!.nlink!==1)throw new Error('cloud_export_output_conflict');
     sameParent();linkSync(temporary,target);sameParent();
     final=inspect(target,bytes,false);
     if(!final||final.dev!==stage!.dev||final.ino!==stage!.ino||final.nlink!==2)throw new Error('cloud_export_output_conflict');
    }
    const fd=openSync(target,constants.O_RDONLY|constants.O_NOFOLLOW);
    try{const stat=fstatSync(fd);if(stat.dev!==final.dev||stat.ino!==final.ino)throw new Error('cloud_export_output_conflict');fsyncSync(fd);}finally{closeSync(fd);}
    fsyncSync(directory);sameParent();
    r.store.put('state',id,{...current,published:{dev:final.dev,ino:final.ino}});
    });
    r.store.transaction(()=>{
    current=r.store.get<ExportJournal>('state',id)!;if(current.completed)throw new Error('approval_required');
    sameParent();const stage=inspect(temporary,bytes,true),final=inspect(target,bytes,false);
    if(!final||final.dev!==current.published?.dev||final.ino!==current.published?.ino||(stage&&(stage.dev!==final.dev||stage.ino!==final.ino)))throw new Error('cloud_export_output_conflict');
    if(stage){
     const owned=inspect(temporary,bytes,true);
     if(!owned||owned.dev!==stage.dev||owned.ino!==stage.ino||owned.nlink>2)throw new Error('cloud_export_output_conflict');
     unlinkSync(temporary);fsyncSync(directory);
    }
    sameParent();r.store.put('state',id,{intent:current.intent,signed:current.signed,completed:true});
    });
   }finally{closeSync(directory);}
 }};
}
/** Only encrypted bundle framing may enter the filesystem delivery journal. */
function encryptedPayload(payload:string){
 const parts=payload.trim().split(':');
 if(parts.length!==3||parts.some(p=>!p||Buffer.from(p,'base64').toString('base64')!==p)||Buffer.from(parts[0]!,'base64').length!==24||Buffer.from(parts[1]!,'base64').length!==16||Buffer.from(parts[2]!,'base64').length<16)throw new Error('cloud_export_invalid_bundle');
}
function inspectRelative(relative:RelativeDirectory,path:string,payload:string,staging:boolean){
 const openSync=relative.open;
 let fd:number;
 try{fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);}catch(error){if((error as {code?:string}).code==='ENOENT')return null;throw new Error('cloud_export_output_conflict',{cause:error});}
 try{
  const stat=fstatSync(fd);
  if(!stat.isFile()||stat.uid!==process.getuid?.()||(stat.mode&0o777)!==0o600||(staging?stat.size>Buffer.byteLength(payload):stat.size!==Buffer.byteLength(payload))||stat.nlink<1||stat.nlink>2||(staging?!payload.startsWith(readFileSync(fd,'utf8')):readFileSync(fd,'utf8')!==payload))throw new Error('cloud_export_output_conflict');
  const named=relative.stat(path);if(named.isSymbolicLink()||named.dev!==stat.dev||named.ino!==stat.ino)throw new Error('cloud_export_output_conflict');
  if(staging&&!basename(path).startsWith('.agentkeychain-export-'))throw new Error('cloud_export_output_conflict');return stat;
 }finally{closeSync(fd);}
}
/** Startup never scans a directory or infers ownership from a filename alone. */
export function cleanupExportStaging(store:CloudStore){
 store.transaction(()=>{
  for(const row of store.all<ExportJournal>('state')){
   if(!row.id.startsWith('export:'))continue;
   const j=row.value;if(!j.accepted||!j.payload||!j.target||!j.staging)continue;
   let directory:number|undefined;
   try{
    encryptedPayload(j.payload);
    if(j.payloadDigest!==hash(j.payload)||row.id!=='export:'+j.intent.outputDigest||output(j.target)!==j.intent.outputDigest||j.staging!==join(dirname(j.target),'.agentkeychain-export-'+j.intent.requestId+'-'+j.payloadDigest+'.tmp'))continue;
    directory=openAbsolute(dirname(j.target),constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    const relative=new RelativeDirectory(directory,dirname(j.target));
    const inspect=(path:string,bytes:string,stage:boolean)=>inspectRelative(relative,path,bytes,stage);
    const unlinkSync=relative.unlink;
    const parent=fstatSync(directory);if(hash(JSON.stringify(['AgentKeychain-export-output-v1',j.target,parent.dev,parent.ino,'agentkeychain-export',1]))!==j.intent.outputDigest)continue;const stage=inspect(j.staging,j.payload,true);if(!stage)continue;
    if(stage.nlink===2){const final=inspect(j.target,j.payload,false);if(!final||final.dev!==stage.dev||final.ino!==stage.ino||j.published?.dev!==stage.dev||j.published?.ino!==stage.ino)continue;}
    const now=lstatSync(dirname(j.target));if(now.dev!==parent.dev||now.ino!==parent.ino||output(j.target)!==j.intent.outputDigest)continue;
    const owned=inspect(j.staging,j.payload,true);if(!owned||owned.dev!==stage.dev||owned.ino!==stage.ino||owned.nlink!==stage.nlink)continue;
    unlinkSync(j.staging);fsyncSync(directory);
   }catch{/* Changed paths or ownership are left untouched for explicit resolution. */}
   finally{if(directory!==undefined)closeSync(directory);}
  }
 });
}
