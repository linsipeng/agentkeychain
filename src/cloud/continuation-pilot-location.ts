import {constants,lstatSync,openSync,fstatSync,closeSync,realpathSync,readdirSync,type BigIntStats} from 'node:fs';
import {basename,dirname,isAbsolute,normalize,parse} from 'node:path';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {installedContinuationPilotScope,type VerifiedInstalledContinuationPilot} from './continuation-pilot-build.ts';
import {base64,exactFields,type SignedManagedOperation} from './protocol.ts';

const domain='AgentKeychain-installed-continuation-pilot-location-v1';
const deny=()=>new Error('cloud_continuation_pilot_location_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const privateDirectory=(s:BigIntStats,uid:number)=>s.isDirectory()&&s.uid===BigInt(uid)&&(s.mode&0o7777n)===0o700n;
const equalIdentity=(a:BigIntStats,b:BigIntStats)=>a.dev===b.dev&&a.ino===b.ino&&a.uid===b.uid&&a.mode===b.mode;
const numericIdentity=(v:unknown):v is string=>typeof v==='string'&&/^(?:0|[1-9][0-9]{0,19})$/.test(v);

export interface PilotLocationInspection { readonly state:'empty-disposable-directory';readonly namespace:string;readonly expiresAt:number }

/** Verify an explicitly created, empty, opt-in pilot state root. No mkdir,
 * ordinary Vault resolution, database open or native credential access. Only
 * the independently signed path is touched; the returned namespace is not a
 * storage capability. Keep all actual child-file opens disconnected until
 * descriptor-relative no-follow operations have their own reviewed adapter. */
export async function inspectInstalledPilotLocation(gate:VerifiedInstalledContinuationPilot,location:SignedManagedOperation):Promise<PilotLocationInspection>{
 let fd:number|undefined;
 try{
  const scope=installedContinuationPilotScope(gate),uid=process.getuid?.(),euid=process.geteuid?.();
  if(process.platform!=='linux'||uid===undefined||uid===0||uid!==euid||
    !constants.O_NOFOLLOW||!constants.O_DIRECTORY)throw deny();
  exactFields(location,['canonical','signature']);
  const {canonical,signature}=location;
  if(typeof canonical!=='string'||canonical.length>4096)throw deny();
  base64(signature,64,64);
  const claim:unknown=JSON.parse(canonical);
  exactFields(claim,['version','domain','keyId','installationDigest','path','uid','device','inode','issuedAt','expiresAt']);
  const {path,device,inode,issuedAt,expiresAt}=claim;
  if(typeof path!=='string'||path.length>1024||!isAbsolute(path)||normalize(path)!==path||path.endsWith('/')||path.includes('//')||
     (path.includes('\\')||[...path].some(c=>c.charCodeAt(0)<32||c.charCodeAt(0)===127))||!/^(?:agentkeychain-pilot-[a-z0-9]+(?:-[a-z0-9]+)*)$/.test(basename(path))||
     path.split('/').includes('.agentkeychain')||!numericIdentity(device)||!numericIdentity(inode)||inode==='0'||
     typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
     issuedAt<1||issuedAt>now()||expiresAt<=now()||expiresAt>gate.expiresAt||expiresAt-issuedAt>86400||
     canonical!==JSON.stringify({version:1,domain,keyId:scope.rollout.keyId,installationDigest:scope.installationDigest,
      path,uid,device,inode,issuedAt,expiresAt})||!await verify(scope.rollout.publicKey,signature,canonical))throw deny();

  const checkAncestors=()=>{
   for(let parent=dirname(path);;parent=dirname(parent)){
    const s=lstatSync(parent,{bigint:true});
    if(!s.isDirectory()||(s.uid!==0n&&s.uid!==BigInt(uid)))throw deny();
    // Permit root-owned sticky /tmp-style parents, never arbitrary writable ancestors.
    if((s.mode&0o022n)!==0n&&!(s.uid===0n&&(s.mode&0o1000n)!==0n))throw deny();
    if(parent===parse(path).root)break;
   }
  };
  const checkIdentity=(s:BigIntStats)=>privateDirectory(s,uid)&&s.dev.toString()===device&&s.ino.toString()===inode;
  const namespace='agentkeychain.pilot.'+await digest(JSON.stringify([domain,scope.installationDigest,path,uid,device,inode]));
  if(now()>=expiresAt)throw deny();
  checkAncestors();
  const initial=lstatSync(path,{bigint:true});
  if(!checkIdentity(initial)||realpathSync.native(path)!==path)throw deny();
  fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  const opened=fstatSync(fd,{bigint:true});
  if(!checkIdentity(opened)||!equalIdentity(initial,opened))throw deny();
  if(readdirSync('/proc/self/fd/'+fd).length!==0)throw deny();
  checkAncestors();
  if(realpathSync.native(path)!==path||!equalIdentity(opened,lstatSync(path,{bigint:true}))||
     !equalIdentity(opened,fstatSync(fd,{bigint:true}))||now()>=expiresAt)throw deny();
  installedContinuationPilotScope(gate);
  return Object.freeze({state:'empty-disposable-directory',namespace,expiresAt});
 }catch{throw deny();}finally{if(fd!==undefined)closeSync(fd);}
}
