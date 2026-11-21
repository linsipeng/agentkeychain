/** Test-only offline transfer. Not invoked or shipped by any installer or CLI. */
import {createHash} from 'node:crypto';
import {constants} from 'node:fs';
import {lstat,open,link,mkdtemp,realpath,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {verify} from '../../managed-cloud/shared/contracts.ts';
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {INSTALLED_PILOT_BINARY,installedContinuationPilotScope,type VerifiedInstalledContinuationPilot} from '../../src/cloud/continuation-pilot-build.ts';

export const offlineDomain='AgentKeychain-test-only-pilot-offline-package-v1';
const deny=()=>new Error('pilot_offline_fixture_denied');
const now=()=>Math.floor(Date.now()/1000);

export async function admitDisposablePilotPackage(gate:VerifiedInstalledContinuationPilot,root:string,descriptor:SignedManagedOperation){
 try{
  const scope=installedContinuationPilotScope(gate),uid=process.getuid?.();
  if(process.platform!=='linux'||!uid||process.geteuid?.()!==uid||scope.target!==`linux-${process.arch}`||
     !/^\/tmp\/akc-offline-pilot-[A-Za-z0-9]+$/.test(root)||!constants.O_NOFOLLOW||!constants.O_NONBLOCK)throw deny();
  exactFields(descriptor,['canonical','signature']);
  if(typeof descriptor.canonical!=='string'||!descriptor.canonical.length||descriptor.canonical.length>1024)throw deny();
  base64(descriptor.signature,64,64);
  const claim:unknown=JSON.parse(descriptor.canonical);
  exactFields(claim,['version','domain','mode','installationDigest','keyId','target','name','size','sha256','issuedAt','expiresAt']);
  const {size,sha256,issuedAt,expiresAt}=claim;
  if(typeof size!=='number'||!Number.isSafeInteger(size)||size<=0||size>256*1024*1024||
     typeof sha256!=='string'||!/^[a-f0-9]{64}$/.test(sha256)||typeof issuedAt!=='number'||typeof expiresAt!=='number'||
     !Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||issuedAt<=0||issuedAt>now()||expiresAt<=now()||
     expiresAt>gate.expiresAt||expiresAt-issuedAt>300)throw deny();
  const expected=JSON.stringify({version:1,domain:offlineDomain,mode:'synthetic-only',installationDigest:scope.installationDigest,
   keyId:scope.rollout.keyId,target:scope.target,name:INSTALLED_PILOT_BINARY,size,sha256,issuedAt,expiresAt});
  if(descriptor.canonical!==expected||!await verify(scope.rollout.publicKey,descriptor.signature,expected))throw deny();
  const inbox=join(root,'offline'),install=join(root,'alternate');
  const dir=async(path:string)=>{
   const stat=await lstat(path,{bigint:true});
   if(!stat.isDirectory()||stat.uid!==BigInt(uid)||(stat.mode&0o7777n)!==0o700n||await realpath(path)!==path)throw deny();
   return stat;
  };
  const scratch=await lstat('/tmp',{bigint:true});
  const trustedScratch=(scratch.uid===0n&&(scratch.mode&0o1000n)!==0n)||
   (scratch.uid===BigInt(uid)&&(scratch.mode&0o022n)===0n);
  if(!scratch.isDirectory()||!trustedScratch||await realpath('/tmp')!=='/tmp')throw deny();
  const top=await dir(root),source=await dir(inbox),destination=await dir(install);
  const binary=join(inbox,INSTALLED_PILOT_BINARY),installed=join(install,INSTALLED_PILOT_BINARY);
  const input=await open(binary,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const stat=await input.stat({bigint:true});
   const same=(a:typeof stat,b:typeof stat)=>a.dev===b.dev&&a.ino===b.ino&&a.uid===b.uid&&a.mode===b.mode&&a.size===b.size&&a.nlink===b.nlink;
   if(!stat.isFile()||stat.uid!==BigInt(uid)||stat.nlink!==1n||(stat.mode&0o7022n)!==0n||stat.size!==BigInt(size)||
      !same(stat,await lstat(binary,{bigint:true})))throw deny();
   const temporary=await mkdtemp(join(install,'.fixture-'));
   const copy=join(temporary,'verified');
   try{
    const output=await open(copy,'wx',0o700);
    try{
     const h=createHash('sha256'),chunk=Buffer.allocUnsafe(64*1024);
     let offset=0;
     while(offset<size){
      const {bytesRead}=await input.read(chunk,0,Math.min(chunk.length,size-offset),offset);
      if(bytesRead<=0)throw deny();
      h.update(chunk.subarray(0,bytesRead));
      let sent=0;
      while(sent<bytesRead){
       const result=await output.write(chunk,sent,bytesRead-sent,offset+sent);
       if(result.bytesWritten<=0)throw deny();
       sent+=result.bytesWritten;
      }
      offset+=bytesRead;
     }
     if((await input.read(chunk,0,1,size)).bytesRead!==0||h.digest('hex')!==sha256||
        !same(stat,await input.stat({bigint:true}))||!same(stat,await lstat(binary,{bigint:true})))throw deny();
     await output.chmod(0o700);
    }finally{await output.close();}
    if(now()>=expiresAt||!same(top,await dir(root))||!same(source,await dir(inbox))||
       // Creating and deleting the private staging directory can change stat size/nlink.
       (await dir(install)).ino!==destination.ino||(await dir(install)).dev!==destination.dev)throw deny();
    await link(copy,installed); // Never overwrite a preexisting destination.
    return installed;
   }finally{await rm(temporary,{recursive:true,force:true});}
  }finally{await input.close();}
 }catch{throw deny();}
}
