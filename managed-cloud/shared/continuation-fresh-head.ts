import {base64,exactFields,identifier,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {genesisRoot,type CheckpointKey,type CheckpointSigner} from './checkpoints.ts';
import {digest,verify} from './contracts.ts';
import {canonicalGrant,canonicalPackage,type EnrollmentGrant,type KeyPackage} from './device-protocol.ts';
import {verifyContinuationApproval} from './enrollment-continuation.ts';
import {rosterDigest,verifyRoster} from './roster.ts';
import {verifyWitness} from './roster-witness.ts';

export const CONTINUATION_HEAD_DOMAIN='AgentKeychain-enrollment-continuation-current-head-v1';
export const MAIN_CONTINUATION_COMMIT_DOMAIN='AgentKeychain-enrollment-continuation-main-commit-v1';
export const CUSTODY_CONTINUATION_POST_COMMIT_DOMAIN='AgentKeychain-enrollment-continuation-custody-post-commit-v1';
export interface ContinuationFreshHeadRequest {
 readonly nonce:string; readonly grant:string;
 readonly target:SignedManagedOperation; readonly approval:SignedManagedOperation;
 readonly roster:SignedManagedOperation; readonly keyPackage:SignedManagedOperation;
}
interface CustodyPolicy {
 readonly authority:CheckpointKey;
 readonly witnessKeys:readonly CheckpointKey[];
 readonly checkpointKeys:readonly CheckpointKey[];
 readonly recoveryAuthorities:readonly CheckpointKey[];
}
interface StoredHead {event:number;revision:number;sequence:number;digest:string;root:string;roster:string;checkpoint:string;receipt:string}

const reject=()=>new Error('continuation_head_rejected');
const nowSeconds=()=>Math.floor(Date.now()/1000);
const shape=(value:unknown,max:number):SignedManagedOperation=>{
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||value.canonical.length===0||value.canonical.length>max)throw reject();
 base64(value.signature,64,64);
 return {canonical:value.canonical,signature:value.signature};
};
const bytesDigest=(value:SignedManagedOperation)=>digest(JSON.stringify([value.canonical,value.signature]));

async function approvedCurrentHead(db:D1Database,request:ContinuationFreshHeadRequest,policy:CustodyPolicy,localWitnessKey:CheckpointSigner){
  const {nonce,grant}=request;
  if(typeof nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(nonce)||typeof grant!=='string'||grant.length===0||grant.length>4096)throw reject();
  const target=shape(request.target,4096),approval=shape(request.approval,1024),roster=shape(request.roster,64*1024),keyPackage=shape(request.keyPackage,4096);
  const g=JSON.parse(grant) as EnrollmentGrant;
  if(canonicalGrant(g)!==grant||g.issuerDeviceId!==null)throw reject();
  const now=nowSeconds(),r=await verifyRoster(roster,null,now),d=r.active[0];
  const {accountId,tenantId,vaultId,deviceId}=g;
  if(r.accountId!==accountId||r.tenantId!==tenantId||r.vaultId!==vaultId||r.keyEpoch!==g.keyEpoch||
     r.issuer.kind!=='device'||r.issuer.id!==deviceId||!d||d.deviceId!==deviceId||d.signingKey!==g.signingKey||d.wrappingKey!==g.wrappingKey||
     JSON.stringify(r.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities))throw reject();
  const p=JSON.parse(keyPackage.canonical) as KeyPackage;
  if(canonicalPackage(p)!==keyPackage.canonical||p.grantId!==g.requestId||p.vaultId!==vaultId||p.targetDeviceId!==deviceId||p.issuerDeviceId!==deviceId||p.keyEpoch!==g.keyEpoch||
     !await verify(g.signingKey,keyPackage.signature,keyPackage.canonical))throw reject();

  // Never source the head from Main or from a witness carried by the request.
  const head=()=>db.prepare(`SELECT w.event,w.revision,w.sequence,w.digest,w.root,w.roster,w.checkpoint,w.receipt
   FROM roster_witness w WHERE w.tenant_id=? AND w.vault_id=?
   AND NOT EXISTS(SELECT 1 FROM recovery_revocation_witness WHERE tenant_id=w.tenant_id AND vault_id=w.vault_id AND device_id=?)
   AND NOT EXISTS(SELECT 1 FROM trust_devices WHERE account_id=? AND tenant_id=w.tenant_id AND vault_id=w.vault_id AND device_id=? AND revoked=1)
   ORDER BY w.event DESC LIMIT 1`).bind(tenantId,vaultId,deviceId,accountId,deviceId).first<StoredHead>();
  const row=await head(),expected=await rosterDigest(roster);
  if(!row||row.revision!==1||row.digest!==expected||row.roster!==JSON.stringify(roster))throw reject();
  const witness=shape(JSON.parse(row.receipt),4096),checkpoint=shape(JSON.parse(row.checkpoint),4096);
  const w=await verifyWitness(witness,policy.witnessKeys,{accountId,tenantId,vaultId,revision:1,digest:expected},checkpoint);
  if(w.event!==1||w.sequence!==0||w.root!==await genesisRoot(tenantId,vaultId)||
     w.event!==row.event||w.sequence!==row.sequence||w.root!==row.root)throw reject();
  const pin=policy.witnessKeys.find(k=>k.keyId===w.keyId),key=await localWitnessKey.key();
  identifier(policy.authority.keyId);base64(policy.authority.publicKey,32,32);
  if(!pin||pin.keyId!==key.keyId||pin.publicKey!==key.publicKey||
     [g.signingKey,g.wrappingKey,...policy.checkpointKeys.map(k=>k.publicKey),...policy.recoveryAuthorities.map(k=>k.publicKey)].includes(pin.publicKey)||
     [...policy.checkpointKeys,...policy.witnessKeys,...policy.recoveryAuthorities].some(k=>k.publicKey===policy.authority.publicKey))throw reject();

  const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',keyPackage.canonical,keyPackage.signature]));
  const issuedAt=nowSeconds();
  await verifyContinuationApproval(target,approval,{oldGrantCanonical:grant,stage:'put-key-package',payloadDigest,
   rosterDigest:expected,witnessHead:{revision:w.revision,digest:w.digest},authority:policy.authority,issuer:null,now:issuedAt});
  const approvalWindow=JSON.parse(approval.canonical) as {approvedAt:number;expiresAt:number};
  const expiresAt=Math.min(issuedAt+60,approvalWindow.expiresAt,r.expiresAt);
  const stillCurrent=async()=>{
   const after=await head();
   return !!after&&after.event===row.event&&after.receipt===row.receipt&&after.digest===row.digest;
  };
  return {g,w,pin,witness,target,approval,approvalWindow,nonce,issuedAt,expiresAt,payloadDigest,stillCurrent};
}

/** Internal read-only preflight; the local signer remains unexposed. */
export async function proveFreshContinuationHead(
 db:D1Database, request:ContinuationFreshHeadRequest, policy:CustodyPolicy, localWitnessKey:CheckpointSigner,
):Promise<{witness:SignedManagedOperation;freshHead:SignedManagedOperation}>{
 try{
  exactFields(request,['nonce','grant','target','approval','roster','keyPackage']);
  const {g,w,pin,witness,approval,nonce,issuedAt,expiresAt,payloadDigest,stillCurrent}=await approvedCurrentHead(db,request,policy,localWitnessKey);
  if(expiresAt<=issuedAt)throw reject();
  const canonical=JSON.stringify({domain:CONTINUATION_HEAD_DOMAIN,keyId:w.keyId,nonce,requestId:g.requestId,
   witnessDigest:await bytesDigest(witness),approvalDigest:await bytesDigest(approval),payloadDigest,issuedAt,expiresAt});
  const signature=await localWitnessKey.sign(canonical);
  if(!await verify(pin.publicKey,signature,canonical))throw reject();
  if(!await stillCurrent()||nowSeconds()>=expiresAt)throw reject();
  return {witness,freshHead:{canonical,signature}};
 }catch{throw reject();}
}

/** Separate internal post-commit Custody assertion. Authenticating Main's
 * purpose-specific signed claim precedes the independent Custody snapshot.
 * This proves the sample occurred after that claim, not independent storage.
 * Pins/keys are local Custody configuration; no HTTP, RPC or write path. */
export async function provePostCommitContinuationHead(
 db:D1Database, request:ContinuationFreshHeadRequest,
 priorFreshHead:SignedManagedOperation, mainCommit:SignedManagedOperation,
 policy:CustodyPolicy&{readonly mainCommitAuthority:CheckpointKey;readonly otherReleaseKeys:readonly CheckpointKey[]},
 localWitnessKey:CheckpointSigner,
):Promise<SignedManagedOperation>{
 try{
  exactFields(request,['nonce','grant','target','approval','roster','keyPackage']);
  const main=shape(mainCommit,4096),prior=shape(priorFreshHead,2048),mainPin=policy.mainCommitAuthority;
  identifier(mainPin.keyId);base64(mainPin.publicKey,32,32);
  if([policy.authority,...policy.witnessKeys,...policy.checkpointKeys,...policy.recoveryAuthorities,...policy.otherReleaseKeys]
    .some(pin=>pin.keyId===mainPin.keyId||pin.publicKey===mainPin.publicKey)||
    !await verify(mainPin.publicKey,main.signature,main.canonical))throw reject();
  const c:unknown=JSON.parse(main.canonical),observedAt=nowSeconds();
  exactFields(c,['version','domain','keyId','nonce','continuationId','requestId','accountId','tenantId','vaultId','deviceId','keyEpoch',
   'stage','intentDigest','approvalDigest','payloadDigest','witnessDigest','custodyFreshHeadDigest','issuedAt','expiresAt']);
  if(c.version!==1||c.domain!==MAIN_CONTINUATION_COMMIT_DOMAIN||c.keyId!==mainPin.keyId||
     typeof c.nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(c.nonce)||c.nonce===request.nonce||
     typeof c.issuedAt!=='number'||typeof c.expiresAt!=='number'||!Number.isSafeInteger(c.issuedAt)||!Number.isSafeInteger(c.expiresAt)||
     c.issuedAt>observedAt||c.expiresAt<=observedAt||c.expiresAt-c.issuedAt>60||
     await bytesDigest(prior)!==c.custodyFreshHeadDigest)throw reject();

  // New read after authenticating the signed transaction-owner claim.
  const {g,w,pin,witness,target,approval,approvalWindow,nonce,issuedAt,expiresAt,payloadDigest,stillCurrent}=await approvedCurrentHead(db,request,policy,localWitnessKey);
  if(mainPin.publicKey===g.signingKey||mainPin.publicKey===g.wrappingKey||c.issuedAt<approvalWindow.approvedAt||c.expiresAt>approvalWindow.expiresAt)throw reject();
  const {id:continuationId}=JSON.parse(target.canonical) as {id:string};
  const witnessDigest=await bytesDigest(witness),approvalDigest=await bytesDigest(approval),intentDigest=await digest(target.canonical);
  if(main.canonical!==JSON.stringify({version:1,domain:MAIN_CONTINUATION_COMMIT_DOMAIN,keyId:mainPin.keyId,nonce:c.nonce,continuationId,
   requestId:g.requestId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,deviceId:g.deviceId,keyEpoch:g.keyEpoch,
   stage:'put-key-package',intentDigest,approvalDigest,payloadDigest,witnessDigest,custodyFreshHeadDigest:await bytesDigest(prior),
   issuedAt:c.issuedAt,expiresAt:c.expiresAt}))throw reject();

  const f:unknown=JSON.parse(prior.canonical);
  exactFields(f,['domain','keyId','nonce','requestId','witnessDigest','approvalDigest','payloadDigest','issuedAt','expiresAt']);
  if(typeof f.issuedAt!=='number'||typeof f.expiresAt!=='number'||!Number.isSafeInteger(f.issuedAt)||!Number.isSafeInteger(f.expiresAt)||
     f.issuedAt<approvalWindow.approvedAt||f.issuedAt>c.issuedAt||c.expiresAt>f.expiresAt||
     f.expiresAt>approvalWindow.expiresAt||f.expiresAt-f.issuedAt>60||
     prior.canonical!==JSON.stringify({domain:CONTINUATION_HEAD_DOMAIN,keyId:w.keyId,nonce:c.nonce,requestId:g.requestId,
      witnessDigest,approvalDigest,payloadDigest,issuedAt:f.issuedAt,expiresAt:f.expiresAt})||
     !await verify(pin.publicKey,prior.signature,prior.canonical))throw reject();
  const postExpiry=Math.min(expiresAt,c.expiresAt);
  if(!await stillCurrent()||nowSeconds()>=postExpiry)throw reject();
  const canonical=JSON.stringify({version:1,domain:CUSTODY_CONTINUATION_POST_COMMIT_DOMAIN,keyId:w.keyId,nonce,
   mainCommitDigest:await bytesDigest(main),requestId:g.requestId,continuationId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,
   deviceId:g.deviceId,keyEpoch:g.keyEpoch,witnessDigest,payloadDigest,issuedAt,expiresAt:postExpiry});
  const signature=await localWitnessKey.sign(canonical);
  if(!await verify(pin.publicKey,signature,canonical)||!await stillCurrent()||nowSeconds()>=postExpiry)throw reject();
  return {canonical,signature};
 }catch{throw reject();}
}
