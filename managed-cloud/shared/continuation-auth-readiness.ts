import {base64,exactFields,identifier,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {genesisRoot,type CheckpointKey} from './checkpoints.ts';
import {digest,verify} from './contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from './device-protocol.ts';
import {canonicalContinuationIntent} from './enrollment-continuation.ts';
import {rosterDigest,verifyRoster} from './roster.ts';
import {verifyWitness} from './roster-witness.ts';

export const CONTINUATION_AUTH_READY_DOMAIN='AgentKeychain-enrollment-continuation-auth-ready-v1';
export const CONTINUATION_AUTH_READY_SECONDS=30;
const fields=['version','domain','keyId','nonce','grantDigest','intentDigest','witnessDigest','payloadDigest','rosterDigest',
 'requestId','accountId','tenantId','vaultId','deviceId','keyEpoch','issuedAt','expiresAt'];
const invalid=()=>new Error('invalid_continuation_auth_readiness');
export function canonicalContinuationAuthReadiness(input:unknown):string {
 exactFields(input,fields);
 if(input.version!==1||input.domain!==CONTINUATION_AUTH_READY_DOMAIN||typeof input.nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(input.nonce))throw invalid();
 for(const k of ['keyId','requestId','accountId','tenantId','vaultId','deviceId'])identifier(input[k]);
 for(const k of ['grantDigest','intentDigest','witnessDigest','payloadDigest','rosterDigest'])
  if(typeof input[k]!=='string'||!/^[a-f0-9]{64}$/.test(input[k] as string))throw invalid();
 for(const k of ['keyEpoch','issuedAt','expiresAt'])if(!Number.isSafeInteger(input[k])||(input[k] as number)<1)throw invalid();
 if((input.expiresAt as number)<=(input.issuedAt as number)||(input.expiresAt as number)-(input.issuedAt as number)>CONTINUATION_AUTH_READY_SECONDS)throw invalid();
 return JSON.stringify(Object.fromEntries(fields.map(k=>[k,input[k]])));
}

/** Proof-only pre-approval verification. The Auth caller scopes/signs approval
 * separately after Passkey. Its trusted challenge is random and generated
 * after UV. The independent Custody issuer must recheck its live head and
 * revocation state; this helper does not mint readiness or authorize a write. */
export async function verifyContinuationAuthReadiness(proof:SignedManagedOperation,expected:{
 nonce:string;oldGrantCanonical:string;target:SignedManagedOperation;roster:SignedManagedOperation;witness:SignedManagedOperation;
 payloadDigest:string;witnessPins:readonly CheckpointKey[];now:number;requestedAt:number;
}):Promise<void>{
 try{
  exactFields(proof,['canonical','signature']);
  if(typeof proof.canonical!=='string'||proof.canonical.length>4096||expected.oldGrantCanonical.length>4096||expected.target.canonical.length>4096||
     expected.roster.canonical.length>16384||expected.witness.canonical.length>4096)throw invalid();
  base64(proof.signature,64,64);
  const g=JSON.parse(expected.oldGrantCanonical) as EnrollmentGrant, t=JSON.parse(expected.target.canonical),p=JSON.parse(proof.canonical);
  if(canonicalGrant(g)!==expected.oldGrantCanonical||canonicalContinuationIntent(t)!==expected.target.canonical||
     canonicalContinuationAuthReadiness(p)!==proof.canonical||g.issuerDeviceId!==null||g.expiresAt>expected.requestedAt||
     !Number.isSafeInteger(expected.now)||!Number.isSafeInteger(expected.requestedAt)||expected.requestedAt>expected.now||
     p.issuedAt<expected.requestedAt||p.issuedAt>expected.now||p.expiresAt<=expected.now||p.expiresAt>t.expiresAt)throw invalid();
  const grantDigest=await digest(expected.oldGrantCanonical),intentDigest=await digest(expected.target.canonical);
  const head=await rosterDigest(expected.roster),r=await verifyRoster(expected.roster,null,expected.now,true),active=r.active[0];
  if(r.revision!==1||r.accountId!==g.accountId||r.tenantId!==g.tenantId||r.vaultId!==g.vaultId||r.keyEpoch!==g.keyEpoch||
     r.issuer.kind!=='device'||r.issuer.id!==g.deviceId||r.active.length!==1||r.revoked.length||
     active?.deviceId!==g.deviceId||active.signingKey!==g.signingKey||active.wrappingKey!==g.wrappingKey||
     p.expiresAt>r.expiresAt||t.stage!=='put-key-package'||t.originalGrantDigest!==grantDigest||
     t.rosterDigest!==head||t.witnessHead?.revision!==1||t.witnessHead.digest!==head||t.payloadDigest!==expected.payloadDigest||
     (['requestId','accountId','tenantId','vaultId','deviceId','signingKey','wrappingKey','issuerDeviceId','keyEpoch'] as const).some(k=>t[k]!==g[k])||
     !await verify(g.signingKey,expected.target.signature,expected.target.canonical))throw invalid();
  const w=await verifyWitness(expected.witness,expected.witnessPins,{accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,revision:1,digest:head});
  const pin=expected.witnessPins.find(pin=>pin.keyId===w.keyId);
  if(w.event!==1||w.sequence!==0||w.root!==await genesisRoot(g.tenantId,g.vaultId)||!pin||
     [...r.checkpointKeys,...r.recoveryAuthorities].some(k=>k.publicKey===pin.publicKey)||
     [g.signingKey,g.wrappingKey].includes(pin.publicKey))throw invalid();
  if(proof.canonical!==canonicalContinuationAuthReadiness({version:1,domain:CONTINUATION_AUTH_READY_DOMAIN,keyId:pin.keyId,nonce:expected.nonce,
   grantDigest,intentDigest,witnessDigest:await digest(JSON.stringify([expected.witness.canonical,expected.witness.signature])),
   payloadDigest:expected.payloadDigest,rosterDigest:head,requestId:g.requestId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,
   deviceId:g.deviceId,keyEpoch:g.keyEpoch,issuedAt:p.issuedAt,expiresAt:p.expiresAt})||
   !await verify(pin.publicKey,proof.signature,proof.canonical))throw invalid();
 }catch{throw invalid();}
}
