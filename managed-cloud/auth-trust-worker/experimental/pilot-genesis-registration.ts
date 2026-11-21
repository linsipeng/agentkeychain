import type {RegistrationResponseJSON} from '@simplewebauthn/server';
import {base64,exactFields,type SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import {encode,random,webauthn,type WebAuthnPolicy} from '../../api-worker/webauthn.ts';
import {digest,verify} from '../../shared/contracts.ts';
import type {CheckpointKey} from '../../shared/checkpoints.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import {rosterDigest,verifyRoster} from '../../shared/roster.ts';
import type {GenesisApprovalPolicy} from '../../shared/genesis-approval.ts';

export const PILOT_GENESIS_INVITE_DOMAIN='AgentKeychain-pilot-genesis-registration-invite-v1';
const denied=()=>new Error('pilot_genesis_registration_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const opaque=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);

/** Isolated Auth registration kernel only. The caller is an Auth-owned adapter
 * which must bind browserDigest to a server-generated cookie, exact HTTPS Origin
 * and CSRF. No Main pin import, HTTP, general session, signer or activation. */
export function pilotGenesisRegistration(db:D1Database,identity:WebAuthnPolicy,policy:GenesisApprovalPolicy,inviteKey:CheckpointKey,deadline=Number.MAX_SAFE_INTEGER){
 const u=new URL(identity.origin);
 if(u.protocol!=='https:'||u.origin!==identity.origin||u.port||u.hostname!==identity.rpId||!/^auth-pilot-[a-z0-9-]+\./.test(u.hostname))throw denied();
 async function scope(invite:SignedManagedOperation,grant:string,roster:SignedManagedOperation,browserDigest:string){
  if(!hash(browserDigest)||typeof grant!=='string'||grant.length>4096)throw denied();
  exactFields(invite,['canonical','signature']);exactFields(roster,['canonical','signature']);
  if(typeof invite.canonical!=='string'||invite.canonical.length>2048||typeof roster.canonical!=='string'||roster.canonical.length>16384)throw denied();
  base64(invite.signature,64,64);base64(roster.signature,64,64);base64(inviteKey.publicKey,32,32);
  const g=JSON.parse(grant) as EnrollmentGrant,at=now();
  if(canonicalGrant(g)!==grant||g.issuerDeviceId!==null||g.expiresAt<=at||inviteKey.keyId!==await digest(inviteKey.publicKey)||
     [g.signingKey,g.wrappingKey].includes(inviteKey.publicKey)||
     [policy.authority,...policy.checkpointKeys,...policy.recoveryAuthorities].some(k=>k.keyId===inviteKey.keyId||k.publicKey===inviteKey.publicKey))throw denied();
  const r=await verifyRoster(roster,null,at),d=r.active[0];
  const {accountId,tenantId,vaultId,deviceId,requestId,keyEpoch}=g;
  if(r.accountId!==accountId||r.tenantId!==tenantId||r.vaultId!==vaultId||r.keyEpoch!==keyEpoch||r.revision!==1||
     r.issuer.kind!=='device'||r.issuer.id!==deviceId||r.active.length!==1||r.revoked.length||!d||d.deviceId!==deviceId||
     d.signingKey!==g.signingKey||d.wrappingKey!==g.wrappingKey||
     JSON.stringify(r.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities))throw denied();
  const data:unknown=JSON.parse(invite.canonical);
  exactFields(data,['version','domain','keyId','origin','rpId','id','accountId','tenantId','vaultId','deviceId','requestId','keyEpoch','grantDigest','rosterDigest','issuedAt','expiresAt']);
  const {id,issuedAt,expiresAt}=data;
  if(!opaque(id)||typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
     issuedAt<1||issuedAt>at||expiresAt<=at||expiresAt-issuedAt>600||expiresAt>Math.min(g.expiresAt,r.expiresAt,deadline))throw denied();
  const grantDigest=await digest(grant),rosterHash=await rosterDigest(roster);
  const expected={version:1,domain:PILOT_GENESIS_INVITE_DOMAIN,keyId:inviteKey.keyId,origin:identity.origin,rpId:identity.rpId,id,
   accountId,tenantId,vaultId,deviceId,requestId,keyEpoch,grantDigest,rosterDigest:rosterHash,issuedAt,expiresAt};
  if(invite.canonical!==JSON.stringify(expected)||!await verify(inviteKey.publicKey,invite.signature,invite.canonical))throw denied();
  return {id,accountId,tenantId,vaultId,grantDigest,rosterHash,expiresAt};
 }
 return {
  async begin(invite:SignedManagedOperation,grant:string,roster:SignedManagedOperation,browserDigest:string){
   try{
    const s=await scope(invite,grant,roster,browserDigest),challenge=random(),handle=random();
    const options=await webauthn.registrationOptions(identity,handle,challenge);
    const row=await db.prepare(`INSERT INTO pilot_genesis_registration
     (id,account,tenant,vault,grant_digest,roster_digest,browser_digest,handle,challenge_digest,expires)
     SELECT ?,?,?,?,?,?,?,?,?,? WHERE ?>unixepoch() RETURNING id`)
     .bind(s.id,s.accountId,s.tenantId,s.vaultId,s.grantDigest,s.rosterHash,browserDigest,handle,await digest(challenge),s.expiresAt,s.expiresAt).first();
    if(!row)throw denied();
    return options;
   }catch{throw denied();}
  },
  async complete(invite:SignedManagedOperation,grant:string,roster:SignedManagedOperation,browserDigest:string,response:RegistrationResponseJSON){
   try{
    const s=await scope(invite,grant,roster,browserDigest);
    if(JSON.stringify(response).length>32_768)throw denied();
    const filter='id=? AND account=? AND tenant=? AND vault=? AND grant_digest=? AND roster_digest=? AND browser_digest=? AND expires=? AND expires>unixepoch() AND credential IS NULL';
    const args=[s.id,s.accountId,s.tenantId,s.vaultId,s.grantDigest,s.rosterHash,browserDigest,s.expiresAt] as const;
    const row=await db.prepare('SELECT challenge_digest FROM pilot_genesis_registration WHERE '+filter).bind(...args).first<{challenge_digest:string}>();
    if(!row)throw denied();
    const c=await webauthn.registration(identity,row.challenge_digest,response);
    const consumed=await db.prepare('UPDATE pilot_genesis_registration SET credential=?,cose_key=?,counter=? WHERE '+filter+
     ' AND challenge_digest=? RETURNING id').bind(c.id,encode(c.publicKey),c.counter,...args,row.challenge_digest).first();
    if(!consumed)throw denied();
   }catch{throw denied();}
  },
 };
}
