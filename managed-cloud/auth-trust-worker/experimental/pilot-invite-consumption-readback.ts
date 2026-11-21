/** Unwired Auth-local readback of persisted invite use. No route, token,
 * credential material, or generic signer. */
import {base64,exactFields,type SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import {digest,verify} from '../../shared/contracts.ts';
import type {CheckpointKey,CheckpointSigner} from '../../shared/checkpoints.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import {verifyPendingPilotMainInviteLink,type ExistingMainMapping,type PilotMainInvitePolicy} from '../../shared/pilot-main-invite-link.ts';

export const PILOT_INVITE_READBACK='AgentKeychain-pilot-auth-invite-consumption-readback-v1';
export const PILOT_INVITE_READBACK_REQUEST='AgentKeychain-pilot-auth-invite-consumption-request-v1';
const denied=()=>new Error('pilot_auth_invite_consumption_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const hashEnvelope=(v:SignedManagedOperation)=>digest(JSON.stringify([v.canonical,v.signature]));
type Roles=Readonly<{mode:'invite-consumption-v1'; authority:Readonly<CheckpointKey>; signer:CheckpointSigner;
 reservedRolePins:readonly Readonly<CheckpointKey>[]}>;
export function pilotInviteConsumptionDeviceProof(nonce:string,requestedAt:number,linkDigest:string){
 return JSON.stringify([PILOT_INVITE_READBACK_REQUEST,nonce,requestedAt,linkDigest]);
}
function operation(input:unknown,max:number){
 exactFields(input,['canonical','signature']);
 if(typeof input.canonical!=='string'||!input.canonical||new TextEncoder().encode(input.canonical).length>max)throw denied();
 base64(input.signature,64,64);
 return {canonical:input.canonical,signature:input.signature};
}

/** Service-side only: `expected` must come from an independent trusted Main
 * linkage resolver, not a public request or Auth decision. The exact Admin
 * link and original-device PoP authorize this read, not consent by itself.
 * Do not publish an RPC taking policy, mapping, or signer from a caller. */
export async function readPilotAuthInvitationConsumption(
 db:Pick<D1Database,'withSession'>,raw:unknown,expected:ExistingMainMapping,policy:PilotMainInvitePolicy,role?:Roles,
):Promise<Readonly<SignedManagedOperation>>{
 try{
  if(role?.mode!=='invite-consumption-v1'||typeof role.signer?.key!=='function'||typeof role.signer?.sign!=='function'||
     typeof raw!=='string'||raw.length>64*1024||new TextEncoder().encode(raw).length>64*1024)throw denied();
  const input:unknown=JSON.parse(raw);
  exactFields(input,['version','domain','nonce','requestedAt','invite','authApproval','roster','mainLink','deviceSignature']);
  const {nonce,requestedAt,deviceSignature}=input,at=now();
  if(typeof nonce!=='string'||nonce.length!==43||!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(nonce)||
     typeof requestedAt!=='number'||!Number.isSafeInteger(requestedAt)||requestedAt<1||requestedAt>at||at>=requestedAt+30)throw denied();
  base64(deviceSignature,64,64);
  const selection={invite:operation(input.invite,4096),authApproval:operation(input.authApproval,2048),
   roster:operation(input.roster,16384),mainLink:operation(input.mainLink,4096)};
  if(raw!==JSON.stringify({version:1,domain:PILOT_INVITE_READBACK_REQUEST,nonce,requestedAt,...selection,deviceSignature}))throw denied();
  const grant=JSON.parse(expected.grantCanonical) as EnrollmentGrant;
  if(canonicalGrant(grant)!==expected.grantCanonical||grant.issuerDeviceId!==null)throw denied();
  const mainLinkDigest=await hashEnvelope(selection.mainLink);
  if(!await verify(grant.signingKey,deviceSignature,pilotInviteConsumptionDeviceProof(nonce,requestedAt,mainLinkDigest)))throw denied();
  await verifyPendingPilotMainInviteLink(selection,expected,policy);
  const {authority,signer,reservedRolePins}=role;
  if(!reservedRolePins.length||reservedRolePins.length>16)throw denied();
  for(const pin of reservedRolePins){base64(pin.publicKey,32,32);if(pin.keyId!==await digest(pin.publicKey))throw denied();}
  base64(authority.publicKey,32,32);
  if(authority.keyId!==await digest(authority.publicKey)||
     [grant.signingKey,grant.wrappingKey,policy.authority.publicKey,policy.inviteAuthority.publicKey,policy.mainLinkAuthority.publicKey,
      ...policy.checkpointKeys.map(p=>p.publicKey),...policy.recoveryAuthorities.map(p=>p.publicKey),
      ...reservedRolePins.map(p=>p.publicKey)].includes(authority.publicKey))throw denied();
  const key=await signer.key();
  if(key.keyId!==authority.keyId||key.publicKey!==authority.publicKey)throw denied();
  const invite=JSON.parse(selection.invite.canonical) as {id:string;expiresAt:number;grantDigest:string;rosterDigest:string};
  const approval=JSON.parse(selection.authApproval.canonical) as {decisionId:string;expiresAt:number};
  const link=JSON.parse(selection.mainLink.canonical) as {expiresAt:number};
  const liveUntil=Math.min(requestedAt+30,invite.expiresAt,approval.expiresAt,link.expiresAt,grant.expiresAt,expected.installationExpiresAt);
  const read=()=>db.withSession('first-primary').prepare(`
   SELECT r.expires AS registrationUntil,c.expires AS challengeUntil FROM pilot_genesis_registration r
   JOIN auth_genesis_pins p ON p.account=r.account AND p.tenant=r.tenant AND p.vault=r.vault AND p.credential=r.credential AND p.active=1
   JOIN auth_genesis_challenges c ON c.account=r.account AND c.tenant=r.tenant AND c.vault=r.vault AND c.credential=r.credential
     AND c.grant_digest=r.grant_digest AND c.roster_digest=r.roster_digest
   JOIN pilot_genesis_browser_guard b ON b.challenge_id=c.id AND b.browser_digest=r.browser_digest AND b.finalize=1
   JOIN auth_genesis_decisions d ON d.id=c.id AND d.grant_digest=c.grant_digest
   WHERE r.id=? AND r.account=? AND r.tenant=? AND r.vault=? AND r.grant_digest=? AND r.roster_digest=?
     AND r.expires=? AND r.expires>unixepoch() AND c.expires>unixepoch() AND d.id=? AND d.canonical=? AND d.signature=?
  `).bind(invite.id,grant.accountId,grant.tenantId,grant.vaultId,invite.grantDigest,invite.rosterDigest,
   invite.expiresAt,approval.decisionId,selection.authApproval.canonical,selection.authApproval.signature)
   .first<{registrationUntil:number;challengeUntil:number}>();
  const row=await read(),issuedAt=now();
  if(!row||row.registrationUntil!==invite.expiresAt||!Number.isSafeInteger(row.challengeUntil)||issuedAt<requestedAt)throw denied();
  const expiresAt=Math.min(liveUntil,row.challengeUntil);
  if(issuedAt>=expiresAt)throw denied();
  const canonical=JSON.stringify({version:1,domain:PILOT_INVITE_READBACK,keyId:authority.keyId,nonce,requestDigest:await digest(raw),
   inviteDigest:await hashEnvelope(selection.invite),authApprovalDigest:await hashEnvelope(selection.authApproval),mainLinkDigest,
   installationDigest:expected.installationDigest,profileDigest:expected.profileDigest,issuedAt,expiresAt});
  const signature=await signer.sign(canonical);
  base64(signature,64,64);
  if(!await verify(authority.publicKey,signature,canonical)||JSON.stringify(await read())!==JSON.stringify(row)||now()>=expiresAt)throw denied();
  return Object.freeze({canonical,signature});
 }catch{throw denied();}
}
