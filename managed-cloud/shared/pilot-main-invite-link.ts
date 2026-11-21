/** Pending authorization contract, not an account resolver or issuance path. */
import {URL} from 'node:url';
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {CheckpointKey} from './checkpoints.ts';
import {digest,verify} from './contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from './device-protocol.ts';
import {verifyGenesisApproval,type GenesisApprovalPolicy} from './genesis-approval.ts';
import {rosterDigest} from './roster.ts';

export const PILOT_MAIN_INVITE_LINK='AgentKeychain-pilot-main-admin-invite-link-v1';
const inviteDomain='AgentKeychain-pilot-genesis-registration-invite-v1';
const denied=()=>new Error('pilot_main_invite_link_unavailable');
const now=()=>Math.floor(Date.now()/1000);
type Pin=Readonly<CheckpointKey>;
/** Independently provisioned Admin mapping and verified installation scope.
 * This must not be inferred from the invitation, Auth receipt or caller IDs. */
type ExistingMainMapping=Readonly<{
 grantCanonical:string;installationDigest:string;profileDigest:string;installationExpiresAt:number;
 authOrigin:string;rpId:string;
}>;
type Policy=GenesisApprovalPolicy&Readonly<{inviteAuthority:Pin;mainLinkAuthority:Pin}>;
const sha=(v:SignedManagedOperation)=>digest(JSON.stringify([v.canonical,v.signature]));
function digestShape(value:unknown):value is string{
 return typeof value==='string'&&value.length===64&&/^[a-f0-9]{64}$/.test(value);
}
function envelope(value:unknown):SignedManagedOperation{
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||!value.canonical||new TextEncoder().encode(value.canonical).length>4096)throw denied();
 base64(value.signature,64,64);
 return {canonical:value.canonical,signature:value.signature};
}
function window(input:Record<string,unknown>,deadline:number,at:number){
 const {issuedAt,expiresAt}=input;
 if(typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
    issuedAt<1||issuedAt>at||expiresAt<=at||expiresAt>deadline||expiresAt-issuedAt>600)throw denied();
 return {issuedAt,expiresAt};
}

/** Existing Auth decision bytes verify consent to the grant/roster, not
 * signed proof that a particular invite was consumed and linked in Main.
 * Until a distinct trusted Auth readback binds those exact bytes, even a
 * verified Admin link is pending only. No D1 lookup, mutation or credentials. */
export async function verifyPendingPilotMainInviteLink(
 input:unknown, expected:ExistingMainMapping, policy:Policy,
):Promise<Readonly<{state:'pending-auth-invite-consumption-proof'}>>{
 try{
  const at=now();
  const {grantCanonical,installationDigest,profileDigest,installationExpiresAt,authOrigin,rpId}=expected;
  if(!digestShape(installationDigest)||!digestShape(profileDigest)||!Number.isSafeInteger(installationExpiresAt)||
     installationExpiresAt<=at||typeof grantCanonical!=='string'||grantCanonical.length>4096)throw denied();
  const origin=new URL(authOrigin);
  if(origin.origin!==authOrigin||origin.protocol!=='https:'||origin.port||origin.hostname!==rpId)throw denied();
  const grant=JSON.parse(grantCanonical) as EnrollmentGrant;
  if(canonicalGrant(grant)!==grantCanonical||grant.issuerDeviceId!==null||grant.expiresAt<=at)throw denied();
  const {accountId,tenantId,vaultId,deviceId,requestId,keyEpoch}=grant;
  const {inviteAuthority,mainLinkAuthority}=policy;
  const required=[inviteAuthority,mainLinkAuthority,policy.authority,...policy.checkpointKeys,...policy.recoveryAuthorities];
  const all=required.map(p=>p.publicKey).concat(grant.signingKey,grant.wrappingKey);
  if(new Set(all).size!==all.length)throw denied();
  for(const p of required){base64(p.publicKey,32,32);if(p.keyId!==await digest(p.publicKey))throw denied();}

  exactFields(input,['invite','authApproval','roster','mainLink']);
  const invite=envelope(input.invite),authApproval=envelope(input.authApproval),mainLink=envelope(input.mainLink);
  exactFields(input.roster,['canonical','signature']);
  const {canonical,signature}=input.roster;
  if(typeof canonical!=='string'||!canonical||new TextEncoder().encode(canonical).length>16384)throw denied();
  base64(signature,64,64);
  const roster={canonical,signature};
  const approval=await verifyGenesisApproval(authApproval,grantCanonical,roster,policy,at);

  const inviteData:unknown=JSON.parse(invite.canonical);
  exactFields(inviteData,['version','domain','keyId','origin','rpId','id','accountId','tenantId','vaultId','deviceId','requestId','keyEpoch',
   'grantDigest','rosterDigest','issuedAt','expiresAt']);
  const id=inviteData.id;
  if(typeof id!=='string'||id.length!==43||!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(id))throw denied();
  const grantDigest=await digest(grantCanonical),rosterHash=await rosterDigest(roster);
  const invitation=window(inviteData,Math.min(grant.expiresAt,installationExpiresAt),at);
  if(invite.canonical!==JSON.stringify({version:1,domain:inviteDomain,keyId:inviteAuthority.keyId,origin:authOrigin,rpId,id,
   accountId,tenantId,vaultId,deviceId,requestId,keyEpoch,grantDigest,rosterDigest:rosterHash,...invitation})||
   !await verify(inviteAuthority.publicKey,invite.signature,invite.canonical))throw denied();

  const link:unknown=JSON.parse(mainLink.canonical);
  exactFields(link,['version','domain','keyId','accountId','tenantId','vaultId','deviceId','requestId','keyEpoch','grantDigest',
   'inviteDigest','authApprovalDigest','installationDigest','profileDigest','issuedAt','expiresAt']);
  const times=window(link,Math.min(approval.expiresAt,invitation.expiresAt,installationExpiresAt,grant.expiresAt),at);
  if(times.issuedAt<Math.max(approval.issuedAt,invitation.issuedAt)||
     mainLink.canonical!==JSON.stringify({version:1,domain:PILOT_MAIN_INVITE_LINK,keyId:mainLinkAuthority.keyId,
      accountId,tenantId,vaultId,deviceId,requestId,keyEpoch,grantDigest,inviteDigest:await sha(invite),
      authApprovalDigest:await sha(authApproval),installationDigest,profileDigest,...times})||
     !await verify(mainLinkAuthority.publicKey,mainLink.signature,mainLink.canonical)||now()>=times.expiresAt)throw denied();
  return Object.freeze({state:'pending-auth-invite-consumption-proof'});
 }catch{throw denied();}
}
