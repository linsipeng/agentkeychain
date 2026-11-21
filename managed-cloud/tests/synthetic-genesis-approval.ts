import {digest} from '../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import {canonicalGenesisApproval,GENESIS_APPROVAL_DOMAIN,type GenesisApproval} from '../shared/genesis-approval.ts';
import {canonicalRoster,ROSTER_DOMAIN,rosterDigest,type TrustedDeviceRoster} from '../shared/roster.ts';

const bytes=(value:ArrayBuffer)=>btoa(String.fromCharCode(...new Uint8Array(value)));
export async function signingFixture(){
 const pair=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 const publicKey=bytes(await crypto.subtle.exportKey('raw',pair.publicKey));
 const sign=async (message:string)=>bytes(await crypto.subtle.sign('Ed25519',pair.privateKey,new TextEncoder().encode(message)));
 return {publicKey,keyId:await digest(publicKey),sign};
}

export async function enrollmentFixture(now:number, vaultId='vault'){
 const [authority,device,checkpoint,recovery]=await Promise.all([signingFixture(),signingFixture(),signingFixture(),signingFixture()]);
 const wrapping=await crypto.subtle.generateKey('X25519',true,['deriveBits']) as CryptoKeyPair;
 const grant:EnrollmentGrant={version:1,requestId:'request',accountId:'account',tenantId:'tenant',vaultId,deviceId:'device',signingKey:device.publicKey,wrappingKey:bytes(await crypto.subtle.exportKey('raw',wrapping.publicKey)),issuerDeviceId:null,keyEpoch:1,expiresAt:now+480};
 const keyPin=({keyId,publicKey}:{keyId:string;publicKey:string})=>({keyId,publicKey});
 const policy={authority:keyPin(authority),checkpointKeys:[keyPin(checkpoint)],recoveryAuthorities:[keyPin(recovery)]};
 const initial:TrustedDeviceRoster={version:1,accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,revision:1,previousDigest:null,keyEpoch:grant.keyEpoch,active:[{deviceId:grant.deviceId,signingKey:grant.signingKey,wrappingKey:grant.wrappingKey}],revoked:[],issuer:{kind:'device',id:grant.deviceId},issuedAt:now,expiresAt:now+720,checkpointKeys:policy.checkpointKeys,recoveryAuthorities:policy.recoveryAuthorities,recovery:null};
 const signedRoster=async (change:Partial<TrustedDeviceRoster>={})=>{const canonical=canonicalRoster({...initial,...change});return {canonical,signature:await device.sign(ROSTER_DOMAIN+canonical)};};
 const roster=await signedRoster();
 const approval=async (change:Partial<GenesisApproval>={},grantBytes=canonicalGrant(grant),signed=roster)=>{
  const data:GenesisApproval={version:1,audience:'custodian:roster-genesis',decisionId:'approval',authorityKeyId:authority.keyId,grantDigest:await digest(grantBytes),rosterDigest:await rosterDigest(signed),issuedAt:now-1,expiresAt:now+60,...change};
  const canonical=canonicalGenesisApproval(data);
  return {proof:{canonical,signature:await authority.sign(GENESIS_APPROVAL_DOMAIN+canonical)},data};
 };
 return {authority,device,checkpoint,grant,policy,roster,signedRoster,approval};
}
