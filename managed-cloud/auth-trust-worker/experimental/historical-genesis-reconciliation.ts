/** Auth-owned local provenance predicate. Not a readback route or fresh authority. */
import {base64,exactFields,type SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import {digest} from '../../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import {verifyGenesisApproval,type GenesisApprovalPolicy} from '../../shared/genesis-approval.ts';
import {rosterDigest} from '../../shared/roster.ts';

/** Require the independently persisted exact receipt. An expired authorization
 * may explain an existing admission only; never authorize a new admission. */
export async function hasExactHistoricalGenesisApproval(auth:D1Database,grant:string,roster:SignedManagedOperation,
 proof:SignedManagedOperation,policy:GenesisApprovalPolicy):Promise<boolean>{
 try{
  if(typeof grant!=='string'||!grant.length||grant.length>4096) return false;
  for(const [value,max] of [[proof,2048],[roster,16384]] as const){
   exactFields(value,['canonical','signature']);
   if(typeof value.canonical!=='string'||!value.canonical.length||value.canonical.length>max)return false;
   base64(value.signature,64,64);
  }
  const g=JSON.parse(grant) as EnrollmentGrant,now=Math.floor(Date.now()/1000),issuedAt:unknown=JSON.parse(proof.canonical).issuedAt;
  if(canonicalGrant(g)!==grant||g.issuerDeviceId!==null||g.expiresAt>=now||typeof issuedAt!=='number'||issuedAt>now)return false;
  const historical=await verifyGenesisApproval(proof,grant,roster,policy,issuedAt);
  const [grantHash,rosterHash]=await Promise.all([digest(grant),rosterDigest(roster)]);
  const row=await auth.withSession('first-primary').prepare(`
    SELECT d.canonical,d.signature FROM auth_genesis_decisions d
    JOIN auth_genesis_challenges c ON c.id=d.id AND c.grant_digest=d.grant_digest
    JOIN auth_genesis_pins p USING(account,tenant,vault,credential)
    WHERE d.id=? AND c.account=? AND c.tenant=? AND c.vault=?
      AND c.grant_digest=? AND c.roster_digest=? AND c.expires>=? AND p.active=1
  `).bind(historical.decisionId,g.accountId,g.tenantId,g.vaultId,grantHash,rosterHash,historical.expiresAt)
   .first<SignedManagedOperation>();
  return !!row&&row.canonical===proof.canonical&&row.signature===proof.signature;
 }catch{return false;}
}
