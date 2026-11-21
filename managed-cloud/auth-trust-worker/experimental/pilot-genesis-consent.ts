import type {AuthenticationResponseJSON} from '@simplewebauthn/server';
import type {SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import type {WebAuthnPolicy} from '../../api-worker/webauthn.ts';
import type {CheckpointSigner} from '../../shared/checkpoints.ts';
import {verifyGenesisApproval,type GenesisApprovalPolicy} from '../../shared/genesis-approval.ts';
import {genesisIssuer} from './genesis-issuer.ts';
import type {pilotGenesisRegistration} from './pilot-genesis-registration.ts';

const denied=()=>new Error('pilot_genesis_consent_unavailable');
export function pilotGenesisConsent(db:D1Database,identity:WebAuthnPolicy,policy:GenesisApprovalPolicy,signer:CheckpointSigner,
 registration:ReturnType<typeof pilotGenesisRegistration>){
 const allow=(invite:SignedManagedOperation,grant:string,roster:SignedManagedOperation,browser:string)=>
  registration.authorizeConsent(invite,grant,roster,browser);
 return {
  async begin(invite:SignedManagedOperation,grant:string,roster:SignedManagedOperation,browser:string){
   const s=await allow(invite,grant,roster,browser);
   const opened=await genesisIssuer(db,identity,policy,signer,browser).begin(grant,roster);
   const exact=JSON.parse(grant);
   return {...opened,display:{purpose:'approve-first-device-genesis',accountId:s.accountId,vaultId:s.vaultId,deviceId:exact.deviceId}};
  },
  async complete(invite:SignedManagedOperation,grant:string,roster:SignedManagedOperation,browser:string,id:string,response:AuthenticationResponseJSON){
   await allow(invite,grant,roster,browser);
   return genesisIssuer(db,identity,policy,signer,browser).complete(id,grant,roster,response);
  },
  async readback(invite:SignedManagedOperation,grant:string,roster:SignedManagedOperation,browser:string,id:string):Promise<SignedManagedOperation>{
   const s=await allow(invite,grant,roster,browser);
   const read=()=>db.prepare(`SELECT d.canonical,d.signature FROM auth_genesis_decisions d
    JOIN auth_genesis_challenges c ON c.id=d.id AND c.grant_digest=d.grant_digest
    JOIN pilot_genesis_browser_guard b ON b.challenge_id=c.id AND b.finalize=1 AND b.browser_digest=?
    JOIN pilot_genesis_registration r ON r.browser_digest=b.browser_digest AND r.account=c.account AND r.tenant=c.tenant
      AND r.vault=c.vault AND r.credential=c.credential AND r.grant_digest=c.grant_digest AND r.roster_digest=c.roster_digest
    JOIN auth_genesis_pins p ON p.account=r.account AND p.tenant=r.tenant AND p.vault=r.vault AND p.credential=r.credential
    WHERE d.id=? AND r.id=? AND r.grant_digest=? AND r.roster_digest=? AND p.active=1 AND r.expires>unixepoch() AND c.expires>unixepoch()`)
    .bind(browser,id,s.id,s.grantDigest,s.rosterHash).first<{canonical:string;signature:string}>();
   const got=await read();
   if(!got)throw denied();
   const checked=await verifyGenesisApproval(got,grant,roster,policy);
   const after=await read();
   if(!after||after.canonical!==got.canonical||after.signature!==got.signature||checked.decisionId!==id||
      checked.expiresAt<=Math.floor(Date.now()/1000))throw denied();
   return got;
  },
 };
}
