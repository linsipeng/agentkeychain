import type {AuthenticationResponseJSON} from '@simplewebauthn/server';
import type {SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import {genesisRoot,type CheckpointKey,type CheckpointSigner} from '../../shared/checkpoints.ts';
import {digest,verify} from '../../shared/contracts.ts';
import {canonicalGrant,canonicalPackage,type EnrollmentGrant,type KeyPackage} from '../../shared/device-protocol.ts';
import {canonicalContinuationIntent,canonicalContinuationReceipt,CONTINUATION_WINDOW_SECONDS,verifyContinuationApproval} from '../../shared/enrollment-continuation.ts';
import {verifyGenesisApproval,type GenesisApprovalPolicy} from '../../shared/genesis-approval.ts';
import {rosterDigest,verifyRoster} from '../../shared/roster.ts';
import {verifyWitness} from '../../shared/roster-witness.ts';
import {decode,random,webauthn,type WebAuthnPolicy} from '../../api-worker/webauthn.ts';

type StageInput={oldGrantCanonical:string;target:SignedManagedOperation;roster:SignedManagedOperation;keyPackage:SignedManagedOperation};
type Pin={credential:string;handle:string;cose_key:string;counter:number};
type Prior={id:string;canonical:string;signature:string};
const unavailable=()=>new Error('continuation_approval_unavailable');
/** Unwired Auth-only issuer. The caller must be a separate authenticated UI which
 * displays the exact stage. Signer and latest Custodian readback are operator
 * bindings, never request inputs. This exposes neither signing nor registration. */
export function continuationIssuer(db:D1Database,identity:WebAuthnPolicy,policy:{
 genesis:GenesisApprovalPolicy;authority:CheckpointKey;witnesses:readonly CheckpointKey[];
},signer:CheckpointSigner,latestWitness:(tenant:string,vault:string)=>Promise<SignedManagedOperation|null>){
 const origin=new URL(identity.origin);
 const {authority,genesis,witnesses}=policy;
 if(origin.protocol!=='https:'||origin.origin!==identity.origin||origin.hostname!==identity.rpId||!witnesses.length||
    [genesis.authority,...genesis.checkpointKeys,...genesis.recoveryAuthorities,...witnesses].some(p=>p.keyId===authority.keyId||p.publicKey===authority.publicKey))throw unavailable();
 async function validate(input:StageInput){
  if(input.oldGrantCanonical.length>4096||input.target.canonical.length>4096||input.keyPackage.canonical.length>4096||input.roster.canonical.length>16384)
   throw unavailable();
  const now=Math.floor(Date.now()/1000),g=JSON.parse(input.oldGrantCanonical) as EnrollmentGrant;
  if(canonicalGrant(g)!==input.oldGrantCanonical||g.issuerDeviceId!==null||g.expiresAt>now||
     witnesses.some(p=>p.publicKey===g.signingKey||p.publicKey===g.wrappingKey)||
     [g.signingKey,g.wrappingKey].includes(authority.publicKey))throw unavailable();
  const scope=[g.accountId,g.tenantId,g.vaultId],grantDigest=await digest(input.oldGrantCanonical),head=await rosterDigest(input.roster);
  const prior=await db.prepare(`SELECT d.id,d.canonical,d.signature FROM auth_genesis_decisions d JOIN auth_genesis_challenges c ON c.id=d.id
   WHERE c.account=? AND c.tenant=? AND c.vault=? AND d.grant_digest=? AND c.grant_digest=d.grant_digest AND c.roster_digest=?`)
   .bind(...scope,grantDigest,head).first<Prior>();
  if(!prior)throw unavailable();
  const historical={canonical:prior.canonical,signature:prior.signature};
  const priorApproval=await verifyGenesisApproval(historical,input.oldGrantCanonical,input.roster,genesis,JSON.parse(prior.canonical).issuedAt);
  if(priorApproval.decisionId!==prior.id)throw unavailable();
  const r=await verifyRoster(input.roster,null,now,true);
  if(r.active.length!==1||r.revoked.length)throw unavailable();
  const witness=await latestWitness(g.tenantId,g.vaultId);
  if(!witness)throw unavailable();
  const w=await verifyWitness(witness,witnesses,{accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,revision:1,digest:head});
  if(w.event!==1||w.sequence!==0||w.root!==await genesisRoot(g.tenantId,g.vaultId))throw unavailable();
  const p=JSON.parse(input.keyPackage.canonical) as KeyPackage;
  if(canonicalPackage(p)!==input.keyPackage.canonical||p.vaultId!==g.vaultId||p.targetDeviceId!==g.deviceId||
     p.issuerDeviceId!==g.deviceId||p.grantId!==g.requestId||p.keyEpoch!==g.keyEpoch||
     !await verify(g.signingKey,input.keyPackage.signature,input.keyPackage.canonical))throw unavailable();
  const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',input.keyPackage.canonical,input.keyPackage.signature]));
  const target=JSON.parse(input.target.canonical);
  if(canonicalContinuationIntent(target)!==input.target.canonical||!await verify(g.signingKey,input.target.signature,input.target.canonical)||
     target.stage!=='put-key-package'||target.originalGrantDigest!==grantDigest||target.payloadDigest!==payloadDigest||
     target.rosterDigest!==head||target.witnessHead?.revision!==1||target.witnessHead.digest!==head||
     (['requestId','accountId','tenantId','vaultId','deviceId','signingKey','wrappingKey','issuerDeviceId','keyEpoch'] as const)
      .some(k=>target[k]!==g[k])||target.expiresAt<=now||target.expiresAt>now+CONTINUATION_WINDOW_SECONDS)throw unavailable();
  return {scope,prior,now,head,payloadDigest,expires:Math.min(target.expiresAt,now+120),intentDigest:await digest(input.target.canonical)};
 }
 return {
  async begin(input:StageInput){
   try{
    const {scope,prior,expires,intentDigest}=await validate(input);
    const pin=await db.prepare('SELECT credential FROM auth_genesis_pins WHERE account=? AND tenant=? AND vault=? AND active=1').bind(...scope).first<Pin>();
    if(!pin)throw unavailable();
    const id=random(),challenge=random();
    await db.prepare('INSERT INTO auth_continuation_challenges VALUES(?,?,?,?,?,?,?,?,?)').bind(id,await digest(challenge),...scope,pin.credential,prior.id,intentDigest,expires).run();
    const options=await webauthn.authenticationOptions(identity,challenge);
    return {id,options:{...options,allowCredentials:[{id:pin.credential,type:'public-key' as const}]}};
   }catch{throw unavailable();}
  },
  async complete(id:string,input:StageInput,assertion:AuthenticationResponseJSON){
   try{
    if(typeof id!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(id)||JSON.stringify(assertion).length>32768)throw unavailable();
    const {scope,prior,now,head,payloadDigest,expires,intentDigest}=await validate(input);
    const row=await db.prepare(`SELECT c.challenge_digest,c.expires,p.credential,p.handle,p.cose_key,p.counter
     FROM auth_continuation_challenges c JOIN auth_genesis_pins p USING(account,tenant,vault,credential)
     WHERE c.id=? AND c.account=? AND c.tenant=? AND c.vault=? AND c.prior_decision_id=? AND c.intent_digest=? AND c.expires>unixepoch()
      AND p.active=1 AND NOT EXISTS(SELECT 1 FROM auth_continuation_decisions d WHERE d.id=c.id OR d.intent_digest=c.intent_digest)`)
      .bind(id,...scope,prior.id,intentDigest).first<Pin&{challenge_digest:string;expires:number}>();
    if(!row||(assertion.response.userHandle&&assertion.response.userHandle!==row.handle))throw unavailable();
    const counter=await webauthn.authentication(identity,row.challenge_digest,assertion,{id:row.credential,publicKey:decode(row.cose_key),counter:row.counter});
    if((counter||row.counter)&&counter<=row.counter)throw unavailable();
    const pin=await signer.key();
    if(pin.keyId!==authority.keyId||pin.publicKey!==authority.publicKey)throw unavailable();
    const expiresAt=Math.min(expires,row.expires);
    const canonical=canonicalContinuationReceipt({version:1,domain:'AgentKeychain-enrollment-continuation-approval-v1',intentDigest,authorityKeyId:pin.keyId,approvedAt:now,expiresAt});
    const signature=await signer.sign(canonical);
    await verifyContinuationApproval(input.target,{canonical,signature},{oldGrantCanonical:input.oldGrantCanonical,stage:'put-key-package',payloadDigest,
     rosterDigest:head,witnessHead:{revision:1,digest:head},authority,issuer:null,now});
    const [decision]=await db.batch([
     db.prepare(`INSERT INTO auth_continuation_decisions
      SELECT c.id,c.intent_digest,?,? FROM auth_continuation_challenges c JOIN auth_genesis_pins p USING(account,tenant,vault,credential)
      JOIN auth_genesis_decisions old ON old.id=c.prior_decision_id
      WHERE c.id=? AND c.intent_digest=? AND old.canonical=? AND old.signature=? AND c.expires>unixepoch() AND ?>unixepoch()
       AND p.active=1 AND p.counter=? AND p.cose_key=? AND p.handle=? RETURNING id`)
      .bind(canonical,signature,id,intentDigest,prior.canonical,prior.signature,expiresAt,row.counter,row.cose_key,row.handle),
     db.prepare(`UPDATE auth_genesis_pins SET counter=? WHERE account=? AND tenant=? AND vault=? AND credential=?
      AND EXISTS(SELECT 1 FROM auth_continuation_decisions WHERE id=? AND canonical=? AND signature=?)`)
      .bind(counter,...scope,row.credential,id,canonical,signature),
    ]);
    if(!decision?.results.length)throw unavailable();
    return {canonical,signature};
   }catch{throw unavailable();}
  },
 };
}
