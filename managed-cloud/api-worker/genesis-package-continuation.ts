import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {CheckpointKey} from '../shared/checkpoints.ts';
import {ApiError,digest,verify} from '../shared/contracts.ts';
import {canonicalPackage,type EnrollmentGrant,type KeyPackage} from '../shared/device-protocol.ts';
import {verifyContinuationApproval} from '../shared/enrollment-continuation.ts';
import {parseRoster,rosterDigest,verifyRoster} from '../shared/roster.ts';
import {verifyWitness} from '../shared/roster-witness.ts';

/** Internal, unwired stage. Only an operator-pinned configuration may supply
 * authority and witness keys; witness must come from independently current
 * Custodian readback, never from caller-supplied keys or a Main-only answer. */
export async function consumeGenesisPackageContinuation(db:D1Database,input:{
 oldGrantCanonical:string;
 target:SignedManagedOperation;approval:SignedManagedOperation;keyPackage:SignedManagedOperation;
 witness:SignedManagedOperation;roster:SignedManagedOperation;
},pins:{authority:CheckpointKey;witnesses:readonly CheckpointKey[]}){
 const now=Math.floor(Date.now()/1000),g=JSON.parse(input.oldGrantCanonical) as EnrollmentGrant;
 if(g.issuerDeviceId!==null||pins.witnesses.some(pin=>pin.publicKey===pins.authority.publicKey||pin.publicKey===g.signingKey||pin.publicKey===g.wrappingKey))
  throw new ApiError('approval_required');
 const roster=parseRoster(input.roster),head=await rosterDigest(input.roster);
 if(roster.revision!==1||roster.accountId!==g.accountId||roster.tenantId!==g.tenantId||roster.vaultId!==g.vaultId||
    roster.keyEpoch!==g.keyEpoch||roster.issuer.kind!=='device'||roster.issuer.id!==g.deviceId||roster.active.length!==1||roster.revoked.length||
    roster.active[0]?.deviceId!==g.deviceId||roster.active[0].signingKey!==g.signingKey||roster.active[0].wrappingKey!==g.wrappingKey)
  throw new ApiError('approval_required');
 await verifyRoster(input.roster,null,now,true);
 const w=await verifyWitness(input.witness,pins.witnesses,{accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,revision:1,digest:head});
 const p=JSON.parse(input.keyPackage.canonical) as KeyPackage;
 if(canonicalPackage(p)!==input.keyPackage.canonical||p.vaultId!==g.vaultId||p.grantId!==g.requestId||
    p.targetDeviceId!==g.deviceId||p.issuerDeviceId!==g.deviceId||p.keyEpoch!==g.keyEpoch||
    !await verify(g.signingKey,input.keyPackage.signature,input.keyPackage.canonical))
  throw new ApiError('invalid_signature');
 const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',input.keyPackage.canonical,input.keyPackage.signature]));
 await verifyContinuationApproval(input.target,input.approval,{
  oldGrantCanonical:input.oldGrantCanonical,stage:'put-key-package',payloadDigest,rosterDigest:head,witnessHead:{revision:w.revision,digest:w.digest},
  authority:pins.authority,issuer:null,now,
 });
 const {id}=JSON.parse(input.target.canonical) as {id:string};
 const {expiresAt}=JSON.parse(input.approval.canonical) as {expiresAt:number};
 const intent=JSON.stringify(input.target),approval=JSON.stringify(input.approval),witness=JSON.stringify(input.witness);
 const [,readback]=await db.batch<{signed_intent:string;signed_approval:string;witness:string;package_canonical:string;package_signature:string}>([
  db.prepare(`INSERT INTO genesis_package_continuations SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
   WHERE NOT EXISTS(SELECT 1 FROM genesis_package_continuations WHERE id=?)`).bind(id,g.requestId,g.accountId,g.tenantId,g.vaultId,g.deviceId,g.keyEpoch,input.oldGrantCanonical,
    intent,approval,head,input.roster.canonical,input.roster.signature,witness,input.keyPackage.canonical,input.keyPackage.signature,expiresAt,id),
  db.prepare('SELECT signed_intent,signed_approval,witness,package_canonical,package_signature FROM genesis_package_continuations WHERE id=?').bind(id),
 ]);
 const row=readback?.results[0];
 if(!row||row.signed_intent!==intent||row.signed_approval!==approval||row.witness!==witness||
    row.package_canonical!==input.keyPackage.canonical||row.package_signature!==input.keyPackage.signature)
  throw new ApiError('idempotency_conflict');
 return {accepted:true};
}
