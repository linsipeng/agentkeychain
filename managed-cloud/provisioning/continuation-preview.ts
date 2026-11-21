/** Offline synthetic role preview. Never emits a deployable manifest. */
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {verifyReleaseManifest,verifyContinuationAuthority,verifyContinuationCommitAuthority,verifyContinuationRolloutAuthority} from '../../src/cloud/config.ts';
import {digest} from '../shared/contracts.ts';

const rejected=()=>new Error('invalid_synthetic_continuation_preview');
const syntheticHost=/^[a-z][a-z0-9-]{0,31}\.fixture\.invalid$/;
function artifact(input:unknown,max:number):SignedManagedOperation{
 exactFields(input,['canonical','signature']);
 if(typeof input.canonical!=='string'||!input.canonical||input.canonical.length>max)throw rejected();
 base64(input.signature,64,64);
 return {canonical:input.canonical,signature:input.signature};
}
/** The independently supplied public root is not accepted from the request.
 * This returns a review matrix, not a signed activation capability. */
export async function compileSyntheticContinuationPreview(input:unknown, trustedSyntheticRoot:Uint8Array){
 try{
  exactFields(input,['scope','authOrigin','manifest','approvalAppendix','mainCommitAppendix','rolloutAppendix']);
  if(input.scope!=='local-synthetic'||trustedSyntheticRoot.byteLength!==32)throw rejected();
  const root=new Uint8Array(trustedSyntheticRoot),manifest=artifact(input.manifest,16384),approval=artifact(input.approvalAppendix,1024),
   main=artifact(input.mainCommitAppendix,1024),rollout=artifact(input.rolloutAppendix,1024);
  const policy=verifyReleaseManifest(manifest,root),web=new URL(policy.webOrigin),manifestDigest=await digest(manifest.canonical);
  if(!syntheticHost.test(web.hostname)||web.port||!policy.releaseId.startsWith('fixture-')||
     policy.apiOrigin!=='https://api.'+web.hostname||input.authOrigin!=='https://auth.'+web.hostname||
     policy.protocolMin!==2||policy.protocolMax!==2||!policy.witnessKeys?.length||!policy.recoveryAuthorities?.length||!policy.recoveryServices)throw rejected();

  const approvalKey=await verifyContinuationAuthority(policy,approval);
  const mainKey=await verifyContinuationCommitAuthority(policy,main);
  const rolloutKey=await verifyContinuationRolloutAuthority(policy,rollout);
  const all=[...policy.checkpointKeys,...policy.witnessKeys,...policy.recoveryAuthorities,
   policy.recoveryServices.api,policy.recoveryServices.custodian,approvalKey,mainKey,rolloutKey];
  const rootValue=Buffer.from(root).toString('base64');
  for(const p of all)if(p.keyId!==await digest(p.publicKey)||p.publicKey===rootValue)throw rejected();
  if(new Set(all.map(p=>p.keyId)).size!==all.length||new Set(all.map(p=>p.publicKey)).size!==all.length)throw rejected();
  return Object.freeze({
   kind:'agentkeychain-continuation-local-preview-v1',scope:'local-synthetic',deployable:false,publicIngress:false,
   release:Object.freeze({id:policy.releaseId,digest:manifestDigest}),
   origins:Object.freeze({web:policy.webOrigin,api:policy.apiOrigin,auth:input.authOrigin}),
   roles:Object.freeze({
    main:Object.freeze({store:'main-fixture',commitKeyId:mainKey.keyId,custodyCapability:'post-commit-proof-only'}),
    auth:Object.freeze({store:'auth-fixture',approvalKeyId:approvalKey.keyId,custodyCapability:'preapproval-readiness-only'}),
    custody:Object.freeze({store:'custody-fixture',witnessKeyIds:Object.freeze(policy.witnessKeys.map(p=>p.keyId)),ingress:'private-only'}),
    rollout:Object.freeze({keyId:rolloutKey.keyId,authorizes:'none-without-separate-fixture-permit'}),
   }),
   remaining:Object.freeze(['owned-disposable-account-and-zone','reviewed-role-operators','real-independent-auth-ingress','cross-account-transport-if-required']),
  } as const);
 }catch{throw rejected();}
}
