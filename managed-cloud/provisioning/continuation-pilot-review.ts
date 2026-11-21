/** Offline review only. Config fragments omit activation mode and all routes. */
import {verifyContinuationAuthority,verifyContinuationCommitAuthority,verifyContinuationRolloutAuthority} from '../../src/cloud/config.ts';
import {installedContinuationPilotScope,verifyInstalledContinuationPilot,type ContinuationPilotBuildArtifact} from '../../src/cloud/continuation-pilot-build.ts';
import {base64,exactFields} from '../../src/cloud/protocol.ts';
import {digest,verify} from '../shared/contracts.ts';

export const PILOT_TARGET_DOMAIN='AgentKeychain-continuation-same-account-target-v1';
const reject=()=>new Error('invalid_continuation_pilot_target');
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const id=/^[a-f0-9]{32}$/;
const domain=/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;
const blockedZones=['invalid','test','example','localhost','example.com','example.net','example.org','workers.dev','pages.dev'];

export async function reviewContinuationPilotTarget(input:unknown,trusted:{
 readonly pilotRootPublicKey:string;readonly target:string;readonly protectedDatabaseIds:readonly string[];
}){
 try{
  input=JSON.parse(JSON.stringify(input));
  exactFields(input,['installation','targetClaim']);
  const artifact=input.installation as ContinuationPilotBuildArtifact;
  const {pilotRootPublicKey,target}=trusted,protectedIds=[...trusted.protectedDatabaseIds];
  if(protectedIds.length<3||protectedIds.length>256||protectedIds.some(x=>!uuid.test(x))||new Set(protectedIds).size!==protectedIds.length)throw reject();
  const gate=await verifyInstalledContinuationPilot(artifact,pilotRootPublicKey,target);
  const {policy,authOrigin}=installedContinuationPilotScope(gate);
  const v=input.targetClaim;exactFields(v,['canonical','signature']);
  if(typeof v.canonical!=='string'||v.canonical.length>4096||typeof v.signature!=='string')throw reject();
  base64(v.signature,64,64);
  const c:unknown=JSON.parse(v.canonical);
  exactFields(c,['version','domain','mode','installationDigest','namespace','accountId','zoneId','zone','webOrigin','apiOrigin','authOrigin','databases','expiresAt']);
  const {namespace,accountId,zoneId,zone,expiresAt}=c;
  if(typeof namespace!=='string'||namespace.length<4||namespace.length>24||!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(namespace)||
     typeof accountId!=='string'||!id.test(accountId)||typeof zoneId!=='string'||!id.test(zoneId)||zoneId===accountId||
     accountId==='0'.repeat(32)||zoneId==='0'.repeat(32)||typeof zone!=='string'||!domain.test(zone)||
     blockedZones.some(x=>zone===x||zone.endsWith('.'+x))||expiresAt!==gate.expiresAt)throw reject();
  if(policy.webOrigin!=='https://web-pilot-'+namespace+'.'+zone||policy.apiOrigin!=='https://api.web-pilot-'+namespace+'.'+zone||
     authOrigin!=='https://auth-pilot-'+namespace+'.'+zone)throw reject();
  exactFields(c.databases,['auth','main','custody']);
  const {auth:authDb,main:mainDb,custody:custodyDb}=c.databases;
  if(typeof authDb!=='string'||typeof mainDb!=='string'||typeof custodyDb!=='string')throw reject();
  const ids=[authDb,mainDb,custodyDb];
  if(ids.some(x=>!uuid.test(x)||protectedIds.includes(x))||new Set(ids).size!==3)throw reject();
  const installationDigest=await digest(JSON.stringify([artifact.installation.canonical,artifact.installation.signature]));
  const canonical=JSON.stringify({version:1,domain:PILOT_TARGET_DOMAIN,mode:'same-account-disposable-only',
   installationDigest,namespace,accountId,zoneId,zone,webOrigin:policy.webOrigin,apiOrigin:policy.apiOrigin,authOrigin,
   databases:{auth:authDb,main:mainDb,custody:custodyDb},expiresAt});
  if(canonical!==v.canonical||!await verify(pilotRootPublicKey,v.signature,canonical))throw reject();
  const [authority,mainCommitAuthority,rollout]=await Promise.all([
   verifyContinuationAuthority(policy,artifact.authAppendix),verifyContinuationCommitAuthority(policy,artifact.commitAppendix),
   verifyContinuationRolloutAuthority(policy,artifact.rolloutAppendix)]);
  const genesis=JSON.parse(artifact.installation.canonical).genesisPin as {keyId:string;publicKey:string};
  if(policy.witnessKeys?.length!==1||!policy.recoveryServices||!policy.recoveryAuthorities?.length)throw reject();
  const witness=policy.witnessKeys[0]!,checkpointKeys=policy.checkpointKeys,recoveryAuthorities=policy.recoveryAuthorities;
  const name=(role:string)=>'akc-pilot-'+namespace+'-'+role;
  const service=(binding:string,entrypoint:string)=>({binding,service:name('custody'),entrypoint});
  const make=(role:string,bundle:string,binding:string,database_id:string,services:object[],vars:Record<string,string>)=>
   ({name:name(role),bundle,workers_dev:false,preview_urls:false,compatibility_date:'2026-07-16',
     compatibility_flags:['nodejs_compat'],ingress:'unbound',d1_databases:[{binding,database_name:name(role),database_id}],services,vars});
  const end=String(gate.expiresAt);
  const auth=make('auth','dist/auth-trust-worker/pilot-continuation.js','AUTH',authDb,
   [service('PILOT_CUSTODY_READINESS','PilotCustodyReadiness')],{PILOT_AUTH_ORIGIN:authOrigin,PILOT_AUTH_EXPIRES_AT:end,
    PILOT_AUTH_PINS:JSON.stringify({genesis,approval:authority,checkpointKeys,recoveryAuthorities,witnesses:[witness]})});
  const main=make('main','dist/api-worker/pilot-continuation-post.js','MAIN',mainDb,
   [service('PILOT_CUSTODY_FRESH','PilotCustodyFresh'),service('PILOT_CUSTODY_POST','PilotCustodyPost')],{
    PILOT_MAIN_ORIGIN:policy.apiOrigin,PILOT_MAIN_EXPIRES_AT:end,PILOT_CUSTODY_WITNESS:JSON.stringify(witness),
    PILOT_MAIN_APPROVAL_PIN:JSON.stringify(authority),PILOT_MAIN_COMMIT_PIN:JSON.stringify(mainCommitAuthority)});
  const custody=make('custody','dist/custody-trust-worker/pilot-continuation.js','CUSTODIAN',custodyDb,[],{
   PILOT_CUSTODY_EXPIRES_AT:end,PILOT_CUSTODY_PINS:JSON.stringify({authority,witness,mainCommitAuthority,checkpointKeys,recoveryAuthorities,
    otherReleaseKeys:[genesis,rollout,policy.recoveryServices.api,policy.recoveryServices.custodian]})});
  return {kind:'continuation-pilot-review-v1',targetAuthorizedByPilotRoot:true,ownershipVerified:false,deployable:false,
   target:{accountId,zoneId,zone,webOrigin:policy.webOrigin,apiOrigin:policy.apiOrigin,authOrigin,expiresAt},
   privateRoles:{auth,main,custody},pending:['verify-account-zone-and-resource-noncollision','wire-operator-owned-signers',
    'review-empty-role-d1-schema-and-secure-injection','wire-independent-first-device-enrollment-and-custody-admission',
    'run-installed-cli-against-exact-hosted-graph','approve-exact-public-routes']} as const;
 }catch{throw reject();}
}
