import {URL} from 'node:url';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {verifyContinuationAuthority,verifyContinuationCommitAuthority,verifyContinuationHandoffOrigin,
 verifyContinuationRolloutAuthority,verifyReleaseManifest} from './config.ts';
import {base64,exactFields,type SignedManagedOperation} from './protocol.ts';
import {releaseArtifact} from './release.generated.ts';

const domain='AgentKeychain-continuation-installed-pilot-build-v1';
const deny=()=>new Error('cloud_continuation_pilot_not_provisioned');
export const INSTALLED_PILOT_CONTRACT='continuation-https-pilot-v1';
export const INSTALLED_PILOT_BINARY='agentkeychain-continuation-pilot';
export interface ContinuationPilotBuildArtifact {
 manifest:SignedManagedOperation;
 authOriginAppendix:SignedManagedOperation;
 authAppendix:SignedManagedOperation;
 commitAppendix:SignedManagedOperation;
 rolloutAppendix:SignedManagedOperation;
 installation:SignedManagedOperation;
}

function namespaceOrigin(origin:string):URL{
 const u=new URL(origin);
 if(u.origin!==origin||u.protocol!=='https:'||u.port||!u.hostname.includes('.')||
    !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(u.hostname)||
    /^\d+(\.\d+){3}$/.test(u.hostname)||u.hostname.endsWith('.localhost'))throw deny();
 return u;
}

/** Pure bootstrap: only separately compiled pilot pin/config artifacts can
 * reach this gate. No runtime override, enrollment storage, or transport. */
export async function verifyInstalledContinuationPilot(artifact:ContinuationPilotBuildArtifact,rootPublicKey:string,target:string){
 try{
  if(!/^(darwin|linux)-(arm64|x64)$/.test(target))throw deny();
  exactFields(artifact,['manifest','authOriginAppendix','authAppendix','commitAppendix','rolloutAppendix','installation']);
  base64(rootPublicKey,32,32);
  const standard=releaseArtifact();
  if(!standard||standard.rootPublicKey===rootPublicKey)throw deny();
  const existing=verifyReleaseManifest(standard.manifest,Buffer.from(standard.rootPublicKey,'base64'));
  const manifest=verifyReleaseManifest(artifact.manifest,Buffer.from(rootPublicKey,'base64'));
  if(!/^continuation-pilot-[a-z0-9-]{4,64}$/.test(manifest.releaseId)||!manifest.witnessKeys?.length||
     manifest.protocolMin!==2||manifest.protocolMax!==2)throw deny();
  const [authOrigin,auth,main,rollout]=await Promise.all([
   verifyContinuationHandoffOrigin(manifest,artifact.authOriginAppendix),verifyContinuationAuthority(manifest,artifact.authAppendix),
   verifyContinuationCommitAuthority(manifest,artifact.commitAppendix),verifyContinuationRolloutAuthority(manifest,artifact.rolloutAppendix),
  ]);
  const web=namespaceOrigin(manifest.webOrigin),api=namespaceOrigin(manifest.apiOrigin),authUrl=namespaceOrigin(authOrigin);
  const current=namespaceOrigin(existing.webOrigin).hostname;
  if(!/^api\.web-pilot-[a-z0-9](?:[a-z0-9-]{0,39}[a-z0-9])?\./.test(api.hostname)||api.hostname!=='api.'+web.hostname||
    !/^auth-pilot-[a-z0-9]+(?:-[a-z0-9]+)*\./.test(authUrl.hostname)||
    [web,api,authUrl].some(u=>u.hostname===current||u.hostname.endsWith('.'+current)))throw deny();
  const manifestPins=(p:typeof manifest)=>[...p.checkpointKeys,...(p.witnessKeys??[]),...(p.recoveryAuthorities??[]),
   ...(p.recoveryServices?[p.recoveryServices.api,p.recoveryServices.custodian]:[])];
  const signedDigest=(item:SignedManagedOperation)=>digest(JSON.stringify([item.canonical,item.signature]));
  const {installation}=artifact;
  exactFields(installation,['canonical','signature']);
  if(typeof installation.canonical!=='string'||installation.canonical.length>2048)throw deny();
  base64(installation.signature,64,64);
  const claim:unknown=JSON.parse(installation.canonical);
  exactFields(claim,['version','domain','mode','contract','target','manifestDigest','authOriginDigest','authPinDigest','mainPinDigest','rolloutPinDigest','genesisPin','issuedAt','expiresAt']);
  exactFields(claim.genesisPin,['keyId','publicKey']);
  const {keyId:genesisKeyId,publicKey:genesisPublicKey}=claim.genesisPin;
  if(typeof genesisKeyId!=='string'||typeof genesisPublicKey!=='string')throw deny();
  base64(genesisPublicKey,32,32);
  const genesisPin={keyId:genesisKeyId,publicKey:genesisPublicKey};
  const pins=[...manifestPins(manifest),auth,main,rollout,genesisPin];
  const oldPins=manifestPins(existing);
  if(oldPins.some(p=>p.publicKey===rootPublicKey)||pins.some(p=>p.publicKey===rootPublicKey||p.publicKey===standard.rootPublicKey||
    oldPins.some(k=>k.keyId===p.keyId||k.publicKey===p.publicKey))||new Set(pins.map(p=>p.keyId)).size!==pins.length||
    new Set(pins.map(p=>p.publicKey)).size!==pins.length)throw deny();
  for(const pin of pins)if(pin.keyId!==await digest(pin.publicKey))throw deny();
  const {issuedAt,expiresAt}=claim,now=Math.floor(Date.now()/1000);
  if(typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
    issuedAt<1||issuedAt>now||expiresAt<=now||expiresAt-issuedAt>7*86400)throw deny();
  const canonical=JSON.stringify({version:1,domain,mode:'disposable-only',contract:INSTALLED_PILOT_CONTRACT,target,
   manifestDigest:await signedDigest(artifact.manifest),authOriginDigest:await signedDigest(artifact.authOriginAppendix),
   authPinDigest:await signedDigest(artifact.authAppendix),mainPinDigest:await signedDigest(artifact.commitAppendix),
   rolloutPinDigest:await signedDigest(artifact.rolloutAppendix),genesisPin,issuedAt,expiresAt});
  if(installation.canonical!==canonical||!await verify(rootPublicKey,installation.signature,canonical)||Math.floor(Date.now()/1000)>=expiresAt)throw deny();
  return Object.freeze({releaseId:manifest.releaseId,contract:INSTALLED_PILOT_CONTRACT,expiresAt});
 }catch{throw deny();}
}
