import {URL} from 'node:url';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {verifyContinuationAuthority,verifyContinuationCommitAuthority,verifyContinuationHandoffOrigin,
 verifyContinuationRolloutAuthority,verifyReleaseManifest,type ManagedEndpointPolicy} from './config.ts';
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
 nativeReaderAppendix?:SignedManagedOperation;
}

export interface VerifiedInstalledContinuationPilot {
 readonly releaseId:string;
 readonly contract:typeof INSTALLED_PILOT_CONTRACT;
 readonly expiresAt:number;
}
type TransportScope={policy:ManagedEndpointPolicy;authOrigin:string;authOriginAppendix:SignedManagedOperation;
 authAppendix:SignedManagedOperation;commitAppendix:SignedManagedOperation;
 rollout:Readonly<{keyId:string;publicKey:string}>;installationDigest:string;target:string};
const installedScopes=new WeakMap<VerifiedInstalledContinuationPilot,Readonly<TransportScope>>();
const nativeReaderDomain='AgentKeychain-installed-continuation-pilot-native-reader-v1';
export const INSTALLED_PILOT_NATIVE_READER_ABI='pilot-broker-inspect-v1';
type PublicPin=Readonly<{keyId:string;publicKey:string}>;
const nativeReaderScopes=new WeakMap<VerifiedInstalledContinuationPilot,Readonly<{
 installationDigest:string;target:string;nativeImageSha256:string;abi:typeof INSTALLED_PILOT_NATIVE_READER_ABI;
 readerPin:PublicPin;expiresAt:number;
}>>();
/** This verifies signed intent only. A consumer must still prove executable,
 * kernel peer, fresh response, and held profile identity before using it. */
export function installedContinuationPilotNativeReaderScope(gate:VerifiedInstalledContinuationPilot){
 const scope=nativeReaderScopes.get(gate);
 if(!scope||Math.floor(Date.now()/1000)>=Math.min(gate.expiresAt,scope.expiresAt))throw deny();
 return scope;
}

async function verifyNativeReaderAppendix(value:unknown,rootPublicKey:string,installationDigest:string,target:string,
 installationIssuedAt:number,installationExpiresAt:number,forbidden:readonly PublicPin[]){
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||Buffer.byteLength(value.canonical)>2048)throw deny();
 base64(value.signature,64,64);
 const claim:unknown=JSON.parse(value.canonical);
 exactFields(claim,['version','domain','installationDigest','target','nativeImageSha256','abi','readerPin','issuedAt','expiresAt']);
 exactFields(claim.readerPin,['keyId','publicKey']);
 const {keyId,publicKey}=claim.readerPin;
 const {nativeImageSha256,issuedAt,expiresAt}=claim;
 if(typeof keyId!=='string'||typeof publicKey!=='string'||typeof nativeImageSha256!=='string'||
    nativeImageSha256.length!==64||!/^[a-f0-9]{64}$/.test(nativeImageSha256)||
    typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
    issuedAt<installationIssuedAt||issuedAt>Math.floor(Date.now()/1000)||expiresAt<=issuedAt||
    expiresAt>installationExpiresAt||expiresAt<=Math.floor(Date.now()/1000))throw deny();
 base64(publicKey,32,32);
 if(keyId!==await digest(publicKey)||forbidden.some(pin=>pin.keyId===keyId||pin.publicKey===publicKey))throw deny();
 const readerPin=Object.freeze({keyId,publicKey}),abi=INSTALLED_PILOT_NATIVE_READER_ABI;
 const canonical=JSON.stringify({version:1,domain:nativeReaderDomain,installationDigest,target,nativeImageSha256,abi,readerPin,issuedAt,expiresAt});
 if(canonical!==value.canonical||!await verify(rootPublicKey,value.signature,canonical)||Math.floor(Date.now()/1000)>=expiresAt)throw deny();
 return Object.freeze({installationDigest,target,nativeImageSha256,abi,readerPin,expiresAt});
}

export function installedContinuationPilotScope(gate:VerifiedInstalledContinuationPilot){
 const scope=installedScopes.get(gate);
 if(!scope||Math.floor(Date.now()/1000)>=gate.expiresAt)throw deny();
 return scope;
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
  // Take an immutable local snapshot before the first asynchronous check.
  artifact=JSON.parse(JSON.stringify(artifact)) as ContinuationPilotBuildArtifact;
  if(!/^(darwin|linux)-(arm64|x64)$/.test(target))throw deny();
  const nativeReaderPresent=Object.hasOwn(artifact,'nativeReaderAppendix');
  exactFields(artifact,['manifest','authOriginAppendix','authAppendix','commitAppendix','rolloutAppendix','installation',
   ...(nativeReaderPresent?['nativeReaderAppendix']:[])]);
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
    !/^auth-pilot-[a-z0-9]+(?:-[a-z0-9]+)*\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(authUrl.hostname)||
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
  const installationDigest=await signedDigest(installation);
  const gate=Object.freeze({releaseId:manifest.releaseId,contract:INSTALLED_PILOT_CONTRACT,expiresAt});
  if(nativeReaderPresent){
   const scope=await verifyNativeReaderAppendix(artifact.nativeReaderAppendix,rootPublicKey,installationDigest,target,issuedAt,expiresAt,
    [...pins,...oldPins,{keyId:await digest(rootPublicKey),publicKey:rootPublicKey},
     {keyId:await digest(standard.rootPublicKey),publicKey:standard.rootPublicKey}]);
   nativeReaderScopes.set(gate,scope);
  }
  if(Math.floor(Date.now()/1000)>=expiresAt)throw deny();
  installedScopes.set(gate,Object.freeze({policy:manifest,authOrigin,authOriginAppendix:Object.freeze(artifact.authOriginAppendix),
   authAppendix:Object.freeze(artifact.authAppendix),commitAppendix:Object.freeze(artifact.commitAppendix),rollout,
   installationDigest,target}));
  return gate;
 }catch{throw deny();}
}
