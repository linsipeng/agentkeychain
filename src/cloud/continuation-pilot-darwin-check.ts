/** Signed contracts for the separately built Darwin candidate. No spawn,
 * Keychain calls, normal installer, activation or profile integration. */
import {base64,exactFields,type SignedManagedOperation} from './protocol.ts';
import {installedContinuationPilotScope,type VerifiedInstalledContinuationPilot} from './continuation-pilot-build.ts';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';

export const DARWIN_NATIVE_LOCATION_DOMAIN='AgentKeychain-installed-pilot-darwin-keychain-check-v1';
export const DARWIN_NATIVE_HELPER_DOMAIN='AgentKeychain-installed-pilot-darwin-helper-v1';
export const DARWIN_NATIVE_CHECK='scoped-native-location-verified-not-active';
const deny=()=>new Error('darwin_pilot_native_candidate_denied');
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const identity=(v:unknown):v is string=>typeof v==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(v)&&BigInt(v)<=18446744073709551615n;
const clock=()=>Math.floor(Date.now()/1000);

function sortedJSON(input:Record<string,unknown>){
 return JSON.stringify(Object.fromEntries(Object.keys(input).sort().map(k=>[k,input[k]])));
}
function signed(value:unknown):SignedManagedOperation{
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||!value.canonical.length||value.canonical.length>4096)throw deny();
 base64(value.signature,64,64);
 return {canonical:value.canonical,signature:value.signature};
}
function windows(issuedAt:unknown,expiresAt:unknown,limit:number,now:number){
 return typeof issuedAt==='number'&&typeof expiresAt==='number'&&Number.isSafeInteger(issuedAt)&&Number.isSafeInteger(expiresAt)&&
  issuedAt>0&&issuedAt<=now&&now<expiresAt&&expiresAt<=limit&&expiresAt-issuedAt<=900;
}
export async function verifyDarwinPilotNativeInputs(gate:VerifiedInstalledContinuationPilot,input:{
 readonly location:unknown;readonly helperAppendix:unknown;readonly examinedHelperSha256:string;readonly target:string;
 readonly uid:number;readonly now?:number;
}):Promise<Readonly<{nativeInput:string;expectedStatus:typeof DARWIN_NATIVE_CHECK}>>{
 try{
  const scope=installedContinuationPilotScope(gate),at=input.now??clock();
  if(input.target!==scope.target||!/^darwin-(arm64|x64)$/.test(input.target)||!hash(input.examinedHelperSha256)||
    !Number.isSafeInteger(input.uid)||input.uid<=0||input.uid>0xffffffff)throw deny();
  const location=signed(input.location),helper=signed(input.helperAppendix);
  const raw:unknown=JSON.parse(location.canonical),h:unknown=JSON.parse(helper.canonical);
  exactFields(raw,['version','domain','installationDigest','keyId','directory','directoryDevice','directoryInode',
   'fileDevice','fileInode','uid','namespace','issuedAt','expiresAt']);
  exactFields(h,['version','domain','installationDigest','keyId','target','helperSha256','issuedAt','expiresAt']);
  const {directory,directoryDevice,directoryInode,fileDevice,fileInode,issuedAt,expiresAt}=raw;
  if(typeof directory!=='string'||!/^\/private\/tmp\/akc-pilot-native-[a-f0-9]{32}$/.test(directory)||
    !identity(directoryDevice)||!identity(directoryInode)||directoryInode==='0'||!identity(fileDevice)||fileDevice!==directoryDevice||
    !identity(fileInode)||fileInode==='0'||!windows(issuedAt,expiresAt,gate.expiresAt,at)||!windows(h.issuedAt,h.expiresAt,gate.expiresAt,at))throw deny();
  const common={version:1,installationDigest:scope.installationDigest,keyId:scope.rollout.keyId};
  const namespace='agentkeychain.pilot.'+await digest(JSON.stringify([DARWIN_NATIVE_LOCATION_DOMAIN,scope.installationDigest,
   directory,String(input.uid),directoryDevice,directoryInode]));
  const expectedLocation=sortedJSON({...common,domain:DARWIN_NATIVE_LOCATION_DOMAIN,directory,directoryDevice,directoryInode,
   fileDevice,fileInode,uid:input.uid,namespace,issuedAt,expiresAt});
  const expectedHelper=sortedJSON({...common,domain:DARWIN_NATIVE_HELPER_DOMAIN,target:input.target,
   helperSha256:input.examinedHelperSha256,issuedAt:h.issuedAt,expiresAt:h.expiresAt});
  if(location.canonical!==expectedLocation||helper.canonical!==expectedHelper||
    !await verify(scope.rollout.publicKey,location.signature,location.canonical)||
    !await verify(scope.rollout.publicKey,helper.signature,helper.canonical))throw deny();
  return Object.freeze({nativeInput:sortedJSON({...location}),expectedStatus:DARWIN_NATIVE_CHECK});
 }catch{throw deny();}
}

/** Trust passed only during explicit compile, never as runtime args/env. Uses
 * generated public literals, not resource or launch authorization. */
export function darwinPilotNativeTrustSwift(gate:VerifiedInstalledContinuationPilot):string{
 const scope=installedContinuationPilotScope(gate);
 if(!/^darwin-(arm64|x64)$/.test(scope.target))throw deny();
 return 'enum PilotNativeTrust {\n'+
  ' static let rolloutPublicKey = '+JSON.stringify(scope.rollout.publicKey)+'\n'+
  ' static let installationDigest = '+JSON.stringify(scope.installationDigest)+'\n'+
  ' static let expiresAt: Int64 = '+gate.expiresAt+'\n}\n';
}
