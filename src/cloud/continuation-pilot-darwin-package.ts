/** Offline staging-byte comparison only. No Apple identity verification, installer or launch authority. */
import {createHash} from 'node:crypto';
import {verify} from '../../managed-cloud/shared/contracts.ts';
import {INSTALLED_PILOT_BINARY,installedContinuationPilotScope,verifyInstalledContinuationPilot,
 type ContinuationPilotBuildArtifact} from './continuation-pilot-build.ts';
import {base64,exactFields,type SignedManagedOperation} from './protocol.ts';

export const DARWIN_PILOT_PACKAGE_DOMAIN='AgentKeychain-installed-pilot-darwin-package-index-v1';
export const DARWIN_PILOT_NATIVE_BINARY='agentkeychain-continuation-pilot-native';
export const DARWIN_PILOT_CLI_IDENTIFIER='org.agentkeychain.continuation-pilot.cli';
export const DARWIN_PILOT_NATIVE_IDENTIFIER='org.agentkeychain.continuation-pilot.native';
type Target='darwin-arm64'|'darwin-x64';
const deny=()=>new Error('darwin_pilot_package_denied');
const now=()=>Math.floor(Date.now()/1000);

/** The controlled packager supplies the two staging payload bytes and an independently approved
 * Team ID. The returned immutable metadata never contains executable paths or launch capability. */
export async function verifyDarwinPilotPackageStaging(
 artifact:ContinuationPilotBuildArtifact,rootPublicKey:string,index:SignedManagedOperation,
 policy:Readonly<{target:Target;publisherTeamId:string}>,payloads:unknown,
){
 try{
  const {target,publisherTeamId}=policy;
  if(!/^darwin-(arm64|x64)$/.test(target)||!/^[A-Z0-9]{10}$/.test(publisherTeamId))throw deny();
  exactFields(index,['canonical','signature']);
  const {canonical,signature}=index;
  if(typeof canonical!=='string'||canonical.length>2048)throw deny();
  base64(signature,64,64);
  const claim:unknown=JSON.parse(canonical);
  exactFields(claim,['version','domain','mode','installationDigest','target','publisherTeamId','cliIdentifier',
   'cliSha256','nativeIdentifier','nativeSha256','issuedAt','expiresAt']);
  const {issuedAt,expiresAt}=claim;
  if(typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||
     !Number.isSafeInteger(expiresAt)||issuedAt<1||issuedAt>now()||expiresAt<=now())throw deny();
  exactFields(payloads,[INSTALLED_PILOT_BINARY,DARWIN_PILOT_NATIVE_BINARY]);
  const sha=(value:unknown)=>{
   if(!Buffer.isBuffer(value)||!value.length||value.length>256*1024*1024||
      !(value.buffer instanceof ArrayBuffer))throw deny();
   return createHash('sha256').update(value).digest('hex');
  };
  // Snapshot synchronously as digests before the first await; no mutable Buffer is returned.
  const cliSha256=sha(payloads[INSTALLED_PILOT_BINARY]),nativeSha256=sha(payloads[DARWIN_PILOT_NATIVE_BINARY]);
  if(cliSha256===nativeSha256)throw deny();
  const gate=await verifyInstalledContinuationPilot(artifact,rootPublicKey,target);
  const {installationDigest}=installedContinuationPilotScope(gate);
  const expected=JSON.stringify({version:1,domain:DARWIN_PILOT_PACKAGE_DOMAIN,mode:'disposable-only',
   installationDigest,target,publisherTeamId,cliIdentifier:DARWIN_PILOT_CLI_IDENTIFIER,cliSha256,
   nativeIdentifier:DARWIN_PILOT_NATIVE_IDENTIFIER,nativeSha256,issuedAt,expiresAt});
  if(expiresAt>gate.expiresAt||canonical!==expected||!await verify(rootPublicKey,signature,canonical)||
     now()>=expiresAt)throw deny();
  return Object.freeze({state:'staged-bytes-match-signed-index-not-authorized' as const,releaseId:gate.releaseId,
   installationDigest,target,publisherTeamId,cliSha256,nativeSha256,expiresAt});
 }catch{throw deny();}
}
