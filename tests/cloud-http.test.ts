import { URL } from "node:url";
import {expect,test} from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalManifest,verifyReleaseManifest} from '../src/cloud/config.ts';
import {ManagedHttpClient} from '../src/cloud/http.ts';
import {createDevice} from '../src/cloud/device.ts';
const b64=(x:Uint8Array)=>Buffer.from(x).toString('base64');
export async function testPolicy(){await sodium.ready;const key=sodium.crypto_sign_keypair();const canonical=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[{keyId:'test',publicKey:b64(key.publicKey)}]});return {policy:verifyReleaseManifest({canonical,signature:b64(sodium.crypto_sign_detached(canonical,key.privateKey))},key.publicKey),key};}
test('HTTP refuses redirects, large bodies and unverified policies; proof headers never in query',async()=>{
 const {policy}=await testPolicy(),identity=await createDevice('vault','device');let count=0;
 const http=new ManagedHttpClient(policy,identity,async(url,init)=>{
  count++;expect(new URL(url).origin).toBe(policy.apiOrigin);expect(init.redirect).toBe('error');
  if(url.endsWith('/challenge'))return Response.json({challengeId:'challenge',challenge:'synthetic',deviceId:'device',vaultId:'vault',expiresAt:Math.floor(Date.now()/1000)+60});
  if(url.endsWith('/token'))return Response.json({token:'synthetic',expiresIn:900,deviceId:'device',vaultId:'vault',tokenType:'DeviceProof'});
  expect(new globalThis.Headers(init.headers).has('x-device-proof')).toBe(true);return Response.json({ok:true});
 });
 expect(await http.call('/v1/devices/approvals',{})).toEqual({ok:true});expect(count).toBe(3);
 await expect(http.call('https://evil.invalid',{})).rejects.toThrow();
 const bad=new ManagedHttpClient(policy,identity,async()=>new Response('x'.repeat(1024*1024+1)));
 await expect(bad.publicCall('/v1/devices/authorize',{})).rejects.toThrow('cloud_response_too_large');
 expect(()=>new ManagedHttpClient({...policy},identity)).toThrow('unverified');
});
test('recovered sessions bind refresh possession to target signatures and converge after response loss',async()=>{
 const {policy}=await testPolicy(),identity=await createDevice('vault','x'.repeat(43)),credential=Buffer.from('c'.repeat(43));let lost=true,token='';
 const network:ConstructorParameters<typeof ManagedHttpClient>[2]=async(url,init)=>{
  expect(new URL(url).pathname).toBe('/v1/devices/recovery-refresh');const body=JSON.parse(init.body as string),{signature,...signed}=body;
  expect(sodium.crypto_sign_verify_detached(Buffer.from(signature,'base64'),JSON.stringify(['AgentKeychain-recovery-refresh-v1',signed]),Buffer.from(identity.record.publicKey,'base64'))).toBe(true);
  if(token)expect(body.sessionToken===token).toBe(true);token=body.sessionToken;
  if(lost){lost=false;throw new Error('response_lost');}return Response.json({token,deviceId:identity.record.deviceId,vaultId:'vault',tokenType:'DeviceProof',expiresIn:900});
 };
 const first=new ManagedHttpClient(policy,identity,network);first.setRefreshCredential(credential);await expect(first.session()).rejects.toThrow('cloud_network_unavailable');first.logout();
 const resumed=new ManagedHttpClient(policy,identity,network);resumed.setRefreshCredential(credential);await resumed.session();resumed.logout();credential.fill(0);identity.privateKey.fill(0);
});
