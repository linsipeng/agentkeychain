/** Synthetic-only Worker with its own Auth D1. Never exported by a production Worker. */
import {WorkerEntrypoint} from 'cloudflare:workers';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {genesisIssuer} from '../auth-trust-worker/experimental/genesis-issuer.ts';
import {genesisReadback,genesisReadbackIntent} from '../auth-trust-worker/experimental/genesis-readback.ts';
import {encode,random,webauthn} from '../api-worker/webauthn.ts';
import {digest} from '../shared/contracts.ts';
import type {EnrollmentGrant} from '../shared/device-protocol.ts';
import type {GenesisApprovalPolicy} from '../shared/genesis-approval.ts';
import {rosterDigest} from '../shared/roster.ts';
import {virtualAuthenticator} from './virtual-authenticator.ts';

const identity={origin:'https://independent-auth.fixture.invalid',rpId:'independent-auth.fixture.invalid'};
interface Env {AUTH:D1Database;AUTHORITY_PRIVATE:string;APPROVAL_POLICY:string}
const binary=(b:string)=>Uint8Array.from(atob(b),c=>c.charCodeAt(0));
const base64=(b:ArrayBuffer)=>btoa(String.fromCharCode(...new Uint8Array(b)));
export default class GenesisTransportFixture extends WorkerEntrypoint<Env>{
 async issueAndDropResponse(grant:string,roster:SignedManagedOperation,sessionToken:string,csrf:string){
  const {AUTH:db}=this.env,policy=JSON.parse(this.env.APPROVAL_POLICY) as GenesisApprovalPolicy;
  const key=await crypto.subtle.importKey('pkcs8',binary(this.env.AUTHORITY_PRIVATE),'Ed25519',false,['sign']);
  const issuer=genesisIssuer(db,identity,policy,{key:async()=>policy.authority,sign:async m=>base64(await crypto.subtle.sign('Ed25519',key,new TextEncoder().encode(m)))});
  const {accountId,tenantId,vaultId}=JSON.parse(grant) as EnrollmentGrant;
  const auth=await virtualAuthenticator('ES256'),handle=random(),challenge=random();
  const credential=await webauthn.registration(identity,await digest(challenge),await auth.register(challenge,identity));
  await db.prepare('INSERT INTO auth_genesis_pins VALUES(?,?,?,?,?,?,?,1)').bind(accountId,tenantId,vaultId,handle,credential.id,encode(credential.publicKey),credential.counter).run();
  const intent=await issuer.begin(grant,roster);
  const assertion=await auth.assert(intent.options.challenge,{...identity,counter:1,userHandle:handle});
  const result=await issuer.complete(intent.id,grant,roster,assertion);
  // The production-independent Auth front door does not yet exist. These
  // fixture rows model scoped authorization after the real approval succeeds.
  const session=await digest(sessionToken),action=await genesisReadbackIntent(intent.id,await digest(grant),await rosterDigest(roster));
  const now=Math.floor(Date.now()/1000),validUntil=Math.min(now+45,(JSON.parse(result.canonical) as {expiresAt:number}).expiresAt);
  await db.batch([
   db.prepare('INSERT INTO auth_genesis_view_sessions VALUES(?,?,?,?,?,1,0,?)').bind(session,await digest(csrf),accountId,tenantId,vaultId,validUntil),
   db.prepare('INSERT INTO auth_genesis_view_grants VALUES(?,?,?,?)').bind(session,action,now,validUntil),
  ]);
  // The real receipt never crosses this transport. The caller already has the
  // opaque challenge reference and must use the scoped readback to recover it.
  return intent.id;
 }
 async syntheticReadback(headers:Record<string,string>,body:string){
  const response=await this.fetch(new Request(identity.origin+'/v1/auth/first-device-receipt',{method:'POST',headers,body}));
  return JSON.stringify({status:response.status,body:await response.json()});
 }
 override async fetch(request:Request){
  return genesisReadback(this.env.AUTH,identity.origin,JSON.parse(this.env.APPROVAL_POLICY) as GenesisApprovalPolicy)(request);
 }
}
