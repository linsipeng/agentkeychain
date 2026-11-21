import {test,expect} from 'bun:test';
import {Database} from 'bun:sqlite';
import sodium from 'libsodium-wrappers-sumo';
import {createCloudKeys,destroyCloudKeys,sealKeyPackage} from '../src/cloud/crypto.ts';
import {CloudStore} from '../src/cloud/persistence.ts';
import {MemorySecureStore} from '../src/platform/secure-store.ts';
import {canonicalManifest,verifyReleaseManifest} from '../src/cloud/config.ts';
import {protectEnrollmentKeys} from '../src/cloud/enrollment-intent.ts';
import {selfAnchor} from '../src/cloud/enrollment.ts';
import {prepareContinuationBrowserHandoff} from '../src/cloud/continuation-handoff.ts';
import type {CloudFetch} from '../src/cloud/http.ts';
import {canonicalGrant} from '../managed-cloud/shared/device-protocol.ts';
import {digest,verify} from '../managed-cloud/shared/contracts.ts';
import {handoffCodeDigest,handoffDevicePollProof,handoffPrepareProof,handoffStageDigest} from '../managed-cloud/shared/continuation-handoff-wire.ts';

test('CLI restarts with the same protected handoff; no plaintext pair code in network or URL',async()=>{
 await sodium.ready;
 const keys=await createCloudKeys(),root=sodium.crypto_sign_keypair(),witness=sodium.crypto_sign_keypair(),checkpoint=sodium.crypto_sign_keypair();
 const b64=(x:Uint8Array)=>Buffer.from(x).toString('base64'),sign=(x:string)=>b64(sodium.crypto_sign_detached(x,root.privateKey));
 const manifest=canonicalManifest({version:1,releaseId:'fixture',apiOrigin:'https://api.local.invalid',webOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,
  checkpointKeys:[{keyId:'checkpoint',publicKey:b64(checkpoint.publicKey)}],witnessKeys:[{keyId:'witness',publicKey:b64(witness.publicKey)}]});
 const policy=verifyReleaseManifest({canonical:manifest,signature:sign(manifest)},root.publicKey);
 const proof=async(authOrigin:string)=>{const canonical=JSON.stringify({version:1,domain:'AgentKeychain-continuation-auth-origin-pilot-v1',manifestDigest:await digest(manifest),authOrigin});return {canonical,signature:sign(canonical)};};
 const authOrigin='https://auth.local.invalid',authOriginAppendix=await proof(authOrigin),now=Math.floor(Date.now()/1000);
 const fresh={version:1 as const,requestId:'original',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'device',keyEpoch:1,issuerDeviceId:null,
  signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),expiresAt:now+150};
 const g={...fresh,expiresAt:now-20},oldGrantCanonical=canonicalGrant(g),roster=selfAnchor(fresh,keys,policy,true).signedRoster;
 const keyPackage=sealKeyPackage(keys.vdk,{vaultId:g.vaultId,targetDeviceId:g.deviceId,keyEpoch:g.keyEpoch,issuerDeviceId:g.deviceId,grantId:g.requestId},keys.wrappingPublic,keys.signingPrivate);
 const secure=new MemorySecureStore(),db=new Database(':memory:'),store=new CloudStore(db,keys.csk);
 const key='pending-continuation-browser-handoff',bodies:string[]=[],shown:string[]=[];
 const wire:CloudFetch=async(url,options)=>{
  expect(url).toBe(authOrigin+'/v1/auth/continuation-handoff/prepare');
  expect(options).toMatchObject({method:'POST',redirect:'error',credentials:'omit'});
  const raw=String(options.body),input=JSON.parse(raw);bodies.push(raw);
  expect(Object.keys(input).sort()).toEqual(['codeDigest','expiresAt','locator','signature','stage']);
  expect(await verify(g.signingKey,input.signature,handoffPrepareProof(input.locator,input.codeDigest,await handoffStageDigest(input.stage),input.expiresAt))).toBe(true);
  if(bodies.length===1)throw new Error('simulated lost commit response');
  if(bodies.length===2)return Response.json({locator:'m'.repeat(43)});
  return Response.json({locator:input.locator});
 };
 const options={secure,store,policy,authOriginAppendix,oldGrantCanonical,roster,keyPackage,network:wire,displayPairCode:(code:string)=>{shown.push(code);}};
 try{
  await protectEnrollmentKeys(secure,keys);
  store.put('state','pending',{requestId:g.requestId,deviceId:g.deviceId});
  store.put('state','pending-approved',{requestId:g.requestId,deviceId:g.deviceId,vaultId:g.vaultId});
  store.put('state','pending-self-roster',roster);store.put('state','pending-package',keyPackage);
  await expect(prepareContinuationBrowserHandoff({...options,authOriginAppendix:await proof(policy.webOrigin)})).rejects.toThrow('invalid_continuation_auth_origin');
  expect(bodies).toHaveLength(0);
  await expect(prepareContinuationBrowserHandoff(options)).rejects.toThrow('cloud_continuation_handoff_unavailable');
  const saved=store.get<{locator:string;code:string;expiresAt:number;codeDigest:string}>('state',key)!;
  expect(await handoffCodeDigest(saved.locator,saved.code)).toBe(saved.codeDigest);expect(shown).toEqual([]);
  const restarted=new CloudStore(db,keys.csk);
  try{
   await expect(prepareContinuationBrowserHandoff({...options,store:restarted})).rejects.toThrow('cloud_continuation_handoff_unavailable');
   expect(shown).toEqual([]);
   const result=await prepareContinuationBrowserHandoff({...options,store:restarted});
   expect(result.browserUrl).toBe(authOrigin+'/continuation/approve#handoff='+saved.locator);
   expect(shown).toEqual([saved.code]);expect(bodies).toHaveLength(3);expect(new Set(bodies).size).toBe(1);
   expect(bodies[0]).not.toContain('"code":"'+saved.code+'"');
   expect(restarted.get('state','enrollment')).toBeNull();
   const raw=db.query('SELECT ciphertext FROM cloud_state WHERE id=?').get(key) as {ciphertext:Uint8Array};
   expect(Buffer.from(raw.ciphertext).includes(Buffer.from(saved.code))).toBe(false);
   const state=restarted.get<Record<string,unknown>>('state',key)!;
   restarted.put('state',key,{...state,expiresAt:now-1});
   await expect(prepareContinuationBrowserHandoff({...options,store:restarted})).rejects.toThrow('cloud_continuation_handoff_expired');
   expect(bodies).toHaveLength(3);
  }finally{restarted.destroy();}
 }finally{destroyCloudKeys(keys);store.destroy();db.close();}
});

test('synthetic continuation reuses one exact handoff and Main commit after losing its reply',async()=>{
 await sodium.ready;
 const {advanceSyntheticContinuation,showSyntheticContinuationHandoff}=await import('../src/cloud/continuation-machine.ts');
 const {canonicalContinuationReceipt}=await import('../managed-cloud/shared/enrollment-continuation.ts');
 const {rosterDigest}=await import('../managed-cloud/shared/roster.ts');
 const {WITNESS_DOMAIN}=await import('../managed-cloud/shared/roster-witness.ts');
 const {genesisRoot}=await import('../managed-cloud/shared/checkpoints.ts');
 const keys=await createCloudKeys(),secure=new MemorySecureStore(),db=new Database(':memory:'),store=new CloudStore(db,keys.csk);
 const actor=()=>sodium.crypto_sign_keypair(),root=actor(),w=actor(),cp=actor(),auth=actor(),main=actor(),rollout=actor();
 const b64=(v:Uint8Array)=>Buffer.from(v).toString('base64');
 const signed=(canonical:string,who:typeof root,domain='')=>({canonical,signature:b64(sodium.crypto_sign_detached(domain+canonical,who.privateKey))});
 const sd=(v:{canonical:string;signature:string})=>digest(JSON.stringify([v.canonical,v.signature]));
 const now=Math.floor(Date.now()/1000),authOrigin='https://auth.local.invalid',apiOrigin='https://api.local.invalid';
 const manifest=canonicalManifest({version:1,releaseId:'fixture',apiOrigin,webOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,
  checkpointKeys:[{keyId:'cp',publicKey:b64(cp.publicKey)}],witnessKeys:[{keyId:'custody',publicKey:b64(w.publicKey)}]});
 const policy=verifyReleaseManifest(signed(manifest,root),root.publicKey),manifestDigest=await digest(manifest);
 const appendix=(domain:string,keyId:string,who:typeof root)=>signed(JSON.stringify({version:1,domain,manifestDigest,keyId,publicKey:b64(who.publicKey)}),root);
 const authAppendix=appendix('AgentKeychain-continuation-release-pin-v1','auth',auth),commitAppendix=appendix('AgentKeychain-continuation-main-commit-release-pin-v1','main',main);
 const rolloutAppendix=appendix('AgentKeychain-continuation-rollout-release-pin-v1','rollout',rollout);
 const authOriginAppendix=signed(JSON.stringify({version:1,domain:'AgentKeychain-continuation-auth-origin-pilot-v1',manifestDigest,authOrigin}),root);
 const grant={version:1 as const,requestId:'r',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d',keyEpoch:1,issuerDeviceId:null,
  signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),expiresAt:now-5};
 const oldGrantCanonical=canonicalGrant(grant),roster=selfAnchor({...grant,expiresAt:now+150},keys,policy,true).signedRoster,head=await rosterDigest(roster);
 const keyPackage=sealKeyPackage(keys.vdk,{vaultId:'v',targetDeviceId:'d',keyEpoch:1,issuerDeviceId:'d',grantId:'r'},keys.wrappingPublic,keys.signingPrivate);
 const witness=signed(JSON.stringify({version:1,keyId:'custody',accountId:'a',tenantId:'t',vaultId:'v',event:1,revision:1,digest:head,sequence:0,
  root:await genesisRoot('t','v'),checkpointDigest:await digest('synthetic-checkpoint')}),w,WITNESS_DOMAIN);
 const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',keyPackage.canonical,keyPackage.signature]));
 let publish=0,polls=0,launches=0,displayed=0,commits=0,posts=0;
 let published:{locator:string;stage:import('../managed-cloud/shared/continuation-handoff-wire.ts').ContinuationHandoffStage}|undefined;
 const pollNonces=new Set<string>();
 const nonces:string[]=[],prepareWrites:string[]=[];let localCode='',localUrl='';
 type Flow=Parameters<typeof advanceSyntheticContinuation>[3];
 const flow:Flow={authOriginAppendix,oldGrantCanonical,roster,keyPackage,
  prepareNetwork:async(url,init)=>{expect(url).toBe(authOrigin+'/v1/auth/continuation-handoff/prepare');publish++;prepareWrites.push(String(init.body));published=JSON.parse(String(init.body));if(publish===1)throw new Error('test_prepare_reply_lost');return Response.json({locator:published!.locator});},
  authorize:async intentDigest=>({authAppendix,commitAppendix,rolloutAppendix,capability:signed(JSON.stringify({version:1,domain:'AgentKeychain-continuation-rollout-capability-v1',
   mode:'synthetic-only',manifestDigest,keyId:'rollout',intentDigest,authAppendixDigest:await sd(authAppendix),commitAppendixDigest:await sd(commitAppendix),witnessKeyId:'custody',
   issuedAt:now,expiresAt:now+60}),rollout)}),
  open:async browserUrl=>{expect(browserUrl.startsWith(authOrigin+'/continuation/approve#handoff=')).toBe(true);launches++;localUrl=browserUrl;throw new Error('test_interrupted_before_browser');},
  displayPairCode:code=>{expect(code).toMatch(/^[0-9]{8}$/);displayed++;localCode=code;},
  pollNetwork:async (url,init)=>{
   expect(url).toBe(authOrigin+'/v1/auth/continuation-handoff/poll');
   expect(init).toMatchObject({redirect:'error',credentials:'omit',cache:'no-store',method:'POST',headers:{'content-type':'application/json'}});
   const b=JSON.parse(String(init.body));
   expect(Object.keys(b).sort()).toEqual(['intentDigest','locator','nonce','signature','stageDigest','timestamp']);
   expect(b.locator).toBe(published!.locator);expect(b.intentDigest).toBe(await digest(published!.stage.target.canonical));expect(b.stageDigest).toBe(await handoffStageDigest(published!.stage));
   expect(pollNonces.has(b.nonce)).toBe(false);pollNonces.add(b.nonce);
   expect(await verify(grant.signingKey,b.signature,handoffDevicePollProof(b.locator,b.intentDigest,b.stageDigest,b.nonce,b.timestamp))).toBe(true);
   if(++polls===1)return Response.json({status:'pending'},{status:202});
   if(polls===2)return Response.json({oversized:'a'.repeat(5000)});
   const receipt=canonicalContinuationReceipt({version:1,domain:'AgentKeychain-enrollment-continuation-approval-v1',
    intentDigest:b.intentDigest,authorityKeyId:'auth',approvedAt:now,expiresAt:now+60});
   return Response.json({status:'approved',approval:signed(receipt,polls===3?main:auth)});
  },
  custodyHead:async ({nonce,approval})=>({witness,freshHead:signed(JSON.stringify({domain:'AgentKeychain-enrollment-continuation-current-head-v1',
   keyId:'custody',nonce,requestId:'r',witnessDigest:await sd(witness),approvalDigest:await sd(approval),payloadDigest,issuedAt:now,expiresAt:now+50}),w)}),
  commitOrRead:async (origin,{stage,approval,nonce,fresh})=>{
   expect(origin).toBe(apiOrigin);nonces.push(nonce);
   if(++commits===1)throw new Error('test_main_response_lost');
   return signed(JSON.stringify({version:1,domain:'AgentKeychain-enrollment-continuation-main-commit-v1',keyId:'main',nonce,
    continuationId:JSON.parse(stage.target.canonical).id,requestId:'r',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d',keyEpoch:1,stage:'put-key-package',
    intentDigest:await digest(stage.target.canonical),approvalDigest:await sd(approval),payloadDigest,witnessDigest:await sd(witness),custodyFreshHeadDigest:await sd(fresh.freshHead),
    issuedAt:now,expiresAt:now+40}),main);
  },
  custodyPost:async (nonce,commit)=>{
   posts++;expect(nonces).not.toContain(nonce);
   return signed(JSON.stringify({version:1,domain:'AgentKeychain-enrollment-continuation-custody-post-commit-v1',keyId:'custody',nonce,
    mainCommitDigest:await sd(commit),requestId:'r',continuationId:JSON.parse(commit.canonical).continuationId,accountId:'a',tenantId:'t',vaultId:'v',
    deviceId:'d',keyEpoch:1,witnessDigest:await sd(witness),payloadDigest,issuedAt:now,expiresAt:now+35}),w);
  },
 };
 try{
  await protectEnrollmentKeys(secure,keys);
  store.put('state','pending',{requestId:'r',deviceId:'d'});store.put('state','pending-approved',{requestId:'r',deviceId:'d',vaultId:'v'});
  store.put('state','pending-self-roster',roster);store.put('state','pending-package',keyPackage);
  const step=()=>advanceSyntheticContinuation(secure,store,policy,flow);
  const manual=()=>showSyntheticContinuationHandoff(store,policy,flow,(url,code)=>{expect(url).toBe(localUrl);expect(code).toBe(localCode);});
  await expect(step()).rejects.toThrow('cloud_continuation_handoff_unavailable');
  await expect(manual()).rejects.toThrow('cloud_continuation_not_provisioned');
  await expect(step()).rejects.toThrow('test_interrupted_before_browser');
  await manual();
  expect(new Set(prepareWrites).size).toBe(1);
  expect([publish,launches,displayed,polls,commits,posts]).toEqual([2,1,1,0,0,0]);
  expect(await step()).toBe('waiting-for-approval');
  expect(commits).toBe(0);
  await expect(step()).rejects.toThrow('cloud_continuation_approval_unavailable'); // oversized response
  await expect(step()).rejects.toThrow('cloud_continuation_approval_unavailable'); // wrong receipt signer
  expect(commits).toBe(0);
  await expect(step()).rejects.toThrow('test_main_response_lost');
  expect(store.get('state','enrollment')).toBeNull();
  expect(await step()).toBe('active');
  expect(nonces).toHaveLength(2);expect(new Set(nonces).size).toBe(1);
  expect([publish,launches,displayed,polls,commits,posts]).toEqual([2,1,1,4,2,1]);
  expect(store.get('state','enrollment')).toMatchObject({deviceId:'d',vdk:b64(keys.vdk)});
  expect(store.get('state','pending-continuation-browser-handoff')).toBeNull();
 }finally{destroyCloudKeys(keys);store.destroy();db.close();}
});
