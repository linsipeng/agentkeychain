/** Synthetic two-process protocol rehearsal, NOT native/installed peer authorization. */
import assert from 'node:assert/strict';
import {createHash,createPrivateKey,createPublicKey,generateKeyPairSync,randomBytes,sign,verify} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {pipeline} from 'node:stream/promises';
import {Readable} from 'node:stream';
import {canonicalPilotBrokerRequest,parsePilotBrokerRequest,parsePilotBrokerResponse,emptyPilotBrokerReference,
 transitionPilotBrokerReference} from '../../src/cloud/pilot-broker-wire.ts';

const limit=192*1024,abi='pilot-broker-fixture-inspect-v1',scopeDomain='AgentKeychain-test-broker-scope-v1\0';
const reqDomain='AgentKeychain-test-broker-request-v1\0',replyDomain='AgentKeychain-test-broker-reply-v1\0';
const blocked=()=>new Error('synthetic_broker_denied');
const hash=b=>createHash('sha256').update(b).digest('hex');
const random=()=>randomBytes(32).toString('hex');
const wire=b=>Buffer.from(b).toString('base64url');
const unestablished='wire-not-established';
function exact(value,keys) {
 if(!value||typeof value!=='object'||Array.isArray(value))throw blocked();
 if(Object.keys(value).length!==keys.length||keys.some(k=>!Object.hasOwn(value,k)))throw blocked();
}
function bytes(encoded,lo,hi){
 if(typeof encoded!=='string'||!encoded||encoded.length>Math.ceil(hi*4/3)||!/^[A-Za-z0-9_-]+$/.test(encoded))throw blocked();
 const b=Buffer.from(encoded,'base64url');
 if(b.length<lo||b.length>hi||wire(b)!==encoded)throw blocked();
 return b;
}
function id(value){
 if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value))throw blocked();
 return value;
}
function publicKey(value){
 return createPublicKey({key:bytes(value,44,44),format:'der',type:'spki'});
}
function generated(transfer=false){
 const k=generateKeyPairSync('ed25519');
 return {key:k.privateKey,pub:wire(k.publicKey.export({format:'der',type:'spki'})),...(transfer?{pkcs8:wire(k.privateKey.export({format:'der',type:'pkcs8'}))}:{})};
}
const stringify=v=>JSON.stringify(v);
const decode=b=>new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(b);
function pack(value){
 const b=typeof value==='string'?Buffer.from(value):value;
 assert.ok(b.length>0&&b.length<=limit);
 const h=Buffer.alloc(4);h.writeUInt32BE(b.length);
 return Buffer.concat([h,b]);
}
async function frame(input){
 const chunks=[];let used=0;
 for await(const b of input){
  used+=b.length;
  if(used>limit+4)throw blocked();
  chunks.push(b);
 }
 const raw=Buffer.concat(chunks,used);
 if(raw.length<5||raw.readUInt32BE()!==raw.length-4)throw blocked();
 return decode(raw.subarray(4));
}
function encodeSigned(domain,value,key){
 const canonical=stringify(value);
 return {canonical,signature:wire(sign(null,Buffer.from(domain+canonical),key))};
}
function verified(domain,envelope,key){
 exact(envelope,['canonical','signature']);
 if(typeof envelope.canonical!=='string'||!envelope.canonical||envelope.canonical.length>limit||
    !verify(null,Buffer.from(domain+envelope.canonical),publicKey(key),bytes(envelope.signature,64,64)))throw blocked();
 return JSON.parse(envelope.canonical);
}
function boundScope(capsule,trustedRoot){
 const s=verified(scopeDomain,capsule,trustedRoot);
 exact(s,['version','abi','run','profileDigest','clientKey','brokerKey']);
 id(s.run);id(s.profileDigest);publicKey(s.clientKey);publicKey(s.brokerKey);
 if(s.version!==1||s.abi!==abi||new Set([trustedRoot,s.clientKey,s.brokerKey]).size!==3||
    stringify({version:1,abi,run:s.run,profileDigest:s.profileDigest,clientKey:s.clientKey,brokerKey:s.brokerKey})!==capsule.canonical)throw blocked();
 return s;
}
function request(scope,requestId,bodyBytes,client){
 return encodeSigned(reqDomain,{version:1,abi,run:scope.run,profileDigest:scope.profileDigest,requestId,body:wire(bodyBytes)},client);
}
function receiveRequest(raw,s){
 const envelope=JSON.parse(raw);
 if(stringify(envelope)!==raw)throw blocked();
 const q=verified(reqDomain,envelope,s.clientKey);
 exact(q,['version','abi','run','profileDigest','requestId','body']);
 const requestId=id(q.requestId),body=decode(bytes(q.body,1,128*1024));
 if(stringify({version:1,abi,run:s.run,profileDigest:s.profileDigest,requestId,body:q.body})!==envelope.canonical)throw blocked();
 const parsed=parsePilotBrokerRequest(body);
 if(parsed.profileDigest!==s.profileDigest||parsed.op!=='inspect')throw blocked(); // this fixture intentionally cannot mutate
 return {requestId,body};
}
function reply(s,requestId,requestBody,response,brokerKey){
 return encodeSigned(replyDomain,{version:1,abi,run:s.run,profileDigest:s.profileDigest,requestId,
  requestDigest:hash(requestBody),body:wire(Buffer.from(response))},brokerKey);
}
function receiveReply(raw,s,requestId,requestBody){
 const envelope=JSON.parse(raw);
 if(stringify(envelope)!==raw)throw blocked();
 const p=verified(replyDomain,envelope,s.brokerKey);
 exact(p,['version','abi','run','profileDigest','requestId','requestDigest','body']);
 if(stringify({version:1,abi,run:s.run,profileDigest:s.profileDigest,requestId,
  requestDigest:hash(requestBody),body:p.body})!==envelope.canonical)throw blocked();
 const result=parsePilotBrokerResponse(decode(bytes(p.body,1,128*1024)));
 if(result.kind!=='empty'||result.profileDigest!==s.profileDigest)throw blocked();
 return result;
}

async function child(){
 try{
  // FD 3 is fixture provisioning from its privately spawned parent, not a
  // permission scheme. Never use this bootstrap for an installed binary.
  const bootstrapRaw=await frame(createReadStream(null,{fd:3})),bootstrap=JSON.parse(bootstrapRaw);
  exact(bootstrap,['root','scope','broker']);
  if(stringify(bootstrap)!==bootstrapRaw)throw blocked();
  const s=boundScope(bootstrap.scope,bootstrap.root);
  const secret=bytes(bootstrap.broker,48,48);
  let key;
  try{key=createPrivateKey({key:secret,format:'der',type:'pkcs8'});}finally{secret.fill(0);}
  if(wire(createPublicKey(key).export({format:'der',type:'spki'}))!==s.brokerKey)throw blocked();
  const q=receiveRequest(await frame(process.stdin),s),state=emptyPilotBrokerReference(s.profileDigest);
  const outcome=transitionPilotBrokerReference(s.profileDigest,state,q.body);
  if(outcome.state!==state)throw blocked();
  process.stdout.write(pack(stringify(reply(s,q.requestId,q.body,outcome.response,key))));
 }catch{process.stderr.write(unestablished+'\n');process.exitCode=1;}
}

async function parent(){
 const root=generated(),client=generated(),broker=generated(true);
 const identity={version:1,abi,run:random(),profileDigest:random(),clientKey:client.pub,brokerKey:broker.pub};
 const scope=encodeSigned(scopeDomain,identity,root.key);
 const bootstrap={root:root.pub,scope,broker:broker.pkcs8};
 const body=canonicalPilotBrokerRequest({version:1,op:'inspect',profileDigest:identity.profileDigest}),requestId=random();
 const signed=request(identity,requestId,Buffer.from(body),client.key);
 async function exchange(message,provision=bootstrap,holdInput=false){
  const p=spawn(process.execPath,['--experimental-transform-types',fileURLToPath(import.meta.url),'--child'],
   {stdio:['pipe','pipe','pipe','pipe'],timeout:holdInput?500:8000,killSignal:'SIGKILL',env:{NODE_NO_WARNINGS:'1'}});
  const exited=new Promise((resolve,reject)=>{
   p.once('error',reject);
   p.once('close',(code,signal)=>resolve({code,signal}));
  });
  const stderr=new Array();let stderrBytes=0;
  const errors=(async()=>{
   for await(const chunk of p.stderr){
    stderrBytes+=chunk.length;
    if(stderrBytes>128){p.kill('SIGKILL');throw blocked();}
    stderr.push(chunk);
   }
   return Buffer.concat(stderr).toString();
  })();
  const writes=Promise.allSettled([pipeline(Readable.from([pack(stringify(provision))]),p.stdio[3]),holdInput?Promise.resolve():pipeline(Readable.from([message]),p.stdin)]);
  const [output,error,status,sent]=await Promise.all([frame(p.stdout).catch(()=>null),errors,exited,writes]);
  return {output,stderr:error,status,sent};
 }
 const result=await exchange(pack(stringify(signed)));
 assert.deepEqual(result.status,{code:0,signal:null});
 assert.ok(result.sent.every(x=>x.status==='fulfilled'));
 assert.deepEqual(receiveReply(result.output,identity,requestId,body),{version:1,kind:'empty',profileDigest:identity.profileDigest});
 assert.throws(()=>receiveReply(result.output,identity,random(),body));
 assert.throws(()=>receiveReply(result.output,identity,requestId,body+' '));
 const illegal=stringify({version:1,op:'activate',profileDigest:identity.profileDigest});
 const record={nonce:wire(Buffer.alloc(24)),ciphertext:wire(Buffer.alloc(24,17))};
 const deniedSeed=canonicalPilotBrokerRequest({version:1,op:'seed-pending',profileDigest:identity.profileDigest,record});
 const oversized=Buffer.alloc(limit+5,0x41);
 oversized.writeUInt32BE(limit+1,0);
 const cases=[
  [oversized],
  [pack(Buffer.from([0xc0,0xaf]))],
  [pack(stringify(signed)).subarray(0,-1)],
  [pack(stringify(request(identity,requestId,Buffer.from(illegal),client.key)))],
  [pack(stringify(request(identity,requestId,Buffer.from(deniedSeed),client.key)))],
  [pack(stringify(request(identity,requestId,Buffer.from([0xc0,0xaf]),client.key)))],
  [pack(stringify(request({...identity,profileDigest:random()},requestId,Buffer.from(body),client.key)))],
  [pack(stringify(request(identity,requestId,Buffer.from(body),root.key)))],
  [Buffer.concat([pack(stringify(signed)),pack(stringify(signed))])],
  [Buffer.from([0xff,0xff,0xff,0xff,0x00])],
  [pack(stringify(request({...identity,run:random()},requestId,Buffer.from(body),client.key)))],
  [pack(stringify(signed)),{...bootstrap,broker:generated(true).pkcs8}],
  [pack(stringify(signed)),{...bootstrap,scope:encodeSigned(scopeDomain,{...identity,abi:'foreign-abi'},root.key)}],
 ];
 for(const [message,init] of cases){
  const denied=await exchange(message,init);
  assert.deepEqual(denied.status,{code:1,signal:null});
  assert.equal(denied.output,null);assert.equal(denied.stderr,unestablished+'\n');
 }
 const timedOut=await exchange(Buffer.alloc(0),bootstrap,true);
 assert.deepEqual(timedOut.status,{code:null,signal:'SIGKILL'});
 assert.equal(timedOut.output,null);
 console.log('PASS two-process synthetic pipe: scoped Ed25519, exact reply, bounded UTF-8 and mutation denial');
}

if(process.argv.length===3&&process.argv[2]==='--child')await child();
else if(process.argv.length===2)await parent();
else throw blocked();
