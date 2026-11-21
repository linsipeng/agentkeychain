import {expect,test} from 'bun:test';
import {canonicalPilotBrokerRequest,parsePilotBrokerRequest,pilotBrokerOperationDigest} from '../src/cloud/pilot-broker-wire.ts';

const profileDigest='1'.repeat(64),previousDigest='2'.repeat(64),record={nonce:Buffer.alloc(24).toString('base64url'),ciphertext:Buffer.alloc(24,5).toString('base64url')};
const advance={version:1,op:'advance',profileDigest,previousDigest,previousGeneration:3,step:'approval-recorded',record} as const;

test('pilot broker wire binds exact step, previous generation and opaque record to recovery digest',()=>{
 const bytes=canonicalPilotBrokerRequest(advance),operationDigest=pilotBrokerOperationDigest(bytes);
 expect(parsePilotBrokerRequest(bytes)).toEqual(advance);
 expect(pilotBrokerOperationDigest(bytes)).toBe(operationDigest);
 expect(pilotBrokerOperationDigest(canonicalPilotBrokerRequest({...advance,previousDigest:'3'.repeat(64)}))).not.toBe(operationDigest);
 expect(parsePilotBrokerRequest(canonicalPilotBrokerRequest({version:1,op:'recover',profileDigest,operationDigest})))
  .toEqual({version:1,op:'recover',profileDigest,operationDigest});
});

test('pilot broker wire denies noncanonical bytes, skipped stages and ambient or activation scope',()=>{
 for(const bad of [{...advance,op:'activate'},{...advance,op:'exec',sql:'SELECT 1'},
  {...advance,path:'/tmp/pilot'},{...advance,slot:'csk'},{...advance,secret:'anything'},
  {...advance,previousGeneration:1},{...advance,step:'pending'},
  {...advance,record:{...record,extra:'field'}},{...advance,record:{...record,nonce:record.nonce+'='}},
  {...advance,record:{...record,ciphertext:Buffer.alloc(65537).toString('base64url')}}])
  expect(()=>canonicalPilotBrokerRequest(bad)).toThrow();
 const bytes=canonicalPilotBrokerRequest(advance);
 expect(()=>parsePilotBrokerRequest(bytes+' ')).toThrow('pilot_broker_request_denied');
 expect(()=>parsePilotBrokerRequest(bytes.replace('"version":1','"version":1,"version":1'))).toThrow('pilot_broker_request_denied');
 expect(()=>pilotBrokerOperationDigest(canonicalPilotBrokerRequest({version:1,op:'inspect',profileDigest}))).toThrow('pilot_broker_request_denied');
});

import {canonicalPilotBrokerResponse,emptyPilotBrokerReference,parsePilotBrokerResponse,transitionPilotBrokerReference,type PilotBrokerReferenceState}
 from '../src/cloud/pilot-broker-wire.ts';
const wire=(value:object)=>canonicalPilotBrokerRequest(value);
const seed=wire({version:1,op:'seed-pending',profileDigest,record});
const inspect=wire({version:1,op:'inspect',profileDigest});
const tx=(state:PilotBrokerReferenceState,bytes:string)=>transitionPilotBrokerReference(profileDigest,state,bytes);
const moved=(step:string,generation:number,previous:string,chosen=record)=>wire({version:1,op:'advance',profileDigest,
 previousDigest:previous,previousGeneration:generation,step,record:chosen});

test('all six immutable phases advance once and retained replay precedes stale CAS',()=>{
 const empty=emptyPilotBrokerReference(profileDigest);
 expect(parsePilotBrokerResponse(tx(empty,inspect).response)).toEqual({version:1,kind:'empty',profileDigest});
 const first=tx(empty,seed);
 expect(pilotBrokerOperationDigest(seed)).toBe('0437e784aa6a0e820eac661a91829a727c38c19bed567e6b7a27c36b2703fda8');
 expect(parsePilotBrokerResponse(first.response)).toMatchObject({previousDigest:null,kind:'receipt',
  recordDigest:'17fd1754d3466313ac81f39f2cc129eecbb3966d5f3b78bc6ec851568d4f9e45'});

 let state=first.state;
 const history=[{request:seed,response:first.response}];
 const later=['handoff-recorded','handoff-published','approval-recorded','preflight-recorded','owner-proof-recorded'];
 for(const step of later){
  const previous=state.receipts.at(-1)!;
  const request=moved(step,previous.generation,previous.operationDigest);
  const next=tx(state,request);state=next.state;history.push({request,response:next.response});
 }
 for(const {request,response} of history){
  expect(tx(state,request)).toEqual({state,response});
  const recover=wire({version:1,op:'recover',profileDigest,operationDigest:pilotBrokerOperationDigest(request)});
  const readback=tx(state,recover);
  expect(readback.state).toBe(state);expect(readback.response).toBe(response);
 }
 expect(parsePilotBrokerResponse(tx(state,inspect).response)).toMatchObject({kind:'snapshot',receipt:{generation:6,step:'owner-proof-recorded'}});
 expect(()=>tx(state,JSON.stringify({version:1,op:'activate',profileDigest}))).toThrow();
});

test('competing and contradictory receipts, stale CAS, wrong profile or altered snapshot deny',()=>{
 const first=tx(emptyPilotBrokerReference(profileDigest),seed);
 const original=moved('handoff-recorded',1,first.state.receipts[0]!.operationDigest);
 const second=tx(first.state,original);
 const alternative={...record,ciphertext:Buffer.alloc(24,9).toString('base64url')};
 const loser=moved('handoff-recorded',1,first.state.receipts[0]!.operationDigest,alternative);
 expect(()=>tx(second.state,loser)).toThrow();
 expect(()=>tx(second.state,moved('handoff-published',2,'4'.repeat(64)))).toThrow();
 expect(()=>transitionPilotBrokerReference('f'.repeat(64),second.state,inspect)).toThrow();
 expect(()=>tx(second.state,wire({version:1,op:'recover',profileDigest,operationDigest:'8'.repeat(64)}))).toThrow();
 const badReceipt={...second.state.receipts[1]!,operationDigest:second.state.receipts[0]!.operationDigest};
 expect(()=>tx({...second.state,receipts:[second.state.receipts[0]!,badReceipt]},seed)).toThrow();
 const [,tail]=second.state.receipts;
 const contradicted={...second.state,receipts:[second.state.receipts[0]!,{...tail!,recordDigest:'a'.repeat(64)}]};
 expect(()=>tx(contradicted,original)).toThrow();
 const alteredOld={...second.state,receipts:[{...first.state.receipts[0]!,recordDigest:'b'.repeat(64)},tail!]};
 expect(()=>tx(alteredOld,seed)).toThrow();
 expect(()=>parsePilotBrokerResponse(second.response+' ')).toThrow();

 const snapshot=parsePilotBrokerResponse(tx(second.state,inspect).response);
 expect(()=>canonicalPilotBrokerResponse({...snapshot,record:alternative})).toThrow();
});
