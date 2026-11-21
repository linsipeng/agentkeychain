import {createHash} from 'node:crypto';
import {expect,test} from 'bun:test';
import {canonicalPilotActivationDbReceipt,canonicalPilotActivationPreparedSlot,planPilotActivationSlotSuccessor,
 type PilotActivationBasis} from '../src/cloud/continuation-pilot-activation-receipt.ts';

const h=(x:string)=>x.repeat(64);
const sha=(x:string)=>createHash('sha256').update(x).digest('hex');
const basis:PilotActivationBasis={version:1,profileDigest:h('1'),stageDigest:h('2'),commitDigest:h('3'),slotDigest:h('4')};
const attempt=h('5'),db=canonicalPilotActivationDbReceipt(basis,attempt),pending=canonicalPilotActivationPreparedSlot(basis,attempt);
const previous=sha(pending);
const plan=(a:unknown,b:unknown,d=previous)=>planPilotActivationSlotSuccessor(basis,attempt,d,a,b);
const error='cloud_pilot_activation_receipt_denied';

test('only exact commit plus exact pending slot produces a successor; retry after write is idempotent',()=>{
 const next=plan(db,pending);
 expect(previous).toBe('83379c4bad7cc9bc2c64d825e95bbc64900d4e9d8104382ef903b72f211fa5f5');
 expect(sha(db)).toBe('e21ee45e7e35dfc513f8ee89b97b34df0927da78cc2be69274fc51768855e4db');
 expect(sha(next.finalizedCanonical)).toBe('9c46ca31e390700826c31192b4199f291395ab21bb875cbeeeea3bad83432689');
 expect(next).toEqual({kind:'compare-and-record',expectedPreviousDigest:previous,
  databaseReceiptDigest:sha(db),finalizedCanonical:JSON.stringify({...JSON.parse(pending),phase:'finalized',
   previousDigest:previous,databaseReceiptDigest:sha(db)})});
 expect(plan(db,next.finalizedCanonical)).toEqual({...next,kind:'already-recorded'});
 expect(plan(db,pending)).toEqual(next);
 expect(()=>plan(undefined,pending)).toThrow(error);
 expect(()=>plan(db,undefined)).toThrow(error);
 expect(()=>plan(undefined,next.finalizedCanonical)).toThrow(error);
 expect(()=>plan(db,next.finalizedCanonical,h('9'))).toThrow(error);
});

test('both copies must independently match exactly the expected scope and operation',()=>{
 for(const f of ['profileDigest','stageDigest','commitDigest','slotDigest'] as const){
  const other={...basis,[f]:h('9')};
  const otherDb=canonicalPilotActivationDbReceipt(other,attempt),otherSlot=canonicalPilotActivationPreparedSlot(other,attempt);
  expect(()=>plan(otherDb,pending)).toThrow(error);
  expect(()=>plan(db,otherSlot)).toThrow(error);
  expect(()=>plan(otherDb,otherSlot,sha(otherSlot))).toThrow(error);
 }
 expect(()=>plan(canonicalPilotActivationDbReceipt(basis,h('9')),pending)).toThrow(error);
 expect(()=>plan(db,canonicalPilotActivationPreparedSlot(basis,h('9')))).toThrow(error);
 expect(()=>plan(db,pending,h('9'))).toThrow(error);
});

test('never repairs contradictory history, malformed bytes or a slot without exact previous and DB digests',()=>{
 const finalized=plan(db,pending).finalizedCanonical;
 for(const raw of [' '+finalized,finalized.replace('"version":1,','"version":1,"version":1,'),
  finalized.replace(previous,h('a')),finalized.replace(sha(db),h('b')),JSON.stringify({...JSON.parse(finalized),active:true}),
  JSON.parse(finalized),false,null,'x'.repeat(2049)])expect(()=>plan(db,raw)).toThrow(error);
 expect(()=>plan(db+' ',pending)).toThrow(error);
 expect(()=>canonicalPilotActivationPreparedSlot({...basis,stageDigest:h('b')+'\n'},attempt)).toThrow(error);
});
