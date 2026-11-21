/** Opt-in fixture only. The protected half is a pure expected vector, not a
 * native protected-slot observation, an activation or a CAS authorization. */
import {createHash} from 'node:crypto';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {expect,test} from 'bun:test';
import {canonicalPilotActivationDbReceipt,canonicalPilotActivationPreparedSlot,planPilotActivationSlotSuccessor,
 type PilotActivationBasis} from '../../src/cloud/continuation-pilot-activation-receipt.ts';

const sha=(v:string)=>createHash('sha256').update(v).digest('hex');

test('true SQLite commit and crash/reopen preserve the exact planner DB receipt',async()=>{
 const sqlite=process.env.AKC_SQLITE_FIXTURE_DIR;
 if(!sqlite||process.platform!=='linux')throw Error('pinned Linux SQLite fixture directory required');
 const dir=await mkdtemp('/tmp/akc-activation-db-rehearsal-');
 try{
  // Exact synthetic projection already known to the pinned C rollback fixture.
  const operation='0bc11b4b3ede7bd0008a5cb7ab18e51eef45d1039f76edc64fc731675b11cfd6';
  const frame='{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH"}';
  const basis:PilotActivationBasis={version:1,profileDigest:'1'.repeat(64),stageDigest:'2'.repeat(64),
   commitDigest:sha(JSON.stringify(['AgentKeychain-local-activation-fixture-projection-v1',2,operation,frame])),slotDigest:'4'.repeat(64)};
  const attempt='5'.repeat(64),expected=canonicalPilotActivationDbReceipt(basis,attempt);
  const pending=canonicalPilotActivationPreparedSlot(basis,attempt),predecessor=sha(pending);
  const header=join(dir,'activation-receipt.h'),binary=join(dir,'rehearsal');
  await writeFile(header,'#define ACTIVATION_DB_RECEIPT '+JSON.stringify(expected)+'\n',{flag:'wx',mode:0o600});
  const compile=Bun.spawnSync(['cc','-std=c11','-Wall','-Wextra','-Werror','-pedantic','-DAKC_DB_ACTIVATION_REHEARSAL=1',
   '-I',sqlite,'-include',header,'tests/native/pilot_sqlite_broker_receipt.c',join(sqlite,'sqlite3.o'),
   '-lm','-lpthread','-ldl','-o',binary],{timeout:12000});
  expect(compile.exitCode,compile.stderr.toString()).toBe(0);
  await rm(header);
  const run=Bun.spawnSync([binary],{env:{},timeout:15000});
  expect(run.exitCode,run.stderr.toString()).toBe(0);
  expect(run.stdout.toString()).toBe(expected+'\n');
  const observed=run.stdout.toString().slice(0,-1);
  const proposed=planPilotActivationSlotSuccessor(basis,attempt,predecessor,observed,pending);
  expect(proposed.kind).toBe('compare-and-record');
  expect(proposed.databaseReceiptDigest).toBe(sha(expected));
  expect(()=>planPilotActivationSlotSuccessor(basis,attempt,predecessor,null,pending)).toThrow('cloud_pilot_activation_receipt_denied');
  expect(()=>planPilotActivationSlotSuccessor(basis,attempt,predecessor,observed.replace(basis.commitDigest,'0'.repeat(64)),pending))
   .toThrow('cloud_pilot_activation_receipt_denied');
 }finally{await rm(dir,{force:true,recursive:true});}
},35000);
