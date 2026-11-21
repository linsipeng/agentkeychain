import {WorkerEntrypoint} from 'cloudflare:workers';
import {base64,exactFields} from '../../src/cloud/protocol.ts';
import type {ReleaseTrustManifest} from '../../src/cloud/config.ts';
import type {CheckpointKey,CheckpointSigner} from '../shared/checkpoints.ts';
import {digest} from '../shared/contracts.ts';
import {admitGenesis,type GenesisAdmissionRequest} from '../shared/genesis-admission.ts';

const mode='independent-v1';
export interface GenesisAdmissionEnv {
 CUSTODIAN:D1Database;
 ROSTER_WITNESS_SIGNER?:CheckpointSigner;
 RECOVERY_TRUST_POLICY?:{manifest():Promise<string>};
 /** Provision both on Custody, never on the main API graph. */
 GENESIS_ADMISSION_MODE?:string;
 GENESIS_APPROVAL_PIN?:string;
}

/** Transitional compatibility only. Incomplete or invalid independent
 * configuration cannot reactivate the old unwitnessed genesis path. */
export function legacyGenesisEnabled(env:GenesisAdmissionEnv):boolean{
 return env.GENESIS_ADMISSION_MODE===undefined&&env.GENESIS_APPROVAL_PIN===undefined;
}

async function approvalPin(raw:string|undefined):Promise<CheckpointKey>{
 if(typeof raw!=='string'||!raw||raw.length>256)throw new Error('unavailable');
 const value:unknown=JSON.parse(raw);
 exactFields(value,['keyId','publicKey']);
 const {keyId,publicKey}=value;
 base64(publicKey,32,32);
 if(keyId!==await digest(publicKey))throw new Error('unavailable');
 return {keyId,publicKey};
}

/** Privately bound, single-purpose service. It never accepts a caller-provided
 * policy, enrollment-success flag or verifier. Do not expose through HTTP. */
export class GenesisAdmission extends WorkerEntrypoint<GenesisAdmissionEnv>{
 override async fetch(){return new Response(null,{status:404});}

 async admit(value:GenesisAdmissionRequest){
  const env=this.env;
  if(env.GENESIS_ADMISSION_MODE!==mode||!env.ROSTER_WITNESS_SIGNER||!env.RECOVERY_TRUST_POLICY)throw new Error('genesis_admission_unavailable');
  let authority:CheckpointKey,policy:Required<ReleaseTrustManifest>,witness:CheckpointKey;
  try{
   authority=await approvalPin(env.GENESIS_APPROVAL_PIN);
   policy=JSON.parse(await env.RECOVERY_TRUST_POLICY.manifest()) as Required<ReleaseTrustManifest>;
   witness=await env.ROSTER_WITNESS_SIGNER.key();
   if(!policy.witnessKeys.some(p=>p.keyId===witness.keyId&&p.publicKey===witness.publicKey)||
      [...policy.checkpointKeys,...policy.witnessKeys,...policy.recoveryAuthorities,policy.recoveryServices.api,policy.recoveryServices.custodian].some(p=>p.publicKey===authority.publicKey))throw new Error('unavailable');
  }catch{throw new Error('genesis_admission_unavailable');}
  try{
   exactFields(value,['proof','grant','roster','checkpoint']);
   return await admitGenesis(env.CUSTODIAN,value,{authority,checkpointKeys:policy.checkpointKeys,recoveryAuthorities:policy.recoveryAuthorities},{...witness,signer:env.ROSTER_WITNESS_SIGNER});
  }catch{throw new Error('genesis_admission_rejected');}
 }
}
