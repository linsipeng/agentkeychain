import {authorityEntrypoint,keysEntrypoint,signerEntrypoint,AccountAttesterBase,RosterGenesisAuthorityBase} from '../shared/trust-runtime.ts';
export class CheckpointSigner extends signerEntrypoint('api','checkpoint') {}
export class RecoveryAuthority extends authorityEntrypoint('api') {}
export class RosterGenesisAuthority extends RosterGenesisAuthorityBase {}
export class RecoveryKeys extends keysEntrypoint('api') {}
export class RecoveryReleaseSigner extends signerEntrypoint('api','release') {}
export class AccountAttester extends AccountAttesterBase {}
export default {fetch(){return new Response(null,{status:404});}};
