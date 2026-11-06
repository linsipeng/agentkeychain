import {authorityEntrypoint,keysEntrypoint,signerEntrypoint,RecoveryTrustPolicyBase} from '../shared/trust-runtime.ts';
export class RecoveryAuthority extends authorityEntrypoint('custodian') {}
export class RecoveryKeys extends keysEntrypoint('custodian') {}
export class RosterWitnessSigner extends signerEntrypoint('custodian','witness') {}
export class RecoveryTrustSigner extends signerEntrypoint('custodian','trust') {}
export class RecoveryReleaseSigner extends signerEntrypoint('custodian','release') {}
export class RecoveryTrustPolicy extends RecoveryTrustPolicyBase {}
export default {fetch(){return new Response(null,{status:404});}};
