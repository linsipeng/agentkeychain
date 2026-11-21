import {parseRoster} from '../shared/roster.ts';
import {verify} from '../shared/contracts.ts';
import { recoveryKeyring } from '../shared/recovery-keyring.ts';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { encode64, type SealedShare } from '../shared/recovery-crypto.ts';
import { digest } from '../shared/contracts.ts';
import { recoveryAuthority,recoveryAccountAttester } from '../shared/recovery-authorization.ts';
import type { CancelAuthorization, RecoveryEvidence } from '../shared/recovery.ts';
const realNow=Date.now;
const accountPair=crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as Promise<CryptoKeyPair>;
const pair = crypto.subtle.generateKey('X25519', true, ['deriveBits']) as Promise<CryptoKeyPair>;
const revocations=new Set<string>();
const devices = new Map<string, string>();
const verifiers = new Map<string, string>();
const authority = recoveryAuthority({ device: async (a, t, v, d) => devices.get(JSON.stringify([a, t, v, d])) ?? null, accountVerifier: async (a) => verifiers.get(a) ?? null });
/** Only compiled into test harnesses, never API/Custodian production bundles. */
export class RecoveryTestService extends WorkerEntrypoint {
    override async fetch() { return new Response(null, { status: 404 }); }
    async allowRevocation(canonical:string){revocations.add(canonical);}
    async rosterRevocation(canonical:string){return revocations.has(canonical);}
    async key() { const publicKey = encode64(new Uint8Array(await crypto.subtle.exportKey('raw', (await pair).publicKey))); return { keyId: await digest(publicKey), publicKey }; }
    async rewrap(keyId: string, box: SealedShare, source: string, target: string, context: string) { const key = await this.key(); return (await recoveryKeyring(new Map([[key.keyId, await pair]]), key.keyId)).rewrap(keyId, box, source, target, context); }
    async trust(a: string, t: string, v: string, d: string, key: string | null) {
        const id = JSON.stringify([a, t, v, d]);
        if (key)
            devices.set(id, key);
        else
            devices.delete(id);
    }
    async verifier(a: string, key: string) { verifiers.set(a, key); }
    async clock(offset:number){Date.now=()=>realNow()+offset;}
    async accountKey(){return {keyId:'synthetic-account',publicKey:encode64(new Uint8Array(await crypto.subtle.exportKey('raw',(await accountPair).publicKey)))};}
    async attest(canonical:string){return recoveryAccountAttester({key:()=>this.accountKey(),sign:async m=>encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',(await accountPair).privateKey,new TextEncoder().encode(m))))},{accountVerifier:async a=>verifiers.get(a)??null}).attest(canonical);}
    async cancel(c: string, a: CancelAuthorization) { return authority.cancel(c, a); }
    async complete(c: string, p: string, s: string) { return authority.complete(c, p, s); }
    async enrollment(c: string, s: string) { return authority.enrollment(c, s); }
    async authorize(c: string, e: RecoveryEvidence) { return authority.authorize(c, e); }
}
/** Mirrors the dedicated production RPC surface; only the test harness may seed trust. */
export class RosterGenesisAuthority extends WorkerEntrypoint {
    override async fetch() { return new Response(null, { status: 404 }); }
    async rosterGenesis(s:import('../../src/cloud/protocol.ts').SignedManagedOperation){const r=parseRoster(s),key=devices.get(JSON.stringify([r.accountId,r.tenantId,r.vaultId,r.issuer.id]));return !!key&&await verify(key,s.signature,'AgentKeychain-trusted-roster-v1\0'+s.canonical);}
}
export default RecoveryTestService;
export class RecoveryAuthority extends RecoveryTestService {
}
export class RecoveryKeys extends RecoveryTestService {
}

const releasePair=crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as Promise<CryptoKeyPair>;
export class RecoveryReleaseSigner extends WorkerEntrypoint {
 override async fetch(){return new Response(null,{status:404});}
 async key(){const publicKey=encode64(new Uint8Array(await crypto.subtle.exportKey('raw',(await releasePair).publicKey)));return {keyId:await digest(publicKey),publicKey};}
 async sign(message:string){return encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',(await releasePair).privateKey,new TextEncoder().encode(message))));}
}
const trustPair=crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as Promise<CryptoKeyPair>;
let trustManifest='';
export class RecoveryTrustSigner extends WorkerEntrypoint {
 override async fetch(){return new Response(null,{status:404});}
 async key(){const publicKey=encode64(new Uint8Array(await crypto.subtle.exportKey('raw',(await trustPair).publicKey)));return {keyId:await digest(publicKey),publicKey};}
 async sign(message:string){return encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',(await trustPair).privateKey,new TextEncoder().encode(message))));}
 async manifest(){if(!trustManifest)throw new Error('unprovisioned');return trustManifest;}
 async configure(canonical:string){trustManifest=canonical;}
}

const witnessPair=crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as Promise<CryptoKeyPair>;
export class RosterWitnessSigner extends WorkerEntrypoint {
 override async fetch(){return new Response(null,{status:404});}
 async key(){const publicKey=encode64(new Uint8Array(await crypto.subtle.exportKey('raw',(await witnessPair).publicKey)));return {keyId:await digest(publicKey),publicKey};}
 async sign(message:string){return encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',(await witnessPair).privateKey,new TextEncoder().encode(message))));}
}
