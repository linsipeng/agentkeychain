import { expect } from 'vitest';
import { deviceFetch } from '../api-worker/device-http.ts';
import { encode64, open, type SealedShare } from '../shared/recovery-crypto.ts';
import { random } from '../api-worker/webauthn.ts';
import { env } from 'cloudflare:workers';
export async function signedRecoveryTarget() {
    const signing = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    const wrapping = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    const target = { id: random(), packageId: random(), targetDeviceId: random(), signingKey: encode64(new Uint8Array(await crypto.subtle.exportKey('raw', signing.publicKey))), wrappingKey: encode64(new Uint8Array(await crypto.subtle.exportKey('raw', wrapping.publicKey))), nonce: random() };
    const call = (route: string, body: unknown) => deviceFetch(new Request('https://local.invalid/v1/devices/' + route, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}), {...env, AUTH_ORIGIN:'https://local.invalid',TRUSTED_AUTH_SOURCE:{resolve:async()=> 'synthetic-target'}});
    const signature = encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',signing.privateKey,new TextEncoder().encode(JSON.stringify(['AgentKeychain-recovery-target-v1',target])))));
    const challenge = await call('recovery-target-challenge',{target,signature});
    expect(challenge.status).toBe(200);
    const {challengeRef,box} = await challenge.json() as {challengeRef:string;box:SealedShare};
    const proof = encode64(await open(wrapping.privateKey,box,'AgentKeychain-recovery-target-possession-v1\0'+challengeRef+'\0'+JSON.stringify(target)));
    const response = await call('recovery-target',{target,signature,challengeRef,proof});
    expect(response.status).toBe(200);
    return {target,...await response.json() as {requestRef:string}};
}
