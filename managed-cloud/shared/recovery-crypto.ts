import { base64, exactFields } from '../../src/cloud/protocol.ts';
export const encode64 = (v: Uint8Array) => btoa(String.fromCharCode(...v));
export const decode64 = (v: string) => Uint8Array.from(atob(v), c => c.charCodeAt(0));
const utf8 = new TextEncoder();
export interface SealedShare {
    version: 1;
    ephemeralKey: string;
    nonce: string;
    ciphertext: string;
}
export function splitRecoveryKey(key: Uint8Array): [
    Uint8Array,
    Uint8Array
] {
    if (key.length !== 32)
        throw new Error('invalid_key_length');
    const first = crypto.getRandomValues(new Uint8Array(32));
    return [first, Uint8Array.from(key, (v, i) => v ^ first[i]!)];
}
export function joinRecoveryKey(a: Uint8Array, b: Uint8Array) {
    if (a.length !== 32 || b.length !== 32)
        throw new Error('invalid_share_length');
    return Uint8Array.from(a, (v, i) => v ^ b[i]!);
}
async function derived(privateKey: CryptoKey, publicKey: string, context: string) {
    base64(publicKey, 32, 32);
    const peer = await crypto.subtle.importKey('raw', decode64(publicKey), 'X25519', false, []);
    const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, 256);
    const material = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: await crypto.subtle.digest('SHA-256', utf8.encode(context)), info: utf8.encode('AgentKeychain-recovery-wrap-v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function seal(publicKey: string, plaintext: Uint8Array, context: string): Promise<SealedShare> {
    const pair = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const key = await derived(pair.privateKey, publicKey, context);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: utf8.encode(context) }, key, Uint8Array.from(plaintext));
    return { version: 1, ephemeralKey: encode64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))), nonce: encode64(nonce), ciphertext: encode64(new Uint8Array(ciphertext)) };
}
export async function open(privateKey: CryptoKey, box: SealedShare, context: string) {
    exactFields(box, ['version', 'ephemeralKey', 'nonce', 'ciphertext']);
    if (box.version !== 1)
        throw new Error('invalid_share');
    base64(box.nonce, 12, 12);
    base64(box.ciphertext, 16);
    if (box.ciphertext.length > 8192)
        throw new Error('invalid_share');
    const key = await derived(privateKey, box.ephemeralKey, context);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode64(box.nonce), additionalData: utf8.encode(context) }, key, decode64(box.ciphertext)));
}
/** Client-only VDK envelope: 12-byte random nonce followed by AES-GCM ciphertext.
 * Neither service invokes these helpers or receives a reconstructed key. */
export async function wrapVaultKey(recoveryKey: Uint8Array, vdk: Uint8Array, context: string) {
    if (recoveryKey.length !== 32 || vdk.length !== 32)
        throw new Error('invalid_key_length');
    const key = await crypto.subtle.importKey('raw', Uint8Array.from(recoveryKey), 'AES-GCM', false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: utf8.encode(context) }, key, Uint8Array.from(vdk)));
    return encode64(new Uint8Array([...nonce, ...ciphertext]));
}
export async function unwrapVaultKey(recoveryKey: Uint8Array, envelope: string, context: string) {
    if (recoveryKey.length !== 32)
        throw new Error('invalid_key_length');
    base64(envelope, 60, 60);
    const bytes = decode64(envelope), key = await crypto.subtle.importKey('raw', Uint8Array.from(recoveryKey), 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: utf8.encode(context) }, key, bytes.slice(12)));
}
