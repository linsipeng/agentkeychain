/** Synthetic WebAuthn wire producer. Private keys are generated per test in
 * memory only. All CBOR encoding uses the pinned package's encoder; verification
 * always executes the unmocked production SimpleWebAuthn adapter. */
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/server';
import { encode, decode, random } from '../api-worker/webauthn.ts';
const bytes = (value: string) => new TextEncoder().encode(value);
const hash = async (value: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest('SHA-256', value));
const concat = (...parts: Uint8Array[]) => { const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let offset = 0; for (const p of parts) {
    result.set(p, offset);
    offset += p.length;
} return result; };
export interface VectorOptions {
    origin?: string;
    rpId?: string;
    uv?: boolean;
    up?: boolean;
    topOrigin?: string;
    attestationFormat?: string;
    counter?: number;
    type?: string;
    crossOrigin?: boolean;
    badSignature?: boolean;
    userHandle?: string;
}
export async function virtualAuthenticator(algorithm: 'Ed25519' | 'ES256' = 'Ed25519') {
    const keys = await (algorithm === 'Ed25519' ? crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) : crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
    const id = random();
    async function data(challenge: string, registration: boolean, options: VectorOptions) {
        const client = bytes(JSON.stringify({ type: options.type ?? (registration ? 'webauthn.create' : 'webauthn.get'), challenge, origin: options.origin ?? 'https://local.invalid', crossOrigin: options.crossOrigin ?? false, ...(options.topOrigin ? { topOrigin: options.topOrigin } : {}) }));
        const count = new Uint8Array(4);
        new DataView(count.buffer).setUint32(0, options.counter ?? 0);
        const auth = concat(await hash(bytes(options.rpId ?? 'local.invalid')), new Uint8Array([(registration ? 64 : 0) | (options.up === false ? 0 : 1) | (options.uv === false ? 0 : 4)]), count);
        return { client, auth };
    }
    return {
        id,
        async register(challenge: string, options: VectorOptions = {}): Promise<RegistrationResponseJSON> {
            const { client, auth } = await data(challenge, true, options), credential = decode(id);
            const cose = isoCBOR.encode(new Map<number, number | Uint8Array>(algorithm === 'Ed25519' ? [[1, 1], [3, -8], [-1, 6], [-2, publicKey]] : [[1, 2], [3, -7], [-1, 1], [-2, publicKey.slice(1, 33)], [-3, publicKey.slice(33)]]));
            const length = new Uint8Array(2);
            new DataView(length.buffer).setUint16(0, credential.length);
            const authData = concat(auth, new Uint8Array(16), length, credential, cose);
            const attestation = isoCBOR.encode(new Map<string, string | Uint8Array | Map<string, string>>([['fmt', options.attestationFormat ?? 'none'], ['authData', authData], ['attStmt', new Map()]]));
            return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: encode(client), attestationObject: encode(attestation), transports: ['internal'] } };
        },
        async assert(challenge: string, options: VectorOptions = {}): Promise<AuthenticationResponseJSON> {
            const { client, auth } = await data(challenge, false, options);
            let signature = new Uint8Array(await crypto.subtle.sign(algorithm === 'Ed25519' ? 'Ed25519' : { name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, concat(auth, await hash(client))));
            if (algorithm === 'ES256') {
                // Synthetic authenticator encodes WebCrypto P1363 as ASN.1 DER.
                // This is test wire generation, never signature verification.
                const integer = (value: Uint8Array) => { let start = 0; while (start < value.length - 1 && value[start] === 0)
                    start++; let v = value.slice(start); if (v[0]! >= 128)
                    v = concat(new Uint8Array([0]), v); return concat(new Uint8Array([2, v.length]), v); };
                const pair = concat(integer(signature.slice(0, 32)), integer(signature.slice(32)));
                signature = concat(new Uint8Array([48, pair.length]), pair);
            }
            if (options.badSignature)
                signature[0] = signature[0]! ^ 1;
            return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: encode(client), authenticatorData: encode(auth), signature: encode(signature), ...(options.userHandle ? { userHandle: options.userHandle } : {}) } };
        },
    };
}
