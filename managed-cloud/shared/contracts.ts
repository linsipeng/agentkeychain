import { base64, exactFields, parseCanonicalOperation, type SignedManagedOperation } from '../../src/cloud/protocol.ts';
export const REQUEST_MAX = 384 * 1024;
export const PAYLOAD_MAX = 256 * 1024;
export const PAGE_MAX = 512 * 1024;
export type ErrorCode = 'invalid_request' | 'unauthorized' | 'not_found' | 'invalid_signature' | 'payload_too_large' | 'unsupported_media_type' | 'method_not_allowed' | 'idempotency_conflict' | 'invalid_transition' | 'approval_required' | 'replayed_request' | 'internal_error';
export const statuses: Record<ErrorCode, number> = { invalid_request: 400, unauthorized: 401, not_found: 404, invalid_signature: 401, payload_too_large: 413, unsupported_media_type: 415, method_not_allowed: 405, idempotency_conflict: 409, invalid_transition: 409, approval_required: 403, replayed_request: 409, internal_error: 500 };
export class ApiError extends Error {
    constructor(readonly code: ErrorCode) { super(code); }
}
export function errorResponse(error: unknown) { const code = error instanceof ApiError ? error.code : 'internal_error'; return Response.json({ error: { code } }, { status: statuses[code], headers: { 'cache-control': 'no-store' } }); }
export async function digest(text: string) { return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), v => v.toString(16).padStart(2, '0')).join(''); }
export function proofBytes(method: string, path: string, bodyDigest: string, nonce: string, sessionDigest: string) { return JSON.stringify([1, method, path, bodyDigest, nonce, sessionDigest]); }
export async function verify(publicKey: string, signature: string, message: string) {
    try {
        base64(publicKey, 32, 32);
        base64(signature, 64, 64);
        const bytes = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
        const key = await crypto.subtle.importKey('raw', bytes(publicKey), 'Ed25519', false, ['verify']);
        return await crypto.subtle.verify('Ed25519', key, bytes(signature), new TextEncoder().encode(message));
    }
    catch {
        return false;
    }
}
export function validateSigned(input: unknown): SignedManagedOperation {
    try {
        exactFields(input, ['canonical', 'signature']);
        if (typeof input.canonical !== 'string')
            throw new Error();
        if (new TextEncoder().encode(JSON.stringify(input)).byteLength > REQUEST_MAX)
            throw new ApiError('payload_too_large');
        const op = parseCanonicalOperation(input.canonical);
        base64(input.signature, 64, 64);
        if (op.envelope && atob(op.envelope.ciphertext).length + 24 > PAYLOAD_MAX)
            throw new ApiError('payload_too_large');
        return { canonical: input.canonical, signature: input.signature };
    }
    catch (error) {
        if (error instanceof ApiError)
            throw error;
        throw new ApiError('invalid_request');
    }
}
/** Hard byte cap applies to declared and streamed lengths, including chunked bodies. */
export async function boundedBody(request: Request): Promise<string> {
    const length = request.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length))))
        throw new ApiError('invalid_request');
    if (length !== null && Number(length) > REQUEST_MAX)
        throw new ApiError('payload_too_large');
    if (request.headers.has('content-encoding'))
        throw new ApiError('unsupported_media_type');
    const reader = request.body?.getReader();
    if (!reader)
        return '';
    let size = 0;
    const parts: Uint8Array[] = [];
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            size += value.byteLength;
            if (size > REQUEST_MAX) {
                await reader.cancel();
                throw new ApiError('payload_too_large');
            }
            parts.push(value);
        }
    }
    finally {
        reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) {
        bytes.set(part, offset);
        offset += part.length;
    }
    try {
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    }
    catch {
        throw new ApiError('invalid_request');
    }
}
/** Phase 2B placeholder only: no browser or account authentication implementation. */
export interface AccountPrincipal {
    readonly accountId: string;
    readonly authentication: 'passkey';
}
export interface RecoveryContract {
    describe(): Promise<{
        component: string;
        protocol: number;
        recoveryEnabled: boolean;
        bindings: string[];
    }>;
    fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}
/** Same domain-separated digest as the security-reviewed Slice 1 approval contract. */
export function approvalDigest(canonical: string) { return digest("AgentKeychain-approval-v1\0" + canonical); }
