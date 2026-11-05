import { ApiError, boundedBody, digest, errorResponse, verify } from '../shared/contracts.ts';
import { base64, exactFields, identifier } from '../../src/cloud/protocol.ts';
import { challengeProof, enrollmentProof } from '../shared/device-protocol.ts';
import { deviceRepository } from './device-repository.ts';
import { browserRepository, type SessionRow } from './browser-repository.ts';
import { random } from './webauthn.ts';
import { authenticate } from './auth.ts';
import type { BrowserBindings } from './browser-bindings.ts';
import { unavailable } from './browser-auth.ts';
export async function browserDevice(db: D1Database, s: SessionRow, route: string, b: Record<string, unknown>) {
    const repo = deviceRepository(db);
    if (route === 'devices/pending') {
        exactFields(b, ['verificationCode', 'issuerDeviceId']);
        if (typeof b.verificationCode !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(b.verificationCode))
            throw new ApiError('invalid_request');
        if (b.issuerDeviceId !== null)
            identifier(b.issuerDeviceId);
        return repo.pending(s, await digest(b.verificationCode), b.issuerDeviceId as string | null);
    }
    if (route === 'devices/list') {
        exactFields(b, []);
        return repo.list(s);
    }
    if (route === 'devices/approve') {
        exactFields(b, ['canonical', 'signature', 'confirmed']);
        if (b.confirmed !== true || typeof b.canonical !== 'string' || b.canonical.length > 4096 || (b.signature !== null && typeof b.signature !== 'string'))
            throw new ApiError('invalid_request');
        return repo.approve(s, b.canonical, b.signature as string | null);
    }
    const target = route === 'devices/deny' ? 'requestId' : 'deviceId';
    exactFields(b, [target, 'confirmed']);
    identifier(b[target]);
    if (b.confirmed !== true)
        throw new ApiError('approval_required');
    if (route === 'devices/deny')
        return repo.deny(s, b.requestId as string);
    if (route === 'devices/revoke')
        return repo.revoke(s, b.deviceId as string);
    throw new ApiError('not_found');
}
export async function deviceFetch(request: Request, env: BrowserBindings) {
    const repo = deviceRepository(env.MAIN);
    let auditFailure = false;
    try {
        const url = new URL(request.url), route = url.pathname.slice('/v1/devices/'.length);
        if (!['authorize', 'status', 'challenge', 'token', 'enroll', 'key-packages'].includes(route))
            throw new ApiError('not_found');
        if (url.search)
            throw new ApiError('invalid_request');
        if (request.method !== (route === 'key-packages' ? 'GET' : 'POST'))
            throw new ApiError('method_not_allowed');
        if (request.headers.has('cookie'))
            throw new ApiError('unauthorized');
        const raw = await boundedBody(request, 8192);
        if (new TextEncoder().encode(raw).length > 8192)
            throw new ApiError('payload_too_large');
        if (request.method === 'POST' && !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') ?? ''))
            throw new ApiError('unsupported_media_type');
        if (!env.AUTH_ORIGIN || !env.TRUSTED_AUTH_SOURCE)
            return unavailable();
        let configuredOrigin: URL;
        try { configuredOrigin = new URL(env.AUTH_ORIGIN); }
        catch { return unavailable(); }
        if (configuredOrigin.origin !== env.AUTH_ORIGIN || configuredOrigin.protocol !== 'https:' || url.origin !== configuredOrigin.origin)
            return unavailable();
        let sources: string[];
        try { sources = await Promise.all([env.TRUSTED_AUTH_SOURCE.resolve(request.clone() as Request), env.TRUSTED_AUTH_SOURCE.resolve(request.clone() as Request)]); }
        catch { return unavailable(); }
        if (!sources[0] || sources[0] !== sources[1] || !/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(sources[0]))
            return unavailable();
        if (!await browserRepository(env.MAIN).rate('source', await digest('device-source\0' + sources[0]), 120))
            return Response.json({ error: { code: 'rate_limited' } }, { status: 429, headers: { 'cache-control': 'no-store' } });
        auditFailure = true;
        await repo.cleanup();
        let b: Record<string, unknown>;
        try { b = raw ? JSON.parse(raw) as Record<string, unknown> : {}; }
        catch { throw new ApiError('invalid_request'); }
        if (!b || typeof b !== 'object' || Array.isArray(b))
            throw new ApiError('invalid_request');
        let result: unknown;
        if (route === 'authorize') {
            exactFields(b, ['signingKey', 'wrappingKey', 'platform', 'proof']);
            base64(b.signingKey, 32, 32);
            base64(b.wrappingKey, 32, 32);
            base64(b.proof, 64, 64);
            if (b.signingKey === b.wrappingKey || !['macos', 'linux', 'windows', 'other'].includes(b.platform as string))
                throw new ApiError('invalid_request');
            if (!await verify(b.signingKey, b.proof, enrollmentProof(b.signingKey, b.wrappingKey, b.platform as string)))
                throw new ApiError('invalid_signature');
            const deviceCode = random(), verificationCode = random();
            const words = 'amber apple birch blue brook cedar cloud coral dawn dune elm fern field flame frost gold green hill lake leaf lime maple moon moss oak pine plum rain reed river rose snow'.split(' ');
            const phrase = Array.from(crypto.getRandomValues(new Uint8Array(6)), v => words[v & 31]).join(' ');
            const r = await repo.request({ code: await digest(deviceCode), verification: await digest(verificationCode), phrase, signing: b.signingKey, wrapping: b.wrappingKey, platform: b.platform as string });
            result = { ...r, deviceCode, verificationUri: env.AUTH_ORIGIN + '/v1/auth/devices/verification', verificationCode, phrase, expiresIn: 600, interval: 5 };
        }
        else if (route === 'status' || route === 'challenge') {
            const field = route === 'status' ? 'deviceCode' : 'deviceId';
            exactFields(b, [field]);
            if (typeof b[field] !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(b[field] as string))
                throw new ApiError('unauthorized');
            const value = b[field] as string, hash = await digest(value);
            if (!await browserRepository(env.MAIN).rate('identity', hash, 30))
                throw new ApiError('unauthorized');
            if (route === 'status')
                result = await repo.poll(hash);
            else {
                const challenge = random();
                result = { ...await repo.challenge(value, await digest(challenge)), challenge };
            }
        }
        else if (route === 'token') {
            exactFields(b, ['challengeId', 'signature']);
            identifier(b.challengeId);
            base64(b.signature, 64, 64);
            const c = await repo.attempt(b.challengeId);
            if (!await verify(c.signing_key, b.signature, challengeProof(c.id, c.challenge_digest, c.device_id, c.vault_id, c.expires_at)))
                throw new ApiError('invalid_signature');
            const token = random();
            await repo.issue(c.id, await digest(token));
            result = { token, tokenType: 'DeviceProof', expiresIn: 900, deviceId: c.device_id, vaultId: c.vault_id };
        }
        else {
            if (route === 'enroll') {
                exactFields(b, ['canonical', 'signature']);
                if (typeof b.canonical !== 'string' || b.canonical.length > 4096)
                    throw new ApiError('invalid_request');
                base64(b.signature, 64, 64);
            }
            else if (raw)
                throw new ApiError('invalid_request');
            const c = await authenticate(env.MAIN, request, null, raw);
            result = route === 'enroll' ? await repo.putPackage(c, b.canonical as string, b.signature as string) : await repo.ownPackage(c);
        }
        return Response.json(result, { headers: { 'cache-control': 'no-store' } });
    }
    catch (error) {
        try {
            if (auditFailure)
                await repo.rejected();
        }
        catch { /* Never log request data. */ }
        if (error instanceof ApiError)
            return errorResponse(error);
        const message = error instanceof Error ? error.message : '';
        for (const code of ['approval_required', 'not_found', 'idempotency_conflict', 'replayed_request', 'unauthorized'] as const)
            if (message.includes(code))
                return errorResponse(new ApiError(code));
        if (['invalid fields', 'invalid identifier', 'invalid encoding', 'invalid_counter', 'invalid_version', 'independent_keys_required', 'invalid_package'].some(code => message.includes(code)))
            return errorResponse(new ApiError('invalid_request'));
        return errorResponse(new ApiError('internal_error'));
    }
}
