import { browserDevice } from './device-http.ts';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/server';
import { ApiError, boundedBody, digest, errorResponse } from '../shared/contracts.ts';
import { browserRepository, type SessionRow, type ChallengeRow } from './browser-repository.ts';
import { encode, decode, random, webauthn, type WebAuthnPolicy } from './webauthn.ts';
export interface BrowserConfig extends WebAuthnPolicy {
    bootstrapKey: CryptoKey;
    emailKey: CryptoKey;
    lookupKey: CryptoKey;
    /** Trusted local/service-bound verifier; never an HTTP endpoint from user input. */
    verifyEmail(email: string, proof: string): Promise<boolean>;
    /** Service binding must authenticate its source metadata. No header fallback. */
    trustedSource: (request: Request) => Promise<string>;
}
export const unavailable = () => Response.json({ error: { code: 'unavailable' } }, { status: 503, headers: { 'cache-control': 'no-store' } });
// Source identities are canonical opaque lowercase ASCII identifiers, 1–128 bytes.
// Repeated resolution catches per-call randomness. Cross-request stability remains
// the trusted ingress adapter's contract; there is no client-controlled fallback.
async function resolveSource(config: BrowserConfig, request: Request) {
    const values = await Promise.allSettled([Promise.resolve().then(() => config.trustedSource(request.clone() as Request)), Promise.resolve().then(() => config.trustedSource(request.clone() as Request))]);
    if (values.some(v => v.status !== 'fulfilled'))
        throw new Error('invalid_auth_configuration');
    const [a, b] = values as [
        PromiseFulfilledResult<string>,
        PromiseFulfilledResult<string>
    ];
    if (typeof a.value !== 'string' || !/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(a.value) || a.value !== b.value)
        throw new Error('invalid_auth_configuration');
    return a.value;
}
const text = new TextEncoder();
const unauthorized = () => new ApiError('unauthorized');
async function mac(key: CryptoKey, value: string) { return encode(new Uint8Array(await crypto.subtle.sign('HMAC', key, text.encode(value)))); }
export async function emailLookup(config: BrowserConfig, email: string) { return mac(config.lookupKey, 'email\0' + normalizeEmail(email)); }
function normalizeEmail(value: unknown): string {
    if (typeof value !== 'string' || value.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))
        throw unauthorized();
    return value.toLowerCase();
}
function field(body: Record<string, unknown>, name: string, max = 2048): string {
    const value = body[name];
    if (typeof value !== 'string' || !value.length || value.length > max)
        throw unauthorized();
    return value;
}
function exact(body: Record<string, unknown>, fields: string[]) {
    if (Object.keys(body).sort().join(',') !== fields.sort().join(','))
        throw unauthorized();
}
function cookie(request: Request, name: string) {
    const matches = (request.headers.get('cookie') ?? '').split(';').map(v => v.trim()).filter(v => v.startsWith(name + '='));
    if (matches.length !== 1)
        throw unauthorized();
    const value = matches[0]!.slice(name.length + 1);
    if (!value || value.length > 2048)
        throw unauthorized();
    return value;
}
function response(body: unknown, session?: string, csrf?: string, maxAge = 43200) {
    const headers = new Headers({ 'cache-control': 'no-store', 'pragma': 'no-cache' });
    if (session !== undefined && csrf !== undefined) {
        headers.append('set-cookie', `__Host-akc_session=${session}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`);
        headers.append('set-cookie', `__Host-akc_csrf=${csrf}; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
    }
    return Response.json(body, { headers });
}
export function createBrowserAuth(db: D1Database, config: BrowserConfig) {
    const validKey = (key: CryptoKey, name: string, usages: KeyUsage[]) => key?.type === 'secret' && key.algorithm.name === name && usages.every(u => key.usages.includes(u));
    if (!validKey(config.bootstrapKey, 'HMAC', ['sign', 'verify']) || !validKey(config.lookupKey, 'HMAC', ['sign', 'verify']) || !validKey(config.emailKey, 'AES-GCM', ['encrypt', 'decrypt']) || typeof config.verifyEmail !== 'function' || typeof config.trustedSource !== 'function')
        return async () => unavailable();
    const repo = browserRepository(db);
    const configuredOrigin = new URL(config.origin);
    if (configuredOrigin.origin !== config.origin || configuredOrigin.protocol !== 'https:' || configuredOrigin.hostname !== config.rpId)
        throw new Error('invalid_auth_configuration');
    return async (request: Request): Promise<Response> => {
        let auditFailure = false;
        try {
            const url = new URL(request.url), route = url.pathname.replace('/v1/auth/', '');
            if (url.search || url.origin !== config.origin)
                throw unauthorized();
            const routes = ['bootstrap', 'session', 'invitation/verify', 'registration/options', 'registration/verify', 'authentication/options', 'authentication/verify', 'step-up/options', 'step-up/verify', 'logout', 'session/refresh', 'devices/pending', 'devices/approve', 'devices/deny', 'devices/list', 'devices/revoke', 'devices/verification'];
            if (!routes.includes(route))
                throw new ApiError('not_found');
            if (route === 'bootstrap') {
                if (request.method !== 'GET')
                    throw new ApiError('method_not_allowed');
                // Safe bootstrap is stateless. Its HMAC authenticates the CSRF digest
                // and five-minute lifetime. No GET writes D1 or refreshes idle time.
                const csrf = random(), payload = encode(text.encode(JSON.stringify({ n: random(), e: Math.floor(Date.now() / 1000) + 300, c: await digest(csrf) })));
                return response({ authenticated: false }, `p.${payload}.${await mac(config.bootstrapKey, 'bootstrap\0' + payload)}`, csrf, 300);
            }
            const safe = route === 'session' || route === 'devices/verification';
            if (safe && request.method !== 'GET')
                throw new ApiError('method_not_allowed');
            if (!safe && request.method !== 'POST')
                throw new ApiError('method_not_allowed');
            const token = cookie(request, '__Host-akc_session'), sessionHash = await digest(token);
            let session: SessionRow | null = null, csrfDigest: string;
            let bootstrapExpires = 0;
            if (token.startsWith('p.')) {
                const parts = token.split('.');
                if (parts.length !== 3 || !await crypto.subtle.verify('HMAC', config.bootstrapKey, decode(parts[2]!), text.encode('bootstrap\0' + parts[1])))
                    throw unauthorized();
                const payload = JSON.parse(new TextDecoder().decode(decode(parts[1]!))) as {
                    e: number;
                    c: string;
                };
                if (payload.e <= Math.floor(Date.now() / 1000) || await repo.bootstrapUsed(sessionHash))
                    throw unauthorized();
                csrfDigest = payload.c;
                bootstrapExpires = payload.e;
            }
            else {
                session = await repo.session(sessionHash);
                if (!session)
                    throw unauthorized();
                csrfDigest = session.csrf_digest;
            }
            if (route === 'devices/verification') {
                if (!session)
                    throw unauthorized();
                return response({ authentication: 'passkey', verificationCodeRequired: true, submitUri: config.origin + '/v1/auth/devices/pending' });
            }
            if (route === 'session')
                return response(session ? { authenticated: true, accountId: session.account_id, tenantId: session.tenant_id, authentication: 'passkey', absoluteExpires: session.absolute_expires, stepUp: session.step_up_expires !== null && session.step_up_expires > Math.floor(Date.now() / 1000) } : { authenticated: false });
            if (request.headers.get('origin') !== config.origin || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') ?? '') || request.headers.get('sec-fetch-site') === 'cross-site')
                throw unauthorized();
            const csrf = cookie(request, '__Host-akc_csrf');
            if (csrf !== request.headers.get('x-csrf-token') || await digest(csrf) !== csrfDigest)
                throw unauthorized();
            let sourceIdentity: string;
            try {
                sourceIdentity = await resolveSource(config, request);
            }
            catch {
                return unavailable();
            }
            const source = await mac(config.lookupKey, 'source\0' + sourceIdentity);
            if (!await repo.rate('source', source, 120))
                return Response.json({ error: { code: 'rate_limited' } }, { status: 429, headers: { 'cache-control': 'no-store' } });
            await repo.cleanup();
            auditFailure = true;
            const raw = await boundedBody(request, 32768);
            if (text.encode(raw).length > 32768)
                throw unauthorized();
            const body = JSON.parse(raw) as Record<string, unknown>;
            if (!body || typeof body !== 'object' || Array.isArray(body))
                throw unauthorized();
            const accountIdentity = session ? (await repo.identity(session.account_id))?.lookup_hash : undefined;
            if (session && !accountIdentity)
                throw unauthorized();
            const rateIdentity = async (identity: string) => {
                if (!await repo.rate('identity', identity, 30))
                    throw new AuthRateError();
            };
            if (route.startsWith('devices/')) {
                if (!session)
                    throw unauthorized();
                await rateIdentity(accountIdentity!);
                return response(await browserDevice(db, session, route, body));
            }
            if (route === 'logout' || route === 'session/refresh') {
                exact(body, []);
                if (!session)
                    throw unauthorized();
                await rateIdentity(accountIdentity!);
                if (route === 'logout') {
                    await repo.logout(sessionHash);
                    return response({ ok: true }, '', '', 0);
                }
                if (!await repo.touch(sessionHash))
                    throw unauthorized();
                return response({ ok: true });
            }
            if (route === 'invitation/verify') {
                if (session)
                    throw unauthorized();
                exact(body, ['invitation', 'email', 'proof']);
                const email = normalizeEmail(body.email), identity = await emailLookup(config, email);
                await rateIdentity(identity);
                const invite = await digest(field(body, 'invitation'));
                const proof = field(body, 'proof');
                // Both paths always run and settle, even on binding exceptions.
                const [eligible, verified] = await Promise.allSettled([
                    repo.invitation(invite, identity),
                    Promise.resolve().then(() => config.verifyEmail(email, proof)),
                ]);
                if (eligible.status !== 'fulfilled' || verified.status !== 'fulfilled' || eligible.value !== true || verified.value !== true)
                    throw unauthorized();
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const encrypted = encode(iv) + '.' + encode(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: text.encode(identity) }, config.emailKey, text.encode(email))));
                const id = random();
                await repo.saveVerification(id, invite, sessionHash, identity, encrypted);
                return response({ verificationId: id });
            }
            const purpose = route.split('/')[0]!;
            if (!['registration', 'authentication', 'step-up'].includes(purpose))
                throw unauthorized();
            if ((purpose === 'step-up') !== !!session)
                throw unauthorized();
            let action: string | null = null;
            if (purpose === 'step-up') {
                action = field(body, 'actionDigest', 64);
                if (!/^[a-f0-9]{64}$/.test(action))
                    throw unauthorized();
            }
            if (route.endsWith('/options')) {
                let identity: string, verificationId: string | null = null, account: string | null = session?.account_id ?? null;
                if (purpose === 'registration') {
                    exact(body, ['verificationId']);
                    verificationId = field(body, 'verificationId');
                    const verification = await repo.verification(verificationId, sessionHash);
                    if (!verification)
                        throw unauthorized();
                    identity = verification.email_lookup;
                    account = random();
                }
                else if (purpose === 'authentication') {
                    exact(body, ['email']);
                    identity = await emailLookup(config, normalizeEmail(body.email));
                }
                else {
                    exact(body, ['actionDigest']);
                    identity = accountIdentity!;
                }
                await rateIdentity(identity);
                const challenge = random(), id = random();
                const row: ChallengeRow = { auth_expires: session?.absolute_expires ?? bootstrapExpires, id, challenge_digest: await digest(challenge), purpose, session_digest: sessionHash, identity_hash: identity, account_id: purpose === 'registration' ? null : account, verification_id: verificationId, request_digest: await digest(JSON.stringify([purpose, identity, action, account])) };
                // Registration's future user handle is retained separately in the
                // request binding; verification supplies it and recomputes the digest.
                await repo.challenge(row);
                return response({ challengeId: id, ...(purpose === 'registration' ? { userId: account } : {}), options: purpose === 'registration' ? await webauthn.registrationOptions(config, account!, challenge) : await webauthn.authenticationOptions(config, challenge) });
            }
            exact(body, purpose === 'registration' ? ['challengeId', 'userId', 'response'] : purpose === 'step-up' ? ['challengeId', 'actionDigest', 'response'] : ['challengeId', 'response']);
            const c = await repo.attempt(field(body, 'challengeId'), sessionHash, purpose);
            if (!c)
                throw unauthorized();
            await rateIdentity(c.identity_hash);
            const supplied = body.response as RegistrationResponseJSON & AuthenticationResponseJSON;
            let account: string, tenant: string, key, verification;
            if (purpose === 'registration') {
                account = field(body, 'userId', 64);
                if (await digest(JSON.stringify([purpose, c.identity_hash, null, account])) !== c.request_digest)
                    throw unauthorized();
                verification = await repo.verification(c.verification_id!, sessionHash);
                if (!verification)
                    throw unauthorized();
                const verified = await webauthn.registration(config, c.challenge_digest, supplied);
                key = { id: verified.id, account_id: account, public_key: encode(verified.publicKey), counter: verified.counter };
                tenant = crypto.randomUUID();
            }
            else {
                if (await digest(JSON.stringify([purpose, c.identity_hash, action, session?.account_id ?? null])) !== c.request_digest)
                    throw unauthorized();
                const stored = await repo.key(supplied.id, c.identity_hash);
                if (!stored || (session && stored.account_id !== session.account_id) || (supplied.response.userHandle && supplied.response.userHandle !== stored.account_id))
                    throw unauthorized();
                const counter = await webauthn.authentication(config, c.challenge_digest, supplied, { id: stored.id, publicKey: decode(stored.public_key), counter: stored.counter });
                key = { ...stored, counter };
                account = stored.account_id;
                const membership = await repo.membership(account);
                if (!membership)
                    throw unauthorized();
                tenant = session?.tenant_id ?? membership.tenant_id;
            }
            const next = random(), nextCsrf = random(), absoluteExpiry = session?.absolute_expires ?? Math.floor(Date.now() / 1000) + 43200;
            await repo.accept({ challenge: c, account, tenant, key, sessionDigest: await digest(next), csrfDigest: await digest(nextCsrf), absoluteExpiry, actionDigest: action, verification: verification ?? undefined });
            return response({ authenticated: true }, next, nextCsrf, Math.max(0, absoluteExpiry - Math.floor(Date.now() / 1000)));
        }
        catch (error) {
            if (auditFailure) {
                try {
                    await repo.rejected();
                }
                catch { /* Fail closed without logging storage exceptions. */ }
            }
            if (error instanceof AuthRateError)
                return Response.json({ error: { code: 'rate_limited' } }, { status: 429, headers: { 'cache-control': 'no-store' } });
            // Never propagate WebAuthn/SQL/email adapter exceptions (which contain
            // identifiers or response values). All credential failures are identical.
            return errorResponse(error instanceof ApiError ? error : unauthorized());
        }
    };
}
class AuthRateError extends Error {
}
