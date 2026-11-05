import { seal } from '../shared/recovery-crypto.ts';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import type { CancelAuthorization } from '../shared/recovery.ts';
import { recoveryRepository } from './recovery-repository.ts';
import type { SessionRow as RecoverySession } from './browser-repository.ts';
import { approvalRepository } from './approval-repository.ts';
import { validateSigned } from '../shared/contracts.ts';
import { ApiError, boundedBody, digest, errorResponse, verify } from '../shared/contracts.ts';
import { base64, exactFields, identifier } from '../../src/cloud/protocol.ts';
import { canonicalGrant, challengeProof, enrollmentProof } from '../shared/device-protocol.ts';
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
        if (typeof b.verificationCode !== 'string' || !/^(?:[A-Za-z0-9_-]{12}|[A-Za-z0-9_-]{43})$/.test(b.verificationCode))
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
        if (!['pairing-detail', 'pairing-confirm', 'recovery-target', 'recovery-target-challenge', 'recovery-target-status', 'recovery-target-release', 'recovery-target-finish', 'recovery-cancel-confirmation', 'authorize', 'status', 'challenge', 'token', 'enroll', 'key-packages', 'approvals', 'recovery-keys', 'recovery-package', 'recovery-cancel', 'recovery-notifications'].includes(route))
            throw new ApiError('not_found');
        if (url.search)
            throw new ApiError('invalid_request');
        if (request.method !== (route === 'key-packages' ? 'GET' : 'POST'))
            throw new ApiError('method_not_allowed');
        if ((route.startsWith('recovery-target') && (request.headers.has('origin') || request.headers.has('sec-fetch-mode') || request.headers.has('sec-fetch-site'))) || request.headers.has('cookie'))
            throw new ApiError('unauthorized');
        const bodyLimit = route === 'approvals' ? 384 * 1024 : 8192;
        const raw = await boundedBody(request, bodyLimit);
        if (new TextEncoder().encode(raw).length > bodyLimit)
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
        if (route === 'pairing-detail' || route === 'pairing-confirm') {
            exactFields(b,route==='pairing-detail'?['id']:['id','signature']);identifier(b.id);
            const c=await authenticate(env.MAIN,request,null,raw);
            const r=await env.MAIN.prepare("SELECT * FROM device_requests WHERE id=? AND account_id=? AND tenant_id=? AND vault_id=? AND state='bound' AND expires_at>unixepoch()").bind(b.id,c.accountId,c.tenantId,c.vaultId).first<{id:string;device_id:string;signing_key:string;wrapping_key:string;key_epoch:number;expires_at:number;phrase:string}>();
            if(!r)throw new ApiError('not_found');
            const canonical=canonicalGrant({version:1,requestId:r.id,accountId:c.accountId,tenantId:c.tenantId,vaultId:c.vaultId,deviceId:r.device_id,signingKey:r.signing_key,wrappingKey:r.wrapping_key,issuerDeviceId:c.deviceId,keyEpoch:r.key_epoch,expiresAt:r.expires_at});
            const nonce=env.MAIN.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest,c.tenantId,c.vaultId,c.deviceId,c.accountId,c.nonce,c.timestamp);
            if(route==='pairing-confirm') {
                base64(b.signature,64,64);if(!await verify(c.publicKey,b.signature,canonical))throw new ApiError('invalid_signature');
                await env.MAIN.batch([nonce,env.MAIN.prepare('INSERT INTO pairing_confirmations VALUES(?,?,?,?,?,?)').bind(r.id,c.tenantId,c.accountId,c.deviceId,canonical,b.signature)]);
                result={confirmed:true};
            }else{await nonce.run();result={canonical,phrase:r.phrase};}
        }
        else if (route.startsWith('recovery-target-') && route !== 'recovery-target-challenge') {
            exactFields(b,route==='recovery-target-status'?['requestRef','signature']:route==='recovery-target-release'?['requestRef','signature','evidence']:['requestRef','signature','proof','completionSignature']);
            if(typeof b.requestRef!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(b.requestRef))throw new ApiError('unauthorized');
            base64(b.signature,64,64);
            const target=await env.MAIN.prepare('SELECT target FROM recovery_targets WHERE digest=? AND expires_at>unixepoch()').bind(await digest(b.requestRef)).first<string>('target');
            if(!target)throw new ApiError('unauthorized');
            const t=JSON.parse(target) as {id:string;signingKey:string};
            const {signature,...signed}=b;
            if(!await verify(t.signingKey,signature as string,JSON.stringify(['AgentKeychain-recovery-target-call-v1',route,signed])))throw new ApiError('invalid_signature');
            const row=await env.MAIN.prepare("SELECT account_id,tenant_id FROM recovery_sagas WHERE id=? AND request_digest=?").bind(t.id,await import('../shared/recovery.ts').then(m=>m.recoveryAction('start',target))).first<{account_id:string;tenant_id:string}>();
            if(!row)throw new ApiError('not_found');
            const recovery=recoveryRepository(env.MAIN,env),s=row as RecoverySession;
            result=route==='recovery-target-status'?await recovery.detail(s,t.id):route==='recovery-target-release'?await recovery.release(s,t.id,b.evidence as import('../shared/recovery.ts').RecoveryEvidence):await recovery.finish(s,t.id,b.proof as string,b.completionSignature as string);
        }
        else if (route === 'recovery-cancel-confirmation') {
            exactFields(b,['id','authorization']);identifier(b.id);
            const c=await authenticate(env.MAIN,request,null,raw);
            const r=await recoveryRepository(env.MAIN,env).detail({account_id:c.accountId,tenant_id:c.tenantId} as RecoverySession,b.id as string);
            if(!env.RECOVERY_AUTH||!await env.RECOVERY_AUTH.cancel(r.canonical,b.authorization as CancelAuthorization))throw new ApiError('approval_required');
            const confirmationRef=random();
            await env.MAIN.batch([env.MAIN.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest,c.tenantId,c.vaultId,c.deviceId,c.accountId,c.nonce,c.timestamp),env.MAIN.prepare('INSERT INTO recovery_cancel_confirmations VALUES(?,?,?,?,?,unixepoch()+300)').bind(await digest(confirmationRef),b.id,c.accountId,c.tenantId,JSON.stringify(b.authorization))]);
            result={confirmationRef};
        }
        else if (route === 'recovery-target' || route === 'recovery-target-challenge') {
            exactFields(b,route === 'recovery-target-challenge' ? ['target','signature'] : ['target','signature','challengeRef','proof']);
            const t=b.target as Record<string,unknown>;
            exactFields(t,['id','packageId','targetDeviceId','signingKey','wrappingKey','nonce']);
            for(const f of ['id','packageId','targetDeviceId','nonce'])identifier(t[f]);
            base64(t.signingKey,32,32);base64(t.wrappingKey,32,32);base64(b.signature,64,64);
            if(!await verify(t.signingKey,b.signature,JSON.stringify(['AgentKeychain-recovery-target-v1',t])))throw new ApiError('invalid_signature');
            if (t.signingKey === t.wrappingKey || typeof t.targetDeviceId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(t.targetDeviceId)) throw new ApiError('invalid_request');
            if (route === 'recovery-target-challenge') {
                const challengeRef=random(), proof=random();
                const box=await seal(t.wrappingKey as string,new TextEncoder().encode(proof),'AgentKeychain-recovery-target-possession-v1\0'+challengeRef+'\0'+JSON.stringify(t));
                await env.MAIN.batch([
                    env.MAIN.prepare('DELETE FROM recovery_target_challenges WHERE digest IN(SELECT digest FROM recovery_target_challenges WHERE expires_at<=unixepoch() LIMIT 100)'),
                    env.MAIN.prepare('INSERT INTO recovery_target_challenges VALUES(?,?,?,unixepoch()+300)').bind(await digest(challengeRef),JSON.stringify(t),await digest(btoa(proof))),
                ]);
                return Response.json({challengeRef,box},{headers:{'cache-control':'no-store'}});
            }
            identifier(b.challengeRef); base64(b.proof,43,43);
            const consumed=await env.MAIN.prepare('DELETE FROM recovery_target_challenges WHERE digest=? AND target=? AND proof_digest=? AND expires_at>unixepoch() RETURNING digest').bind(await digest(b.challengeRef as string),JSON.stringify(t),await digest(b.proof as string)).first();
            if (!consumed) throw new ApiError('unauthorized');
            const requestRef=random();
            await env.MAIN.prepare('DELETE FROM recovery_targets WHERE digest IN(SELECT digest FROM recovery_targets WHERE expires_at<=unixepoch() LIMIT 100)').run();
            await env.MAIN.prepare('INSERT INTO recovery_targets VALUES(?,?,unixepoch()+172800)').bind(await digest(requestRef),JSON.stringify(t)).run();
            result={requestRef,expiresIn:172800};
        }
        else if (route === 'authorize') {
            exactFields(b, ['signingKey', 'wrappingKey', 'platform', 'proof']);
            base64(b.signingKey, 32, 32);
            base64(b.wrappingKey, 32, 32);
            base64(b.proof, 64, 64);
            if (b.signingKey === b.wrappingKey || !['macos', 'linux', 'windows', 'other'].includes(b.platform as string))
                throw new ApiError('invalid_request');
            if (!await verify(b.signingKey, b.proof, enrollmentProof(b.signingKey, b.wrappingKey, b.platform as string)))
                throw new ApiError('invalid_signature');
            const deviceCode = random(), verificationCode = random().slice(0,12);
            // Three independent 11-bit words preserve 33 bits of comparison entropy.
            const phrase = Array.from(crypto.getRandomValues(new Uint16Array(3)), v => wordlist[v & 2047]).join(' ');
            const r = await repo.request({ code: await digest(deviceCode), verification: await digest(verificationCode), phrase, signing: b.signingKey, wrapping: b.wrappingKey, platform: b.platform as string });
            result = { ...r, deviceCode, verificationUri: env.AUTH_ORIGIN + '/v1/auth/devices/verification', verificationCode, phrase, browserUri: env.AUTH_ORIGIN + '/app/devices/add?code=' + encodeURIComponent(verificationCode), expiresIn: 600, interval: 5 };
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
        else if (route.startsWith('recovery-')) {
            const c=await authenticate(env.MAIN,request,null,raw),recovery=recoveryRepository(env.MAIN,env);
            if(route==='recovery-package') {exactFields(b,['canonical','signature']);if(typeof b.canonical!=='string'||typeof b.signature!=='string')throw new ApiError('invalid_request');result=await recovery.enroll(c,b.canonical,b.signature);}
            else if(route==='recovery-keys') {exactFields(b,[]);result=await recovery.keys();}
            else {
                const s={tenant_id:c.tenantId,account_id:c.accountId} as RecoverySession;
                if(route==='recovery-cancel'){exactFields(b,['id','authorization']);identifier(b.id);result=await recovery.cancel(s,b.id as string,b.authorization as CancelAuthorization,c);}
                else {exactFields(b,['after']);result=await recovery.notifications(s,b.after as number);}
            }
        }
        else if (route === 'approvals') {
            exactFields(b,'summary' in b?['operation','expiresIn','summary']:['operation','expiresIn']);
            const c = await authenticate(env.MAIN, request, null, raw);
            result = await approvalRepository(env.MAIN).create(c,validateSigned(b.operation),b.expiresIn as number,b.summary as {ciphertext:string;nonce:string;signature:string}|undefined);
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
