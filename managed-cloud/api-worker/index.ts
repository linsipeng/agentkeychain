import {acknowledgeRoster} from './roster-witness.ts';
import type { CheckpointSigner } from '../shared/checkpoints.ts';
import { unavailable } from './browser-auth.ts';
import { ApiError, boundedBody, errorResponse, validateSigned, type RecoveryContract } from '../shared/contracts.ts';
import { browserFetch, type BrowserBindings } from './browser-bindings.ts';
import { deviceFetch } from './device-http.ts';
import { authenticate } from './auth.ts';
import { createRepository } from './repository.ts';
export interface Env extends BrowserBindings {
    MAIN: D1Database;
    ASSETS?: Fetcher;
    CHECKPOINT_SIGNER?: CheckpointSigner;
    RECOVERY: RecoveryContract & import('../shared/recovery.ts').RecoveryRPC;
}
export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        try {
            if (new URL(request.url).pathname.startsWith('/v1/devices/'))
                return await deviceFetch(request, env);
            if (new URL(request.url).pathname.startsWith('/v1/auth/'))
                return await browserFetch(request, env);
            const path = new URL(request.url).pathname;
            if (!path.startsWith('/v1/') && env.ASSETS && ['GET','HEAD'].includes(request.method)) {
                if (path.endsWith('.map') || path.includes('/src/') || path.includes('/.')) throw new ApiError('not_found');
                const asset = await env.ASSETS.fetch(request);
                const headers = new Headers(asset.headers);
                headers.set('cache-control','no-store');
                headers.set('content-security-policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
                headers.set('referrer-policy','no-referrer');
                headers.set('x-content-type-options','nosniff');
                headers.set('permissions-policy','camera=(), microphone=(), geolocation=()');
                return new Response(asset.body,{status:asset.status,headers});
            }
            const url = new URL(request.url), match = url.pathname.match(/^\/v1\/vaults\/([A-Za-z0-9_-]{1,128})\/sync\/(push|pull)$/);
            if (!match)
                throw new ApiError('not_found');
            const push = match[2] === 'push';
            if (request.method !== (push ? 'POST' : 'GET'))
                throw new ApiError('method_not_allowed');
            const body = await boundedBody(request);
            if (push) {
                if (url.search)
                    throw new ApiError('invalid_request');
                if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') ?? ''))
                    throw new ApiError('unsupported_media_type');
                let parsed: unknown;
                try {
                    parsed = JSON.parse(body);
                }
                catch {
                    throw new ApiError('invalid_request');
                }
                const signed = validateSigned(parsed);
                const ctx = await authenticate(env.MAIN, request, match[1]!, body);
                if (!env.CHECKPOINT_SIGNER)
                    return unavailable();
                const receipt=await createRepository(env.MAIN, ctx, env.CHECKPOINT_SIGNER).push(signed);
                if(await env.MAIN.prepare('SELECT 1 FROM signed_rosters WHERE tenant_id=? AND vault_id=? LIMIT 1').bind(ctx.tenantId,ctx.vaultId).first()){
                    if(!env.RECOVERY?.witness)return unavailable();
                    const witness=await acknowledgeRoster(env.MAIN,ctx.tenantId,ctx.vaultId,{head:(t,v)=>env.RECOVERY.witnessHead!(t,v),witness:i=>env.RECOVERY.witness!(i)},env.CHECKPOINT_SIGNER);
                    return Response.json({...receipt,witness},{headers:{'cache-control':'no-store'}});
                }
                return Response.json(receipt, { headers: { 'cache-control': 'no-store' } });
            }
            if (body || [...url.searchParams.keys()].some(k => !['cursor', 'limit'].includes(k)) || url.searchParams.getAll('cursor').length > 1 || url.searchParams.getAll('limit').length > 1)
                throw new ApiError('invalid_request');
            const rawLimit = url.searchParams.get('limit') ?? '100';
            if (!/^[1-9]\d{0,2}$/.test(rawLimit) || Number(rawLimit) > 100)
                throw new ApiError('invalid_request');
            const ctx = await authenticate(env.MAIN, request, match[1]!, '');
            if (!env.CHECKPOINT_SIGNER)
                return unavailable();
            return Response.json(await createRepository(env.MAIN, ctx, env.CHECKPOINT_SIGNER).pull(url.searchParams.get('cursor'), Number(rawLimit)), { headers: { 'cache-control': 'no-store' } });
        }
        catch (error) {
            return errorResponse(error);
        }
    }
};
