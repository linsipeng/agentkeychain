import { assertSafeView } from './safe-view';
import { QueryClient } from '@tanstack/react-query';
export const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0, gcTime: 0, refetchOnWindowFocus: true }, mutations: { retry: false } } });
const routes = new Set(['email/request', 'bootstrap', 'session', 'authentication/options', 'authentication/verify', 'invitation/detail', 'invitation/verify', 'registration/options', 'registration/verify', 'logout', 'web/query', 'web/pairing', 'web/options', 'web/verify', 'web/execute', 'recovery/verify', 'recovery/start', 'recovery/status', 'recovery/cancel']);
export class ApiError extends Error {
    constructor(public status: number) { super('Request failed'); }
}
export class PasskeyIncompleteError extends Error {
    constructor() { super('Passkey confirmation did not finish'); }
}
let activityReceipt: string | 0 = 0;
export async function api<T = Record<string, unknown>>(route: string, body?: unknown): Promise<T> {
    if (!routes.has(route))
        throw new Error('Invalid route');
    const previousReceipt = activityReceipt;
    const input = body as {
        view?: string;
    } | undefined;
    if (route === 'web/query' && activityReceipt && ['home', 'activity', 'event'].includes(input?.view ?? ''))
        body = { ...input, receipt: activityReceipt };
    const csrf = document.cookie.split(';').map(x => x.trim()).find(x => x.startsWith('__Host-akc_csrf='))?.slice(16) ?? '';
    const r = await fetch('/v1/auth/' + route, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: body === undefined ? {} : { 'content-type': 'application/json', 'x-csrf-token': csrf }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    if (!r.ok) {
        if (r.status === 401 && (route === 'session' || route.startsWith('web/'))) {
            activityReceipt = 0;
            queryClient.clear();
            window.dispatchEvent(new Event('session-expired'));
        }
        throw new ApiError(r.status);
    }
    const value = await r.json();
    if (['logout', 'authentication/verify', 'registration/verify', 'bootstrap'].includes(route))
        activityReceipt = 0;
    if (activityReceipt === previousReceipt && route === 'web/query' && value.verification === 'verified' && typeof value.receipt === 'string')
        activityReceipt = value.receipt;
    if ((route.startsWith('web/') && route !== 'web/options') || route.startsWith('recovery/')) assertSafeView(value);
    return value as T;
}
const decode = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const encode = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export function supported() { return !!(globalThis.PublicKeyCredential && navigator.credentials); }
export async function passkey(options: Record<string, unknown>, registration = false) {
    if (!supported())
        throw new Error('Unsupported');
    const o = { ...options, challenge: decode(options.challenge as string) };
    let credential: PublicKeyCredential | null;
    if (registration) {
        const user = options.user as PublicKeyCredentialUserEntity & {
            id: string;
        };
        credential = await navigator.credentials.create({ publicKey: { ...o, user: { ...user, id: decode(user.id) } } as unknown as PublicKeyCredentialCreationOptions }) as PublicKeyCredential | null;
    }
    else {
        credential = await navigator.credentials.get({ publicKey: { ...o, allowCredentials: ((options.allowCredentials ?? []) as {
                    id: string;
                    type: 'public-key';
                }[]).map(c => ({ ...c, id: decode(c.id) })) } as PublicKeyCredentialRequestOptions }) as PublicKeyCredential | null;
    }
    if (!credential)
        throw new PasskeyIncompleteError();
    const r = credential.response;
    return { id: credential.id, rawId: encode(credential.rawId), type: 'public-key', clientExtensionResults: credential.getClientExtensionResults(), authenticatorAttachment: credential.authenticatorAttachment ?? undefined, response: registration ? { clientDataJSON: encode(r.clientDataJSON), attestationObject: encode((r as AuthenticatorAttestationResponse).attestationObject), transports: (r as AuthenticatorAttestationResponse).getTransports?.() ?? [] } : { clientDataJSON: encode(r.clientDataJSON), authenticatorData: encode((r as AuthenticatorAssertionResponse).authenticatorData), signature: encode((r as AuthenticatorAssertionResponse).signature), userHandle: (r as AuthenticatorAssertionResponse).userHandle ? encode((r as AuthenticatorAssertionResponse).userHandle!) : null } };
}
export async function stepUp(ref: string) { const o = await api<{
    challengeId: string;
    options: Record<string, unknown>;
}>('web/options', { ref }); await api('web/verify', { ref, challengeId: o.challengeId, response: await passkey(o.options) }); }
