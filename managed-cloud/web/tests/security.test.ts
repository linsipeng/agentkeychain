import { expect, test, vi, afterEach } from 'vitest';
import { api } from '../src/api';
import { en, zh } from '../src/i18n';
afterEach(() => vi.unstubAllGlobals());
test('complete bilingual keys and no protocol vocabulary in ordinary copy', () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(zh).sort());
    expect(Object.values(en).join(' ')).not.toMatch(/\b(?:nonce|digest|ciphertext|Worker|D1|bearer token|key package|sequence)\b/i);
});
test('API uses same-origin credentials, no-store and matching CSRF; rejects custom endpoints', async () => {
    document.cookie = '__Host-akc_csrf=synthetic; Secure; Path=/';
    const f = vi.fn().mockResolvedValue(Response.json({ ok: true }));
    vi.stubGlobal('fetch', f);
    await api('web/query', { view: 'home' });
    expect(f).toHaveBeenCalledWith('/v1/auth/web/query', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', method: 'POST', body: '{"view":"home"}' }));
    expect((f.mock.calls[0][1].headers as Record<string, string>)['x-csrf-token']).toBe('synthetic');
    await expect(api('https://foreign.invalid', {})).rejects.toThrow();
    expect(f).toHaveBeenCalledTimes(1);
});
test('read-model responses reject private and encrypted data before returning to components', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ devices: [{ canonical: 'forbidden' }] })));
    await expect(api('web/query', { view: 'devices' })).rejects.toThrow('Unsafe response');
});

const views=['home','requests','requests-recent','request','devices','device','status','activity','event','history','account','recovery'];
const sensitive=['proof','challenge','authorization','cancelAuthorization','completionSignature','sealed','ephemeralKey','wrapped_vdk','share','custodianShare','secret','credential_value','credentialValue','VDK','vault-data-key','privateKey','private_key','PUBLIC_KEY','signing-key','wrappingKey','wrappedVDK','wrapped_share','apiShare','custodian_share','ciphertext','encryptedEmail','envelope','signature','canonical','actionDigest','csrf_token','bearerToken','nonce','sequence','ordinal','lookup_hash','AKC_KEK_HEX','recoveryKey','raw_key','keyMaterial','plaintext','apiKey','access_key'];
test.each(views)('recursive forbidden fields and spelling variants rejected for %s',async view=>{
    for(const key of sensitive){
        vi.stubGlobal('fetch',vi.fn().mockResolvedValue(Response.json({items:[{nested:[{[key]:'synthetic-forbidden'}]}]})));
        await expect(api('web/query',{view})).rejects.toThrow('Unsafe response');
    }
});

test.each(['recovery/verify','recovery/start','recovery/status','recovery/cancel'])('restricted browser %s rejects every recovery-sensitive response field',async route=>{
    for(const key of sensitive){
        vi.stubGlobal('fetch',vi.fn().mockResolvedValue(Response.json({nested:[{[key]:'synthetic'}]})));
        await expect(api(route,{})).rejects.toThrow('Unsafe response');
    }
});
test.each(['recovery/detail','recovery/release','recovery/finish'])('browser client has no %s transport',async route=>{
    const fetch=vi.fn();vi.stubGlobal('fetch',fetch);
    await expect(api(route,{})).rejects.toThrow('Invalid route');expect(fetch).not.toHaveBeenCalled();
});
