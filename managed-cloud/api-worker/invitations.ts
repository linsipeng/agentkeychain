import { ApiError, digest } from '../shared/contracts.ts';
import { decode, encode } from './webauthn.ts';
import { emailLookup, type BrowserConfig } from './browser-auth.ts';
const text = new TextEncoder();
/** Local provisioning only. Call with the same AUTH_EMAIL_KEY/lookup binding as auth. */
export async function seedInvitation(db: D1Database, config: BrowserConfig, capability: string, email: string, expiresAt: number) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(capability) || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() / 1000)
        throw new ApiError('invalid_request');
    const lookup = await emailLookup(config, email), iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = encode(iv) + '.' + encode(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: text.encode(lookup) }, config.emailKey, text.encode(email.toLowerCase()))));
    await db.prepare('INSERT INTO invitations(digest,email_lookup,encrypted_email,expires_at) VALUES(?,?,?,?)').bind(await digest(capability), lookup, encrypted, expiresAt).run();
}
export async function invitationDetail(db: D1Database, config: BrowserConfig, capability: unknown) {
    if (typeof capability !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(capability))
        throw new ApiError('unauthorized');
    const r = await db.prepare('SELECT encrypted_email,email_lookup,expires_at FROM invitations WHERE digest=? AND expires_at>unixepoch() AND consumed_at IS NULL').bind(await digest(capability)).first<{
        encrypted_email: string | null;
        email_lookup: string;
        expires_at: number;
    }>();
    if (!r?.encrypted_email)
        throw new ApiError('unauthorized');
    const [iv, data] = r.encrypted_email.split('.');
    const email = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(iv!), additionalData: text.encode(r.email_lookup) }, config.emailKey, decode(data!)));
    if (await emailLookup(config, email) !== r.email_lookup)
        throw new ApiError('unauthorized');
    const [local, domain] = email.split('@'), pieces = domain!.split('.');
    return { maskedEmail: local![0] + '***@' + pieces[0]![0] + '***.' + pieces.at(-1), status: 'available', expiresAt: r.expires_at };
}
