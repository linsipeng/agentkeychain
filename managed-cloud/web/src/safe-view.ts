// Normalize spelling variants before inspecting every nested object/array.
const forbidden = /(?:proof|challenge|authorization|sealed|ephemeralkey|secret|credentialvalue|password|privatekey|publickey|signingkey|wrappingkey|wrapped|share|vdk|vaultdatakey|ciphertext|encrypted|envelope|signature|canonical|digest|csrf|token|nonce|sequence|ordinal|lookuphash|kek|recoverykey|rawkey|keymaterial|plaintext|apikey|accesskey)/;
export function assertSafeView(value: unknown): void {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) { value.forEach(assertSafeView); return; }
    for (const [key, child] of Object.entries(value)) {
        const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (forbidden.test(normalized)) throw new Error('Unsafe response');
        assertSafeView(child);
    }
}
