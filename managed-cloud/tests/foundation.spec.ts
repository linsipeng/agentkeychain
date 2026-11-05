import { expect, test } from 'vitest';
import { SELF } from 'cloudflare:test';
test('push rejects oversized requests before authentication or database', async () => {
    const response = await SELF.fetch('https://local.invalid/v1/vaults/v/sync/push', { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(384 * 1024 + 1) });
    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: { code: 'payload_too_large' } });
});
test.each([
    ['/recovery', 'POST', '{}', 404, 'not_found'],
    ['/v1/vaults/v/sync/push', 'GET', undefined, 405, 'method_not_allowed'],
    ['/v1/vaults/v/sync/push', 'POST', '{', 400, 'invalid_request'],
    ['/v1/vaults/v/sync/pull?account_id=foreign', 'GET', undefined, 400, 'invalid_request'],
    ['/v1/vaults/v/sync/pull?limit=101', 'GET', undefined, 400, 'invalid_request'],
    ['/v1/vaults/v/sync/pull?limit=1&limit=2', 'GET', undefined, 400, 'invalid_request'],
])('exact error contract %s %s', async (path, method, body, status, code) => {
    const response = await SELF.fetch('https://local.invalid' + path, { method, headers: { 'content-type': 'application/json' }, body });
    expect(response.status).toBe(status);
    expect(await response.json()).toEqual({ error: { code } });
    expect(response.headers.get('cache-control')).toBe('no-store');
});
test('chunked oversize rejection is streaming, not Content-Length dependent', async () => {
    const { boundedBody } = await import('../shared/contracts.ts');
    let pulls = 0;
    const stream = new ReadableStream<Uint8Array>({ pull(controller) { pulls++; controller.enqueue(new Uint8Array(128 * 1024)); } });
    await expect(boundedBody(new Request('https://local.invalid', { method: 'POST', body: stream }))).rejects.toThrow('payload_too_large');
    expect(pulls).toBeLessThanOrEqual(5);
});
test('envelope limit is checked without database or signature verification', async () => {
    const { canonicalOperation } = await import('../../src/cloud/protocol.ts');
    const canonical = canonicalOperation({ protocolVersion: 2, vaultId: 'v', deviceId: 'd', objectId: 'o', operationId: 'x', kind: 'put', generation: 1, keyEpoch: 1, envelope: { nonce: btoa('n'.repeat(24)), ciphertext: btoa('c'.repeat(256 * 1024)) }, approvalRef: null });
    const response = await SELF.fetch('https://local.invalid/v1/vaults/v/sync/push', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ canonical, signature: btoa('s'.repeat(64)) }) });
    expect(response.status).toBe(413);
});
test('approval digest preserves the reviewed Slice 1 domain separation', async () => {
    const { approvalDigest } = await import('../shared/contracts.ts');
    const { requestDigest } = await import('../../src/auth/approval.ts');
    expect(await approvalDigest('synthetic-canonical-operation')).toBe(requestDigest('synthetic-canonical-operation'));
});
