import { expect, test } from 'vitest';
import { checkpoint, verifyCheckpointPage, advanceRoot, genesisRoot } from '../shared/checkpoints.ts';
import { syntheticSigner as signer } from './synthetic-signer.ts';
test('checkpoint chain rejects key substitution, rollback, hidden suffix and changed page', async () => {
    const s = await signer(), pin = await s.key(), zero = await genesisRoot('t', 'v');
    const versions = [{ serverSequence: 1, signed: { canonical: 'exact-operation', signature: 'exact-signature' } }];
    const root = await advanceRoot(zero, 1, versions[0]!.signed);
    const end = await checkpoint(s, 't', 'v', 1, root.root, zero, root.operationDigest);
    const high = await checkpoint(s, 't', 'v', 2, 'a'.repeat(64), root.root, 'b'.repeat(64));
    const page = { versions, checkpoint: high, pageCheckpoint: end, hasMore: true };
    await verifyCheckpointPage(pin, 't', 'v', 0, zero, 0, page);
    await expect(verifyCheckpointPage(await (await signer()).key(), 't', 'v', 0, zero, 0, page)).rejects.toThrow();
    await expect(verifyCheckpointPage(pin, 't', 'v', 0, zero, 3, page)).rejects.toThrow();
    await expect(verifyCheckpointPage(pin, 't', 'v', 0, zero, 0, { ...page, hasMore: false })).rejects.toThrow();
    await expect(verifyCheckpointPage(pin, 't', 'v', 0, zero, 0, { ...page, versions: [{ ...versions[0]!, signed: { canonical: 'changed', signature: 'exact-signature' } }] })).rejects.toThrow();
});
