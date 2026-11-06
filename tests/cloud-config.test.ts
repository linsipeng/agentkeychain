import { expect, test } from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import { canonicalManifest, verifyReleaseManifest, productionPolicy, assertVerifiedPolicy } from '../src/cloud/config.ts';
await sodium.ready;
test('signed staging release ignores environment origin overrides', () => {
  process.env.AKC_CLOUD_ORIGIN = 'https://attacker.invalid';
  const policy=productionPolicy();
  expect(policy.apiOrigin).toBe('https://api.agentkeychain.soupsam.com');
  expect(policy.apiOrigin).not.toBe(process.env.AKC_CLOUD_ORIGIN);
  expect(() => assertVerifiedPolicy(policy)).not.toThrow();
  delete process.env.AKC_CLOUD_ORIGIN;
});
test('canonical signed release pins allow rotation and reject substitution', () => {
  const root = sodium.crypto_sign_keypair();
  const pins = ['old','new'].map(keyId => ({keyId, publicKey: Buffer.from(sodium.crypto_sign_keypair().publicKey).toString('base64')}));
  const manifest = {version:1, releaseId:'test-release', apiOrigin:'https://synthetic.invalid', protocolMin:2, protocolMax:2, checkpointKeys:pins};
  const canonical = canonicalManifest(manifest);
  const signed = {canonical, signature:Buffer.from(sodium.crypto_sign_detached(canonical,root.privateKey)).toString('base64')};
  expect(verifyReleaseManifest(signed, root.publicKey).checkpointKeys.length).toBe(2);
  expect(() => verifyReleaseManifest({...signed,canonical:canonical.replace('synthetic','attacker')},root.publicKey)).toThrow();
  expect(() => verifyReleaseManifest({...signed,canonical:canonical+' '},root.publicKey)).toThrow();
  for (const apiOrigin of ['http://synthetic.invalid','https://a.invalid/','https://u:p@a.invalid','https://a.invalid/x']) expect(() => canonicalManifest({...manifest,apiOrigin})).toThrow();
  expect(() => canonicalManifest({...manifest,checkpointKeys:[pins[0],pins[0]]})).toThrow();
  expect(() => canonicalManifest({...manifest,protocolMin:3,protocolMax:3})).toThrow();
});
