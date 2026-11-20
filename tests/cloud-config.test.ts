import { expect, test } from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import { canonicalManifest, verifyReleaseManifest, productionPolicy, assertVerifiedPolicy } from '../src/cloud/config.ts';
await sodium.ready;
test('signed dual-origin staging artifact ignores environment overrides', () => {
  const names=['AKC_CLOUD_ORIGIN','AKC_API_ORIGIN','AKC_WEB_ORIGIN','AUTH_ORIGIN','DEVICE_API_ORIGIN'];
  const old=names.map(n=>process.env[n]);
  try {
    for(const n of names)process.env[n]='https://attacker.invalid';
    const policy=productionPolicy();
    expect(policy.apiOrigin).toBe('https://api.agentkeychain.soupsam.com');
    expect(policy.webOrigin).toBe('https://agentkeychain.soupsam.com');
    expect(() => assertVerifiedPolicy(policy)).not.toThrow();
  }
  finally {names.forEach((n,i)=>{if(old[i]===undefined)delete process.env[n];else process.env[n]=old[i];});}
});
test('canonical signed release pins allow rotation and reject substitution', () => {
  const root = sodium.crypto_sign_keypair();
  const pins = ['old','new'].map(keyId => ({keyId, publicKey: Buffer.from(sodium.crypto_sign_keypair().publicKey).toString('base64')}));
  const manifest = {version:1, releaseId:'test-release', apiOrigin:'https://api.synthetic.invalid', webOrigin:'https://synthetic.invalid', protocolMin:2, protocolMax:2, checkpointKeys:pins};
  const canonical = canonicalManifest(manifest);
  const signed = {canonical, signature:Buffer.from(sodium.crypto_sign_detached(canonical,root.privateKey)).toString('base64')};
  expect(verifyReleaseManifest(signed, root.publicKey).checkpointKeys.length).toBe(2);
  expect(() => verifyReleaseManifest({...signed,canonical:canonical.replace('synthetic','attacker')},root.publicKey)).toThrow();
  expect(() => verifyReleaseManifest({...signed,canonical:canonical+' '},root.publicKey)).toThrow();
  for (const apiOrigin of ['http://synthetic.invalid','https://a.invalid/','https://u:p@a.invalid','https://a.invalid/x']) expect(() => canonicalManifest({...manifest,apiOrigin})).toThrow();
  expect(() => canonicalManifest({...manifest,checkpointKeys:[pins[0],pins[0]]})).toThrow();
  expect(() => canonicalManifest({...manifest,protocolMin:3,protocolMax:3})).toThrow();
});

test('dual origins reject missing, noncanonical, same-host and unrelated substitutions',()=>{
 const pin={keyId:'one',publicKey:Buffer.from(sodium.crypto_sign_keypair().publicKey).toString('base64')};
 const value={version:1,releaseId:'dual',apiOrigin:'https://api.product.test',webOrigin:'https://product.test',protocolMin:2,protocolMax:2,checkpointKeys:[pin]};
 const root=sodium.crypto_sign_keypair(),canonical=canonicalManifest(value),signature=Buffer.from(sodium.crypto_sign_detached(canonical,root.privateKey)).toString('base64');
 for(const field of ['apiOrigin','webOrigin'] as const){
  for(const origin of [undefined,'http://product.test','https://product.test/','https://u:p@product.test','https://product.test/path','https://product.test?x','https://product.test#x','https://PRODUCT.test','https://product.test:443'])expect(()=>canonicalManifest({...value,[field]:origin})).toThrow();
  const changed=canonicalManifest({...value,[field]:field==='apiOrigin'?'https://other.product.test':'https://test'});
  expect(()=>verifyReleaseManifest({canonical:changed,signature},root.publicKey)).toThrow('invalid_release_signature');
 }
 for(const apiOrigin of ['https://product.test','https://product.test:8443','https://evilproduct.test','https://product.test.evil.test','https://.product.test','https://api..product.test'])expect(()=>canonicalManifest({...value,apiOrigin})).toThrow();
});
