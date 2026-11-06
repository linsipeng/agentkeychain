import {expect,it} from 'vitest';
import {loadKeyrings,domainSigner,validateRewrap} from '../shared/trust-support.ts';
import {encode64} from '../shared/recovery-crypto.ts';
import {digest,verify} from '../shared/contracts.ts';
import {genesisRoot} from '../shared/checkpoints.ts';
async function ring(){const pair=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair,publicKey=encode64(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey))),keyId=await digest(publicKey);return {activeId:keyId,keys:[{keyId,publicKey,privateKey:encode64(new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey)))}]};}
it('validates key pairs, equality, peer separation and active rotation',async()=>{
 const a=await ring(),b=await ring();await expect(loadKeyrings({a:JSON.stringify(a),b:JSON.stringify(a)},[])).rejects.toThrow();
 await expect(loadKeyrings({a:JSON.stringify(a)},[a.keys[0]!.publicKey])).rejects.toThrow();
 await expect(loadKeyrings({a:JSON.stringify({...a,keys:[{...a.keys[0],publicKey:b.keys[0]!.publicKey}]})},[])).rejects.toThrow();
 const rings=await loadKeyrings({a:JSON.stringify({...b,keys:[...a.keys,...b.keys]})},[]);expect(rings.a!.active.keyId).toBe(b.activeId);expect(rings.a!.keys.size).toBe(2);
});
it('checkpoint signer rejects other domains and noncanonical bytes',async()=>{
 const r=(await loadKeyrings({checkpoint:JSON.stringify(await ring())},[])).checkpoint!;const signer=domainSigner(r,'checkpoint','api');
 const c=JSON.stringify({version:1,tenantId:'tenant',vaultId:'vault',keyId:r.active.keyId,sequence:0,root:await genesisRoot('tenant','vault'),previousRoot:null,operationDigest:null});
 expect(await verify(r.active.publicKey,await signer.sign(c),c)).toBe(true);
 for(const bad of ['hello',JSON.stringify(['AgentKeychain-recovery-account-verified-v1',c]),' '+c,c.replace('"sequence":0','"sequence":-1')])await expect(signer.sign(bad)).rejects.toThrow();
 for(const kind of ['release','witness','trust','account'] as const)await expect(domainSigner(r,kind,'custodian').sign(c)).rejects.toThrow();
});
it('rewrap rejects arbitrary contexts and a substituted target',()=>{
 expect(()=>validateRewrap('api','id','arbitrary','key','arbitrary')).toThrow();
 expect(()=>validateRewrap('custodian','id',JSON.stringify(['AgentKeychain-recovery-share-v1']), 'key',JSON.stringify(['AgentKeychain-recovery-release-v1','{}','api']))).toThrow();
});
it('permits retained public-only signing keys but never a public-only active signer',async()=>{
 const a=await ring(),b=await ring(),old={keyId:a.activeId,publicKey:a.keys[0]!.publicKey};
 const rings=await loadKeyrings({a:JSON.stringify({...b,keys:[old,...b.keys]})},[]);expect(rings.a!.keys.get(a.activeId)?.pair).toBeUndefined();
 await expect(loadKeyrings({a:JSON.stringify({activeId:a.activeId,keys:[old]})},[])).rejects.toThrow();
});
const recovery=()=>({version:1,id:'case',packageId:'package',accountId:'account',tenantId:'tenant',vaultId:'vault',keyEpoch:1,targetDeviceId:'a'.repeat(43),signingKey:encode64(new Uint8Array(32).fill(1)),wrappingKey:encode64(new Uint8Array(32).fill(2)),createdAt:Math.floor(Date.now()/1000),notBefore:Math.floor(Date.now()/1000)+86400,expiresAt:Math.floor(Date.now()/1000)+172800,nonce:'nonce'});
it.each(['checkpoint','release','account','witness','trust'] as const)('%s rejects arbitrary domains, unknown fields and malformed input',async purpose=>{
 const r=(await loadKeyrings({r:JSON.stringify(await ring())},[])).r!,s=domainSigner(r,purpose,purpose==='checkpoint'||purpose==='account'?'api':'custodian');
 for(const input of ['', 'not-json', '{}', 'AgentKeychain-wrong-domain-v1\0{}',JSON.stringify({version:1,extra:true})])await expect(s.sign(input)).rejects.toThrow();
});
it('release signer accepts only its own party and key, with exact canonical fields',async()=>{
 const r=(await loadKeyrings({r:JSON.stringify(await ring())},[])).r!,s=domainSigner(r,'release','api'),c=recovery();
 const value={version:1,party:'api',keyId:r.active.keyId,caseCanonical:JSON.stringify(c),manifestDigest:'a'.repeat(64),evidenceDigest:'b'.repeat(64),expiresAt:c.expiresAt,box:{version:1,ephemeralKey:encode64(new Uint8Array(32)),nonce:encode64(new Uint8Array(12)),ciphertext:encode64(new Uint8Array(48))}};
 const message='AgentKeychain-authenticated-recovery-release-v1\0'+JSON.stringify(value);expect(await verify(r.active.publicKey,await s.sign(message),message)).toBe(true);
 for(const change of [{party:'custodian'},{keyId:'other'},{extra:true},{expiresAt:0}])await expect(s.sign('AgentKeychain-authenticated-recovery-release-v1\0'+JSON.stringify({...value,...change}))).rejects.toThrow();
});
it('rewrap binds target key, account, package, epoch, operator, and canonical bytes',()=>{
 const c=recovery(),source=JSON.stringify(['AgentKeychain-recovery-share-v1',c.packageId,c.accountId,c.tenantId,c.vaultId,c.keyEpoch,'two-party-24h','api','key']),context=JSON.stringify(['AgentKeychain-recovery-release-v1',JSON.stringify(c),'api']);
 expect(validateRewrap('api','key',source,c.wrappingKey,context)).toEqual(c);
 for(const change of [{accountId:'other'},{packageId:'other'},{keyEpoch:2},{wrappingKey:c.signingKey}])expect(()=>validateRewrap('api','key',source,c.wrappingKey,JSON.stringify(['AgentKeychain-recovery-release-v1',JSON.stringify({...c,...change}),'api']))).toThrow();
 expect(()=>validateRewrap('custodian','key',source,c.wrappingKey,context)).toThrow();expect(()=>validateRewrap('api','key',source,c.wrappingKey,' '+context)).toThrow();
});
it('checkpoint contract includes canonical activity checkpoints, rejecting malformed activity domains',async()=>{
 const r=(await loadKeyrings({r:JSON.stringify(await ring())},[])).r!,s=domainSigner(r,'checkpoint','api');
 const value=['AgentKeychain-activity-checkpoint-v2','a'.repeat(64),r.active.keyId,0,'b'.repeat(32),1,'c'.repeat(64)],message=JSON.stringify(value);
 expect(await verify(r.active.publicKey,await s.sign(message),message)).toBe(true);
 for(const mutation of [Object.assign([...value],{0:'AgentKeychain-activity-checkpoint-v1'}),Object.assign([...value],{2:'wrong'}),[...value,true],Object.assign([...value],{5:-1})])await expect(s.sign(JSON.stringify(mutation))).rejects.toThrow();
});
it('rotation decrypts retained wrapping keys while advertising only the active wrapping key',async()=>{
 const {recoveryKeyring}=await import('../shared/recovery-keyring.ts'),{seal,open}=await import('../shared/recovery-crypto.ts');
 const pairs=await Promise.all([0,1,2].map(()=>crypto.subtle.generateKey('X25519',true,['deriveBits']) as Promise<CryptoKeyPair>));
 const values=await Promise.all(pairs.map(async p=>{const publicKey=encode64(new Uint8Array(await crypto.subtle.exportKey('raw',p.publicKey)));return {keyId:await digest(publicKey),publicKey,privateKey:encode64(new Uint8Array(await crypto.subtle.exportKey('pkcs8',p.privateKey)))};}));
 const r=(await loadKeyrings({wrap:JSON.stringify({activeId:values[1]!.keyId,keys:values.slice(0,2)})},[])).wrap!;
 const keys=await recoveryKeyring(new Map([...r.keys].map(([id,k])=>[id,k.pair!])),r.active.keyId);expect((await keys.key()).keyId).toBe(values[1]!.keyId);
 const secret=crypto.getRandomValues(new Uint8Array(32)),box=await seal(values[0]!.publicKey,secret,'source');
 const result=await keys.rewrap(values[0]!.keyId,box,'source',values[2]!.publicKey,'target');expect(await open(pairs[2]!.privateKey,result,'target')).toEqual(secret);
 await expect(keys.rewrap('unknown',box,'source',values[2]!.publicKey,'target')).rejects.toThrow();
});
