import {expect,test} from 'bun:test';
import {spawnSync} from 'node:child_process';
test('release build without a verified manifest fails closed',()=>{
 const r=spawnSync(process.execPath,['scripts/build-release.ts'],{encoding:'utf8',env:{PATH:process.env.PATH!}});
 expect(r.status).not.toBe(0);expect(r.stderr).toContain('cloud_unavailable_not_provisioned');
});
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalManifest} from '../src/cloud/config.ts';
test('signed synthetic release compiles with immutable public manifest and refuses URL flags',async()=>{
 await sodium.ready;const dir=mkdtempSync(join(tmpdir(),'akc-release-'));
 try{
  const key=sodium.crypto_sign_keypair(),publicKey=Buffer.from(key.publicKey).toString('base64');
  const canonical=canonicalManifest({witnessKeys:[{keyId:'witness',publicKey:Buffer.from(sodium.crypto_sign_keypair().publicKey).toString('base64')}],version:1,releaseId:'synthetic-release',apiOrigin:'https://api.release.invalid',webOrigin:'https://release.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[{keyId:'one',publicKey}]});
  writeFileSync(join(dir,'manifest.json'),JSON.stringify({canonical,signature:Buffer.from(sodium.crypto_sign_detached(canonical,key.privateKey)).toString('base64')}));writeFileSync(join(dir,'root-public'),publicKey);
  const binary=join(dir,'client'),build=spawnSync(process.execPath,['scripts/build-release.ts','--manifest',join(dir,'manifest.json'),'--root-public-key',join(dir,'root-public'),'--outfile',binary],{encoding:'utf8'});
  expect(build.status).toBe(0);
  const env={PATH:process.env.PATH!,TMPDIR:tmpdir(),AGENTKEYCHAIN_HOME:dir,AKC_KEYCHAIN_TEST_MODE:'1',AKC_CLOUD_ORIGIN:'https://attacker.invalid',AKC_API_ORIGIN:'https://attacker.invalid',AKC_WEB_ORIGIN:'https://attacker.invalid',AUTH_ORIGIN:'https://attacker.invalid',DEVICE_API_ORIGIN:'https://attacker.invalid'};
  const status=spawnSync(binary,['cloud','status'],{encoding:'utf8',env});expect(status.status,status.stderr).toBe(0);expect(JSON.parse(status.stdout).releaseId).toBe('synthetic-release');
  expect(spawnSync(binary,['cloud','login','--url','https://attacker.invalid'],{env}).status).toBe(1);
 }finally{rmSync(dir,{recursive:true,force:true});}
},60000);
