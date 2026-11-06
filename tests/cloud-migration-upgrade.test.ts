import {URL} from 'node:url';
import {expect,test} from 'bun:test';
import {Database} from 'bun:sqlite';
import {readdirSync,readFileSync} from 'node:fs';
const directory=new URL('../managed-cloud/api-worker/migrations/',import.meta.url);
const migrations=readdirSync(directory).filter(n=>n.endsWith('.sql')).sort();
test('0016 snapshot upgrades revoked-device boundaries once and transaction rollback preserves snapshot',()=>{
 const db=new Database(':memory:');
 for(const name of migrations.filter(n=>n<'0017'))db.exec(readFileSync(new URL(name,directory),'utf8'));
 db.exec("INSERT INTO accounts VALUES('a'); INSERT INTO tenants VALUES('t'); INSERT INTO memberships VALUES('t','a',1); INSERT INTO vaults VALUES('t','v',7),('t','empty',0); INSERT INTO devices VALUES('t','live','a','key',1),('t','revoked','a','old',0); INSERT INTO vault_devices VALUES('t','v','live',1),('t','v','revoked',0),('t','empty','revoked',0)");
 const upgrade=()=>{for(const name of migrations.filter(n=>n>='0017'&&n<'0020'))db.exec(readFileSync(new URL(name,directory),'utf8'));};
 expect(()=>db.transaction(()=>{upgrade();throw new Error('migration interrupted');})()).toThrow('interrupted');
 expect(db.query("SELECT name FROM sqlite_master WHERE name='device_revocation_boundaries'").get()).toBeNull();
 db.transaction(upgrade)();
 expect(db.query('SELECT vault_id,device_id,sequence FROM device_revocation_boundaries ORDER BY vault_id').all()).toEqual([{vault_id:'empty',device_id:'revoked',sequence:0},{vault_id:'v',device_id:'revoked',sequence:7}]);
 expect(()=>db.exec('UPDATE device_revocation_boundaries SET sequence=0')).toThrow('immutable_revocation');
 db.exec("UPDATE vaults SET sequence=8 WHERE id='v'");expect(db.query("SELECT sequence FROM device_revocation_boundaries WHERE vault_id='v'").get()).toEqual({sequence:7});db.close();
});
test('complete signed migration roster includes preexisting revoked identities and accepts the conservative checkpoint',async()=>{
 const sodium=(await import('libsodium-wrappers-sumo')).default;await sodium.ready;
 const {canonicalRoster,ROSTER_DOMAIN,rosterDigest,verifyRoster}=await import('../managed-cloud/shared/roster.ts'),{checkpoint,genesisRoot}=await import('../managed-cloud/shared/checkpoints.ts');
 const db=new Database(':memory:');for(const name of migrations.filter(n=>n<'0017'))db.exec(readFileSync(new URL(name,directory),'utf8'));
 const active=sodium.crypto_sign_keypair(),revoked=sodium.crypto_sign_keypair(),cpKey=sodium.crypto_sign_keypair(),b=(v:Uint8Array)=>Buffer.from(v).toString('base64');
 db.exec("INSERT INTO accounts VALUES('a'); INSERT INTO tenants VALUES('t'); INSERT INTO memberships VALUES('t','a',1); INSERT INTO vaults VALUES('t','v',0)");
 db.run("INSERT INTO devices VALUES('t','active','a',?,1),('t','revoked','a',?,1)",[b(active.publicKey),b(revoked.publicKey)]);
 db.exec("INSERT INTO vault_devices VALUES('t','v','active',1),('t','v','revoked',0)");
 const wrapA=b(sodium.crypto_box_keypair().publicKey),wrapB=b(sodium.crypto_box_keypair().publicKey);db.run("INSERT INTO device_keys VALUES('t','active',?),('t','revoked',?)",[wrapA,wrapB]);
 db.exec("INSERT INTO recovery_packages_v1 VALUES('package','t','v','a',1,'{}','synthetic',1)");
 for(const state of ['prepared','released','completed','cancelled'])db.run('INSERT INTO recovery_sagas(id,tenant_id,vault_id,account_id,package_id,canonical,request_digest,session_digest,state,not_before,expires_at,proof_digest,challenge) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',[state,'t','v','a','package','{}',state,'snapshot',state,1,2,'synthetic','{}']);
 const before=JSON.stringify(db.query('SELECT * FROM recovery_sagas ORDER BY id').all());
 for(const name of migrations.filter(n=>n>='0017'&&n<'0020'))db.exec(readFileSync(new URL(name,directory),'utf8'));
 expect(JSON.stringify(db.query('SELECT * FROM recovery_sagas ORDER BY id').all())).toBe(before);
 const pin={keyId:'checkpoint',publicKey:b(cpKey.publicKey)},cp=await checkpoint({key:async()=>pin,sign:async c=>b(sodium.crypto_sign_detached(c,cpKey.privateKey))},'t','v',0,await genesisRoot('t','v'),null,null),now=Math.floor(Date.now()/1000);
 const canonical=canonicalRoster({version:1,accountId:'a',tenantId:'t',vaultId:'v',revision:1,previousDigest:null,keyEpoch:1,active:[{deviceId:'active',signingKey:b(active.publicKey),wrappingKey:wrapA}],revoked:[{deviceId:'revoked',signingKey:b(revoked.publicKey),wrappingKey:wrapB,revokedRevision:1,acceptedThrough:cp}],issuer:{kind:'device',id:'active'},issuedAt:now,expiresAt:now+3600,checkpointKeys:[pin],recoveryAuthorities:[],recovery:null});
 const signed={canonical,signature:b(sodium.crypto_sign_detached(ROSTER_DOMAIN+canonical,active.privateKey))};expect((await verifyRoster(signed,null,now,true)).revoked).toHaveLength(1);
 db.run("INSERT INTO signed_rosters VALUES('t','v','a',1,?,NULL,'active',?,?)",[await rosterDigest(signed),canonical,signed.signature]);expect(db.query('SELECT count(*) n FROM signed_rosters').get()).toEqual({n:1});db.close();
});
test('every incremental 0001–0016 backup restores and upgrades without losing active/revoked devices',()=>{
 for(let prefix=1;prefix<=16;prefix++){
  let db=new Database(':memory:');
  for(const name of migrations.slice(0,prefix))db.exec(readFileSync(new URL(name,directory),'utf8'));
  db.exec("INSERT INTO accounts VALUES('snapshot'); INSERT INTO tenants VALUES('tenant'); INSERT INTO memberships VALUES('tenant','snapshot',1); INSERT INTO vaults VALUES('tenant','vault',0); INSERT INTO devices VALUES('tenant','active','snapshot','key-active',1),('tenant','revoked','snapshot','key-revoked',0); INSERT INTO vault_devices VALUES('tenant','vault','active',1),('tenant','vault','revoked',0)");
  const backup=db.serialize();db.close();db=Database.deserialize(backup);
  for(const name of migrations.slice(prefix).filter(n=>n<'0017'))db.exec(readFileSync(new URL(name,directory),'utf8'));
  for(const state of ['pending','approved','denied','cancelled'])db.run("INSERT INTO approval_requests(tenant_id,vault_id,id,account_id,device_id,action,object_id,request_digest,expires_at,state) VALUES('tenant','vault',?,'snapshot','active','put','object',?,9999999999,?)",[state,state,state]);
  const approvals=JSON.stringify(db.query('SELECT * FROM approval_requests ORDER BY ordinal').all());
  for(const name of migrations.filter(n=>n>='0017'&&n<'0020'))db.exec(readFileSync(new URL(name,directory),'utf8'));
  expect(JSON.stringify(db.query('SELECT * FROM approval_requests ORDER BY ordinal').all())).toBe(approvals);
  expect(db.query('SELECT device_id,sequence FROM device_revocation_boundaries').all()).toEqual([{device_id:'revoked',sequence:0}]);
  expect(db.query('PRAGMA foreign_key_check').all()).toEqual([]);db.close();
 }
});

test('last-device upgrade preserves legacy package bytes without inventing readiness',()=>{
 const db=new Database(':memory:');for(const name of migrations.filter(n=>n<'0022'))db.exec(readFileSync(new URL(name,directory),'utf8'));
 db.exec("INSERT INTO accounts VALUES('a');INSERT INTO tenants VALUES('t');INSERT INTO memberships VALUES('t','a',1);INSERT INTO vaults VALUES('t','v',0);INSERT INTO devices VALUES('t','d','a','synthetic',1);INSERT INTO vault_devices VALUES('t','v','d',1);INSERT INTO recovery_packages_v1 VALUES('p','t','v','a',1,'{}','synthetic-signature',1)");
 const before=JSON.stringify(db.query('SELECT * FROM recovery_packages_v1').all());
 for(const name of migrations.filter(n=>n>='0022'))db.exec(readFileSync(new URL(name,directory),'utf8'));
 expect(JSON.stringify(db.query('SELECT * FROM recovery_packages_v1').all())).toBe(before);
 expect(db.query('SELECT * FROM recovery_readiness').all()).toEqual([]);
 expect(db.query('SELECT device_id,package_id FROM last_device_vaults').all()).toEqual([{device_id:'d',package_id:null}]);
 expect(db.query('PRAGMA foreign_key_check').all()).toEqual([]);db.close();
});
