import {expect,test} from 'bun:test';
import {Database} from 'bun:sqlite';
import {CloudStore} from '../src/cloud/persistence.ts';
import {MemorySecureStore} from '../src/platform/secure-store.ts';
import {randomBytes} from 'node:crypto';
import {migrate} from '../src/db/migrate.ts';
test('encrypted rows bind table/key and rollback transactions, preserve legacy bytes',()=>{
 const db=new Database(':memory:');migrate(db);
 db.run("INSERT INTO secrets VALUES('old',X'0102',X'0304','[]',NULL,1,1,1,NULL)");
 const before=JSON.stringify(db.query('SELECT * FROM secrets').all());
 const store=new CloudStore(db,randomBytes(32));
 expect(JSON.stringify(db.query('SELECT * FROM secrets').all())).toBe(before);
 store.put('state','one',{synthetic:'private-value'});expect(store.get('state','one')).toEqual({synthetic:'private-value'});
 expect(JSON.stringify(db.query('SELECT * FROM cloud_state').all()).includes('private-value')).toBe(false);
 db.run("UPDATE cloud_state SET id='two' WHERE id='one'");expect(()=>store.get('state','two')).toThrow();
 expect(()=>store.transaction(()=>{store.put('outbox','op',{secret:'test'});throw new Error('crash');})).toThrow();
 expect(store.all('outbox')).toEqual([]);
 db.close();
});
test('secure anchor rejects rollback and equal-sequence forks; leases fence stale owners',async()=>{
 const db=new Database(':memory:'),store=new CloudStore(db,randomBytes(32)),secure=new MemorySecureStore();
 await store.checkAnchor(secure,{sequence:2,root:'a'},[{sequence:2,root:'a'}],true);
 await expect(store.checkAnchor(secure,{sequence:1,root:'b'},[])).rejects.toThrow();
 await expect(store.checkAnchor(secure,{sequence:2,root:'b'},[])).rejects.toThrow();
 expect(store.acquireLease('first',100,1000)).toBe(true);expect(store.acquireLease('second',101,1000)).toBe(false);
 expect(store.acquireLease('second',1101,1000)).toBe(true);expect(()=>store.assertLease('first',1102)).toThrow();db.close();
});
import {mkdtempSync,linkSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
test('hard-linked and symlinked cloud databases are refused before cloud migration',()=>{
 const root=mkdtempSync(join(tmpdir(),'akc-cloud-links-')),path=join(root,'original.db');
 try{const original=new Database(path);migrate(original);original.close();linkSync(path,join(root,'hard.db'));symlinkSync(path,join(root,'sym.db'));
  for(const name of ['hard.db','sym.db']){const db=new Database(join(root,name));try{expect(()=>new CloudStore(db,randomBytes(32))).toThrow('unsafe_cloud_database');}finally{db.close();}}
  const db=new Database(path,{readonly:true});expect(db.query("SELECT 1 FROM sqlite_master WHERE name='cloud_state'").get()).toBeNull();db.close();
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('a missing independent checkpoint anchor is not silently re-created',async()=>{
 const db=new Database(':memory:'),store=new CloudStore(db,randomBytes(32));
 try{await expect(store.checkAnchor(new MemorySecureStore(),{sequence:0,root:'test'},[])).rejects.toThrow('cloud_checkpoint_anchor_missing');}finally{db.close();}
});
