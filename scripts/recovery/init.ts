import {Database} from 'bun:sqlite';
import {readFileSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,sep} from 'node:path';
import {migrate} from '../../src/db/migrate.ts';
import {initVault} from '../../src/cli/init.ts';
const {home,password}=JSON.parse(readFileSync(0,'utf8')) as {home:string;password:string};
if(!realpathSync(home).startsWith(realpathSync(tmpdir())+sep))throw new Error('test_home_required');
const db=new Database(join(home,'vault.db'));try{migrate(db);await initVault(db,password);}finally{db.close();}
