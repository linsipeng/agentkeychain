import {expect,test} from 'bun:test';
import {Database,constants as sqlite} from 'bun:sqlite';
import {closeSync,constants,fstatSync,linkSync,lstatSync,mkdtempSync,openSync,realpathSync,rmSync,symlinkSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

test('Linux descriptor-relative exclusive child creation is safe, but SQLite no-follow cannot open the procfd path',()=>{
 if(process.platform!=='linux'||!process.getuid?.())return;
 const root=realpathSync.native(mkdtempSync(join(tmpdir(),'akc-pilot-native-test-')));
 const parent=openSync(root,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
 let child:number|undefined;
 try{
  const sibling=join(root,'unrelated-fixture');
  writeFileSync(sibling,'unchanged sample',{mode:0o600});
  const profile=join('/proc/self/fd',String(parent),'profile.sqlite');
  // The fixture only probes Unix flags in a throwaway directory, never the
  // installed profile or an existing SQLite file. No application keys.
  symlinkSync(sibling,join(root,'profile.sqlite'));
  const create=()=>openSync(profile,constants.O_RDWR|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  expect(create).toThrow();
  rmSync(join(root,'profile.sqlite'));
  linkSync(sibling,join(root,'profile.sqlite'));
  expect(create).toThrow();
  rmSync(join(root,'profile.sqlite'));
  expect(readFileSync(sibling,'utf8')).toBe('unchanged sample');
  child=create();
  const opened=fstatSync(child,{bigint:true}),named=lstatSync(profile,{bigint:true});
  expect([named.dev,named.ino]).toEqual([opened.dev,opened.ino]);
  expect(opened.isFile()).toBe(true);expect(opened.nlink).toBe(1n);expect(opened.mode&0o777n).toBe(0o600n);
  // Keep this real runtime regression until a descriptor-based VFS can meet
  // the requirement. Never retry without the NOFOLLOW flag or by ordinary path.
  let db:Database|undefined;
  try{
   expect(()=>{db=new Database(profile,sqlite.SQLITE_OPEN_READWRITE|sqlite.SQLITE_OPEN_NOFOLLOW);})
    .toThrow(expect.objectContaining({code:'SQLITE_CANTOPEN_SYMLINK'}));
  }finally{db?.close();}
 }finally{
  if(child!==undefined)closeSync(child);
  closeSync(parent);rmSync(root,{recursive:true,force:true});
 }
});
