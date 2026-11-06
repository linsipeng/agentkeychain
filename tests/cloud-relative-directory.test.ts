import {test,expect} from 'bun:test';
import {mkdtempSync,mkdirSync,renameSync,symlinkSync,openSync,closeSync,constants,writeFileSync,readFileSync,existsSync,rmSync,fstatSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {RelativeDirectory} from '../src/platform/relative-directory.ts';
test('directory-relative publication and cleanup remain on the opened inode after parent substitution',()=>{
 const root=mkdtempSync(join(tmpdir(),'akc-dirfd-')),parent=join(root,'parent'),moved=join(root,'moved'),other=join(root,'other');mkdirSync(parent);mkdirSync(other);
 const fd=openSync(parent,constants.O_RDONLY|constants.O_DIRECTORY),relative=new RelativeDirectory(fd,parent);
 try{
  const file=relative.open(join(parent,'stage'),constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY);writeFileSync(file,'encrypted-test');expect(fstatSync(file).mode&0o777).toBe(0o600);closeSync(file);
  renameSync(parent,moved);symlinkSync(other,parent);writeFileSync(join(other,'stage'),'unrelated');
  relative.link(join(parent,'stage'),join(parent,'final'));relative.unlink(join(parent,'stage'));
  expect(readFileSync(join(moved,'final'),'utf8')).toBe('encrypted-test');expect(readFileSync(join(other,'stage'),'utf8')).toBe('unrelated');expect(existsSync(join(other,'final'))).toBe(false);
  expect(()=>relative.link(join(parent,'final'),join(parent,'final'))).toThrow();expect(()=>relative.open(join(parent,'../other/stage'),constants.O_RDONLY)).toThrow();
 }finally{closeSync(fd);rmSync(root,{recursive:true,force:true});}
});
