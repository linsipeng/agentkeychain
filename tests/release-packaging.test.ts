import {expect,test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const assets=['agentkeychain-darwin-arm64','agentkeychain-darwin-x64','agentkeychain-linux-arm64',
 'agentkeychain-linux-x64','agentkeychain-secure-store-darwin-arm64','agentkeychain-secure-store-darwin-x64'];
const run=(args:string[],env:Record<string,string|undefined>={PATH:process.env.PATH!,TMPDIR:tmpdir()})=>
 spawnSync(process.execPath,['scripts/package-release.ts',...args],{encoding:'utf8',env});

test('release files have an exact installer-compatible manifest; missing and tampered helpers fail closed',()=>{
 const dir=mkdtempSync(join(tmpdir(),'akc-package-test-'));
 try{
  for(const asset of assets.slice(0,-1))writeFileSync(join(dir,asset),'fixture-'+asset);
  expect(run(['manifest',dir]).status).not.toBe(0);
  const last=assets.at(-1)!,helper=join(dir,last);
  symlinkSync(join(dir,assets[0]!),helper);
  expect(run(['manifest',dir]).status).not.toBe(0);
  rmSync(helper);writeFileSync(helper,'fixture-'+last);
  writeFileSync(join(dir,'extra'),'not a release file');
  expect(run(['manifest',dir]).status).not.toBe(0);
  rmSync(join(dir,'extra'));
  expect(run(['manifest',dir]).status).toBe(0);
  expect(readFileSync(join(dir,'SHA256SUMS'),'utf8').trim().split('\n').map(line=>line.split('  ')[1])).toEqual(assets);
  expect(run(['verify',dir]).status).toBe(0);
  writeFileSync(helper,'tampered');
  expect(run(['verify',dir]).status).not.toBe(0);
 }finally{rmSync(dir,{recursive:true,force:true});}
});

test('tagged production packing rejects PRs, branches, malformed tags, and missing release policy',()=>{
 const dir=mkdtempSync(join(tmpdir(),'akc-package-tag-test-'));
 const target=process.platform+'-'+process.arch;
 // The release gate targets supported POSIX platforms only.
 if(process.platform!=='darwin'&&process.platform!=='linux'){rmSync(dir,{recursive:true});return;}
 try{
  const version=(JSON.parse(readFileSync('package.json','utf8')) as {version:string}).version;
  const validTag='v'+version;
  const env={PATH:process.env.PATH!,TMPDIR:tmpdir(),GITHUB_EVENT_NAME:'push',GITHUB_REF_TYPE:'tag',GITHUB_REF_NAME:validTag};
  for(const bad of [{GITHUB_EVENT_NAME:'pull_request'},{GITHUB_REF_TYPE:'branch'},{GITHUB_REF_NAME:validTag+'-rc'},{GITHUB_REF_NAME:'v999.0.0'}]){
   expect(run(['tagged',target,dir],{...env,...bad}).stderr).toContain('explicit_release_tag_required');
  }
  expect(run(['tagged',target,dir],env).stderr).toContain('approved_release_policy_required');
 }finally{rmSync(dir,{recursive:true,force:true});}
});
