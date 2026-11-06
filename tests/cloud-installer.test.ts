import {expect,test} from 'bun:test';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,statSync} from 'node:fs';
import {tmpdir,platform,arch} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
test('installer probes metadata before atomic executable replacement with no vault or service access',()=>{
 const root=mkdtempSync(join(tmpdir(),'akc-installer-')),stub=join(root,'stub'),target=join(root,'bin'),assets=join(root,'assets');for(const d of [stub,target,assets])mkdirSync(d,{mode:0o700});
 try{
  const asset=`agentkeychain-${platform()==='darwin'?'darwin':'linux'}-${arch()==='arm64'?'arm64':'x64'}`;
  const body='#!/bin/sh\nif [ "$1" = cloud ] && [ "$2" = compatibility ]; then\n  test "$(cat "$AKC_INSTALL_TEST_TARGET")" = old || exit 8\n  touch "$AKC_INSTALL_TEST_PROBED"\n  echo \'{"cloudSchema":1,"protocolMin":2,"protocolMax":2}\'\nelse echo synthetic; fi\n';
  writeFileSync(join(assets,asset),body);writeFileSync(join(assets,'SHA256SUMS'),createHash('sha256').update(body).digest('hex')+'  '+asset+'\n');writeFileSync(join(target,'agentkeychain'),'old',{mode:0o755});
  writeFileSync(join(stub,'curl'),'#!/bin/sh\n[ "$1" = -fsSL ] && [ "$2" = -o ] || exit 3\ncp "$AKC_INSTALL_TEST_ASSETS/${4##*/}" "$3"\n',{mode:0o755});
  const result=spawnSync('/bin/sh',['install.sh','--version','v-synthetic','--dir',target],{encoding:'utf8',env:{PATH:stub+':/usr/bin:/bin',HOME:root,AKC_INSTALL_TEST_ASSETS:assets,AKC_INSTALL_TEST_TARGET:join(target,'agentkeychain'),AKC_INSTALL_TEST_PROBED:join(root,'probed')}});
  expect(result.status).toBe(0);expect(readFileSync(join(target,'agentkeychain'),'utf8')).toBe(body);expect(statSync(join(root,'probed')).isFile()).toBe(true);expect(statSync(join(target,'agentkeychain')).mode&0o111).toBe(0o111);
 }finally{rmSync(root,{recursive:true,force:true});}
});
for(const fault of ['stop','binary','helper','restart','rollback','none'])test(`installer pair rollback: ${fault}`,()=>{
 const root=mkdtempSync(join(tmpdir(),'akc-pair-')),stub=join(root,'stub'),target=join(root,'bin'),assets=join(root,'assets');for(const d of [stub,target,assets])mkdirSync(d,{mode:0o700});
 try{
  const tag=`${platform()==='darwin'?'darwin':'linux'}-${arch()==='arm64'?'arm64':'x64'}`,asset='agentkeychain-'+tag,helper='agentkeychain-secure-store-'+tag;
  const old='#!/bin/sh\ncase "$3" in status) echo \'{"installed":true,"running":true}\';; stop) [ "$FAULT" != stop ] || exit 1;; start) echo restored >> "$LOG";; esac\n';
  const next='#!/bin/sh\nif [ "$2" = compatibility ]; then echo \'{"cloudSchema":1,"nativeHelper":"required","helperABI":1,"helperVersion":"1"}\'; elif [ "$3" = start ]; then [ "$FAULT" != restart ] && [ "$FAULT" != rollback ]; fi\n';
  const helperBody='#!/bin/sh\necho \'{"helperABI":1,"helperVersion":"1"}\'\n';
  writeFileSync(join(target,'agentkeychain'),old,{mode:0o755});writeFileSync(join(target,'agentkeychain-secure-store'),'old-helper',{mode:0o755});
  writeFileSync(join(assets,asset),next);writeFileSync(join(assets,helper),helperBody);writeFileSync(join(assets,'SHA256SUMS'),[[asset,next],[helper,helperBody]].map(([n,b])=>createHash('sha256').update(b!).digest('hex')+'  '+n+'\n').join(''));
  writeFileSync(join(stub,'curl'),'#!/bin/sh\ncp "$ASSETS/${4##*/}" "$3"\n',{mode:0o755});
  writeFileSync(join(stub,'mv'),'#!/bin/sh\nfor arg do dest="$arg"; done\ncase "$FAULT:$dest" in binary:*/agentkeychain|helper:*/agentkeychain-secure-store) if [ ! -f "$FAILED" ]; then touch "$FAILED"; exit 1; fi;; rollback:*) case "$*" in *restore*) exit 1;; esac;; esac\nexec /bin/mv "$@"\n',{mode:0o755});
  const result=spawnSync('/bin/sh',['install.sh','--version','v-synthetic','--dir',target],{encoding:'utf8',env:{PATH:stub+':/usr/bin:/bin',HOME:root,ASSETS:assets,FAULT:fault,LOG:join(root,'service-log'),FAILED:join(root,'failed')}});
  expect(result.status).toBe(fault==='none'?0:1);
  if(fault==='none'){expect(readFileSync(join(target,'agentkeychain'),'utf8')).toBe(next);expect(readFileSync(join(target,'agentkeychain-secure-store'),'utf8')).toBe(helperBody);}
  else if(fault==='rollback')expect(result.stderr).toContain('rollback failed');
  else{expect(readFileSync(join(target,'agentkeychain'),'utf8')).toBe(old);expect(readFileSync(join(target,'agentkeychain-secure-store'),'utf8')).toBe('old-helper');expect(readFileSync(join(root,'service-log'),'utf8')).toContain('restored');}
 }finally{rmSync(root,{recursive:true,force:true});}
});
