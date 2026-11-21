import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {lstat,mkdir,mkdtemp,readFile,readdir,rename,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalManifest,verifyReleaseManifest} from '../src/cloud/config.ts';
import type {SignedManagedOperation} from '../src/cloud/protocol.ts';
import {VERSION} from '../src/index.ts';

const targets=['darwin-arm64','darwin-x64','linux-arm64','linux-x64'] as const;
const checksums='SHA256SUMS';
const expectedAssets=[...targets.map(target=>'agentkeychain-'+target),
 'agentkeychain-secure-store-darwin-arm64','agentkeychain-secure-store-darwin-x64'].sort();
const [command,targetOrDir,maybeDir]=process.argv.slice(2);
function capture(binary:string,args:string[],env:Record<string,string|undefined>) {
 const result=spawnSync(binary,args,{encoding:'utf8',env});
 if(result.status!==0)throw new Error('invalid_release_binary_metadata');
 return result.stdout.trim();
}

async function build(kind:'candidate'|'tagged',target:string,outdir:string) {
 if(!targets.some(value=>value===target)||target!==process.platform+'-'+process.arch)throw new Error('wrong_release_runner');
 const pkg=JSON.parse(await readFile('package.json','utf8')) as {version:string};
 if(pkg.version!==VERSION)throw new Error('release_version_mismatch');
 const work=await mkdtemp(join(tmpdir(),'akc-release-package-'));
 try{
  let manifest:SignedManagedOperation,rootPublicKey:string,releaseId:string;
  if(kind==='candidate'){
   const root=sodium.crypto_sign_keypair();
   const publicKey=(key:Uint8Array)=>Buffer.from(key).toString('base64');
   const pin=(keyId:string)=>{const key=sodium.crypto_sign_keypair();try{return {keyId,publicKey:publicKey(key.publicKey)};}finally{key.privateKey.fill(0);}};
   releaseId='candidate-fixture';
   try{
    const canonical=canonicalManifest({version:1,releaseId,apiOrigin:'https://api.candidate.invalid',webOrigin:'https://candidate.invalid',
     protocolMin:2,protocolMax:2,checkpointKeys:[pin('checkpoint')],witnessKeys:[pin('witness')]});
    manifest={canonical,signature:Buffer.from(sodium.crypto_sign_detached(canonical,root.privateKey)).toString('base64')};
    rootPublicKey=publicKey(root.publicKey);
   }finally{root.privateKey.fill(0);}
  }else{
   const tag=process.env.GITHUB_REF_NAME;
   if(process.env.GITHUB_EVENT_NAME!=='push'||process.env.GITHUB_REF_TYPE!=='tag'||
     !tag||!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag)||tag!=='v'+VERSION)throw new Error('explicit_release_tag_required');
   const encoded=process.env.AKC_RELEASE_MANIFEST,root=process.env.AKC_RELEASE_ROOT_PUBLIC_KEY,id=process.env.AKC_RELEASE_ID;
   if(!encoded||!root||!id)throw new Error('approved_release_policy_required');
   manifest=JSON.parse(encoded) as SignedManagedOperation;
   const policy=verifyReleaseManifest(manifest,Buffer.from(root,'base64'));
   if(policy.releaseId!==id||/candidate|fixture|staging/i.test(id)||
      [policy.apiOrigin,policy.webOrigin].some(origin=>new URL(origin).hostname.endsWith('.invalid'))||
      !policy.recoveryAuthorities?.length||!policy.recoveryServices||!policy.witnessKeys?.length)
     throw new Error('invalid_production_release_policy');
   rootPublicKey=root;releaseId=id;
  }

  const fixture=join(work,'empty'),stage=join(work,'assets');
  await mkdir(fixture,{mode:0o700});await mkdir(stage);
  const env={PATH:process.env.PATH!,DEVELOPER_DIR:process.env.DEVELOPER_DIR,
    TMPDIR:work,HOME:fixture,AGENTKEYCHAIN_HOME:fixture,AKC_KEYCHAIN_TEST_MODE:'1'};
  const manifestPath=join(work,'manifest.json'),rootPath=join(work,'root-public-key');
  await writeFile(manifestPath,JSON.stringify(manifest),{mode:0o600});
  await writeFile(rootPath,rootPublicKey,{mode:0o600});
  const asset='agentkeychain-'+target,cli=join(stage,asset);
  const result=spawnSync(process.execPath,['scripts/build-release.ts','--manifest',manifestPath,'--root-public-key',rootPath,'--outfile',cli],{env,stdio:'inherit'});
  if(result.status!==0)throw new Error('release_package_build_failed');
  const compatibility=JSON.parse(capture(cli,['cloud','compatibility','--json'],env)) as {nativeHelper:string;helperABI:number;helperVersion:string};
  if(capture(cli,['--version'],env)!=='agentkeychain v'+VERSION||
     compatibility.nativeHelper!==(process.platform==='darwin'?'required':'none'))throw new Error('incompatible_release_binary');
  const state=JSON.parse(capture(cli,['cloud','status','--json'],env)) as {releaseId?:string};
  if(state.releaseId!==releaseId)throw new Error('wrong_embedded_release_policy');
  if(process.platform==='darwin'){
   const helper=join(stage,'agentkeychain-secure-store'),native=JSON.parse(capture(helper,['--compatibility'],env)) as {helperABI:number;helperVersion:string};
   if(native.helperABI!==compatibility.helperABI||native.helperVersion!==compatibility.helperVersion)throw new Error('incompatible_native_helper');
   const arch=process.arch==='arm64'?'arm64':'x86_64';
   if(capture('/usr/bin/lipo',['-archs',cli],env)!==arch||capture('/usr/bin/lipo',['-archs',helper],env)!==arch)throw new Error('wrong_release_binary_architecture');
   await rename(helper,join(stage,'agentkeychain-secure-store-'+target));
  }
  await mkdir(outdir,{recursive:true});
  for(const name of await readdir(stage))await Bun.write(join(outdir,name),Bun.file(join(stage,name)));
 }finally{await rm(work,{recursive:true,force:true});}
}

async function exactChecksums(directory:string,verify:boolean) {
 const names=(await readdir(directory)).sort();
 const expected=(verify?[...expectedAssets,checksums]:expectedAssets.slice()).sort();
 if(JSON.stringify(names)!==JSON.stringify(expected))throw new Error('unexpected_release_asset_set');
 const lines=[];
 for(const name of expectedAssets){
  const path=join(directory,name),stat=await lstat(path);
  if(!stat.isFile()||!stat.size)throw new Error('invalid_release_asset:'+name);
  const hash=createHash('sha256');
  for await(const chunk of createReadStream(path))hash.update(chunk);
  lines.push(hash.digest('hex')+'  '+name+'\n');
 }
 const output=lines.join(''),manifest=join(directory,checksums);
 if(verify){
  if(!(await lstat(manifest)).isFile()||await readFile(manifest,'utf8')!==output)throw new Error('invalid_release_asset_checksums');
 }else await writeFile(manifest,output,{flag:'wx'});
}

if((command==='candidate'||command==='tagged')&&targetOrDir&&maybeDir)await build(command,targetOrDir,resolve(maybeDir));
else if((command==='manifest'||command==='verify')&&targetOrDir&&!maybeDir)await exactChecksums(resolve(targetOrDir),command==='verify');
else throw new Error('usage: package-release.ts candidate|tagged <target> <dir> | manifest|verify <dir>');
