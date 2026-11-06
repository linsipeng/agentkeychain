import {buildNative} from './build-native.ts';
/** Release-only build. Public signing root and signed manifest are explicit build inputs.
 * This never accepts runtime environment configuration or signs an artifact itself. */
import {readFile} from 'node:fs/promises';
import {resolve,dirname,join} from 'node:path';
import {verifyReleaseManifest} from '../src/cloud/config.ts';
import type {SignedManagedOperation} from '../src/cloud/protocol.ts';
const args=process.argv.slice(2);
const option=(name:string)=>{const at=args.indexOf(name);return at>=0?args[at+1]:undefined;};
const manifestPath=option('--manifest'),rootPath=option('--root-public-key'),outfile=option('--outfile');
if(!manifestPath||!rootPath||!outfile)throw new Error('cloud_unavailable_not_provisioned: release requires --manifest, --root-public-key and --outfile');
const manifest=JSON.parse(await readFile(manifestPath,'utf8')) as SignedManagedOperation;
const rootPublicKey=(await readFile(rootPath,'utf8')).trim(),root=Buffer.from(rootPublicKey,'base64');
if(root.toString('base64')!==rootPublicKey)throw new Error('invalid_release_root');
if(!verifyReleaseManifest(manifest,root).witnessKeys?.length)throw new Error('cloud_witness_not_provisioned');
const artifact={manifest,rootPublicKey};
const result=await Bun.build({entrypoints:[resolve('src/cli/index.ts')],compile:{outfile:resolve(outfile)},plugins:[{name:'verified-release-trust',setup(build){build.onLoad({filter:/release\.generated\.ts$/},()=>({contents:`export function releaseArtifact(){return ${JSON.stringify(artifact)};}`,loader:'ts'}));}}]});
if(!result.success)throw new Error('release_build_failed');

await buildNative(join(dirname(resolve(outfile)),'agentkeychain-secure-store'));
