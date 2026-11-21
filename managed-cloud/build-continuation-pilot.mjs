/** Explicit, nondefault build. Generates a Worker bundle, never deploys it. */
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
const root=fileURLToPath(new URL('./',import.meta.url));
const bundle=await build({absWorkingDir:root,entryPoints:['web/src/continuation-approval-browser.ts'],
 bundle:true,format:'esm',platform:'browser',write:false,target:'es2022'});
const genesisBrowser=await build({absWorkingDir:root,entryPoints:['web/src/pilot-genesis-browser.ts'],
 bundle:true,format:'esm',platform:'browser',write:false,target:'es2022'});
await build({absWorkingDir:root,entryPoints:['auth-trust-worker/pilot-continuation.ts'],
 outfile:'dist/auth-trust-worker/pilot-continuation.js',bundle:true,format:'esm',platform:'neutral',
 mainFields:['module','main'],external:['cloudflare:workers','cloudflare:email','node:buffer','node:net'],
 target:'es2022',define:{AKC_PILOT_BROWSER_BUNDLE:JSON.stringify(bundle.outputFiles[0].text),AKC_PILOT_GENESIS_BROWSER_BUNDLE:JSON.stringify(genesisBrowser.outputFiles[0].text)}});
await build({absWorkingDir:root,entryPoints:['api-worker/pilot-continuation-main.ts'],
 outfile:'dist/api-worker/pilot-continuation-post.js',bundle:true,format:'esm',platform:'neutral',
 mainFields:['module','main'],external:['cloudflare:workers','cloudflare:email','node:buffer','node:net'],target:'es2022'});
await build({absWorkingDir:root,entryPoints:['custody-trust-worker/pilot-continuation.ts'],
 outfile:'dist/custody-trust-worker/pilot-continuation.js',bundle:true,format:'esm',platform:'neutral',
 mainFields:['module','main'],external:['cloudflare:workers','node:buffer'],target:'es2022'});
