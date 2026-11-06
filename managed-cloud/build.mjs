import { execFileSync } from 'node:child_process';
execFileSync(process.execPath,['node_modules/vite/bin/vite.js','build','web'],{stdio:'inherit'});
import { build } from 'esbuild';
await build({entryPoints:['api-worker/index.ts','recovery-worker/index.ts','auth-trust-worker/index.ts','api-trust-worker/index.ts','custody-trust-worker/index.ts'], outdir:'dist', outbase:'.', bundle:true, format:'esm', platform:'neutral', mainFields:['module','main'], external:['cloudflare:workers','cloudflare:email','node:buffer','node:net'], target:'es2022'});
