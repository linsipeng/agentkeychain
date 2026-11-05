import { execFileSync } from 'node:child_process';
execFileSync(process.execPath,['node_modules/vite/bin/vite.js','build','web'],{stdio:'inherit'});
import { build } from 'esbuild';
await build({entryPoints:['api-worker/index.ts','recovery-worker/index.ts'], outdir:'dist', outbase:'.', bundle:true, format:'esm', platform:'neutral', mainFields:['module','main'], external:['cloudflare:workers','node:buffer'], target:'es2022'});
