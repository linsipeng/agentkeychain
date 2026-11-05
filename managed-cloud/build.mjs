import { build } from 'esbuild';
await build({entryPoints:['api-worker/index.ts','recovery-worker/index.ts'], outdir:'dist', outbase:'.', bundle:true, format:'esm', platform:'neutral', external:['cloudflare:workers','node:buffer'], target:'es2022'});
