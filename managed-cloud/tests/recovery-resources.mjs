/** Capture host workerd diagnostics; a Worker console spy cannot see these. */
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
const run = spawnSync(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', 'tests/recovery.spec.ts', '--testNamePattern', 'completed two-Worker recovery publishes|public email recovery completes|completion response loss resumes|two real Workers|partial RPC failure|aged no-device|activation failure after custody|RPC data ownership'], {
    cwd: new URL('..', import.meta.url), encoding: 'utf8',
    env: {...process.env, PWD: new URL('..', import.meta.url).pathname, CI: '1', WRANGLER_SEND_METRICS: 'false'},
});
const output = (run.stdout ?? '') + (run.stderr ?? '');
process.stdout.write(output);
assert.equal(run.status, 0, 'Recovery resource regression must execute successfully');
assert.match(output, /[1-9]\d* passed/, 'Must execute recovery tests');
assert.doesNotMatch(output, /RPC result was not disposed|undisposed|not disposed properly/i, 'Recovery resources must be released, including successful RPC followed by a negative exception');
console.log('Recovery resource diagnostics: no undisposed-resource warning.');
