// Compiled platform-injection acceptance only; never imported by the release CLI.
import {runCloud} from '../../src/cli/cloud.ts';
import {runExport} from '../../src/cli/export.ts';
try{if(process.argv[2]==='export')await runExport(process.argv.slice(3),'win32');else await runCloud(process.argv.slice(2),'win32');process.exit(2);}catch(error){if(!(error instanceof Error)||error.message!=='cloud_platform_unsupported')process.exit(3);process.exit(0);}
