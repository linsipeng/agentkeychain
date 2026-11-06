import {bootstrap} from './bootstrap.ts';
process.env.AGENTKEYCHAIN_HOME=bootstrap.home;
process.env.AKC_KEYCHAIN_TEST_MODE='1';
delete process.env.AKC_PASSWORD;
await import('../../src/cli/index.ts');
