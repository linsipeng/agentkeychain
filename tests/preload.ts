// Fail closed for every direct or scripted `bun test` run. Keychain tests must
// inject explicit stub binaries; test code may never discover host keychain
// commands through PATH.
process.env["AKC_KEYCHAIN_TEST_MODE"] = "1";