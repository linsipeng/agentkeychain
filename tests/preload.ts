// Fail closed for every direct or scripted `bun test` run. Keychain tests must
// inject explicit stub binaries inside an explicit isolated stub root; inherited
// host paths and credentials are removed before any test module loads.
process.env["AKC_KEYCHAIN_TEST_MODE"] = "1";
delete process.env["AKC_KEYCHAIN_SECURITY_BIN"];
delete process.env["AKC_KEYCHAIN_SECRET_TOOL_BIN"];
delete process.env["AKC_KEYCHAIN_TEST_STUB_ROOT"];
delete process.env["AGENTKEYCHAIN_HOME"];
delete process.env["AKC_PASSWORD"];
