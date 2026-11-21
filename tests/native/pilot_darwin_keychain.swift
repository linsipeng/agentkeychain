// Standalone synthetic native acceptance. Never installed or compiled into the CLI.
// Opens two pre-created disposable file-based Keychains. Does not create,
// delete, unlock, configure, enumerate their contents, or change any search list.
import Foundation
import Security
import Darwin

enum GateFailure: Error { case denied, mismatch, unexpectedStatus }
func require(_ value: Bool) throws { if !value { throw GateFailure.denied } }
func signedStatus(_ status: OSStatus) throws { if status != errSecSuccess { throw GateFailure.unexpectedStatus } }

func keychainPath(_ keychain: SecKeychain) throws -> String {
 var size: UInt32 = UInt32(PATH_MAX)
 var chars = [CChar](repeating: 0, count: Int(size))
 try chars.withUnsafeMutableBufferPointer { buffer in
  guard let ptr = buffer.baseAddress else { throw GateFailure.denied }
  try signedStatus(SecKeychainGetPath(keychain, &size, ptr))
 }
 guard let end = chars.firstIndex(of: 0), end > 0, end < chars.count else { throw GateFailure.denied }
 let bytes = chars[..<end].map { UInt8(bitPattern: $0) }
 guard let path = String(bytes: bytes, encoding: .utf8) else { throw GateFailure.denied }
 return path
}

func snapshot() throws -> [String] {
 // Observe configuration only, never read default items. Return it only for
 // before/after comparison in this process and never print paths.
 var list: CFArray?
 try signedStatus(SecKeychainCopySearchList(&list))
 guard let entries = list as? [SecKeychain] else { throw GateFailure.denied }
 var standard: SecKeychain?
 let status = SecKeychainCopyDefault(&standard)
 guard status == errSecNoDefaultKeychain || status == errSecSuccess else { throw GateFailure.unexpectedStatus }
 if status == errSecSuccess && standard == nil { throw GateFailure.denied }
 return [try standard.map(keychainPath) ?? ""] + (try entries.map(keychainPath))
}

func privateMetadata(_ path: String, directory: Bool) throws -> stat {
 var row = stat()
 try require(path.withCString { lstat($0, &row) } == 0)
 let type = directory ? S_IFDIR : S_IFREG
 try require((row.st_mode & mode_t(S_IFMT)) == mode_t(type) &&
             row.st_uid == geteuid() &&
             (row.st_mode & 0o7777) == (directory ? 0o700 : 0o600) &&
             (directory || row.st_nlink == 1))
 return row
}

struct Fixture {
 let path: String
 let keychain: SecKeychain
 let device: dev_t
 let inode: ino_t
 let expectedService: String

 init(directory: String, basename: String, outside: [String], expectedService: String) throws {
  try require(["pilot-primary.keychain-db", "pilot-sibling.keychain-db"].contains(basename))
  let path = directory + "/" + basename
  let row = try privateMetadata(path, directory: false)
  try require(!outside.contains(path))
  for candidate in outside where !candidate.isEmpty {
   // A fixture may not alias an existing/default search-list database.
   var known = stat()
   if candidate.withCString({ lstat($0, &known) }) == 0 {
    try require(known.st_dev != row.st_dev || known.st_ino != row.st_ino)
   }
  }
  var selected: SecKeychain?
  try signedStatus(path.withCString { SecKeychainOpen($0, &selected) })
  guard let loaded = selected else { throw GateFailure.denied }
  self.path = path
  self.keychain = loaded
  self.device = row.st_dev
  self.inode = row.st_ino
  self.expectedService = expectedService
  try recheck()
 }

 func recheck() throws {
  let row = try privateMetadata(path, directory: false)
  let explicit = try keychainPath(keychain)
  try require(row.st_dev == device && row.st_ino == inode && explicit == path)
  var status: SecKeychainStatus = 0
  try signedStatus(SecKeychainGetStatus(keychain, &status))
  let expected = kSecUnlockStateStatus | kSecReadPermStatus | kSecWritePermStatus
  try require((status & expected) == expected)
 }

 func attributes(service: String, account: String) throws -> [String: Any] {
  try recheck()
  try require(service == expectedService && service.range(of: #"^agentkeychain\.pilot\.[a-f0-9]{64}$"#, options: .regularExpression) != nil &&
              account == "synthetic-acceptance-marker")
  return [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
          kSecAttrAccount as String: account]
 }

 func add(_ service: String, _ account: String, _ value: Data) throws {
  var item = try attributes(service: service, account: account)
  item[kSecUseKeychain as String] = keychain
  item[kSecValueData as String] = value
  try signedStatus(SecItemAdd(item as CFDictionary, nil))
 }

 func read(_ service: String, _ account: String) throws -> Data? {
  var query = try attributes(service: service, account: account)
  query[kSecMatchSearchList as String] = [keychain]
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  query[kSecReturnData as String] = true
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  if status == errSecItemNotFound { return nil }
  try signedStatus(status)
  guard let bytes = result as? Data else { throw GateFailure.mismatch }
  return bytes
 }

 func remove(_ service: String, _ account: String) throws {
  var query = try attributes(service: service, account: account)
  query[kSecMatchSearchList as String] = [keychain]
  try signedStatus(SecItemDelete(query as CFDictionary))
 }
}

func run() throws {
 // Explicitly gated to a GitHub-hosted disposable account; marker is a
 // guard, not a substitute for operator/runner isolation. CI never runs this.
 let env = ProcessInfo.processInfo.environment
 try require(CommandLine.arguments.count == 2 && getuid() != 0 && getuid() == geteuid() &&
             env["GITHUB_ACTIONS"] == "true" && env["RUNNER_ENVIRONMENT"] == "github-hosted" &&
             env["AKC_DISPOSABLE_DARWIN_FIXTURE"] == "explicit-two-keychains-v1")
 let root = CommandLine.arguments[1]
 let url = URL(fileURLWithPath: root, isDirectory: true)
 try require(root.hasPrefix("/") && url.resolvingSymlinksInPath().path == root &&
             url.lastPathComponent.range(of: #"^akc-pilot-native-[a-f0-9]{32}$"#, options: .regularExpression) != nil)
 _ = try privateMetadata(root, directory: true)
 var aliases = Set<String>()
 let before = try snapshot()
 for configured in before where !configured.isEmpty {
  aliases.insert(configured)
  aliases.insert(URL(fileURLWithPath: configured).resolvingSymlinksInPath().path)
 }
 // Same random synthetic namespace and exact slot in both stores. This
 // isolates the keychain boundary independently of the namespace check.
 let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() +
              UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
 let service = "agentkeychain.pilot." + suffix
 try require(suffix != String(repeating: "0", count: 64))
 let one = try Fixture(directory: root, basename: "pilot-primary.keychain-db", outside: Array(aliases), expectedService: service)
 let two = try Fixture(directory: root, basename: "pilot-sibling.keychain-db", outside: Array(aliases), expectedService: service)
 try require(one.device != two.device || one.inode != two.inode)
 let slot = "synthetic-acceptance-marker", first = Data("synthetic-primary".utf8), second = Data("synthetic-sibling".utf8)
 // Check local policy without submitting an ordinary namespace to Security.
 do { _ = try one.attributes(service: "agentkeychain.vault", account: "master-password"); throw GateFailure.mismatch }
 catch GateFailure.denied { }
 do { _ = try one.attributes(service: "agentkeychain.pilot." + String(repeating: "0", count: 64), account: slot); throw GateFailure.mismatch }
 catch GateFailure.denied { }
 let initiallyOne = try one.read(service, slot), initiallyTwo = try two.read(service, slot)
 try require(initiallyOne == nil && initiallyTwo == nil)
 try one.add(service, slot, first)
 defer { try? one.remove(service, slot) }
 try require(try two.read(service, slot) == nil)
 try two.add(service, slot, second)
 defer { try? two.remove(service, slot) }
 let inOne = try one.read(service, slot), inTwo = try two.read(service, slot)
 try require(inOne == first && inTwo == second)
 try one.remove(service, slot)
 let cleared = try one.read(service, slot), unaffected = try two.read(service, slot)
 try require(cleared == nil && unaffected == second)
 try two.remove(service, slot)
 try require(try two.read(service, slot) == nil)
 try require(try snapshot() == before)
 print("PASS disposable Keychain: exact service, explicit store, isolated sibling and unchanged default/search list")
}

do { try run() } catch {
 FileHandle.standardError.write(Data("darwin_pilot_keychain_acceptance_denied\n".utf8))
 exit(1)
}
