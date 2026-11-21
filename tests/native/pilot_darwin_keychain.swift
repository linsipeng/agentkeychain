// Standalone synthetic native acceptance. Never installed or compiled into the CLI.
// Item checks use two explicit disposable file-based Keychains. Optional
// preparation is limited to two new private fixtures. No configuration mutators
// are called; an observed search-list/default delta causes failure.
import Foundation
import Security
import Darwin

// Closed enumeration only: do not reflect Error descriptions or arguments.
enum GatePhase: String {
 case argumentShape, runnerUID, runnerGitHub, runnerHosted, fixtureMode, rootCanonical, rootIdentity, scratchCanonical
 case ancestorStat, ancestorIdentity, ancestorSticky, ancestorModes, rootCreate, randomSource, randomShape
 case snapshotSearch, snapshotSearchDecode, snapshotDefault, snapshotDefaultDecode
 case fixtureBasename, fixtureAbsent, fixtureAlreadyExists, fixtureMetadata
 case filesystemType, filesystemOwner, filesystemPermissions, filesystemLinkCount
 case fixtureAlias, fixtureOpen, fixtureOpenRef, fixtureIdentity, fixturePairDistinct
 case securityPath, securityPathBuffer, securityPathEncoding, securityStatus, securityFlags
 case createBeforeSnapshot, createAfterSnapshot, createAPI, createRefPath, createMetadata
 case unlockAPI, unlockAfterSnapshot, unlockedFlags, provisionIdentity, provisionFinalSnapshot
 case provisionStatusBeforeUnlock, provisionStatusAfterUnlock
 case slotPolicy, itemAdd, itemRead, itemReadDecode, itemDelete
 case ordinaryPolicyCheck, otherNamespacePolicyCheck, itemsInitiallyAbsent, siblingInitiallyAbsent
 case itemsIndependent, siblingAfterPrimaryDeletion, siblingDeleted, finalSnapshot
}
enum GateFailure: Error {
 case denied(GatePhase), osStatus(GatePhase, OSStatus), posix(GatePhase, Int32)
 var message: String {
  switch self {
  case .denied(let phase): return "phase=" + phase.rawValue
  case .osStatus(let phase, let value): return "phase=" + phase.rawValue + " osstatus=" + String(value)
  case .posix(let phase, let value): return "phase=" + phase.rawValue + " errno=" + String(value)
  }
 }
}
func require(_ value: Bool, _ phase: GatePhase) throws { if !value { throw GateFailure.denied(phase) } }
func signedStatus(_ status: OSStatus, _ phase: GatePhase) throws {
 if status != errSecSuccess { throw GateFailure.osStatus(phase, status) }
}
// Read errno immediately after the failing syscall. No path is logged.
func syscallStatus(_ status: Int32, _ phase: GatePhase) throws {
 if status != 0 { throw GateFailure.posix(phase, errno) }
}

func keychainPath(_ keychain: SecKeychain) throws -> String {
 var size: UInt32 = UInt32(PATH_MAX)
 var chars = [CChar](repeating: 0, count: Int(size))
 try chars.withUnsafeMutableBufferPointer { buffer in
  guard let ptr = buffer.baseAddress else { throw GateFailure.denied(.securityPathBuffer) }
  try signedStatus(SecKeychainGetPath(keychain, &size, ptr), .securityPath)
 }
 guard let end = chars.firstIndex(of: 0), end > 0, end < chars.count else { throw GateFailure.denied(.securityPathBuffer) }
 let bytes = chars[..<end].map { UInt8(bitPattern: $0) }
 guard let path = String(bytes: bytes, encoding: .utf8) else { throw GateFailure.denied(.securityPathEncoding) }
 return path
}

func snapshot() throws -> [String] {
 // Observe configuration only, never read default items. Return it only for
 // before/after comparison in this process and never print paths.
 var list: CFArray?
 try signedStatus(SecKeychainCopySearchList(&list), .snapshotSearch)
 guard let entries = list as? [SecKeychain] else { throw GateFailure.denied(.snapshotSearchDecode) }
 var standard: SecKeychain?
 let status = SecKeychainCopyDefault(&standard)
 guard status == errSecNoDefaultKeychain || status == errSecSuccess else { throw GateFailure.osStatus(.snapshotDefault, status) }
 if status == errSecSuccess && standard == nil { throw GateFailure.denied(.snapshotDefaultDecode) }
 return [try standard.map(keychainPath) ?? ""] + (try entries.map(keychainPath))
}

func privateMetadata(_ path: String, directory: Bool, phase: GatePhase = .fixtureMetadata) throws -> stat {
 var row = stat()
 try syscallStatus(path.withCString { lstat($0, &row) }, phase)
 let type = directory ? S_IFDIR : S_IFREG
 try require((row.st_mode & mode_t(S_IFMT)) == mode_t(type), .filesystemType)
 try require(row.st_uid == geteuid(), .filesystemOwner)
 try require((row.st_mode & 0o7777) == (directory ? 0o700 : 0o600), .filesystemPermissions)
 try require(directory || row.st_nlink == 1, .filesystemLinkCount)
 return row
}

struct Fixture {
 let path: String
 let keychain: SecKeychain
 let device: dev_t
 let inode: ino_t
 let expectedService: String

 init(directory: String, basename: String, outside: [String], expectedService: String) throws {
  try require(["pilot-primary.keychain-db", "pilot-sibling.keychain-db"].contains(basename), .fixtureBasename)
  let path = directory + "/" + basename
  let row = try privateMetadata(path, directory: false)
  try require(!outside.contains(path), .fixtureAlias)
  for candidate in outside where !candidate.isEmpty {
   // A fixture may not alias an existing/default search-list database.
   var known = stat()
   if candidate.withCString({ lstat($0, &known) }) == 0 {
    try require(known.st_dev != row.st_dev || known.st_ino != row.st_ino, .fixtureAlias)
   }
  }
  var selected: SecKeychain?
  try signedStatus(path.withCString { SecKeychainOpen($0, &selected) }, .fixtureOpen)
  guard let loaded = selected else { throw GateFailure.denied(.fixtureOpenRef) }
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
  try require(row.st_dev == device && row.st_ino == inode && explicit == path, .fixtureIdentity)
  var status: SecKeychainStatus = 0
  try signedStatus(SecKeychainGetStatus(keychain, &status), .securityStatus)
  let expected = kSecUnlockStateStatus | kSecReadPermStatus | kSecWritePermStatus
  try require((status & expected) == expected, .securityFlags)
 }

 func attributes(service: String, account: String) throws -> [String: Any] {
  try recheck()
  try require(service == expectedService && service.range(of: #"^agentkeychain\.pilot\.[a-f0-9]{64}$"#, options: .regularExpression) != nil &&
              account == "synthetic-acceptance-marker", .slotPolicy)
  return [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
          kSecAttrAccount as String: account]
 }

 func add(_ service: String, _ account: String, _ value: Data) throws {
  var item = try attributes(service: service, account: account)
  item[kSecUseKeychain as String] = keychain
  item[kSecValueData as String] = value
  try signedStatus(SecItemAdd(item as CFDictionary, nil), .itemAdd)
 }

 func read(_ service: String, _ account: String) throws -> Data? {
  var query = try attributes(service: service, account: account)
  query[kSecMatchSearchList as String] = [keychain]
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  query[kSecReturnData as String] = true
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  if status == errSecItemNotFound { return nil }
  try signedStatus(status, .itemRead)
  guard let bytes = result as? Data else { throw GateFailure.denied(.itemReadDecode) }
  return bytes
 }

 func remove(_ service: String, _ account: String) throws {
  var query = try attributes(service: service, account: account)
  query[kSecMatchSearchList as String] = [keychain]
  try signedStatus(SecItemDelete(query as CFDictionary), .itemDelete)
 }
}

// Candidate fixture preparation only. Public SecKeychainCreate uses the
// private-path branch in the reviewed Apple Security source. Check observed
// default/search-list state around each create on the disposable runner.
func provisionDisposableKeychains(before: [String]) throws -> String {
 let parent = "/private/tmp"
 let parentURL = URL(fileURLWithPath: parent, isDirectory: true)
 try require(parentURL.resolvingSymlinksInPath().path == parent, .scratchCanonical)
 // Only the fixed canonical system scratch ancestor is accepted. Its writable
 // final component must be root-owned + sticky; the new child is owner-only.
 for name in ["/", "/private", parent] {
  var metadata = stat()
  try syscallStatus(name.withCString { lstat($0, &metadata) }, .ancestorStat)
  try require((metadata.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) && metadata.st_uid == 0, .ancestorIdentity)
  if name == parent { try require((metadata.st_mode & 0o1000) != 0, .ancestorSticky) }
  else { try require((metadata.st_mode & 0o022) == 0, .ancestorModes) }
 }
 let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
 try require(suffix.range(of: #"^[a-f0-9]{32}$"#, options: .regularExpression) != nil, .randomShape)
 let root = parent + "/akc-pilot-native-" + suffix
 try syscallStatus(root.withCString { mkdir($0, 0o700) }, .rootCreate)
 let original = try privateMetadata(root, directory: true, phase: .rootIdentity)
 try require(URL(fileURLWithPath: root, isDirectory: true).resolvingSymlinksInPath().path == root, .rootCanonical)
 // No recursive filesystem cleanup and no Keychain delete or config API.
 // Only dispose the ephemeral runner; partial synthetic fixtures remain there.
 func checkRoot() throws {
  let current = try privateMetadata(root, directory: true, phase: .rootIdentity)
  try require(current.st_dev == original.st_dev && current.st_ino == original.st_ino, .rootIdentity)
 }
 func create(_ name: String) throws {
  try require(["pilot-primary.keychain-db", "pilot-sibling.keychain-db"].contains(name), .fixtureBasename)
  try checkRoot()
  try require(try snapshot() == before, .createBeforeSnapshot)
  let path = root + "/" + name
  var old = stat()
  let existsStatus = path.withCString { lstat($0, &old) }
  let existsErrno = errno
  if existsStatus == 0 { throw GateFailure.denied(.fixtureAlreadyExists) }
  if existsStatus != -1 || existsErrno != ENOENT { throw GateFailure.posix(.fixtureAbsent, existsErrno) }
  var entropy = Data(count: 32)
  defer { entropy.resetBytes(in: 0..<entropy.count) }
  try signedStatus(entropy.withUnsafeMutableBytes { raw in
   guard let address = raw.baseAddress else { return errSecParam }
   return SecRandomCopyBytes(kSecRandomDefault, raw.count, address)
  }, .randomSource)
  // Produce canonical UTF-8 ASCII without making a String or passing the
  // generated value to argv, environment, stdout, or a separate process.
  let hex = Array("0123456789abcdef".utf8)
  var password = Data(count: 64)
  defer { password.resetBytes(in: 0..<password.count) }
  for i in 0..<entropy.count {
   password[2 * i] = hex[Int(entropy[i] >> 4)]
   password[2 * i + 1] = hex[Int(entropy[i] & 15)]
  }
  var selected: SecKeychain?
  let createStatus = path.withCString { file in password.withUnsafeBytes { raw in
   SecKeychainCreate(file, UInt32(raw.count), raw.baseAddress, false, nil, &selected)
  } }
  // Use only the returned new fixture. If the observable search list/default
  // changed, abort: never compensate by writing preferences.
  try require(try snapshot() == before, .createAfterSnapshot)
  try checkRoot()
  try signedStatus(createStatus, .createAPI)
  guard let keychain = selected, try keychainPath(keychain) == path else { throw GateFailure.denied(.createRefPath) }
  let created = try privateMetadata(path, directory: false, phase: .createMetadata)
  var status: SecKeychainStatus = 0
  try signedStatus(SecKeychainGetStatus(keychain, &status), .provisionStatusBeforeUnlock)
  if (status & kSecUnlockStateStatus) == 0 {
   let unlockStatus = password.withUnsafeBytes { raw in
    SecKeychainUnlock(keychain, UInt32(raw.count), raw.baseAddress, true)
   }
   try require(try snapshot() == before, .unlockAfterSnapshot)
   try checkRoot()
   try signedStatus(unlockStatus, .unlockAPI)
  }
  try signedStatus(SecKeychainGetStatus(keychain, &status), .provisionStatusAfterUnlock)
  try require((status & kSecUnlockStateStatus) != 0, .unlockedFlags)
  let still = try privateMetadata(path, directory: false)
  try require(still.st_dev == created.st_dev && still.st_ino == created.st_ino, .provisionIdentity)
  try require(try snapshot() == before, .provisionFinalSnapshot)
 }
 try create("pilot-primary.keychain-db")
 try create("pilot-sibling.keychain-db")
 try checkRoot()
 return root
}

func run() throws {
 // Explicitly gated to a GitHub-hosted disposable account; marker is a
 // guard, not a substitute for operator/runner isolation.
 let env = ProcessInfo.processInfo.environment
 try require(CommandLine.arguments.count == 2, .argumentShape)
 try require(getuid() != 0 && getuid() == geteuid(), .runnerUID)
 try require(env["GITHUB_ACTIONS"] == "true", .runnerGitHub)
 try require(env["RUNNER_ENVIRONMENT"] == "github-hosted", .runnerHosted)
 let argument = CommandLine.arguments[1]
 let provision = argument == "--provision-disposable"
 let marker = provision ? "create-two-private-keychains-v1" : "explicit-two-keychains-v1"
 try require(env["AKC_DISPOSABLE_DARWIN_FIXTURE"] == marker, .fixtureMode)
 let before = try snapshot()
 let root = provision ? try provisionDisposableKeychains(before: before) : argument
 let url = URL(fileURLWithPath: root, isDirectory: true)
 try require(root.hasPrefix("/") && url.resolvingSymlinksInPath().path == root &&
             url.lastPathComponent.range(of: #"^akc-pilot-native-[a-f0-9]{32}$"#, options: .regularExpression) != nil, .rootCanonical)
 _ = try privateMetadata(root, directory: true, phase: .rootIdentity)
 var aliases = Set<String>()
 for configured in before where !configured.isEmpty {
  aliases.insert(configured)
  aliases.insert(URL(fileURLWithPath: configured).resolvingSymlinksInPath().path)
 }
 // Same random synthetic namespace and exact slot in both stores. This
 // isolates the keychain boundary independently of the namespace check.
 let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() +
              UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
 let service = "agentkeychain.pilot." + suffix
 try require(suffix != String(repeating: "0", count: 64), .randomShape)
 let one = try Fixture(directory: root, basename: "pilot-primary.keychain-db", outside: Array(aliases), expectedService: service)
 let two = try Fixture(directory: root, basename: "pilot-sibling.keychain-db", outside: Array(aliases), expectedService: service)
 try require(one.device != two.device || one.inode != two.inode, .fixturePairDistinct)
 let slot = "synthetic-acceptance-marker", first = Data("synthetic-primary".utf8), second = Data("synthetic-sibling".utf8)
 // Check local policy without submitting an ordinary namespace to Security.
 do { _ = try one.attributes(service: "agentkeychain.vault", account: "master-password"); throw GateFailure.denied(.ordinaryPolicyCheck) }
 catch GateFailure.denied(.slotPolicy) { }
 do { _ = try one.attributes(service: "agentkeychain.pilot." + String(repeating: "0", count: 64), account: slot); throw GateFailure.denied(.otherNamespacePolicyCheck) }
 catch GateFailure.denied(.slotPolicy) { }
 let initiallyOne = try one.read(service, slot), initiallyTwo = try two.read(service, slot)
 try require(initiallyOne == nil && initiallyTwo == nil, .itemsInitiallyAbsent)
 try one.add(service, slot, first)
 defer { try? one.remove(service, slot) }
 try require(try two.read(service, slot) == nil, .siblingInitiallyAbsent)
 try two.add(service, slot, second)
 defer { try? two.remove(service, slot) }
 let inOne = try one.read(service, slot), inTwo = try two.read(service, slot)
 try require(inOne == first && inTwo == second, .itemsIndependent)
 try one.remove(service, slot)
 let cleared = try one.read(service, slot), unaffected = try two.read(service, slot)
 try require(cleared == nil && unaffected == second, .siblingAfterPrimaryDeletion)
 try two.remove(service, slot)
 try require(try two.read(service, slot) == nil, .siblingDeleted)
 try require(try snapshot() == before, .finalSnapshot)
 print("PASS disposable Keychain: exact service, explicit store, isolated sibling and unchanged default/search list")
}

do { try run() } catch let failure as GateFailure {
 FileHandle.standardError.write(Data(("darwin_pilot_keychain_acceptance_denied " + failure.message + "\n").utf8))
 exit(1)
} catch {
 FileHandle.standardError.write(Data("darwin_pilot_keychain_acceptance_denied phase=unexpected\n".utf8))
 exit(1)
}
