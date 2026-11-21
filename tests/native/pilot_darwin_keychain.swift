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
 case canonicalLookup, ancestorStat, ancestorIdentity, ancestorSticky, ancestorModes, rootCreate, randomSource, randomShape
 case directoryOpen, directoryStat, childStat
 case snapshotSearch, snapshotSearchDecode, snapshotDefault, snapshotDefaultDecode
 case fixtureBasename, fixtureAbsent, fixtureAlreadyExists, fixtureMetadata
 case filesystemType, filesystemOwner, fixtureFilePermissions, fixtureDirectoryPermissions, filesystemLinkCount
 case fixtureAlias, fixtureOpen, fixtureOpenRef, fixturePairDistinct
 case fixtureVisibleDevice, fixtureVisibleInode, fixtureVisibleOwner, fixtureVisibleMode
 case fixtureRetainedDevice, fixtureRetainedInode, fixtureNativePath
 case securityPath, securityPathBuffer, securityPathEncoding, securityStatus, securityFlags
 case createBeforeSnapshot, createAfterSnapshot, createAPI, createRefPath
 case unlockAPI, unlockAfterSnapshot, unlockedFlags, provisionIdentity, provisionFinalSnapshot
 case provisionStatusBeforeUnlock, provisionStatusAfterUnlock
 case slotPolicy, itemAdd, itemRead, itemReadDecode, itemDelete
 case ordinaryPolicyCheck, otherNamespacePolicyCheck, itemsInitiallyAbsent, siblingInitiallyAbsent
 case itemsIndependent, siblingAfterPrimaryDeletion, siblingDeleted, finalSnapshot
 case atomicWriteContents, atomicWritePreferences
}
enum FixtureStep: String {
 case openPrimary, openSibling, ordinaryPolicy, otherNamespacePolicy
 case initialPrimary, initialSibling, addPrimary, afterAddPrimary, afterPrimaryAddSiblingCheck
 case addSibling, afterAddSibling, readPrimaryAfterBothAdds, readSiblingAfterBothAdds
 case removePrimary, afterRemovePrimary, siblingAfterPrimaryRemoval
 case removeSibling, afterRemoveSibling
}
enum GateFailure: Error {
 case denied(GatePhase), osStatus(GatePhase, OSStatus), posix(GatePhase, Int32)
 indirect case fixture(FixtureStep, GateFailure), mode(GatePhase, UInt32)
 var message: String {
  switch self {
  case .denied(let phase): return "phase=" + phase.rawValue
  case .osStatus(let phase, let value): return "phase=" + phase.rawValue + " osstatus=" + String(value)
  case .posix(let phase, let value): return "phase=" + phase.rawValue + " errno=" + String(value)
  case .fixture(let step, let nested): return "fixture_step=" + step.rawValue + " " + nested.message
  case .mode(let phase, let value): return "phase=" + phase.rawValue + " mode=" + String(value, radix: 8)
  }
 }
}
func fixtureStep<T>(_ step: FixtureStep, _ body: () throws -> T) throws -> T {
 do { return try body() }
 catch let failure as GateFailure { throw GateFailure.fixture(step, failure) }
}
func require(_ value: Bool, _ phase: GatePhase) throws { if !value { throw GateFailure.denied(phase) } }
func signedStatus(_ status: OSStatus, _ phase: GatePhase) throws {
 if status != errSecSuccess { throw GateFailure.osStatus(phase, status) }
}
// Read errno immediately after the failing syscall. No path is logged.
func syscallStatus(_ status: Int32, _ phase: GatePhase) throws {
 if status != 0 { throw GateFailure.posix(phase, errno) }
}

// Foundation's URL.resolvingSymlinksInPath may remove a leading /private.
// Compare the POSIX canonical spelling instead, without accepting aliases.
func canonicalPOSIX(_ path: String) throws -> String {
 var chars = [CChar](repeating: 0, count: Int(PATH_MAX))
 let canonical = try chars.withUnsafeMutableBufferPointer { buf -> String in
  guard let buffer = buf.baseAddress else { throw GateFailure.denied(.canonicalLookup) }
  let result = path.withCString { realpath($0, buffer) }
  guard result != nil else { throw GateFailure.posix(.canonicalLookup, errno) }
  guard let value = String(validatingUTF8: buffer) else { throw GateFailure.denied(.canonicalLookup) }
  return value
 }
 return canonical
}

func directoryFD(_ path: String, at parent: Int32? = nil) throws -> Int32 {
 let fd = path.withCString { name in
  if let parent = parent { return openat(parent, name, O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC) }
  return open(name, O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC)
 }
 guard fd >= 0 else { throw GateFailure.posix(.directoryOpen, errno) }
 return fd
}

func statDirectory(_ fd: Int32) throws -> stat {
 var row = stat()
 try syscallStatus(fstat(fd, &row), .directoryStat)
 try require((row.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR), .filesystemType)
 return row
}
func sameIdentity(_ a: stat, _ b: stat) -> Bool {
 a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_mode == b.st_mode
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
 try checkPrivateMetadata(row, directory: directory)
 return row
}
func checkPrivateMetadata(_ row: stat, directory: Bool) throws {
 let type = directory ? S_IFDIR : S_IFREG
 try require((row.st_mode & mode_t(S_IFMT)) == mode_t(type), .filesystemType)
 try require(row.st_uid == geteuid(), .filesystemOwner)
 let mode = row.st_mode & 0o7777
 if mode != (directory ? 0o700 : 0o600) {
  throw GateFailure.mode(directory ? .fixtureDirectoryPermissions : .fixtureFilePermissions, UInt32(mode))
 }
 try require(directory || row.st_nlink == 1, .filesystemLinkCount)
}
func fixtureMetadata(directory: Int32, name: String, path: String) throws -> stat {
 var row = stat()
 try syscallStatus(name.withCString { fstatat(directory, $0, &row, AT_SYMLINK_NOFOLLOW) }, .childStat)
 try checkPrivateMetadata(row, directory: false)
 let visible = try privateMetadata(path, directory: false)
 try require(row.st_dev == visible.st_dev, .fixtureVisibleDevice)
 try require(row.st_ino == visible.st_ino, .fixtureVisibleInode)
 try require(row.st_uid == visible.st_uid, .fixtureVisibleOwner)
 try require(row.st_mode == visible.st_mode, .fixtureVisibleMode)
 return row
}

struct Fixture {
 let path: String
 let name: String
 let directoryFD: Int32
 let keychain: SecKeychain
 let device: dev_t
 private(set) var inode: ino_t
 let expectedService: String
 let outside: [String]

 init(directory: String, directoryFD: Int32, basename: String, outside: [String], expectedService: String) throws {
  try require(["pilot-primary.keychain-db", "pilot-sibling.keychain-db"].contains(basename), .fixtureBasename)
  let path = directory + "/" + basename
  let row = try fixtureMetadata(directory: directoryFD, name: basename, path: path)
  try Fixture.rejectAliases(path: path, row: row, outside: outside)
  var selected: SecKeychain?
  try signedStatus(path.withCString { SecKeychainOpen($0, &selected) }, .fixtureOpen)
  guard let loaded = selected else { throw GateFailure.denied(.fixtureOpenRef) }
  self.path = path
  self.name = basename
  self.directoryFD = directoryFD
  self.keychain = loaded
  self.device = row.st_dev
  self.inode = row.st_ino
  self.expectedService = expectedService
  self.outside = outside
  try recheck()
 }

 private static func rejectAliases(path: String, row: stat, outside: [String]) throws {
  try require(!outside.contains(path), .fixtureAlias)
  for candidate in outside where !candidate.isEmpty {
   var known = stat()
   if candidate.withCString({ lstat($0, &known) }) == 0 {
    try require(known.st_dev != row.st_dev || known.st_ino != row.st_ino, .fixtureAlias)
   }
  }
 }

 // The file-backed provider can atomically replace its own database during a
 // successful scoped write. This is never an entrypoint for opens or reads.
 // No other mutation can update the expected identity.
 func afterSuccessfulScopedWrite(_ service: String, _ account: String, expected: Data?,
                                 untouchedSibling: Fixture, preferences: [String]) throws -> Fixture {
  try require(try snapshot() == preferences, .atomicWritePreferences)
  try untouchedSibling.recheck()
  let replacement = try fixtureMetadata(directory: directoryFD, name: name, path: path)
  try require(replacement.st_dev == device, .fixtureRetainedDevice)
  try require(replacement.st_dev != untouchedSibling.device || replacement.st_ino != untouchedSibling.inode, .fixturePairDistinct)
  try Fixture.rejectAliases(path: path, row: replacement, outside: outside)
  var candidate = self
  candidate.inode = replacement.st_ino
  try candidate.recheck()
  let observed = try candidate.read(service, account)
  try require(observed == expected, .atomicWriteContents)
  try candidate.recheck()
  try untouchedSibling.recheck()
  try require(try snapshot() == preferences, .atomicWritePreferences)
  return candidate
 }

 func recheck() throws {
  let row = try fixtureMetadata(directory: directoryFD, name: name, path: path)
  let explicit = try keychainPath(keychain)
  try require(row.st_dev == device, .fixtureRetainedDevice)
  try require(row.st_ino == inode, .fixtureRetainedInode)
  try require(explicit == path, .fixtureNativePath)
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
  if status == errSecItemNotFound {
   try recheck()
   return nil
  }
  try signedStatus(status, .itemRead)
  try recheck()
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
func provisionDisposableKeychains(before: [String]) throws -> (path: String, fd: Int32) {
 let parent = "/private/tmp"
 try require(try canonicalPOSIX(parent) == parent, .scratchCanonical)
 // Anchor from the root and refuse symlinks at every trusted ancestor.
 let rootFD = try directoryFD("/")
 defer { close(rootFD) }
 let privateFD = try directoryFD("private", at: rootFD)
 defer { close(privateFD) }
 let scratchFD = try directoryFD("tmp", at: privateFD)
 defer { close(scratchFD) }
 for (path, fd) in [("/", rootFD), ("/private", privateFD), (parent, scratchFD)] {
  let metadata = try statDirectory(fd)
  var visible = stat()
  try syscallStatus(path.withCString { lstat($0, &visible) }, .ancestorStat)
  try require(metadata.st_uid == 0 && sameIdentity(metadata, visible), .ancestorIdentity)
  if fd == scratchFD { try require((metadata.st_mode & 0o1000) != 0, .ancestorSticky) }
  else { try require((metadata.st_mode & 0o022) == 0, .ancestorModes) }
 }
 let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
 try require(suffix.range(of: #"^[a-f0-9]{32}$"#, options: .regularExpression) != nil, .randomShape)
 let leaf = "akc-pilot-native-" + suffix
 let root = parent + "/" + leaf
 try syscallStatus(leaf.withCString { mkdirat(scratchFD, $0, 0o700) }, .rootCreate)
 let fd = try directoryFD(leaf, at: scratchFD)
 var transferFD = false
 defer { if !transferFD { close(fd) } }
 let original = try statDirectory(fd)
 try checkPrivateMetadata(original, directory: true)
 let visible = try privateMetadata(root, directory: true, phase: .rootIdentity)
 try require(sameIdentity(visible, original), .rootIdentity)
 try require(try canonicalPOSIX(root) == root, .rootCanonical)
 // No recursive filesystem cleanup and no Keychain delete or config API.
 // Only dispose the ephemeral runner; partial synthetic fixtures remain there.
 func checkRoot() throws {
  let current = try privateMetadata(root, directory: true, phase: .rootIdentity)
  let retained = try statDirectory(fd)
  try require(sameIdentity(current, original) && sameIdentity(retained, original), .rootIdentity)
 }
 func create(_ name: String) throws {
  try require(["pilot-primary.keychain-db", "pilot-sibling.keychain-db"].contains(name), .fixtureBasename)
  try checkRoot()
  try require(try snapshot() == before, .createBeforeSnapshot)
  let path = root + "/" + name
  var old = stat()
  let existsStatus = name.withCString { fstatat(fd, $0, &old, AT_SYMLINK_NOFOLLOW) }
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
  let created = try fixtureMetadata(directory: fd, name: name, path: path)
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
  let still = try fixtureMetadata(directory: fd, name: name, path: path)
  try require(still.st_dev == created.st_dev && still.st_ino == created.st_ino, .provisionIdentity)
  try require(try snapshot() == before, .provisionFinalSnapshot)
 }
 try create("pilot-primary.keychain-db")
 try create("pilot-sibling.keychain-db")
 try checkRoot()
 transferFD = true
 return (root, fd)
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
 func requireCanonicalRoot(_ path: String) throws {
  let leaf = path.split(separator: "/").last.map { String($0) } ?? ""
  try require(path.hasPrefix("/") && leaf.range(of: #"^akc-pilot-native-[a-f0-9]{32}$"#, options: .regularExpression) != nil, .rootCanonical)
  try require(try canonicalPOSIX(path) == path, .rootCanonical)
 }
 let location: (path: String, fd: Int32)
 if provision {
  location = try provisionDisposableKeychains(before: before)
 } else {
  try requireCanonicalRoot(argument)
  location = (argument, try directoryFD(argument))
 }
 defer { close(location.fd) }
 let root = location.path
 try requireCanonicalRoot(root)
 let named = try privateMetadata(root, directory: true, phase: .rootIdentity)
 try require(sameIdentity(named, try statDirectory(location.fd)), .rootIdentity)
 var aliases = Set<String>()
 for configured in before where !configured.isEmpty {
  aliases.insert(configured)
  if let resolved = try? canonicalPOSIX(configured) { aliases.insert(resolved) }
 }
 // Same random synthetic namespace and exact slot in both stores. This
 // isolates the keychain boundary independently of the namespace check.
 let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() +
              UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
 let service = "agentkeychain.pilot." + suffix
 try require(suffix != String(repeating: "0", count: 64), .randomShape)
 var one = try fixtureStep(.openPrimary) {
  try Fixture(directory: root, directoryFD: location.fd, basename: "pilot-primary.keychain-db", outside: Array(aliases), expectedService: service)
 }
 var two = try fixtureStep(.openSibling) {
  try Fixture(directory: root, directoryFD: location.fd, basename: "pilot-sibling.keychain-db", outside: Array(aliases), expectedService: service)
 }
 try require(one.device != two.device || one.inode != two.inode, .fixturePairDistinct)
 let slot = "synthetic-acceptance-marker", first = Data("synthetic-primary".utf8), second = Data("synthetic-sibling".utf8)
 // Check local policy without submitting an ordinary namespace to Security.
 try fixtureStep(.ordinaryPolicy) {
  do { _ = try one.attributes(service: "agentkeychain.vault", account: "master-password"); throw GateFailure.denied(.ordinaryPolicyCheck) }
  catch GateFailure.denied(.slotPolicy) { }
 }
 try fixtureStep(.otherNamespacePolicy) {
  do { _ = try one.attributes(service: "agentkeychain.pilot." + String(repeating: "0", count: 64), account: slot); throw GateFailure.denied(.otherNamespacePolicyCheck) }
  catch GateFailure.denied(.slotPolicy) { }
 }
 let initiallyOne = try fixtureStep(.initialPrimary) { try one.read(service, slot) }
 let initiallyTwo = try fixtureStep(.initialSibling) { try two.read(service, slot) }
 try require(initiallyOne == nil && initiallyTwo == nil, .itemsInitiallyAbsent)
 try fixtureStep(.addPrimary) {
  try two.recheck()
  try one.add(service, slot, first)
 }
 one = try fixtureStep(.afterAddPrimary) {
  try one.afterSuccessfulScopedWrite(service, slot, expected: first, untouchedSibling: two, preferences: before)
 }
 try fixtureStep(.afterPrimaryAddSiblingCheck) { try require(try two.read(service, slot) == nil, .siblingInitiallyAbsent) }
 try fixtureStep(.addSibling) {
  try one.recheck()
  try two.add(service, slot, second)
 }
 two = try fixtureStep(.afterAddSibling) {
  try two.afterSuccessfulScopedWrite(service, slot, expected: second, untouchedSibling: one, preferences: before)
 }
 let inOne = try fixtureStep(.readPrimaryAfterBothAdds) { try one.read(service, slot) }
 let inTwo = try fixtureStep(.readSiblingAfterBothAdds) { try two.read(service, slot) }
 try require(inOne == first && inTwo == second, .itemsIndependent)
 try fixtureStep(.removePrimary) {
  try two.recheck()
  try one.remove(service, slot)
 }
 one = try fixtureStep(.afterRemovePrimary) {
  try one.afterSuccessfulScopedWrite(service, slot, expected: nil, untouchedSibling: two, preferences: before)
 }
 let cleared = try fixtureStep(.afterRemovePrimary) { try one.read(service, slot) }
 let unaffected = try fixtureStep(.siblingAfterPrimaryRemoval) { try two.read(service, slot) }
 try require(cleared == nil && unaffected == second, .siblingAfterPrimaryDeletion)
 try fixtureStep(.removeSibling) {
  try one.recheck()
  try two.remove(service, slot)
 }
 two = try fixtureStep(.afterRemoveSibling) {
  try two.afterSuccessfulScopedWrite(service, slot, expected: nil, untouchedSibling: one, preferences: before)
 }
 try fixtureStep(.afterRemoveSibling) {
  try require(try two.read(service, slot) == nil && one.read(service, slot) == nil, .siblingDeleted)
 }
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
