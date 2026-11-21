// Separate installed-candidate probe. Does not read/write/delete Keychain
// items, create or unlock keychains, use defaults, or activate the CLI.
import Foundation
import CryptoKit
import Security
import Darwin

private enum Refused: Error { case closed, posix(Int32) }
private func require(_ condition: Bool) throws { if !condition { throw Refused.closed } }
private func hex(_ bytes: SHA256.Digest) -> String {
 bytes.map { String(format: "%02x", $0) }.joined()
}
private let domain = "AgentKeychain-installed-pilot-darwin-keychain-check-v1"
private let expectedLeaf = "pilot-primary.keychain-db"

private struct Envelope: Codable { let canonical: String; let signature: String }
private struct Claim: Codable {
 let version: Int
 let domain: String
 let installationDigest: String
 let keyId: String
 let directory: String
 let directoryDevice: String
 let directoryInode: String
 let fileDevice: String
 let fileInode: String
 let uid: UInt32
 let namespace: String
 let issuedAt: Int64
 let expiresAt: Int64
}
private func time() -> Int64 { Int64(Date().timeIntervalSince1970) }
private func canonicalPath(_ path: String) throws -> String {
 var chars = [CChar](repeating: 0, count: Int(PATH_MAX))
 return try chars.withUnsafeMutableBufferPointer { buffer in
  guard let ptr = buffer.baseAddress else { throw Refused.closed }
  let result = path.withCString { realpath($0, ptr) }
  let error = errno
  guard result != nil else { throw Refused.posix(error) }
  guard let canonical = String(validatingUTF8: ptr) else { throw Refused.closed }
  return canonical
 }
}
private func nativePath(_ keychain: SecKeychain) throws -> String {
 var size = UInt32(PATH_MAX)
 var chars = [CChar](repeating: 0, count: Int(size))
 return try chars.withUnsafeMutableBufferPointer { buffer in
  guard let ptr = buffer.baseAddress, SecKeychainGetPath(keychain, &size, ptr) == errSecSuccess,
        buffer.contains(0), let path = String(validatingUTF8: ptr) else { throw Refused.closed }
  return path
 }
}
private func openedDirectory(_ name: String, parent: Int32? = nil) throws -> Int32 {
 let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
 let fd = name.withCString { actual in
  if let parent = parent { return openat(parent, actual, flags) }
  return open(actual, flags)
 }
 try require(fd >= 0)
 return fd
}
private func fmetadata(_ fd: Int32) throws -> stat {
 var metadata = stat()
 try require(fstat(fd, &metadata) == 0)
 return metadata
}
private func same(_ a: stat, _ b: stat) -> Bool {
 a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_mode == b.st_mode
}
private func number(_ input: String) -> Bool {
 guard let parsed = UInt64(input) else { return false }
 return String(parsed) == input
}
private func matched(_ metadata: stat, uid: UInt32, directory: Bool, device: String, inode: String) throws {
 try require(metadata.st_uid == uid)
 try require((metadata.st_mode & mode_t(S_IFMT)) == mode_t(directory ? S_IFDIR : S_IFREG))
 try require((metadata.st_mode & 0o7777) == (directory ? 0o700 : 0o600))
 try require(directory || metadata.st_nlink == 1)
 try require(String(metadata.st_dev) == device && String(metadata.st_ino) == inode)
}
private func visible(_ path: String) throws -> stat {
 var metadata = stat()
 try require(path.withCString { lstat($0, &metadata) } == 0)
 return metadata
}

private func checkNoConfiguredAlias(path: String, identity: stat) throws {
 var list: CFArray?
 try require(SecKeychainCopySearchList(&list) == errSecSuccess)
 guard let configured = list as? [SecKeychain] else { throw Refused.closed }
 var defaultKeychain: SecKeychain?
 let status = SecKeychainCopyDefault(&defaultKeychain)
 try require(status == errSecNoDefaultKeychain || (status == errSecSuccess && defaultKeychain != nil))
 for ref in configured + (defaultKeychain.map { [$0] } ?? []) {
  let name = try nativePath(ref)
  try require(name != path)
  // Nonexistent configured names may survive in the list. Only accept
  // ENOENT corroborated by lstat (absent) or a terminal symlink proven
  // dangling by a second canonical lookup. EACCES, ENOTDIR, ELOOP and other errors fail closed.
  try require(name.hasPrefix("/"))
  let canonical: String
  do { canonical = try canonicalPath(name) }
  catch Refused.posix(let error) where error == ENOENT {
   var entry = stat()
   let found = name.withCString { lstat($0, &entry) }
   let lookupError = errno
   if found == -1 && lookupError == ENOENT { continue }
   try require(found == 0 && (entry.st_mode & mode_t(S_IFMT)) == mode_t(S_IFLNK))
   // Re-check the resolved lookup after verifying the terminal type.
   do {
    _ = try canonicalPath(name)
    throw Refused.closed
   } catch Refused.posix(let secondError) where secondError == ENOENT { continue }
  }
  try require(canonical != path)
  let row = try visible(canonical)
  try require(row.st_dev != identity.st_dev || row.st_ino != identity.st_ino)
 }
}

private func verifyClaim() throws -> Claim {
 var input = Data()
 while input.count <= 8192 {
  guard let block = try FileHandle.standardInput.read(upToCount: 8193 - input.count), !block.isEmpty else { break }
  input.append(block)
 }
 try require(!input.isEmpty && input.count <= 8192)
 // Canonical envelope as well as claim rejects duplicates and extra fields.
 let dec = JSONDecoder(), enc = JSONEncoder()
 enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
 let envelope = try dec.decode(Envelope.self, from: input)
 try require(try enc.encode(envelope) == input)
 // Compare decoded content to the independently configured trust, not a
 // public key supplied through stdin/argv/environment.
 let bytes = Data(envelope.canonical.utf8)
 let claim = try dec.decode(Claim.self, from: bytes)
 try require(try enc.encode(claim) == bytes)
 guard let pin = Data(base64Encoded: PilotNativeTrust.rolloutPublicKey),
       let signature = Data(base64Encoded: envelope.signature) else { throw Refused.closed }
 let key = try Curve25519.Signing.PublicKey(rawRepresentation: pin)
 let when = time()
 try require(claim.version == 1 && claim.domain == domain && claim.installationDigest == PilotNativeTrust.installationDigest &&
             claim.keyId == hex(SHA256.hash(data: Data(PilotNativeTrust.rolloutPublicKey.utf8))) &&
             envelope.signature == signature.base64EncodedString() &&
             claim.uid == getuid() && claim.uid != 0 && getuid() == geteuid() &&
             claim.issuedAt > 0 && claim.issuedAt <= when && claim.expiresAt > when &&
             claim.expiresAt <= PilotNativeTrust.expiresAt && claim.expiresAt - claim.issuedAt <= 900)
 try require(key.isValidSignature(signature, for: bytes))
 try require([claim.directoryDevice, claim.directoryInode, claim.fileDevice, claim.fileInode].allSatisfy(number))
 try require(claim.fileDevice == claim.directoryDevice && claim.directoryInode != "0" && claim.fileInode != "0")
 let scope = [domain, claim.installationDigest, claim.directory, String(claim.uid), claim.directoryDevice, claim.directoryInode]
 let requestedNamespace = "agentkeychain.pilot." + hex(SHA256.hash(data: try enc.encode(scope)))
 try require(claim.namespace == requestedNamespace)
 return claim
}

private func run() throws {
 let env = ProcessInfo.processInfo.environment
 try require(CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "check-scoped-store" &&
             env["GITHUB_ACTIONS"] == "true" && env["RUNNER_ENVIRONMENT"] == "github-hosted" &&
             env["AKC_DARWIN_NATIVE_CANDIDATE"] == "check-signed-disposable-v1")
 let claim = try verifyClaim()
 let dir = claim.directory
 let prefix = "/private/tmp/akc-pilot-native-"
 try require(dir.hasPrefix(prefix) && dir.dropFirst(prefix.count).count == 32 &&
             dir.dropFirst(prefix.count).utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) })
 try require(try canonicalPath(dir) == dir)
 let slash = try openedDirectory("/")
 defer { close(slash) }
 let privateFD = try openedDirectory("private", parent: slash)
 defer { close(privateFD) }
 let tmp = try openedDirectory("tmp", parent: privateFD)
 defer { close(tmp) }
 for (fd, name) in [(slash, "/"), (privateFD, "/private"), (tmp, "/private/tmp")] {
  let row = try fmetadata(fd)
  try require(row.st_uid == 0)
  try require(same(row, try visible(name)))
  if fd == tmp { try require((row.st_mode & 0o1000) != 0) }
  else { try require((row.st_mode & 0o022) == 0) }
 }
 let dirFD = try openedDirectory(String(dir.dropFirst("/private/tmp/".count)), parent: tmp)
 defer { close(dirFD) }
 let path = dir + "/" + expectedLeaf
 func checkFile() throws -> stat {
  let directory = try fmetadata(dirFD)
  try matched(directory, uid: claim.uid, directory: true, device: claim.directoryDevice, inode: claim.directoryInode)
  try require(same(directory, try visible(dir)))
  var anchored = stat()
  try require(expectedLeaf.withCString { fstatat(dirFD, $0, &anchored, AT_SYMLINK_NOFOLLOW) } == 0)
  try matched(anchored, uid: claim.uid, directory: false, device: claim.fileDevice, inode: claim.fileInode)
  try require(same(anchored, try visible(path)))
  return anchored
 }
 let initial = try checkFile()
 try checkNoConfiguredAlias(path: path, identity: initial)
 var ref: SecKeychain?
 try require(path.withCString { SecKeychainOpen($0, &ref) } == errSecSuccess)
 guard let exact = ref else { throw Refused.closed }
 try require(try nativePath(exact) == path)
 var flags: SecKeychainStatus = 0
 try require(SecKeychainGetStatus(exact, &flags) == errSecSuccess)
 let expected = kSecUnlockStateStatus | kSecReadPermStatus | kSecWritePermStatus
 try require((flags & expected) == expected)
 try require(same(initial, try checkFile()))
 try checkNoConfiguredAlias(path: path, identity: initial)
 try require(time() < claim.expiresAt)
 print("{\"version\":1,\"state\":\"scoped-native-location-verified-not-active\"}")
}
do { try run() } catch {
 FileHandle.standardError.write(Data("darwin_pilot_native_candidate_denied\n".utf8))
 exit(1)
}
