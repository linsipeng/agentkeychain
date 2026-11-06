// Build as agentkeychain-secure-store beside the signed CLI. Input/output are private pipes.
import Foundation
import Security
struct Input: Decodable { let action: String; let service: String; let account: String; let value: String? }
func run() throws {
 if CommandLine.arguments == [CommandLine.arguments[0], "--compatibility"] {
  FileHandle.standardOutput.write(Data("{\"helperABI\":1,\"helperVersion\":\"1\"}\n".utf8)); return
 }
 let data = FileHandle.standardInput.readDataToEndOfFile()
 guard data.count <= 65536 else { throw NSError(domain: "input", code: 1) }
 let r = try JSONDecoder().decode(Input.self, from: data)
 let master = (r.service == "agentkeychain.vault" || r.service.hasPrefix("agentkeychain.vault.")) && r.account == "master-password"
 guard master || (r.service.hasPrefix("agentkeychain.cloud.") && ["enrollment-intent", "csk", "signing-private", "wrapping-private", "refresh-credential", "checkpoint-anchor", "roster-anchor", "recovery-intent", "recovery-anchor"].contains(r.account)) else { throw NSError(domain: "input", code: 1) }
 let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: r.service, kSecAttrAccount as String: r.account]
 var status: OSStatus = errSecParam
 if r.action == "get" {
  var q = query; q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
  var result: CFTypeRef?; status = SecItemCopyMatching(q as CFDictionary, &result)
  if status == errSecSuccess, let bytes = result as? Data { FileHandle.standardOutput.write(bytes) }
  if status == errSecItemNotFound { return }
 } else if r.action == "put", let value = r.value, Data(base64Encoded: value) != nil {
  let bytes = master ? Data(base64Encoded: value)! : Data(value.utf8)
  status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: bytes] as CFDictionary)
  if status == errSecItemNotFound {
   var q = query; if master { q[kSecAttrLabel as String] = "AgentKeychain Vault Master Password" }; q[kSecValueData as String] = bytes; q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
   status = SecItemAdd(q as CFDictionary, nil)
  }
 } else if r.action == "remove" { status = SecItemDelete(query as CFDictionary); if status == errSecItemNotFound { return } }
 guard status == errSecSuccess else { throw NSError(domain: "secure_store", code: 1) }
}
do { try run() } catch { exit(1) }
