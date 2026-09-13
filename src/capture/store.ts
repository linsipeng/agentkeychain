import { inferCredentialScope } from "./scope.ts";
import {
  startSecureCapture,
  type SecureCaptureHandle,
  type SecureCaptureOptions,
} from "./server.ts";
import { openDb } from "../vault.ts";
import { listSecrets, storeSecret } from "../secrets.ts";
import { loadIdentityByName } from "../identity.ts";
import { resolveVaultKek } from "../unlock.ts";

export interface SecureStoreRequest {
  name: string;
  purpose: string;
  openBrowser?: boolean;
  timeoutMs?: number;
}

export async function requestSecureStore(request: SecureStoreRequest): Promise<SecureCaptureHandle> {
  const name = request.name.trim();
  const purpose = request.purpose.trim();
  if (!name) throw new Error("secret name is required");
  if (!purpose) throw new Error("credential purpose is required");

  const checkDb = openDb();
  try {
    if (listSecrets(checkDb).some((item) => item.name === name)) {
      throw new Error(`secret '${name}' already exists — overwrite or rotation requires explicit approval`);
    }
  } finally {
    checkDb.close();
  }

  const decision = inferCredentialScope(name, purpose);
  const captureOptions: SecureCaptureOptions = {
    name,
    purpose,
    scope: decision.scope,
    permission: decision.permission,
    onSubmit: async (value) => {
      const db = openDb();
      const kek = await resolveVaultKek(db);
      try {
        if (listSecrets(db).some((item) => item.name === name)) {
          throw new Error("secret already exists");
        }
        const agent = loadIdentityByName(db, "default");
        if (!agent) throw new Error("default identity not found");
        await storeSecret(db, {
          name,
          value,
          scopes: [decision.scope],
          metadata: { purpose, permission: decision.permission, capture: "local-loopback" },
          kek,
          agent,
        });
      } finally {
        kek.fill(0);
        db.close();
      }
    },
    ...(request.openBrowser === undefined ? {} : { openBrowser: request.openBrowser }),
    ...(request.timeoutMs === undefined ? {} : { timeoutMs: request.timeoutMs }),
  };
  return startSecureCapture(captureOptions);
}
