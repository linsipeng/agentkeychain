-- Device-reported processed cursor on authenticated, successful pulls. Delivery
-- alone is not acknowledgement. No browser command can write this observation.
CREATE TABLE device_sync_progress (
 tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, device_id TEXT NOT NULL,
 last_seen INTEGER NOT NULL, acknowledged INTEGER NOT NULL CHECK(acknowledged>=0),
 PRIMARY KEY(tenant_id,vault_id,device_id),
 FOREIGN KEY(tenant_id,vault_id) REFERENCES vaults(tenant_id,id),
 FOREIGN KEY(tenant_id,device_id) REFERENCES devices(tenant_id,id)
);
