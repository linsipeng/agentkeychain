import type {AuthenticationResponseJSON} from '@simplewebauthn/server';
import {decode,random,webauthn,type WebAuthnPolicy} from '../../api-worker/webauthn.ts';
import {digest} from '../../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import type {CheckpointSigner} from '../../shared/checkpoints.ts';
import {canonicalGenesisApproval,GENESIS_APPROVAL_DOMAIN,verifyGenesisApproval,type GenesisApprovalPolicy} from '../../shared/genesis-approval.ts';
import {rosterDigest,verifyRoster} from '../../shared/roster.ts';
import type {SignedManagedOperation} from '../../../src/cloud/protocol.ts';

type Pin = {credential:string;handle:string;cose_key:string;counter:number};
type Challenge = Pin & {challenge_digest:string;expires:number};
const unavailable = () => new Error('genesis_approval_unavailable');

/** A local Auth-owned slice, not a Worker route or RPC. An independent authenticated
 * UI must display exact intent before calling it. Never bind the DB to Main;
 * credential pins must originate in Auth's own verified registration. */
export function genesisIssuer(db: D1Database, identity: WebAuthnPolicy, policy: GenesisApprovalPolicy, signer: CheckpointSigner, pilotBrowserDigest?:string) {
    const url = new URL(identity.origin);
    if (url.protocol !== 'https:' || url.origin !== identity.origin || url.hostname !== identity.rpId)
        throw unavailable();
    const pilot=url.hostname.startsWith('auth-pilot-');
    if(pilot!==(pilotBrowserDigest!==undefined)||(pilotBrowserDigest!==undefined&&!/^[a-f0-9]{64}$/.test(pilotBrowserDigest)))throw unavailable();
    async function intent(grantBytes:string, roster:SignedManagedOperation) {
        const now=Math.floor(Date.now()/1000);
        if (typeof grantBytes!=='string' || grantBytes.length>4096 || typeof roster?.canonical!=='string' || roster.canonical.length>16_384)
            throw unavailable();
        const grant=JSON.parse(grantBytes) as EnrollmentGrant;
        if (canonicalGrant(grant)!==grantBytes || grant.issuerDeviceId!==null || grant.expiresAt<=now) throw unavailable();
        const r=await verifyRoster(roster,null,now), d=r.active[0];
        if (!d || r.accountId!==grant.accountId || r.tenantId!==grant.tenantId || r.vaultId!==grant.vaultId ||
            r.keyEpoch!==grant.keyEpoch || r.issuer.kind!=='device' || r.issuer.id!==grant.deviceId ||
            d.deviceId!==grant.deviceId || d.signingKey!==grant.signingKey || d.wrappingKey!==grant.wrappingKey ||
            JSON.stringify(r.checkpointKeys)!==JSON.stringify(policy.checkpointKeys) ||
            JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities)) throw unavailable();
        const scope=[grant.accountId,grant.tenantId,grant.vaultId],grantDigest=await digest(grantBytes),rosterHash=await rosterDigest(roster);
        let expires=Math.min(grant.expiresAt,r.expiresAt,now+180);
        if(pilotBrowserDigest!==undefined){
            const row=await db.prepare(`SELECT r.expires FROM pilot_genesis_registration r JOIN auth_genesis_pins p USING (account,tenant,vault,credential)
              WHERE r.account=? AND r.tenant=? AND r.vault=? AND r.grant_digest=? AND r.roster_digest=? AND r.browser_digest=?
              AND r.expires>unixepoch() AND p.active=1`).bind(...scope,grantDigest,rosterHash,pilotBrowserDigest).first<{expires:number}>();
            if(!row)throw unavailable();
            expires=Math.min(expires,row.expires);
        }
        return {scope,now,expires,grantDigest,rosterDigest:rosterHash};
    }
    return {
        async begin(grant:string, roster:SignedManagedOperation) {
            try {
                const {scope,expires,grantDigest,rosterDigest}=await intent(grant,roster);
                const pin=await db.prepare('SELECT credential FROM auth_genesis_pins WHERE account=? AND tenant=? AND vault=? AND active=1').bind(...scope).first<Pin>();
                if (!pin) throw unavailable();
                const id=random(), challenge=random();
                const insert=db.prepare('INSERT INTO auth_genesis_challenges VALUES(?,?,?,?,?,?,?,?,?)')
                  .bind(id,await digest(challenge),...scope,pin.credential,grantDigest,rosterDigest,expires);
                if(pilotBrowserDigest===undefined)await insert.run();
                else await db.batch([db.prepare('INSERT INTO pilot_genesis_browser_guard(challenge_id,browser_digest) VALUES (?,?)')
                  .bind(id,pilotBrowserDigest),insert]);
                const options=await webauthn.authenticationOptions(identity,challenge);
                return {id,options:{...options,allowCredentials:[{id:pin.credential,type:'public-key' as const}]}};
            } catch {throw unavailable();}
        },
        async complete(id:string,grant:string,roster:SignedManagedOperation,assertion:AuthenticationResponseJSON) {
            try {
                const {scope,now,expires,grantDigest,rosterDigest}=await intent(grant,roster);
                if (typeof id!=='string' || !/^[A-Za-z0-9_-]{43}$/.test(id) || JSON.stringify(assertion).length>32_768) throw unavailable();
                const row=await db.prepare(`SELECT c.challenge_digest,c.expires,p.credential,p.handle,p.cose_key,p.counter
                    FROM auth_genesis_challenges c JOIN auth_genesis_pins p USING (account,tenant,vault,credential)
                    WHERE c.id=? AND c.account=? AND c.tenant=? AND c.vault=? AND c.grant_digest=? AND c.roster_digest=?
                    AND c.expires>unixepoch() AND p.active=1 AND NOT EXISTS(SELECT 1 FROM auth_genesis_decisions WHERE id=c.id OR grant_digest=c.grant_digest)`)
                    .bind(id,...scope,grantDigest,rosterDigest).first<Challenge>();
                if (!row || (assertion.response.userHandle && assertion.response.userHandle!==row.handle)) throw unavailable();
                const counter=await webauthn.authentication(identity,row.challenge_digest,assertion,{id:row.credential,publicKey:decode(row.cose_key),counter:row.counter});
                if ((counter || row.counter) && counter<=row.counter) throw unavailable();
                const key=await signer.key();
                if (key.keyId!==policy.authority.keyId || key.publicKey!==policy.authority.publicKey) throw unavailable();
                const validUntil=Math.min(expires,row.expires);
                const canonical=canonicalGenesisApproval({version:1,audience:'custodian:roster-genesis',decisionId:id,authorityKeyId:key.keyId,grantDigest,rosterDigest,issuedAt:now,expiresAt:validUntil});
                const signature=await signer.sign(GENESIS_APPROVAL_DOMAIN+canonical);
                await verifyGenesisApproval({canonical,signature},grant,roster,policy);
                const guard=pilotBrowserDigest===undefined?[]:[db.prepare(`UPDATE pilot_genesis_browser_guard SET finalize=1
                  WHERE challenge_id=? AND browser_digest=? AND finalize=0`).bind(id,pilotBrowserDigest)];
                const results=await db.batch([
                    ...guard,
                    db.prepare(`INSERT INTO auth_genesis_decisions
                      SELECT c.id,c.grant_digest,?,? FROM auth_genesis_challenges c JOIN auth_genesis_pins p USING (account,tenant,vault,credential)
                      WHERE c.id=? AND c.expires>unixepoch() AND ?>unixepoch() AND p.active=1 AND p.counter=? AND p.cose_key=? AND p.handle=?
                      RETURNING id`).bind(canonical,signature,id,validUntil,row.counter,row.cose_key,row.handle),
                    db.prepare(`UPDATE auth_genesis_pins SET counter=? WHERE account=? AND tenant=? AND vault=? AND credential=? AND EXISTS
                      (SELECT 1 FROM auth_genesis_decisions WHERE id=? AND canonical=? AND signature=?)`).bind(counter,...scope,row.credential,id,canonical,signature),
                ]);
                if (!results[guard.length]?.results.length) throw unavailable();
                return {canonical,signature};
            } catch {throw unavailable();}
        },
    };
}
