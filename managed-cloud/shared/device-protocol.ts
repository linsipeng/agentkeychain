import { base64, exactFields, identifier } from '../../src/cloud/protocol.ts';
import { digest } from './contracts.ts';
export interface EnrollmentGrant {
    version: 1;
    requestId: string;
    accountId: string;
    tenantId: string;
    vaultId: string;
    deviceId: string;
    signingKey: string;
    wrappingKey: string;
    issuerDeviceId: string | null;
    keyEpoch: number;
    expiresAt: number;
}
export interface KeyPackage {
    version: 1;
    vaultId: string;
    targetDeviceId: string;
    keyEpoch: number;
    wrappedVDK: string;
    issuerDeviceId: string;
    grantId: string;
}
const integer = (v: unknown) => { if (!Number.isSafeInteger(v) || (v as number) < 1)
    throw new Error('invalid_counter'); };
export function canonicalGrant(input: unknown): string {
    exactFields(input, ['version', 'requestId', 'accountId', 'tenantId', 'vaultId', 'deviceId', 'signingKey', 'wrappingKey', 'issuerDeviceId', 'keyEpoch', 'expiresAt']);
    if (input.version !== 1)
        throw new Error('invalid_version');
    for (const k of ['requestId', 'accountId', 'tenantId', 'vaultId', 'deviceId'])
        identifier(input[k]);
    if (input.issuerDeviceId !== null)
        identifier(input.issuerDeviceId);
    base64(input.signingKey, 32, 32);
    base64(input.wrappingKey, 32, 32);
    if (input.signingKey === input.wrappingKey)
        throw new Error('independent_keys_required');
    integer(input.keyEpoch);
    integer(input.expiresAt);
    return JSON.stringify({ version: 1, requestId: input.requestId, accountId: input.accountId, tenantId: input.tenantId, vaultId: input.vaultId, deviceId: input.deviceId, signingKey: input.signingKey, wrappingKey: input.wrappingKey, issuerDeviceId: input.issuerDeviceId, keyEpoch: input.keyEpoch, expiresAt: input.expiresAt });
}
export function canonicalPackage(input: unknown): string {
    exactFields(input, ['version', 'vaultId', 'targetDeviceId', 'keyEpoch', 'wrappedVDK', 'issuerDeviceId', 'grantId']);
    if (input.version !== 1)
        throw new Error('invalid_version');
    for (const k of ['vaultId', 'targetDeviceId', 'issuerDeviceId', 'grantId'])
        identifier(input[k]);
    integer(input.keyEpoch);
    base64(input.wrappedVDK, 48);
    if ((input.wrappedVDK as string).length > 2048)
        throw new Error('invalid_package');
    return JSON.stringify({ version: 1, vaultId: input.vaultId, targetDeviceId: input.targetDeviceId, keyEpoch: input.keyEpoch, wrappedVDK: input.wrappedVDK, issuerDeviceId: input.issuerDeviceId, grantId: input.grantId });
}
export function requestProof(method: string, url: URL, bodyDigest: string, timestamp: number, nonce: string, sessionDigest: string) {
    const params = new URLSearchParams(url.search);
    params.sort();
    const query = params.toString();
    return JSON.stringify(['AgentKeychain-device-request-v1', method, url.pathname + (query ? '?' + query : ''), bodyDigest, timestamp, nonce, sessionDigest]);
}
export const enrollmentProof = (signingKey: string, wrappingKey: string, platform: string) => JSON.stringify(['AgentKeychain-device-authorize-v1', signingKey, wrappingKey, platform]);
export const enrollmentReconcileProof = (requestId: string, deviceId: string, signingKey: string, wrappingKey: string, timestamp: number) =>
    JSON.stringify(['AgentKeychain-enrollment-reconcile-v1', requestId, deviceId, signingKey, wrappingKey, timestamp]);
export const enrollmentRetireProof = (requestId: string, deviceId: string, signingKey: string, wrappingKey: string, timestamp: number) =>
    JSON.stringify(['AgentKeychain-enrollment-retire-v1', requestId, deviceId, signingKey, wrappingKey, timestamp]);
export const enrollmentReplaceProof = (requestId: string, deviceId: string, signingKey: string, wrappingKey: string, timestamp: number, codeDigest: string, verificationDigest: string) =>
    JSON.stringify(['AgentKeychain-enrollment-replace-v1', requestId, deviceId, signingKey, wrappingKey, timestamp, codeDigest, verificationDigest]);
export const actionDigest = (action: string, canonical: string) => digest(JSON.stringify(['AgentKeychain-device-action-v1', action, canonical]));
export const challengeProof = (id: string, challengeDigest: string, deviceId: string, vaultId: string, expiresAt: number) => JSON.stringify(['AgentKeychain-device-challenge-v1', id, challengeDigest, deviceId, vaultId, expiresAt]);
