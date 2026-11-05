import { generateRegistrationOptions, generateAuthenticationOptions, verifyRegistrationResponse, verifyAuthenticationResponse, type RegistrationResponseJSON, type AuthenticationResponseJSON, type WebAuthnCredential } from '@simplewebauthn/server';
import { decodeAttestationObject } from '@simplewebauthn/server/helpers';
import { digest } from '../shared/contracts.ts';
export const encode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
export const decode = (value: string) => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
export const random = () => encode(crypto.getRandomValues(new Uint8Array(32)));
export interface WebAuthnPolicy {
    origin: string;
    rpId: string;
}
// Reject embedded/iframe ceremonies even where upstream tolerates absent topOrigin.
function topLevel(response: RegistrationResponseJSON | AuthenticationResponseJSON) {
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(response.response.clientDataJSON)));
    if (data.crossOrigin === true || data.topOrigin !== undefined)
        throw new Error('invalid_ceremony');
}
export const webauthn = {
    registrationOptions(policy: WebAuthnPolicy, userId: string, challenge: string) {
        return generateRegistrationOptions({ rpName: 'AgentKeychain', rpID: policy.rpId, userName: 'Invited account', userID: decode(userId), challenge: decode(challenge), timeout: 300000, attestationType: 'none', authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' }, supportedAlgorithmIDs: [-7, -8] });
    },
    authenticationOptions(policy: WebAuthnPolicy, challenge: string) {
        return generateAuthenticationOptions({ rpID: policy.rpId, challenge: decode(challenge), timeout: 300000, userVerification: 'required' });
    },
    async registration(policy: WebAuthnPolicy, challengeDigest: string, response: RegistrationResponseJSON) {
        topLevel(response);
        // credProps is an unsigned client hint, not cryptographic proof of residency.
        // Required creation options enforce capability on conforming clients.
        if (response.clientExtensionResults?.credProps?.rk === false)
            throw new Error('invalid_ceremony');
        // Reject non-none before upstream can enter certificate/metadata code.
        if (decodeAttestationObject(decode(response.response.attestationObject)).get('fmt') !== 'none')
            throw new Error('invalid_ceremony');
        const result = await verifyRegistrationResponse({ response, expectedChallenge: async (c) => await digest(c) === challengeDigest, expectedOrigin: policy.origin, expectedRPID: policy.rpId, requireUserVerification: true, requireUserPresence: true, supportedAlgorithmIDs: [-7, -8] });
        if (!result.verified || result.registrationInfo.fmt !== 'none')
            throw new Error('invalid_ceremony');
        return result.registrationInfo.credential;
    },
    async authentication(policy: WebAuthnPolicy, challengeDigest: string, response: AuthenticationResponseJSON, credential: WebAuthnCredential) {
        topLevel(response);
        if (response.id !== credential.id)
            throw new Error('invalid_ceremony');
        // -1 disables only upstream's monotonic-counter rejection, including zero.
        // Signature/UV/UP/RP/challenge verification still runs. SQL compares the
        // verified result against the current stored high-water mark and audits risk.
        const result = await verifyAuthenticationResponse({ response, credential: { ...credential, counter: -1 }, expectedChallenge: async (c) => await digest(c) === challengeDigest, expectedOrigin: policy.origin, expectedRPID: policy.rpId, requireUserVerification: true });
        if (!result.verified || !Number.isInteger(result.authenticationInfo.newCounter) || result.authenticationInfo.newCounter < 0)
            throw new Error('invalid_ceremony');
        return result.authenticationInfo.newCounter;
    },
};
