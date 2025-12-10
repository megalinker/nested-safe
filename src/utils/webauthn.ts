/**
 * Helper: Convert Base64URL string to Uint8Array
 * Handles the difference between Base64URL (WebAuthn) and Base64 (atob)
 */
const base64UrlToUint8Array = (base64Url: string): Uint8Array => {
    const padding = '='.repeat((4 - base64Url.length % 4) % 4);
    const base64 = (base64Url + padding)
        .replace(/-/g, '+')
        .replace(/_/g, '/');

    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
};

/**
 * Trigger the browser's native "Create Passkey" prompt (FaceID/TouchID).
 * Returns a credential ID if successful.
 */
export const registerPasskey = async (username: string): Promise<string> => {
    if (!window.PublicKeyCredential) {
        throw new Error("WebAuthn not supported in this browser");
    }

    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
        challenge,
        rp: {
            name: "Nested Safe Engine",
            id: window.location.hostname,
        },
        user: {
            id: Uint8Array.from(username, c => c.charCodeAt(0)),
            name: username,
            displayName: username,
        },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }], // ES256
        authenticatorSelection: {
            authenticatorAttachment: "platform", // Forces TouchID/FaceID/Windows Hello
            userVerification: "required",
        },
        timeout: 60000,
        attestation: "direct"
    };

    const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
    }) as PublicKeyCredential;

    return credential.id;
};

/**
 * Trigger the browser's native "Use Passkey" prompt.
 * Throws an error if the user cancels or fails biometrics.
 */
export const authenticatePasskey = async (credentialId: string): Promise<boolean> => {
    if (!window.PublicKeyCredential) {
        throw new Error("WebAuthn not supported");
    }

    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    // We explicitly ask for the specific credential we registered
    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        challenge,
        allowCredentials: [{
            // --- FIX: Add 'as BufferSource' to satisfy TypeScript ---
            id: base64UrlToUint8Array(credentialId) as BufferSource,
            type: "public-key",
            transports: ["internal"],
        }],
        userVerification: "required",
    };

    try {
        // This Line triggers the FaceID / TouchID Popup
        await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions
        });
        return true;
    } catch (e) {
        console.error(e);
        return false;
    }
};