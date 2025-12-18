import { extractPasskeyData, type PasskeyArgType } from '@safe-global/protocol-kit';

const STORAGE_PASSKEY_LIST_KEY = 'safe_passkey_list';

export async function createPasskey(): Promise<PasskeyArgType> {
  const displayName = 'Nested Safe Owner';

  // 1. Trigger Browser Passkey Creation
  const credential = (await navigator.credentials.create({
    publicKey: {
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }], // ES256
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'Nested Safe Engine' },
      user: {
        id: crypto.getRandomValues(new Uint8Array(32)),
        name: displayName,
        displayName,
      },
      timeout: 60_000,
      attestation: 'none',
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error('Passkey creation failed.');
  }

  // 2. Extract Data for Safe SDK
  const passkey = await extractPasskeyData(credential);
  return passkey;
}

export function loadPasskeys(): PasskeyArgType[] {
  const raw = localStorage.getItem(STORAGE_PASSKEY_LIST_KEY);
  if (!raw) return [];
  try {
    return JSON.parse(raw) as PasskeyArgType[];
  } catch {
    return [];
  }
}

export function storePasskey(passkey: PasskeyArgType) {
  const all = loadPasskeys();
  // Avoid duplicates based on rawId
  if (!all.find(p => p.rawId === passkey.rawId)) {
    all.push(passkey);
    localStorage.setItem(STORAGE_PASSKEY_LIST_KEY, JSON.stringify(all));
  }
}