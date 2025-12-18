import { Safe4337Pack, type PaymasterOptions } from '@safe-global/relay-kit';
import type { PasskeyArgType } from '@safe-global/protocol-kit';
import type { MetaTransactionData } from '@safe-global/types-kit';
import { toHex } from 'viem';

// Configuration
const RPC_URL = "https://sepolia.base.org";
const API_KEY = import.meta.env.VITE_PIMLICO_API_KEY;
const BUNDLER_URL = `https://api.pimlico.io/v1/base-sepolia/rpc?apikey=${API_KEY}`;
const PAYMASTER_URL = `https://api.pimlico.io/v2/base-sepolia/rpc?apikey=${API_KEY}`;
const ENTRYPOINT_0_7 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

const paymasterOptions: PaymasterOptions = {
    isSponsored: true,
    paymasterUrl: PAYMASTER_URL,
};

export type SafeInfo = {
    address: string;
    isDeployed: boolean;
};

// --- HELPER: Refresh Paymaster Data ---
// Needed when we manually bump verification gas for Passkeys
async function refreshPaymasterData(userOp: any) {
  console.log('[PasskeyClient] Refreshing Paymaster Data...');

  const rpcUserOp = {
    sender: userOp.sender,
    nonce: toHex(BigInt(userOp.nonce)),
    callData: userOp.callData,
    callGasLimit: toHex(BigInt(userOp.callGasLimit)),
    verificationGasLimit: toHex(BigInt(userOp.verificationGasLimit)),
    preVerificationGas: toHex(BigInt(userOp.preVerificationGas)),
    maxFeePerGas: toHex(BigInt(userOp.maxFeePerGas)),
    maxPriorityFeePerGas: toHex(BigInt(userOp.maxPriorityFeePerGas)),
    paymasterVerificationGasLimit: toHex(BigInt(userOp.paymasterVerificationGasLimit || 0n)),
    paymasterPostOpGasLimit: toHex(BigInt(userOp.paymasterPostOpGasLimit || 0n)),
    initCode: userOp.initCode || "0x",
  };

  const body = {
    id: 1,
    jsonrpc: "2.0",
    method: "pm_getPaymasterData",
    params: [
      rpcUserOp,
      ENTRYPOINT_0_7,
      toHex(84532), // Chain ID (Base Sepolia)
      {}
    ]
  };

  const response = await fetch(PAYMASTER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  const json = await response.json();

  if (json.error) {
    throw new Error(`Paymaster refresh failed: ${json.error.message}`);
  }

  const result = json.result;

  // Update userOp with new Paymaster fields
  if (result.paymaster) userOp.paymaster = result.paymaster;
  if (result.paymasterData) userOp.paymasterData = result.paymasterData;
  if (result.paymasterVerificationGasLimit) userOp.paymasterVerificationGasLimit = BigInt(result.paymasterVerificationGasLimit);
  if (result.paymasterPostOpGasLimit) userOp.paymasterPostOpGasLimit = BigInt(result.paymasterPostOpGasLimit);

  // Update gas limits if the paymaster returned updated ones
  if (result.verificationGasLimit) userOp.verificationGasLimit = BigInt(result.verificationGasLimit);
  if (result.preVerificationGas) userOp.preVerificationGas = BigInt(result.preVerificationGas);
  if (result.callGasLimit) userOp.callGasLimit = BigInt(result.callGasLimit);

  console.log('[PasskeyClient] Paymaster Data Refreshed');
}


// Initialize the Safe SDK with the Passkey
export const getSafe4337Pack = async (passkey: PasskeyArgType) => {
    return await Safe4337Pack.init({
        provider: RPC_URL,
        signer: passkey,
        bundlerUrl: BUNDLER_URL,
        paymasterOptions,
        safeModulesVersion: '0.3.0',
        options: { owners: [], threshold: 1 }, 
    });
};

export async function getSafeInfo(passkey: PasskeyArgType): Promise<SafeInfo> {
    const safe4337Pack = await getSafe4337Pack(passkey);
    const protocolKit = safe4337Pack.protocolKit;
    const address = await protocolKit.getAddress();
    const isDeployed = await protocolKit.isSafeDeployed();
    return { address, isDeployed };
}

// Generic Execute Function
export async function executePasskeyTransaction(
    passkey: PasskeyArgType,
    txs: MetaTransactionData[]
): Promise<string> {
    const safe4337Pack = await getSafe4337Pack(passkey);

    // 1. Create UserOp
    let safeOperation = await safe4337Pack.createTransaction({ transactions: txs });
    const userOp = safeOperation.userOperation;

    // 2. GAS FIX for Passkeys (P-256)
    const SAFE_VERIFICATION_GAS = 600_000n; // 500k-600k is usually safe for P256

    if (BigInt(userOp.verificationGasLimit) < SAFE_VERIFICATION_GAS) {
        console.log('[PasskeyClient] Bumping verification gas...');
        userOp.verificationGasLimit = SAFE_VERIFICATION_GAS;
        
        // 3. REFRESH PAYMASTER DATA (Critical!)
        // The previous paymaster signature is now invalid because we changed verificationGasLimit.
        await refreshPaymasterData(userOp);
    }
    
    // 4. Sign UserOp (Triggers FaceID/TouchID)
    const signedSafeOperation = await safe4337Pack.signSafeOperation(safeOperation);
    
    // 5. Send to Bundler
    const userOpHash = await safe4337Pack.executeTransaction({ executable: signedSafeOperation });
    
    return userOpHash;
}