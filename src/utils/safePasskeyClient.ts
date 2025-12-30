import { Safe4337Pack, type PaymasterOptions } from '@safe-global/relay-kit';
import type { PasskeyArgType } from '@safe-global/protocol-kit';
import type { MetaTransactionData } from '@safe-global/types-kit';
import { toHex } from 'viem';
import {
  RPC_URL,
  BUNDLER_URL,
  PAYMASTER_URL,
  ENTRYPOINT_0_7,
  CHAIN_ID
} from '../config';

const paymasterOptions: PaymasterOptions = {
  isSponsored: true,
  paymasterUrl: PAYMASTER_URL,
};

export type SafeInfo = {
  address: string;
  isDeployed: boolean;
};

// --- HELPER: Refresh Paymaster Data ---
async function refreshPaymasterData(userOp: any) {
  console.log('[PasskeyClient] Refreshing Paymaster Data...');

  const hex = (v: any) => toHex(BigInt(v || 0));

  const rpcUserOp: any = {
    sender: userOp.sender,
    nonce: hex(userOp.nonce),
    callData: userOp.callData,
    callGasLimit: hex(userOp.callGasLimit),
    verificationGasLimit: hex(userOp.verificationGasLimit),
    preVerificationGas: hex(userOp.preVerificationGas),
    maxFeePerGas: hex(userOp.maxFeePerGas),
    maxPriorityFeePerGas: hex(userOp.maxPriorityFeePerGas),
    paymasterVerificationGasLimit: hex(userOp.paymasterVerificationGasLimit),
    paymasterPostOpGasLimit: hex(userOp.paymasterPostOpGasLimit),
    signature: userOp.signature || "0x"
  };

  if (userOp.factory && userOp.factory !== '0x') {
    rpcUserOp.factory = userOp.factory;
    rpcUserOp.factoryData = userOp.factoryData || "0x";
  } else if (userOp.initCode && userOp.initCode !== "0x" && userOp.initCode.length > 2) {
    rpcUserOp.factory = userOp.initCode.slice(0, 42);
    rpcUserOp.factoryData = "0x" + userOp.initCode.slice(42);
  }

  const body = {
    id: 1,
    jsonrpc: "2.0",
    method: "pm_getPaymasterData",
    params: [
      rpcUserOp,
      ENTRYPOINT_0_7,
      toHex(CHAIN_ID),
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

  if (result.paymaster) userOp.paymaster = result.paymaster;
  if (result.paymasterData) userOp.paymasterData = result.paymasterData;
  if (result.paymasterVerificationGasLimit) userOp.paymasterVerificationGasLimit = BigInt(result.paymasterVerificationGasLimit);
  if (result.paymasterPostOpGasLimit) userOp.paymasterPostOpGasLimit = BigInt(result.paymasterPostOpGasLimit);

  if (result.verificationGasLimit) userOp.verificationGasLimit = BigInt(result.verificationGasLimit);
  if (result.preVerificationGas) userOp.preVerificationGas = BigInt(result.preVerificationGas);
  if (result.callGasLimit) userOp.callGasLimit = BigInt(result.callGasLimit);

  console.log('[PasskeyClient] Paymaster Data Refreshed');
}

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

export async function executePasskeyTransaction(
  passkey: PasskeyArgType,
  txs: MetaTransactionData[]
): Promise<string> {
  const safe4337Pack = await getSafe4337Pack(passkey);

  let safeOperation = await safe4337Pack.createTransaction({ transactions: txs });
  const userOp = safeOperation.userOperation;

  const SAFE_VERIFICATION_GAS = 600_000n;

  if (BigInt(userOp.verificationGasLimit) < SAFE_VERIFICATION_GAS) {
    console.log('[PasskeyClient] Bumping verification gas...');
    userOp.verificationGasLimit = SAFE_VERIFICATION_GAS;
    await refreshPaymasterData(userOp);
  }

  const signedSafeOperation = await safe4337Pack.signSafeOperation(safeOperation);
  const userOpHash = await safe4337Pack.executeTransaction({ executable: signedSafeOperation });

  return userOpHash;
}