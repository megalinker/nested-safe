import { createPublicClient, http, encodeFunctionData, parseEther, parseUnits, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import { createSmartAccountClient } from "permissionless";
import { entryPoint07Address } from "viem/account-abstraction";
import { getSafe7579SessionAccount } from "../utils/safe7579";
import { ACTIVE_CHAIN, RPC_URL, BUNDLER_URL, USDC_ADDRESS } from "../config";
import { ERC20_ABI } from "../abis";

export const executeSessionTransaction = async (
    safeAddress: string,
    session: any,
    signerCallback: (hash: Hex) => Promise<Hex>,
    txDetails: {
        to?: string; // If ETH/Generic
        recipient?: string; // If USDC
        amount: string;
        token: 'ETH' | 'USDC';
    }
) => {
    const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(RPC_URL) });
    const pimlicoClient = createPimlicoClient({ transport: http(BUNDLER_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

    // 1. Create the 7579 Account Wrapper
    const safeAccount = await getSafe7579SessionAccount(
        publicClient,
        safeAddress as Address,
        session,
        signerCallback
    );

    // 2. Create Smart Client
    const smartClient = createSmartAccountClient({
        account: safeAccount,
        chain: ACTIVE_CHAIN,
        bundlerTransport: http(BUNDLER_URL),
        paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
    });

    // 3. Prepare Payload
    let payload;
    if (txDetails.token === 'USDC') {
        const value = parseUnits(txDetails.amount, 6);
        const calldata = encodeFunctionData({
            abi: ERC20_ABI,
            functionName: "transfer",
            args: [txDetails.recipient as Address, value]
        });
        payload = {
            to: USDC_ADDRESS as Address,
            value: 0n,
            data: calldata
        };
    } else {
        payload = {
            to: txDetails.to as Address,
            value: parseEther(txDetails.amount),
            data: "0x" as Hex
        };
    }

    // 4. Send
    const userOpHash = await smartClient.sendTransaction(payload);
    return userOpHash;
};

// Helper for Automated Schedule Execution (Ephemeral Key)
export const executeAutomatedSchedule = async (
    safeAddress: string,
    storedSessionData: any
) => {
    const { privateKey, session, target, amount, token } = storedSessionData;
    const localAccount = privateKeyToAccount(privateKey);

    return await executeSessionTransaction(
        safeAddress,
        session,
        async (hash) => localAccount.sign({ hash }), // Simple local signer
        { to: target, recipient: target, amount, token }
    );
};