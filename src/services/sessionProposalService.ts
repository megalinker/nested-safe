import {
    createPublicClient, http, encodeFunctionData, concat, pad, toHex,
    type Address, type Hex, parseEther, parseUnits
} from "viem";
import { ACTIVE_CHAIN, RPC_URL, SAFE_7579_ADAPTER_ADDRESS, SMART_SESSIONS_VALIDATOR_ADDRESS, USDC_ADDRESS, PERIODIC_ERC20_POLICY } from "../config";
import { createSessionStruct, createAllowanceSessionStruct, getPermissionId, calculateConfigId } from "../utils/smartSessions";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { SAFE_ABI, ADAPTER_7579_ABI, ENABLE_SESSIONS_ABI } from "../abis";

// Helper to check 7579 status
export const checkAndBundle7579Setup = async (
    publicClient: any,
    safeAddress: string
): Promise<{ batch: any[], log: string[] }> => {
    const batch: any[] = [];
    const logs: string[] = [];
    const targetSafe = safeAddress as Address;
    const adapterAddr = SAFE_7579_ADAPTER_ADDRESS.toLowerCase();
    const FALLBACK_HANDLER_STORAGE_SLOT = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";

    const [isModuleEnabled, rawFallback] = await Promise.all([
        publicClient.readContract({
            address: targetSafe, abi: SAFE_ABI, functionName: "isModuleEnabled", args: [SAFE_7579_ADAPTER_ADDRESS]
        }).catch(() => false),
        publicClient.getStorageAt({ address: targetSafe, slot: FALLBACK_HANDLER_STORAGE_SLOT as Hex }).catch(() => "0x")
    ]);

    if (!isModuleEnabled) {
        logs.push("Bundling 7579 Module Enable & Init...");
        // 1. Enable Module
        batch.push({
            to: targetSafe, value: 0n, operation: 0,
            data: encodeFunctionData({ abi: SAFE_ABI, functionName: "enableModule", args: [SAFE_7579_ADAPTER_ADDRESS] })
        });
        // 2. Init Adapter
        const initData = encodeFunctionData({
            abi: ADAPTER_7579_ABI, functionName: "initializeAccount",
            args: [[{ module: SMART_SESSIONS_VALIDATOR_ADDRESS, initData: "0x", moduleType: 1n }], { registry: "0x0000000000000000000000000000000000000000", attesters: [], threshold: 0 }]
        });
        batch.push({
            to: SAFE_7579_ADAPTER_ADDRESS, value: 0n, operation: 0,
            data: concat([initData, targetSafe])
        });
    }

    const currentFallback = rawFallback && rawFallback !== "0x" ? `0x${rawFallback.slice(-40)}`.toLowerCase() : "0x";
    if (currentFallback !== adapterAddr) {
        logs.push("Bundling Fallback Handler update...");
        batch.push({
            to: targetSafe, value: 0n, operation: 0,
            data: encodeFunctionData({ abi: SAFE_ABI, functionName: "setFallbackHandler", args: [SAFE_7579_ADAPTER_ADDRESS] })
        });
    }

    return { batch, log: logs };
};

export const prepareScheduleProposal = async (
    safeAddress: string,
    recipient: string,
    amount: string,
    token: 'ETH' | 'USDC',
    validAfter: number
) => {
    const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(RPC_URL) });

    // 1. Get Setup Txs
    const { batch, log } = await checkAndBundle7579Setup(publicClient, safeAddress);

    // 2. Create Ephemeral Key
    const privateKey = generatePrivateKey();
    const sessionOwner = privateKeyToAccount(privateKey);
    const salt = pad(toHex(Date.now()), { size: 32 }) as Hex;

    // 3. Create Session Struct
    const session = token === 'ETH'
        ? createSessionStruct(sessionOwner.address, recipient as Address, "0xFFFFFFFF", parseEther(amount), salt, validAfter)
        : createSessionStruct(sessionOwner.address, USDC_ADDRESS as Address, "0xa9059cbb", 0n, salt, validAfter);

    // 4. Add Enable Action
    batch.push({
        to: SMART_SESSIONS_VALIDATOR_ADDRESS, value: 0n, operation: 0,
        data: encodeFunctionData({ abi: ENABLE_SESSIONS_ABI, functionName: "enableSessions", args: [[session]] })
    });

    const permissionId = getPermissionId(session);

    return {
        batch,
        log,
        storageData: { privateKey, session, target: recipient, amount, token, permissionId, startDate: new Date(validAfter * 1000).toLocaleString() }
    };
};

export const prepareAllowanceProposal = async (
    safeAddress: string,
    holder: string,
    amount: string,
    token: 'ETH' | 'USDC', // Currently only supports USDC per logic
    name: string,
    startString: string,
    intervalVal: string,
    intervalUnit: 'minutes' | 'hours' | 'days'
) => {
    if (token === 'ETH') throw new Error("Recurring allowances only support USDC currently.");

    const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(RPC_URL) });

    // 1. Get Setup Txs
    const { batch, log } = await checkAndBundle7579Setup(publicClient, safeAddress);

    // 2. Calculate params
    const salt = pad(toHex(Date.now()), { size: 32 }) as Hex;
    const startUnix = Math.floor(new Date(startString).getTime() / 1000);
    const val = parseInt(intervalVal);

    let refillSeconds = 0;
    if (intervalUnit === 'minutes') refillSeconds = val * 60;
    if (intervalUnit === 'hours') refillSeconds = val * 3600;
    if (intervalUnit === 'days') refillSeconds = val * 86400;

    const amountRaw = parseUnits(amount, 6);

    // 3. Create Session
    const session = createAllowanceSessionStruct(
        holder as Address,
        USDC_ADDRESS as Address,
        amountRaw,
        startUnix,
        salt,
        refillSeconds,
        name || "Untitled Budget",
        holder as Address
    );

    // 4. Add Enable Action
    batch.push({
        to: SMART_SESSIONS_VALIDATOR_ADDRESS, value: 0n, operation: 0,
        data: encodeFunctionData({ abi: ENABLE_SESSIONS_ABI, functionName: "enableSessions", args: [[session]] })
    });

    const permissionId = getPermissionId(session);
    const configId = calculateConfigId(safeAddress as Address, permissionId, USDC_ADDRESS as Address);

    return {
        batch,
        log,
        localData: {
            permissionId, configId, signerAddress: holder, name: name || "Untitled",
            amount, token, start: startString, session, type: 'recurring', interval: `${intervalVal} ${intervalUnit}`
        }
    };
};

export const prepareRevokeAllowance = (permissionId: string) => {
    const data = encodeFunctionData({
        abi: ENABLE_SESSIONS_ABI,
        functionName: "removeSession",
        args: [permissionId as Hex]
    });
    return {
        to: SMART_SESSIONS_VALIDATOR_ADDRESS,
        value: 0n,
        data: data as Hex
    };
};

export const prepareCleanupAllowance = (configId: string, tokenAddress: string) => {
    const data = encodeFunctionData({
        abi: PERIODIC_ERC20_POLICY as any, // Use any if ABI type import issues
        functionName: "revokeAllowance",
        args: [configId as Hex, tokenAddress as Address]
    });
    return {
        to: PERIODIC_ERC20_POLICY,
        value: 0n,
        data: data as Hex
    };
};