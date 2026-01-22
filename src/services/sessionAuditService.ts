import { createPublicClient, http, formatUnits, type Address } from "viem";
import { ACTIVE_CHAIN, RPC_URL, PERIODIC_ERC20_POLICY } from "../config";
import { PERIODIC_POLICY_ABI } from "../abis";

export const scanOnChainAllowances = async (safeAddress: string, localAllowances: any[]) => {
    const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(RPC_URL) });

    const onChainAllowances: any = await publicClient.readContract({
        address: PERIODIC_ERC20_POLICY as Address,
        abi: PERIODIC_POLICY_ABI,
        functionName: "getAllowances",
        args: [safeAddress as Address]
    });

    const zombies: any[] = [];

    for (const allowance of onChainAllowances) {
        // Simple heuristic to detect if we track it locally
        const isControllable = localAllowances.some(local =>
            local.amount === formatUnits(allowance.limit, 6) &&
            local.name === allowance.name
        );

        zombies.push({
            ...allowance,
            formattedLimit: formatUnits(allowance.limit, 6),
            formattedSpent: formatUnits(allowance.amountSpent, 6),
            isControllable,
            // Add other raw props as needed by UI
            configId: allowance.configId,
            token: allowance.token,
            holder: allowance.holder,
            isActive: allowance.isActive
        });
    }

    return zombies;
};