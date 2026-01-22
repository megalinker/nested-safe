import { useState, useEffect, useCallback } from 'react';
import { createPublicClient, http, formatEther, formatUnits, type Hex } from 'viem';
import { ACTIVE_CHAIN, RPC_URL, USDC_ADDRESS, NETWORK } from '../config';
import { SAFE_ABI, ERC20_ABI } from '../abis';
import type { SafeTx } from '../types';

// Define the Service URL locally based on the config Network
const SAFE_TX_SERVICE_URL = NETWORK === 'mainnet'
    ? "https://safe-transaction-base.safe.global/api/v1"
    : "https://safe-transaction-base-sepolia.safe.global/api/v1";

export const useSafeData = (address: string, fallbackOwner?: string) => {
    const [ethBalance, setEthBalance] = useState<string | null>(null);
    const [usdcBalance, setUsdcBalance] = useState<string | null>(null);
    const [owners, setOwners] = useState<string[]>([]);
    const [threshold, setThreshold] = useState<number>(0);
    const [nonce, setNonce] = useState<number>(0);
    
    // History State
    const [history, setHistory] = useState<SafeTx[]>([]);
    const [loadingHistory, setLoadingHistory] = useState(false);

    const fetchData = useCallback(async () => {
        if (!address) return;

        const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(RPC_URL) });

        try {
            // 1. Fetch Balances (Parallel)
            const [eth, usdc] = await Promise.all([
                publicClient.getBalance({ address: address as Hex }),
                publicClient.readContract({ 
                    address: USDC_ADDRESS, 
                    abi: ERC20_ABI, 
                    functionName: "balanceOf", 
                    args: [address as Hex] 
                })
            ]);

            setEthBalance(formatEther(eth));
            setUsdcBalance(formatUnits(usdc, 6));

            // 2. Fetch Safe Config (Owners, Threshold, Nonce)
            try {
                const [safeOwners, safeThresh, safeNonce] = await Promise.all([
                    publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getOwners" }),
                    publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getThreshold" }),
                    publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "nonce" })
                ]);

                setOwners(Array.from(safeOwners));
                setThreshold(Number(safeThresh));
                setNonce(Number(safeNonce));

            } catch (e) {
                // Counterfactual Fallback:
                // If the contract read fails, it likely means the Safe isn't deployed yet.
                // We default to the "Fallback Owner" (usually the Parent Safe) and threshold 1.
                if (fallbackOwner) {
                    setOwners([fallbackOwner]);
                    setThreshold(1);
                } else {
                    setOwners([]);
                    setThreshold(0);
                }
                setNonce(0);
            }

        } catch (e) {
            console.error("General error fetching Safe data:", e);
        }
    }, [address, fallbackOwner]);

    const fetchHistory = useCallback(async () => {
        if (!address) return;
        
        setLoadingHistory(true);
        try {
            const response = await fetch(`${SAFE_TX_SERVICE_URL}/safes/${address}/all-transactions/?ordering=-timestamp&limit=20`);
            if (!response.ok) throw new Error("History fetch failed");
            const data = await response.json();
            setHistory(data.results || []);
        } catch (e) {
            console.error("Failed to fetch history:", e);
            setHistory([]);
        } finally {
            setLoadingHistory(false);
        }
    }, [address]);

    // Auto-fetch data when address changes
    useEffect(() => {
        if (address) {
            fetchData();
        } else {
            // Reset state if no address is selected
            setEthBalance(null);
            setUsdcBalance(null);
            setOwners([]);
            setThreshold(0);
            setNonce(0);
            setHistory([]);
        }
    }, [address, fetchData]);

    return {
        ethBalance,
        usdcBalance,
        owners,
        threshold,
        nonce,
        history,
        loadingHistory,
        fetchData,
        fetchHistory
    };
};