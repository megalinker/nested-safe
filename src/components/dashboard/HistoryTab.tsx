import React from 'react';
import { Icons } from '../shared/Icons';
import { formatEther, formatUnits, decodeFunctionData, parseAbi, type Hex } from 'viem';
import { ACTIVE_CHAIN } from '../../config';
import type { SafeTx } from '../../types';

interface HistoryTabProps {
    txHistory: SafeTx[];
    loadingHistory: boolean;
    fetchHistory: (address: string) => void;
    selectedNestedSafeAddr: string;
}

// Minimal ABI to decode standard ERC20 transfers
const TRANSFER_ABI = parseAbi([
    "function transfer(address to, uint256 amount)"
]);

export const HistoryTab: React.FC<HistoryTabProps> = ({
    txHistory,
    loadingHistory,
    fetchHistory,
    selectedNestedSafeAddr
}) => {

    const getTxDetails = (tx: SafeTx) => {
        const isIncoming = tx.txType === 'ETHEREUM_TRANSACTION';
        const ethValue = BigInt(tx.value || 0);

        // 1. Handle ETH Transfers
        if (ethValue > 0n) {
            return {
                label: isIncoming ? "Received ETH" : "Sent ETH",
                amount: `${formatEther(ethValue)} ETH`,
                isIncoming
            };
        }

        // 2. Handle ERC20 Transfers (USDC)
        // Selector 0xa9059cbb is standard for transfer(address,uint256)
        if (tx.data && tx.data.startsWith("0xa9059cbb")) {
            try {
                const { args } = decodeFunctionData({
                    abi: TRANSFER_ABI,
                    data: tx.data as Hex
                });
                // In this app context, we assume most ERC20s are USDC (6 decimals)
                const amount = formatUnits(args[1], 6);
                return {
                    label: "Sent USDC",
                    amount: `${amount} USDC`,
                    isIncoming: false
                };
            } catch (e) {
                // Fallback if decoding fails
            }
        }

        // 3. Handle Other Interactions
        return {
            label: "Contract Interaction",
            amount: "0 ETH", // or just "-"
            isIncoming: false
        };
    };

    return (
        <div>
            <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Recent Transactions</span>
                <button onClick={() => fetchHistory(selectedNestedSafeAddr)} className="icon-btn"><Icons.Refresh /></button>
            </div>

            {loadingHistory ? (
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', textAlign: 'center', marginTop: '2rem' }}>Loading...</div>
            ) : txHistory.length === 0 ? (
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', textAlign: 'center', marginTop: '2rem' }}>No history found.</div>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {txHistory.map((tx, i) => {
                        // Filter out incoming 0 ETH transactions (often internal triggers)
                        if (tx.txType === 'ETHEREUM_TRANSACTION' && BigInt(tx.value || 0) === 0n) return null;

                        const { label, amount, isIncoming } = getTxDetails(tx);

                        return (
                            <div key={i} className="owner-row" style={{ borderLeft: isIncoming ? '4px solid var(--success)' : '4px solid var(--primary)', padding: '12px' }}>
                                <div>
                                    <div style={{ fontWeight: '600', fontSize: '0.9rem' }}>{label}</div>
                                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{new Date(tx.executionDate).toLocaleDateString()}</div>
                                </div>
                                <div style={{ textAlign: 'right' }}>
                                    <div style={{ fontWeight: '600' }}>{amount}</div>
                                    {tx.transactionHash && (
                                        <a
                                            href={`${ACTIVE_CHAIN.blockExplorers?.default.url}/tx/${tx.transactionHash}`}
                                            target="_blank"
                                            rel="noreferrer"
                                            style={{ fontSize: '0.75rem', color: 'var(--primary)', textDecoration: 'none' }}
                                        >
                                            Explorer <Icons.ExternalLink />
                                        </a>
                                    )}
                                </div>
                            </div>
                        )
                    })}
                </div>
            )}
        </div>
    );
};