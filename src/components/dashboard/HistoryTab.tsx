import React from 'react';
import { Icons } from '../shared/Icons';
import { formatEther } from 'viem';
import { ACTIVE_CHAIN } from '../../config';
import type { SafeTx } from '../../types';

interface HistoryTabProps {
  txHistory: SafeTx[];
  loadingHistory: boolean;
  fetchHistory: (address: string) => void;
  selectedNestedSafeAddr: string;
}

export const HistoryTab: React.FC<HistoryTabProps> = ({
  txHistory,
  loadingHistory,
  fetchHistory,
  selectedNestedSafeAddr
}) => {
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
            const isIncoming = tx.txType === 'ETHEREUM_TRANSACTION';
            const val = formatEther(BigInt(tx.value || 0));
            if (isIncoming && val === "0") return null;
            return (
              <div key={i} className="owner-row" style={{ borderLeft: isIncoming ? '4px solid var(--success)' : '4px solid var(--primary)', padding: '12px' }}>
                <div>
                  <div style={{ fontWeight: '600', fontSize: '0.9rem' }}>{isIncoming ? "Received ETH" : "Executed TX"}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{new Date(tx.executionDate).toLocaleDateString()}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontWeight: '600' }}>{val} ETH</div>
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