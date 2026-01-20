import React from 'react';
import { Icons } from '../shared/Icons';
import type { QueuedTx } from '../../types';

interface QueueTabProps {
  queuedTxs: QueuedTx[];
  nestedNonce: number;
  nestedThreshold: number;
  approvalsMap: Record<string, string[]>;
  selectedSafeAddr: string;
  selectedNestedSafeAddr: string;
  isCurrentSafeOwner: boolean;
  loading: boolean;
  handleRefreshQueue: () => void;
  approveTxHash: (hash: string) => void;
  executeQueuedTx: (tx: QueuedTx) => void;
}

export const QueueTab: React.FC<QueueTabProps> = ({
  queuedTxs,
  nestedNonce,
  nestedThreshold,
  approvalsMap,
  selectedSafeAddr,
  selectedNestedSafeAddr,
  isCurrentSafeOwner,
  loading,
  handleRefreshQueue,
  approveTxHash,
  executeQueuedTx
}) => {
  const currentSafeQueue = queuedTxs.filter(t => {
    if (!selectedNestedSafeAddr) return false;
    return t.safeAddress && t.safeAddress.toLowerCase() === selectedNestedSafeAddr.toLowerCase();
  });

  return (
    <div>
      <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <span>Pending Transactions (Next Nonce: {nestedNonce})</span>
        <button onClick={handleRefreshQueue} className="icon-btn" title="Force Refresh"><Icons.Refresh /></button>
      </div>

      {currentSafeQueue.filter(t => t.nonce >= nestedNonce).length === 0 ? (
        <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>No pending transactions for this Safe.</div>
      ) : (
        currentSafeQueue.filter(t => t.nonce >= nestedNonce).sort((a, b) => a.nonce - b.nonce).map(tx => {
          const approvals = approvalsMap[tx.hash] || [];
          const hasSigned = approvals.some(o => o.toLowerCase() === selectedSafeAddr.toLowerCase());
          const signedCount = approvals.length;
          const readyToExec = signedCount >= nestedThreshold;
          const isNext = tx.nonce === nestedNonce;

          return (
            <div key={tx.hash} style={{ background: 'var(--surface-1)', border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem', marginBottom: '1rem', opacity: isNext ? 1 : 0.6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '10px' }}>
                <div style={{ fontWeight: '600' }}>{tx.description}</div>
                <div className="header-badge" style={{ background: readyToExec ? 'var(--success)' : 'var(--surface-3)', color: 'white' }}>
                  Nonce {tx.nonce}
                </div>
              </div>

              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1rem', fontFamily: 'monospace' }}>
                Hash: {tx.hash.slice(0, 10)}...{tx.hash.slice(-8)}
              </div>

              <div style={{ background: 'var(--surface-2)', padding: '10px', borderRadius: '6px', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '0.8rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Confirmations</span>
                  <span style={{ fontWeight: '600', color: readyToExec ? 'var(--success)' : 'var(--text-main)' }}>
                    {signedCount} / {nestedThreshold}
                  </span>
                </div>

                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  {approvals.length > 0 ? (
                    approvals.map(signer => {
                      const isMe = signer.toLowerCase() === selectedSafeAddr.toLowerCase();
                      return (
                        <div key={signer} style={{
                          display: 'flex', alignItems: 'center', gap: '6px',
                          background: 'rgba(255,255,255,0.05)', border: isMe ? '1px solid var(--primary)' : '1px solid var(--border)',
                          padding: '4px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'JetBrains Mono'
                        }}>
                          {isMe && <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--primary)' }}></span>}
                          {signer.slice(0, 6)}...{signer.slice(-4)}
                          {isMe && <span style={{ fontWeight: 'bold', color: 'var(--primary)' }}>(You)</span>}
                        </div>
                      );
                    })
                  ) : (
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                      No signatures yet
                    </span>
                  )}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                {!hasSigned && (
                  <button className="action-btn secondary" onClick={() => approveTxHash(tx.hash)} disabled={loading || !isCurrentSafeOwner}>
                    <Icons.Check /> Sign (Approve)
                  </button>
                )}
                {(readyToExec || (!hasSigned && (signedCount + 1) >= nestedThreshold)) && isNext && (
                  <button className="action-btn" onClick={() => executeQueuedTx(tx)} disabled={loading || !isCurrentSafeOwner}>
                    Execute Transaction
                  </button>
                )}
                {(!isNext) && <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', alignSelf: 'center' }}>Waiting for previous nonce...</span>}
              </div>
            </div>
          );
        })
      )}
    </div>
  );
};