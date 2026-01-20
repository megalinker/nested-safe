import React from 'react';
import { parseEther, encodeFunctionData, parseUnits, type Address } from 'viem';
import { ERC20_ABI } from '../../abis';
import { TokenSelector } from '../shared/TokenSelector';
import { USDC_ADDRESS } from '../../config';

interface TransferTabProps {
  signerMode: 'main' | 'session';
  activeSession: any;
  selectedToken: 'ETH' | 'USDC';
  setSelectedToken: (t: 'ETH' | 'USDC') => void;
  recipient: string;
  setRecipient: (val: string) => void;
  sendAmount: string;
  setSendAmount: (val: string) => void;
  setScheduleAmount: (val: string) => void; // needed for token selector reset
  loading: boolean;
  isCurrentSafeOwner: boolean;
  nestedThreshold: number;
  handleSessionSpend: () => void;
  proposeTransaction: (to: string, val: bigint, data: any, desc: string) => void;
  addLog: (msg: string, type: 'error') => void;
}

export const TransferTab: React.FC<TransferTabProps> = ({
  signerMode,
  activeSession,
  selectedToken,
  setSelectedToken,
  recipient,
  setRecipient,
  sendAmount,
  setSendAmount,
  setScheduleAmount,
  loading,
  isCurrentSafeOwner,
  nestedThreshold,
  handleSessionSpend,
  proposeTransaction,
  addLog
}) => {
  
  const handleTransfer = () => {
    if (!sendAmount || !recipient) return;

    if (signerMode === 'session') {
      // --- SESSION EXECUTION ---
      if (selectedToken !== activeSession.token) {
        addLog(`Cannot spend ${selectedToken}: Key is only for ${activeSession.token}`, 'error');
        return;
      }
      handleSessionSpend();
    } else {
      // --- MULTISIG PROPOSAL ---
      if (selectedToken === 'ETH') {
        proposeTransaction(recipient, parseEther(sendAmount), "0x", `Transfer ${sendAmount} ETH`);
      } else {
        const amount = parseUnits(sendAmount, 6);
        const data = encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [recipient as Address, amount] });
        proposeTransaction(USDC_ADDRESS, 0n, data, `Transfer ${sendAmount} USDC`);
      }
    }
  };

  return (
    <>
      <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
        <span>{signerMode === 'session' ? "Make Transfer (Session Mode)" : "Make Transfer"}</span>
        {signerMode === 'session' && (
          <span style={{ color: 'var(--success)', fontSize: '0.7rem', fontWeight: 'bold' }}>
            USING SESSION KEY
          </span>
        )}
      </div>

      <TokenSelector 
        selectedToken={selectedToken} 
        onSelect={(t) => { setSelectedToken(t); setSendAmount(""); setScheduleAmount(""); }} 
      />

      {signerMode === 'session' && selectedToken !== activeSession.token && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.1)',
          color: '#f87171',
          padding: '10px',
          borderRadius: '8px',
          marginBottom: '15px',
          fontSize: '0.85rem',
          border: '1px solid rgba(239, 68, 68, 0.2)'
        }}>
          ⚠️ This session key is authorized for <strong>{activeSession.token}</strong>,
          but you have <strong>{selectedToken}</strong> selected.
        </div>
      )}

      <div className="input-group">
        <label>Recipient Address</label>
        <input placeholder="0x..." value={recipient} onChange={e => setRecipient(e.target.value)} />
      </div>

      <div className="input-group">
        <label>Amount ({selectedToken})</label>
        <input type="number" placeholder="0.0" value={sendAmount} onChange={e => setSendAmount(e.target.value)} />
      </div>

      <button
        className="action-btn"
        style={{
          background: signerMode === 'session' ? 'var(--success)' : 'var(--primary)',
          boxShadow: signerMode === 'session' ? '0 0 20px rgba(16, 185, 129, 0.2)' : 'none'
        }}
        onClick={handleTransfer}
        disabled={loading || (signerMode === 'main' && !isCurrentSafeOwner)}
      >
        {signerMode === 'session'
          ? `Spend via Allowance (${activeSession.token})`
          : nestedThreshold > 1
            ? `Create Proposal (${nestedThreshold} sigs needed)`
            : "Execute Transaction"
        }
      </button>

      {signerMode === 'session' && (
        <div style={{ marginTop: '15px', padding: '10px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          <strong>Current Session Limits:</strong><br />
          • Max Spend: {activeSession.amount} {activeSession.token}<br />
          • Max Txs: {activeSession.usage}<br />
          • Permission ID: <span style={{ fontFamily: 'monospace' }}>{activeSession.permissionId.slice(0, 16)}...</span>
        </div>
      )}
    </>
  );
};