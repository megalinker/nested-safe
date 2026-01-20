import React from 'react';
import { Icons } from '../shared/Icons';
import { TokenSelector } from '../shared/TokenSelector';

interface ScheduledTabProps {
  hasStoredSchedule: boolean;
  scheduledInfo: { target: string; amount: string } | null;
  isSessionEnabledOnChain: boolean;
  selectedToken: 'ETH' | 'USDC';
  setSelectedToken: (t: 'ETH' | 'USDC') => void;
  scheduleRecipient: string;
  setScheduleRecipient: (val: string) => void;
  scheduleAmount: string;
  setScheduleAmount: (val: string) => void;
  scheduleDate: string;
  setScheduleDate: (val: string) => void;
  setSendAmount: (val: string) => void; // Needed to clear transfer tab input on token switch
  loading: boolean;
  isCurrentSafeOwner: boolean;
  selectedNestedSafeAddr: string;
  handleCreateSchedule: () => void;
  handleExecuteSchedule: () => void;
  handleRevokeSessionOnChain: () => void;
  fetchData: (address: string) => void;
  handleClearSchedule: () => void;
}

export const ScheduledTab: React.FC<ScheduledTabProps> = ({
  hasStoredSchedule,
  scheduledInfo,
  isSessionEnabledOnChain,
  selectedToken,
  setSelectedToken,
  scheduleRecipient,
  setScheduleRecipient,
  scheduleAmount,
  setScheduleAmount,
  scheduleDate,
  setScheduleDate,
  setSendAmount,
  loading,
  isCurrentSafeOwner,
  selectedNestedSafeAddr,
  handleCreateSchedule,
  handleExecuteSchedule,
  handleRevokeSessionOnChain,
  fetchData,
  handleClearSchedule
}) => {
  
  // Helper to get stored token for display
  const getStoredToken = () => {
    try {
      return JSON.parse(localStorage.getItem("scheduled_session") || "{}").token || "";
    } catch { return ""; }
  };

  return (
    <div>
      <div className="section-label">Scheduled Transfer (Smart Session)</div>
      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
        Create a one-time session key that activates at a specific time.
      </p>

      {!hasStoredSchedule ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <TokenSelector 
            selectedToken={selectedToken} 
            onSelect={(t) => { setSelectedToken(t); setSendAmount(""); setScheduleAmount(""); }} 
          />
          
          <div className="input-group">
            <label>Recipient Address</label>
            <input placeholder="0x..." value={scheduleRecipient} onChange={e => setScheduleRecipient(e.target.value)} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
            <div className="input-group">
              <label>Amount ({selectedToken})</label>
              <input type="number" placeholder="0.0" value={scheduleAmount} onChange={e => setScheduleAmount(e.target.value)} />
            </div>
            <div className="input-group">
              <label>Activation Time (Local)</label>
              <input type="datetime-local" value={scheduleDate} onChange={e => setScheduleDate(e.target.value)} style={{ colorScheme: 'dark' }} />
            </div>
          </div>

          <button className="action-btn" onClick={handleCreateSchedule} disabled={loading || !isCurrentSafeOwner || !scheduleDate}>
            Create Schedule Proposal
          </button>
        </div>
      ) : (
        <div style={{ background: 'var(--surface-1)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '1rem' }}>
            <div style={{ color: isSessionEnabledOnChain ? 'var(--success)' : '#fbbf24' }}>
              {isSessionEnabledOnChain ? <Icons.Check /> : <Icons.Refresh />}
            </div>
            <h3 style={{ margin: 0, fontSize: '1rem' }}>
              {isSessionEnabledOnChain ? "Session Key Active" : "Waiting for Setup Approval"}
            </h3>
          </div>
          <div style={{ fontSize: '0.9rem', marginBottom: '1rem' }}>
            <div><strong>Recipient:</strong> {scheduledInfo?.target}</div>
            <div><strong>Amount:</strong> {scheduledInfo?.amount} {getStoredToken()}</div>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button className="action-btn" onClick={handleExecuteSchedule} disabled={loading || !isSessionEnabledOnChain}>
              Execute Now
            </button>
            {isSessionEnabledOnChain && (
              <button className="action-btn" style={{ background: '#ef4444' }} onClick={handleRevokeSessionOnChain} disabled={loading || !isCurrentSafeOwner}>
                Revoke On-Chain
              </button>
            )}
            <button className="action-btn secondary" onClick={() => fetchData(selectedNestedSafeAddr)} disabled={loading}>
              Check Status
            </button>
            <button className="action-btn secondary" onClick={handleClearSchedule} disabled={loading}>
              Clear Local Data
            </button>
          </div>
        </div>
      )}
    </div>
  );
};