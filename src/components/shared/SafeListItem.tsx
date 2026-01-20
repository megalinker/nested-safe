import React, { useState } from 'react';
import { Icons } from './Icons';
import type { StoredSafe } from '../../types';

interface SafeListItemProps {
  safe: StoredSafe;
  isSelected: boolean;
  onClick: () => void;
  type: 'parent' | 'nested';
  balanceInfo?: { eth: string | null, usdc: string | null };
  onRefresh?: () => void;
  onSettings?: () => void;
}

export const SafeListItem: React.FC<SafeListItemProps> = ({ 
  safe, 
  isSelected, 
  onClick, 
  type, 
  balanceInfo, 
  onRefresh, 
  onSettings 
}) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(safe.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const gradient = type === 'parent'
    ? `linear-gradient(135deg, #${safe.address.slice(2, 8)}, #${safe.address.slice(-6)})`
    : `linear-gradient(135deg, #10b981, #0ea5e9)`;

  return (
    <div className={`safe-card ${isSelected ? 'selected' : ''}`} onClick={onClick}>
      <div className="safe-card-header" style={{ justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div className="safe-avatar" style={{ background: gradient }}></div>
          <div className="safe-name">{safe.name}</div>
        </div>

        <div style={{ display: 'flex', gap: '4px' }}>
          {type === 'parent' && isSelected && onSettings && (
            <button className="icon-btn" onClick={(e) => { e.stopPropagation(); onSettings(); }} title="Manage Signers">
              <Icons.Settings />
            </button>
          )}
          {type === 'nested' && isSelected && onRefresh && (
            <button className="icon-btn" onClick={(e) => { e.stopPropagation(); onRefresh(); }} title="Refresh Balance">
              <Icons.Refresh />
            </button>
          )}
        </div>
      </div>

      <div className="safe-meta">
        <span className="safe-address">{safe.address.slice(0, 6)}...{safe.address.slice(-4)}</span>
        <button className="icon-btn" onClick={handleCopy} title="Copy Address">
          {copied ? <Icons.Check /> : <Icons.Copy />}
        </button>
      </div>

      {type === 'nested' && balanceInfo && (
        <div style={{ marginTop: '12px', fontSize: '0.85rem', color: 'var(--text-secondary)', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>ETH</span>
            <span style={{ color: 'var(--text-main)', fontWeight: '500' }}>
              {balanceInfo.eth !== null ? balanceInfo.eth : <span style={{ opacity: 0.5 }}>...</span>}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>USDC</span>
            <span style={{ color: 'var(--text-main)', fontWeight: '500' }}>
              {balanceInfo.usdc !== null ? balanceInfo.usdc : <span style={{ opacity: 0.5 }}>...</span>}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};