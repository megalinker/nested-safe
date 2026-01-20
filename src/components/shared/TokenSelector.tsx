import React from 'react';

interface TokenSelectorProps {
  selectedToken: 'ETH' | 'USDC';
  onSelect: (token: 'ETH' | 'USDC') => void;
}

export const TokenSelector: React.FC<TokenSelectorProps> = ({ selectedToken, onSelect }) => (
  <div style={{ display: 'flex', gap: '8px', marginBottom: '1rem' }}>
    {(['ETH', 'USDC'] as const).map(t => (
      <button
        key={t}
        onClick={() => onSelect(t)}
        className="chip"
        style={{
          borderColor: selectedToken === t ? 'var(--primary)' : 'var(--border)',
          background: selectedToken === t ? 'rgba(99, 102, 241, 0.1)' : 'transparent',
          color: selectedToken === t ? 'white' : 'var(--text-secondary)'
        }}
      >
        {t}
      </button>
    ))}
  </div>
);