import React from 'react';
import { Icons } from '../shared/Icons';
import { SafeListItem } from '../shared/SafeListItem';
import type { StoredSafe } from '../../types';

interface SidebarProps {
  mySafes: StoredSafe[];
  myNestedSafes: StoredSafe[];
  selectedSafeAddr: string;
  setSelectedSafeAddr: (addr: string) => void;
  selectedNestedSafeAddr: string;
  setSelectedNestedSafeAddr: (addr: string) => void;
  createParentSafe: () => void;
  createNestedSafe: () => void;
  handleLogout: () => void;
  handleReset: () => void;
  handleOpenParentSettings: () => void;
  // ... pass through required props for balances or context
  ethBalance: string | null;
  usdcBalance: string | null;
  signerMode: 'main' | 'session';
  setSignerMode: (mode: 'main' | 'session') => void;
  activeSession: any;
  setActiveSession: (s: any) => void;
  myAllowances: any[];
  refreshNestedSafe: (addr: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = (props) => {
  return (
    <div className="sidebar">
      <div style={{ flex: 1 }}>
        <div className="section-label">
          <span>Signers (Parent Safes)</span>
          <button className="icon-btn" onClick={props.createParentSafe}><Icons.Plus /></button>
        </div>
        <div className="safe-list">
          {props.mySafes.map(safe => (
            <SafeListItem
              key={safe.address}
              safe={safe}
              isSelected={props.selectedSafeAddr === safe.address}
              onClick={() => props.setSelectedSafeAddr(safe.address)}
              type="parent"
              onSettings={props.handleOpenParentSettings}
            />
          ))}
        </div>

        {/* ... The rest of the Signer Context and Nested Safes logic ... */}
        
      </div>
      
      {/* Footer Buttons */}
      <div style={{ marginTop: '2rem', paddingTop: '1rem', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        <button className="action-btn secondary small" style={{ width: '100%', justifyContent: 'center' }} onClick={props.handleLogout}>
          <Icons.LogOut /> Logout
        </button>
        <button className="action-btn secondary small" style={{ width: '100%', opacity: 0.6, fontSize: '0.75rem', justifyContent: 'center' }} onClick={props.handleReset}>
          Reset Application
        </button>
      </div>
    </div>
  );
};