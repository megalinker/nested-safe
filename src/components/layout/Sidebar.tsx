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
    ethBalance: string | null;
    usdcBalance: string | null;
    signerMode: 'main' | 'session';
    setSignerMode: (mode: 'main' | 'session') => void;
    activeSession: any;
    setActiveSession: (s: any) => void;
    myAllowances: any[];
    refreshNestedSafe: (addr: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
    mySafes,
    myNestedSafes,
    selectedSafeAddr,
    setSelectedSafeAddr,
    selectedNestedSafeAddr,
    setSelectedNestedSafeAddr,
    createParentSafe,
    createNestedSafe,
    handleLogout,
    handleReset,
    handleOpenParentSettings,
    ethBalance,
    usdcBalance,
    signerMode,
    setSignerMode,
    activeSession,
    setActiveSession,
    myAllowances,
    refreshNestedSafe
}) => {
    return (
        <div className="sidebar">
            <div style={{ flex: 1 }}>
                {/* --- PARENT SAFES --- */}
                <div className="section-label">
                    <span>Signers (Parent Safes)</span>
                    <button className="icon-btn" onClick={createParentSafe} title="Create New Safe"><Icons.Plus /></button>
                </div>
                <div className="safe-list">
                    {mySafes.map(safe => (
                        <SafeListItem
                            key={safe.address}
                            safe={safe}
                            isSelected={selectedSafeAddr === safe.address}
                            onClick={() => setSelectedSafeAddr(safe.address)}
                            type="parent"
                            onSettings={handleOpenParentSettings}
                        />
                    ))}
                </div>

                <hr style={{ width: '100%', borderColor: 'var(--border)', margin: '1.5rem 0' }} />

                {/* --- SIGNER CONTEXT --- */}
                <div className="section-label">Active Signer Context</div>
                <div style={{ marginBottom: '1.5rem', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <button
                        className={`chip ${signerMode === 'main' ? 'active' : ''}`}
                        style={{ justifyContent: 'center', width: '100%', borderColor: signerMode === 'main' ? 'var(--primary)' : 'var(--border)' }}
                        onClick={() => { setSignerMode('main'); setActiveSession(null); }}
                    >
                        🛡️ Main Account (Multisig)
                    </button>

                    {myAllowances.map((al, i) => (
                        <button
                            key={i}
                            className={`chip ${activeSession?.permissionId === al.permissionId ? 'active' : ''}`}
                            style={{
                                justifyContent: 'center', width: '100%',
                                borderColor: activeSession?.permissionId === al.permissionId ? 'var(--success)' : 'var(--border)',
                                opacity: signerMode === 'session' && activeSession?.permissionId !== al.permissionId ? 0.5 : 1
                            }}
                            onClick={() => {
                                setSignerMode('session');
                                setActiveSession(al);
                            }}
                        >
                            🔑 {al.name || "Key"} ({al.amount} {al.token})
                        </button>
                    ))}
                </div>

                {/* --- NESTED SAFES (TARGETS) --- */}
                <div className="section-label">
                    <span>Managed Safes (Targets)</span>
                    <button className="icon-btn" onClick={createNestedSafe} title="Deploy New Nested Safe"><Icons.Plus /></button>
                </div>
                <div className="safe-list">
                    {myNestedSafes.map(safe => (
                        <SafeListItem
                            key={safe.address}
                            safe={safe}
                            isSelected={selectedNestedSafeAddr === safe.address}
                            onClick={() => setSelectedNestedSafeAddr(safe.address)}
                            type="nested"
                            onRefresh={() => refreshNestedSafe(safe.address)}
                            balanceInfo={selectedNestedSafeAddr === safe.address ? {
                                eth: ethBalance !== null ? parseFloat(ethBalance).toFixed(4) : null,
                                usdc: usdcBalance !== null ? parseFloat(usdcBalance).toFixed(2) : null
                            } : undefined}
                        />
                    ))}
                </div>
            </div>

            {/* --- FOOTER --- */}
            <div style={{ marginTop: '2rem', paddingTop: '1rem', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <button
                    className="action-btn secondary small"
                    style={{ width: '100%', justifyContent: 'center' }}
                    onClick={handleLogout}
                >
                    <Icons.LogOut /> Logout
                </button>

                <button
                    className="action-btn secondary small"
                    style={{ width: '100%', opacity: 0.6, fontSize: '0.75rem', justifyContent: 'center' }}
                    onClick={handleReset}
                >
                    Reset Application
                </button>
            </div>
        </div>
    );
};