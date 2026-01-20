import React from 'react';
import { Icons } from '../shared/Icons';
import { TokenSelector } from '../shared/TokenSelector';

interface AllowancesTabProps {
    // State
    selectedToken: 'ETH' | 'USDC';
    setSelectedToken: (t: 'ETH' | 'USDC') => void;
    allowanceName: string;
    setAllowanceName: (val: string) => void;
    allowanceAmount: string;
    setAllowanceAmount: (val: string) => void;
    allowanceInterval: string;
    setAllowanceInterval: (val: string) => void;
    allowanceUnit: 'minutes' | 'hours' | 'days';
    setAllowanceUnit: (val: 'minutes' | 'hours' | 'days') => void;
    allowanceStart: string;
    setAllowanceStart: (val: string) => void;
    allowanceHolder: string;
    setAllowanceHolder: (val: string) => void;

    // Lists
    nestedOwners: string[];
    mySafes: any[];
    myAllowances: any[];
    zombieAllowances: any[];

    // App State / Flags
    loading: boolean;
    isScanning: boolean;
    isCurrentSafeOwner: boolean;
    selectedNestedSafeAddr: string;

    // Setters needed for side-effects
    setSendAmount: (val: string) => void;
    setScheduleAmount: (val: string) => void;
    setSignerMode: (mode: 'main' | 'session') => void;
    setActiveSession: (session: any) => void;
    setActiveTab: (tab: any) => void;
    addLog: (msg: string, type: 'info') => void;

    // Handlers
    handleCreateAllowance: () => void;
    handleCreateLinkedSchedule: (allowance: any) => void;
    handleCheckSpecific: (allowance: any) => void;
    handleRevokeAllowance: (allowance: any) => void;
    handleScanAllowances: () => void;
    handleCleanUpAllowance: (configId: string, token: string) => void;
}

export const AllowancesTab: React.FC<AllowancesTabProps> = ({
    selectedToken, setSelectedToken,
    allowanceName, setAllowanceName,
    allowanceAmount, setAllowanceAmount,
    allowanceInterval, setAllowanceInterval,
    allowanceUnit, setAllowanceUnit,
    allowanceStart, setAllowanceStart,
    allowanceHolder, setAllowanceHolder,
    nestedOwners, mySafes, myAllowances, zombieAllowances,
    loading, isScanning, isCurrentSafeOwner, selectedNestedSafeAddr,
    setSendAmount, setScheduleAmount, setSignerMode, setActiveSession, setActiveTab, addLog,
    handleCreateAllowance, handleCreateLinkedSchedule, handleCheckSpecific,
    handleRevokeAllowance, handleScanAllowances, handleCleanUpAllowance
}) => {
    return (
        <div>
            <div className="section-label">Recurring Budgets</div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                Create a standing allowance that resets automatically over time.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <TokenSelector
                    selectedToken={selectedToken}
                    onSelect={(t) => { setSelectedToken(t); setSendAmount(""); setScheduleAmount(""); }}
                />

                <div className="input-group">
                    <label>Label (e.g. "Nanny", "Gym")</label>
                    <input type="text" value={allowanceName} onChange={e => setAllowanceName(e.target.value)} placeholder="Untitled Budget" />
                </div>

                <div className="input-group">
                    <label>Spending Amount ({selectedToken})</label>
                    <input type="number" value={allowanceAmount} onChange={e => setAllowanceAmount(e.target.value)} placeholder="0.0" />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                    <div className="input-group">
                        <label>Reset Every</label>
                        <input type="number" value={allowanceInterval} onChange={e => setAllowanceInterval(e.target.value)} />
                    </div>
                    <div className="input-group">
                        <label>Unit</label>
                        <select
                            value={allowanceUnit}
                            onChange={e => setAllowanceUnit(e.target.value as any)}
                            style={{
                                width: '100%', background: 'var(--bg-dark)', border: '1px solid var(--border)',
                                color: 'white', padding: '10px', borderRadius: '8px', fontFamily: 'JetBrains Mono'
                            }}
                        >
                            <option value="minutes">Minutes</option>
                            <option value="hours">Hours</option>
                            <option value="days">Days</option>
                        </select>
                    </div>
                </div>

                <div className="input-group">
                    <label>Valid From</label>
                    <input type="datetime-local" value={allowanceStart} onChange={e => setAllowanceStart(e.target.value)} style={{ colorScheme: 'dark' }} />
                </div>

                {selectedToken === 'ETH' && (
                    <div style={{ padding: '10px', background: 'rgba(239, 68, 68, 0.1)', color: '#f87171', borderRadius: '8px', fontSize: '0.8rem' }}>
                        ⚠️ Recurring allowances currently only support USDC.
                    </div>
                )}

                <div className="input-group">
                    <label>Authorized Owner</label>
                    <select
                        value={allowanceHolder}
                        onChange={(e) => setAllowanceHolder(e.target.value)}
                        style={{
                            width: '100%', background: 'var(--bg-dark)', border: '1px solid var(--border)',
                            color: 'white', padding: '10px', borderRadius: '8px', fontFamily: 'JetBrains Mono'
                        }}
                    >
                        <option value="">-- Select an Owner --</option>
                        {nestedOwners.map(owner => (
                            <option key={owner} value={owner}>
                                {owner} {mySafes.find(s => s.address === owner) ? "(You)" : ""}
                            </option>
                        ))}
                    </select>
                </div>

                <button className="action-btn" onClick={handleCreateAllowance} disabled={loading || !isCurrentSafeOwner || !allowanceStart || !allowanceAmount || selectedToken === 'ETH'}>
                    Propose Budget
                </button>
            </div>

            <div className="section-label" style={{ marginTop: '2.5rem' }}>Active Budgets (Local)</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {myAllowances.map((al, i) => (
                    <div key={i} className="owner-row" style={{ borderLeft: '3px solid var(--primary)' }}>
                        <div style={{ flex: 1 }}>
                            <div style={{ fontSize: '0.9rem', fontWeight: 'bold', color: 'var(--primary)' }}>
                                {al.name || "Untitled"}
                            </div>
                            <div style={{ fontWeight: '500' }}>
                                {al.amount} {al.token}
                                <span style={{ fontSize: '0.75rem', color: 'var(--success)', marginLeft: '6px' }}>(Resets every {al.interval})</span>
                            </div>
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                                ID: {al.permissionId.slice(0, 14)}...
                            </div>
                        </div>

                        <div style={{ display: 'flex', gap: '8px' }}>
                            <button
                                className="action-btn secondary small"
                                style={{ borderColor: '#a855f7', color: '#a855f7', border: '1px solid', background: 'rgba(168, 85, 247, 0.1)' }}
                                onClick={() => handleCreateLinkedSchedule(al)}
                                title="Create a one-off scheduled payment linked to this budget"
                            >
                                <Icons.Plus /> Link Schedule
                            </button>
                            <button
                                className="action-btn secondary small"
                                onClick={() => {
                                    setSignerMode('session');
                                    setActiveSession(al);
                                    setActiveTab('transfer');
                                    addLog(`Selected Key: ${al.permissionId.slice(0, 8)}...`, "info");
                                }}
                            >
                                Use Key
                            </button>
                            <button className="icon-btn" onClick={() => handleCheckSpecific(al)} title="Check Live Status">
                                <Icons.Refresh />
                            </button>
                            <button
                                className="icon-btn"
                                style={{ color: '#ef4444', borderColor: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '6px' }}
                                onClick={() => handleRevokeAllowance(al)}
                                disabled={loading || !isCurrentSafeOwner}
                            >
                                <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" /></svg>
                            </button>
                        </div>
                    </div>
                ))}
            </div>

            {/* On-Chain Audit Section */}
            <hr style={{ margin: '2rem 0', borderColor: 'var(--border)' }} />
            <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>On-Chain Audit</span>
                <button className="action-btn secondary small" onClick={handleScanAllowances} disabled={isScanning || !selectedNestedSafeAddr}>
                    {isScanning ? "Scanning..." : <><Icons.Refresh /> Sync from Chain</>}
                </button>
            </div>

            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                This checks the smart contract directly. It reveals "Zombie" allowances that may exist even if you lost the keys.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {zombieAllowances.length === 0 && !isScanning && (
                    <div style={{ textAlign: 'center', padding: '1rem', border: '1px dashed var(--border)', borderRadius: '8px', color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                        Click "Sync" to fetch data from the blockchain.
                    </div>
                )}

                {zombieAllowances.map((z, i) => (
                    <div key={i} className="owner-row" style={{
                        borderLeft: !z.isActive
                            ? '3px solid var(--text-secondary)'
                            : z.isControllable
                                ? '3px solid var(--success)'
                                : '3px solid #f59e0b',
                        background: 'var(--surface-1)',
                        opacity: !z.isActive ? 0.6 : 1
                    }}>
                        <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ fontWeight: 'bold' }}>{z.name}</span>
                                {!z.isActive && <span className="header-badge" style={{ background: '#52525b' }}>ARCHIVED</span>}
                                {z.isActive && !z.isControllable && <span className="header-badge" style={{ background: '#f59e0b', color: 'black' }}>READ ONLY</span>}
                            </div>
                            <div style={{ fontSize: '0.85rem', marginTop: '4px' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Spent:</span> {z.formattedSpent} / {z.formattedLimit} USDC
                            </div>
                            <div style={{ fontSize: '0.85rem', marginTop: '4px' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Holder:</span> {z.holder.slice(0, 6)}...{z.holder.slice(-4)}
                            </div>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px', fontFamily: 'monospace' }}>
                                ConfigID: {z.configId.slice(0, 10)}...
                            </div>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            {z.isActive && (
                                <button className="icon-btn" title="Clean Up (Disable On-Chain)" onClick={() => handleCleanUpAllowance(z.configId, z.token)} disabled={loading || !isCurrentSafeOwner}>
                                    <Icons.Bug />
                                </button>
                            )}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};