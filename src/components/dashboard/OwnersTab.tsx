import React from 'react';
import { Icons } from '../shared/Icons';
import type { StoredSafe } from '../../types';

interface OwnersTabProps {
    nestedOwners: string[];
    mySafes: StoredSafe[];
    nestedThreshold: number;
    loading: boolean;
    isCurrentSafeOwner: boolean;
    handleAddOwner: (addressOverride?: string) => void;
    handleUpdateThreshold: () => void;
    newThresholdInput: number;
    setNewThresholdInput: (val: number) => void;
    newOwnerInput: string;
    setNewOwnerInput: (val: string) => void;
}

export const OwnersTab: React.FC<OwnersTabProps> = ({
    nestedOwners,
    mySafes,
    nestedThreshold,
    loading,
    isCurrentSafeOwner,
    handleAddOwner,
    handleUpdateThreshold,
    newThresholdInput,
    setNewThresholdInput,
    newOwnerInput,
    setNewOwnerInput
}) => {
    return (
        <>
            <div className="section-label">Active Owners</div>
            {nestedOwners.map(owner => (
                <div key={owner} className="owner-row">
                    <div className="owner-info">
                        <span className="owner-addr">{owner}</span>
                        {mySafes.find(s => s.address.toLowerCase() === owner.toLowerCase()) && <span className="owner-tag">Managed by You</span>}
                    </div>
                </div>
            ))}

            <div className="section-label" style={{ marginTop: '1.5rem' }}>Add from my Parent Safes</div>
            <div className="quick-add-container">
                {mySafes
                    .filter(safe => !nestedOwners.some(o => o.toLowerCase() === safe.address.toLowerCase()))
                    .map(safe => (
                        <button
                            key={safe.address}
                            className="chip"
                            onClick={() => handleAddOwner(safe.address)}
                            disabled={loading || !isCurrentSafeOwner}
                        >
                            <Icons.Plus /> Add {safe.name}
                        </button>
                    ))}
                {mySafes.every(safe => nestedOwners.some(o => o.toLowerCase() === safe.address.toLowerCase())) && (
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>All your safes are already owners.</span>
                )}
            </div>

            <div className="input-group" style={{ marginTop: '1rem' }}>
                <label>Add External Owner Address</label>
                <div style={{ display: 'flex', gap: '10px' }}>
                    <input value={newOwnerInput} onChange={e => setNewOwnerInput(e.target.value)} placeholder="0x..." />
                    <button className="action-btn small" onClick={() => handleAddOwner()} disabled={loading || !isCurrentSafeOwner}>Propose Add</button>
                </div>
            </div>
            <hr style={{ margin: '2rem 0', borderColor: 'var(--border)' }} />
            <div className="section-label">Security Threshold</div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--surface-1)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
                <div>
                    <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Current Policy</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: '600' }}>{nestedThreshold} out of {nestedOwners.length} signatures</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <input type="number" min="1" max={nestedOwners.length} value={newThresholdInput} onChange={(e) => setNewThresholdInput(parseInt(e.target.value))} style={{ width: '60px' }} />
                    <button className="action-btn small" onClick={handleUpdateThreshold} disabled={loading || !isCurrentSafeOwner}>Update</button>
                </div>
            </div>
        </>
    );
};