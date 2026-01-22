import React from 'react';

interface ParentSettingsModalProps {
    isOpen: boolean;
    onClose: () => void;
    parentOwners: string[];
    currentEoa: string;
    newOwnerInput: string;
    setNewOwnerInput: (val: string) => void;
    onAddSigner: () => void;
    loading: boolean;
}

export const ParentSettingsModal: React.FC<ParentSettingsModalProps> = ({
    isOpen,
    onClose,
    parentOwners,
    currentEoa,
    newOwnerInput,
    setNewOwnerInput,
    onAddSigner,
    loading
}) => {
    if (!isOpen) return null;

    return (
        <div style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.8)', zIndex: 999,
            display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
            <div style={{
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                padding: '2rem', borderRadius: '12px', width: '450px', maxWidth: '90%'
            }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
                    <h3 style={{ margin: 0 }}>Manage Parent Safe</h3>
                    <button className="icon-btn" onClick={onClose}>✕</button>
                </div>

                <div className="section-label">Current Owners</div>
                <div style={{ maxHeight: '200px', overflowY: 'auto', marginBottom: '1.5rem', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {parentOwners.map(owner => (
                        <div key={owner} style={{
                            background: 'var(--surface-1)', padding: '10px', borderRadius: '6px',
                            fontFamily: 'JetBrains Mono', fontSize: '0.85rem', border: '1px solid var(--border)'
                        }}>
                            {owner}
                            {currentEoa && owner.toLowerCase() === currentEoa.toLowerCase() &&
                                <span className="owner-tag" style={{ marginLeft: '10px' }}>You</span>
                            }
                        </div>
                    ))}
                </div>

                <div className="section-label">Add New Signer</div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '10px' }}>
                    This will add a new owner address. The threshold will remain 1, meaning any single signer can execute transactions.
                </p>

                <div className="input-group">
                    <input
                        placeholder="New Signer Address (0x...)"
                        value={newOwnerInput}
                        onChange={(e) => setNewOwnerInput(e.target.value)}
                    />
                </div>

                <button
                    className="action-btn"
                    onClick={onAddSigner}
                    disabled={loading || !newOwnerInput}
                >
                    Add Signer
                </button>
            </div>
        </div>
    );
};