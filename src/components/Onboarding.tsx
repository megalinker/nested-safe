import React from 'react';
import { ConnectButton } from "thirdweb/react";
import { client } from "../utils/thirdweb";
import { Icons } from "./shared/Icons";
import type { PasskeyArgType } from "@safe-global/protocol-kit";
import type { StoredSafe } from "../types";

interface OnboardingProps {
  loginMethod: 'thirdweb' | 'passkey' | null;
  eoaAddress: string;
  storedPasskeys: PasskeyArgType[];
  mySafes: StoredSafe[];
  loading: boolean;
  activeChain: any; // Thirdweb Chain object
  handleCreateNewPasskey: () => void;
  handleConnectPasskey: (pk: PasskeyArgType) => void;
  createParentSafe: () => void;
  createNestedSafe: () => void;
}

export const Onboarding: React.FC<OnboardingProps> = ({
  loginMethod,
  eoaAddress,
  storedPasskeys,
  mySafes,
  loading,
  activeChain,
  handleCreateNewPasskey,
  handleConnectPasskey,
  createParentSafe,
  createNestedSafe
}) => {
  return (
    <div className="setup-container">
      <div className={`step-card ${!loginMethod ? 'active' : 'success'}`}>
        <div className="step-icon"><Icons.Key /></div>
        <div style={{ width: '100%' }}>
          <h3>1. Login Method</h3>
          {!loginMethod ? (
            <div style={{ display: 'flex', gap: '10px', marginTop: '10px', flexDirection: 'column' }}>
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                {/* Thirdweb Connect Button with explicit chain prop */}
                <div className="custom-connect-wrapper">
                  <ConnectButton
                    client={client}
                    chain={activeChain}
                    theme={"dark"}
                    connectModal={{ size: "compact" }}
                  />
                </div>

                <button className="action-btn" style={{ background: '#0ea5e9', flex: 1 }} onClick={handleCreateNewPasskey} disabled={loading}>
                  <Icons.Plus /> Create Passkey
                </button>
              </div>

              {storedPasskeys.length > 0 && (
                <div style={{ marginTop: '10px', borderTop: '1px solid var(--border)', paddingTop: '10px' }}>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Saved Passkeys:</label>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '5px' }}>
                    {storedPasskeys.map(pk => (
                      <button key={pk.rawId} className="chip" onClick={() => handleConnectPasskey(pk)}>
                        <Icons.Key /> {pk.rawId.slice(0, 6)}...
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <p className="safe-address">{eoaAddress}</p>
            </div>
          )}
        </div>
      </div>
      <div className={`step-card ${eoaAddress && mySafes.length === 0 ? 'active' : (mySafes.length > 0 ? 'success' : 'disabled')}`}>
        <div className="step-icon"><Icons.Safe /></div>
        <div>
          <h3>2. Create Parent Safe</h3>
          {mySafes.length === 0 && <button className="action-btn" onClick={createParentSafe} disabled={loading}>Create Safe</button>}
        </div>
      </div>
      <div className={`step-card ${mySafes.length > 0 ? 'active' : 'disabled'}`}>
        <div className="step-icon"><Icons.Nested /></div>
        <div>
          <h3>3. Deploy Nested Safe</h3>
          <button className="action-btn" onClick={createNestedSafe} disabled={loading}>Deploy</button>
        </div>
      </div>
    </div>
  );
};