import React, { useEffect, useState, useRef, useMemo } from "react";
import {
  createPublicClient,
  http,
  type WalletClient,
  type Hex,
  parseAbi,
  encodeFunctionData,
  pad,
  parseEther,
  formatEther,
  formatUnits
} from "viem";
import { baseSepolia } from "viem/chains";
import { entryPoint07Address } from "viem/account-abstraction";
import { createSmartAccountClient } from "permissionless";
import { toSafeSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import Safe from "@safe-global/protocol-kit";

import { connectPhantom } from "./utils/phantom";
import "./App.css";

// --- CONFIG ---
const PIMLICO_API_KEY = import.meta.env.VITE_PIMLICO_API_KEY;
const PIMLICO_URL = `https://api.pimlico.io/v2/base-sepolia/rpc?apikey=${PIMLICO_API_KEY}`;
const PUBLIC_RPC = "https://sepolia.base.org";
const USDC_ADDRESS = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

const SAFE_ABI = parseAbi([
  "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool success)",
  "function addOwnerWithThreshold(address owner, uint256 _threshold) public",
  "function getOwners() view returns (address[])",
  "function getThreshold() view returns (uint256)"
]);
const ERC20_ABI = parseAbi(["function balanceOf(address owner) view returns (uint256)"]);

// --- ICONS ---
const Icons = {
  Wallet: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M20 7h-9" /><path d="M14 17H5" /><circle cx="17" cy="17" r="3" /><path d="M7 7V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2h3a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-3" /></svg>,
  Safe: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>,
  Nested: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>,
  Check: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="3" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5" /></svg>,
  Copy: () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>,
  Refresh: () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>,
  Plus: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>,
  ChevronUp: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="18 15 12 9 6 15" /></svg>,
  ChevronDown: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9" /></svg>,
};

// --- TYPES ---
interface StoredSafe { address: string; salt: string; name: string; }
interface LogEntry { msg: string; type: 'info' | 'success' | 'error'; timestamp: string; }

// --- COMPONENTS ---

const SafeListItem = ({ safe, isSelected, onClick }: { safe: StoredSafe, isSelected: boolean, onClick: () => void }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(safe.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const gradient = `linear-gradient(135deg, #${safe.address.slice(2, 8)}, #${safe.address.slice(-6)})`;

  return (
    <div className={`safe-card ${isSelected ? 'selected' : ''}`} onClick={onClick}>
      <div className="safe-card-header">
        <div className="safe-avatar" style={{ background: gradient }}></div>
        <div className="safe-name">{safe.name}</div>
      </div>
      <div className="safe-meta">
        <span className="safe-address">{safe.address.slice(0, 6)}...{safe.address.slice(-4)}</span>
        <button className="icon-btn" onClick={handleCopy} title="Copy Address">
          {copied ? <Icons.Check /> : <Icons.Copy />}
        </button>
      </div>
    </div>
  );
};

// --- MAIN APP ---

const App: React.FC = () => {
  // State
  const [walletClient, setWalletClient] = useState<WalletClient | null>(null);
  const [eoaAddress, setEoaAddress] = useState<string>("");
  const [mySafes, setMySafes] = useState<StoredSafe[]>([]);
  const [selectedSafeAddr, setSelectedSafeAddr] = useState<string>("");
  const [nestedSafeAddress, setNestedSafeAddress] = useState<string>("");

  // Dashboard Logic
  const [activeTab, setActiveTab] = useState<'transfer' | 'owners' | 'settings'>('transfer');
  const [nestedOwners, setNestedOwners] = useState<string[]>([]);
  const [ethBalance, setEthBalance] = useState("0");
  const [usdcBalance, setUsdcBalance] = useState("0");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Forms
  const [recipient, setRecipient] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [newOwnerInput, setNewOwnerInput] = useState("");

  // --- INITIALIZATION ---
  useEffect(() => {
    const savedSafes = localStorage.getItem("mySafes");
    if (savedSafes) {
      const parsed = JSON.parse(savedSafes);
      setMySafes(parsed);
      // Ensure we set the selected safe address properly from storage if unset
      if (parsed.length > 0) setSelectedSafeAddr(parsed[0].address);
    }
    const savedNested = localStorage.getItem("nestedSafeAddress");
    if (savedNested) {
      setNestedSafeAddress(savedNested);
      fetchData(savedNested);
    }
  }, []);

  // --- DERIVED STATE ---
  // This calculates verification status dynamically, fixing the race condition
  const isCurrentSafeOwner = useMemo(() => {
    if (!selectedSafeAddr || nestedOwners.length === 0) return false;
    return nestedOwners.some(o => o.toLowerCase() === selectedSafeAddr.toLowerCase());
  }, [selectedSafeAddr, nestedOwners]);

  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  const addLog = (msg: string, type: 'info' | 'success' | 'error' = 'info') => {
    setLogs(prev => [...prev, { msg, type, timestamp: new Date().toLocaleTimeString() }]);
  };

  // --- ACTIONS ---

  const handleConnect = async () => {
    try {
      setLoading(true);
      const client = await connectPhantom();
      if (!client.account) throw new Error("No account");
      setWalletClient(client);
      setEoaAddress(client.account.address);
      addLog("Wallet connected", 'success');
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  const createParentSafe = async () => {
    if (!walletClient) return;
    try {
      setLoading(true);
      const safeIndex = mySafes.length + 1;
      const salt = BigInt(Date.now()).toString();
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1", saltNonce: BigInt(salt),
      });

      const newSafe: StoredSafe = { address: safeAccount.address, salt, name: `Safe ${safeIndex}` };
      const updated = [...mySafes, newSafe];
      setMySafes(updated);
      setSelectedSafeAddr(newSafe.address);
      localStorage.setItem("mySafes", JSON.stringify(updated));
      addLog(`Created ${newSafe.name}`, 'success');
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  const createNestedSafe = async () => {
    if (!walletClient || !selectedSafeAddr) return;
    try {
      setLoading(true);
      const currentParent = mySafes.find(s => s.address === selectedSafeAddr);
      if (!currentParent) throw new Error("Select a parent safe first");

      const nestedSalt = Date.now().toString();
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
        address: currentParent.address as Hex, saltNonce: BigInt(currentParent.salt)
      });

      const smartAccountClient = createSmartAccountClient({
        account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      const provider = (window as any).phantom?.ethereum || (window as any).ethereum;
      const protocolKit = await Safe.init({
        provider, signer: eoaAddress, predictedSafe: { safeAccountConfig: { owners: [selectedSafeAddr], threshold: 1 }, safeDeploymentConfig: { saltNonce: nestedSalt } }
      });

      const deploymentTx = await protocolKit.createSafeDeploymentTransaction();
      await smartAccountClient.sendTransaction({ to: deploymentTx.to as Hex, value: BigInt(deploymentTx.value), data: deploymentTx.data as Hex });

      const addr = await protocolKit.getAddress();
      setNestedSafeAddress(addr);
      localStorage.setItem("nestedSafeAddress", addr);
      addLog(`Nested Safe Deployed: ${addr}`, 'success');
      fetchData(addr);
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  const fetchData = async (address: string) => {
    const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
    const eth = await publicClient.getBalance({ address: address as Hex });
    setEthBalance(formatEther(eth));
    try {
      const usdc = await publicClient.readContract({ address: USDC_ADDRESS, abi: ERC20_ABI, functionName: "balanceOf", args: [address as Hex] });
      setUsdcBalance(formatUnits(usdc, 6));
    } catch { }
    try {
      const owners = await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getOwners" });
      setNestedOwners(Array.from(owners));
    } catch { }
  };

  const executeTx = async (to: string, val: bigint, data: Hex) => {
    if (!walletClient || !selectedSafeAddr) return;
    try {
      setLoading(true);
      const parent = mySafes.find(s => s.address === selectedSafeAddr);
      if (!parent) return;

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
        address: parent.address as Hex, saltNonce: BigInt(parent.salt)
      });

      const smartClient = createSmartAccountClient({
        account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      const r = pad(parent.address as Hex, { size: 32 });
      const signatures = `${r}${"00".repeat(32)}01` as Hex;

      const callData = encodeFunctionData({
        abi: SAFE_ABI, functionName: "execTransaction",
        args: [to as Hex, val, data, 0, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", signatures]
      });

      const hash = await smartClient.sendTransaction({ to: nestedSafeAddress as Hex, value: 0n, data: callData });
      addLog(`TX Sent: ${hash}`, 'success');
      setTimeout(() => fetchData(nestedSafeAddress), 3000);
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  const handleAddOwner = async () => {
    if (!newOwnerInput) return;
    const data = encodeFunctionData({ abi: SAFE_ABI, functionName: "addOwnerWithThreshold", args: [newOwnerInput as Hex, 1n] });
    await executeTx(nestedSafeAddress, 0n, data);
    setNewOwnerInput("");
  };

  const isDashboard = !!nestedSafeAddress;

  return (
    <div className="app-container">
      <header className="header">
        <span className="header-badge">Base Sepolia</span>
        <h1>Nested Safe Engine</h1>
      </header>

      {!isDashboard ? (
        <div className="setup-container">
          <div className={`step-card ${!eoaAddress ? 'active' : 'success'}`}>
            <div className="step-icon"><Icons.Wallet /></div>
            <div>
              <h3>1. Connect Wallet</h3>
              {!eoaAddress ? (
                <button className="action-btn" onClick={handleConnect} disabled={loading}>Connect Phantom</button>
              ) : <p className="safe-address">{eoaAddress}</p>}
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
      ) : (
        <div className="dashboard-container">
          {/* SIDEBAR */}
          <div className="sidebar">
            <div>
              <div className="section-label">
                <span>My Parent Safes</span>
                <button className="icon-btn" onClick={createParentSafe} title="Create New Safe"><Icons.Plus /></button>
              </div>
              <div className="safe-list">
                {mySafes.map(safe => (
                  <SafeListItem
                    key={safe.address}
                    safe={safe}
                    isSelected={selectedSafeAddr === safe.address}
                    onClick={() => setSelectedSafeAddr(safe.address)}
                  />
                ))}
              </div>
            </div>

            <div className="safe-card" style={{ cursor: 'default', background: 'var(--surface-3)', borderStyle: 'dashed' }}>
              <div className="section-label" style={{ marginBottom: '10px' }}>Target: Nested Safe</div>
              <div className="safe-meta">
                <span className="safe-address">{nestedSafeAddress.slice(0, 10)}...</span>
                <button className="icon-btn" onClick={() => navigator.clipboard.writeText(nestedSafeAddress)}><Icons.Copy /></button>
              </div>
              <div style={{ marginTop: '15px', textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>{ethBalance} ETH</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{usdcBalance} USDC</div>
              </div>
            </div>
          </div>

          {/* MAIN PANEL */}
          <div className="main-panel">
            <div className="panel-header">
              <button className={`tab-btn ${activeTab === 'transfer' ? 'active' : ''}`} onClick={() => setActiveTab('transfer')}>Transfer</button>
              <button className={`tab-btn ${activeTab === 'owners' ? 'active' : ''}`} onClick={() => setActiveTab('owners')}>Owners</button>
              <button className={`tab-btn ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}>Settings</button>
            </div>

            <div className="panel-content">
              {!isCurrentSafeOwner && (
                <div style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24', padding: '10px', borderRadius: '8px', marginBottom: '20px', fontSize: '0.9rem', display: 'flex', gap: '10px' }}>
                  <span>⚠️ The selected Parent Safe is NOT an owner of the Nested Safe. Transactions will fail.</span>
                </div>
              )}

              {activeTab === 'transfer' && (
                <>
                  <div className="input-group">
                    <label>Recipient Address</label>
                    <input placeholder="0x..." value={recipient} onChange={e => setRecipient(e.target.value)} />
                  </div>
                  <div className="input-group">
                    <label>Amount (ETH)</label>
                    <input type="number" placeholder="0.0" value={sendAmount} onChange={e => setSendAmount(e.target.value)} />
                  </div>
                  <button className="action-btn" onClick={() => executeTx(recipient, parseEther(sendAmount), "0x")} disabled={loading || !isCurrentSafeOwner}>
                    {loading ? "Processing..." : "Sign & Send"}
                  </button>
                </>
              )}

              {activeTab === 'owners' && (
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

                  <div className="section-label" style={{ marginTop: '2rem' }}>Quick Add My Safes</div>
                  <div className="quick-add-container">
                    {mySafes.filter(s => !nestedOwners.some(o => o.toLowerCase() === s.address.toLowerCase())).map(s => (
                      <button key={s.address} className="chip" onClick={() => setNewOwnerInput(s.address)}>
                        <Icons.Plus /> {s.name}
                      </button>
                    ))}
                    {mySafes.every(s => nestedOwners.some(o => o.toLowerCase() === s.address.toLowerCase())) && <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>All your safes are owners.</span>}
                  </div>

                  <div className="input-group" style={{ marginTop: '1rem' }}>
                    <label>Add External Owner Address</label>
                    <div style={{ display: 'flex', gap: '10px' }}>
                      <input value={newOwnerInput} onChange={e => setNewOwnerInput(e.target.value)} placeholder="0x..." />
                      <button className="action-btn small" onClick={handleAddOwner} disabled={loading || !isCurrentSafeOwner}>Add</button>
                    </div>
                  </div>
                </>
              )}

              {activeTab === 'settings' && (
                <div>
                  <h3 style={{ margin: '0 0 1rem 0' }}>Reset App</h3>
                  <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                    Clear stored data to restart the onboarding flow. (Safes remain on-chain).
                  </p>
                  <button className="action-btn secondary" onClick={() => {
                    localStorage.clear();
                    window.location.reload();
                  }}>Clear Storage & Reset</button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TERMINAL */}
      <div className="terminal-drawer" style={{ transform: loading || logs.length > 0 ? 'translateY(0)' : 'translateY(100%)' }}>
        <div className="terminal-header" onClick={() => setLogs([])}>
          <span>System Logs (Click to clear)</span>
          <Icons.ChevronDown />
        </div>
        <div className="terminal-content">
          {logs.map((l, i) => <div key={i} className={`log-entry ${l.type}`}>[{l.timestamp}] {l.msg}</div>)}
          <div ref={logsEndRef} />
        </div>
      </div>
    </div>
  );
};

export default App;