import React, { useEffect, useState, useRef } from "react";
import {
  createPublicClient,
  http,
  type WalletClient,
  type Hex,
  parseAbi,
  encodeFunctionData,
  pad,
  formatEther,
  parseEther,
  formatUnits
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import { entryPoint07Address } from "viem/account-abstraction";
import { createSmartAccountClient } from "permissionless";
import { toSafeSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import Safe, { type SafeAccountConfig } from "@safe-global/protocol-kit";

import { connectPhantom } from "./utils/phantom";
import { registerPasskey, authenticatePasskey } from "./utils/webauthn";
import "./App.css";

// --- CONFIG ---
const PIMLICO_API_KEY = import.meta.env.VITE_PIMLICO_API_KEY;
const PIMLICO_URL = `https://api.pimlico.io/v2/base-sepolia/rpc?apikey=${PIMLICO_API_KEY}`;
const PUBLIC_RPC = "https://sepolia.base.org";
const USDC_ADDRESS = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

const SAFE_ABI = parseAbi([
  "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool success)",
  "function addOwnerWithThreshold(address owner, uint256 _threshold) public",
  "function changeThreshold(uint256 _threshold) public",
  "function getOwners() view returns (address[])",
  "function getThreshold() view returns (uint256)"
]);

const ERC20_ABI = parseAbi([
  "function balanceOf(address owner) view returns (uint256)"
]);

// --- ICONS (Simplified for readability) ---
const Icons = {
  Wallet: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M20 7h-9" /><path d="M14 17H5" /><circle cx="17" cy="17" r="3" /><path d="M7 7V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2h3a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-3" /></svg>,
  Safe: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>,
  Nested: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>,
  Check: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="3" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5" /></svg>,
  Copy: () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>,
  Refresh: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>,
  Send: () => <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>,
  Settings: () => <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" /></svg>,
  ChevronUp: () => <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="18 15 12 9 6 15" /></svg>,
  ChevronDown: () => <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9" /></svg>,
  Fingerprint: () => <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M2 12a10 10 0 0 1 10-10 10 10 0 0 1 10 10" /><path d="M12 16v-4" /><path d="M8 12a4 4 0 0 1 8 0" /></svg>
};

interface LogEntry {
  msg: string;
  type: 'info' | 'success' | 'error' | 'warning';
  timestamp: string;
}

// --- SETUP CARD COMPONENT ---
const StepCard = ({
  title, desc, isActive, isDone, isDisabled, actionLabel, onAction, address, Icon, loading
}: any) => {
  const copyToClipboard = (text: string) => navigator.clipboard.writeText(text);

  return (
    <div className={`step-card ${isActive ? 'active' : ''} ${isDone ? 'success' : ''} ${isDisabled ? 'disabled' : ''}`}>
      <div className="step-icon">
        {isDone ? <Icons.Check /> : <Icon />}
      </div>
      <div className="step-info">
        <h3>{title}</h3>
        <p>{desc}</p>

        {address && (
          <div className="address-pill">
            <span>{address.slice(0, 10)}...{address.slice(-8)}</span>
            <button className="copy-icon" onClick={() => copyToClipboard(address)}><Icons.Copy /></button>
          </div>
        )}

        {!isDone && onAction && (
          <button className="action-btn" onClick={onAction} disabled={loading || isDisabled} style={{ marginTop: '1rem' }}>
            {loading && isActive ? "Processing..." : actionLabel}
          </button>
        )}
      </div>
    </div>
  );
};

// --- MAIN APP COMPONENT ---

const App: React.FC = () => {
  // --- STATE ---
  const [walletClient, setWalletClient] = useState<WalletClient | null>(null);
  const [eoaAddress, setEoaAddress] = useState<string>("");
  const [primarySafeAddress, setPrimarySafeAddress] = useState<string>("");
  const [nestedSafeAddress, setNestedSafeAddress] = useState<string>("");
  const [passkeyAddress, setPasskeyAddress] = useState<string>("");
  const [passkeyId, setPasskeyId] = useState<string>("");
  const [isVerified, setIsVerified] = useState(false);

  // Dashboard State
  const [ethBalance, setEthBalance] = useState("0");
  const [usdcBalance, setUsdcBalance] = useState("0");
  const [nestedOwners, setNestedOwners] = useState<string[]>([]);
  const [nestedThreshold, setNestedThreshold] = useState<number>(0);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // UI State
  const [activeTab, setActiveTab] = useState<'transfer' | 'owners' | 'settings'>('transfer');
  const [showTerminal, setShowTerminal] = useState(true);

  // Forms
  const [sendAmount, setSendAmount] = useState("");
  const [recipient, setRecipient] = useState("");
  const [newOwnerInput, setNewOwnerInput] = useState("");
  const [newThresholdInput, setNewThresholdInput] = useState(1);
  const [updateThresholdInput, setUpdateThresholdInput] = useState(1);
  const [selectedSigner, setSelectedSigner] = useState<'phantom' | 'passkey'>('phantom');

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const savedPrimary = localStorage.getItem("primarySafeAddress");
    const savedNested = localStorage.getItem("nestedSafeAddress");
    const savedPasskey = localStorage.getItem("passkeyAddress");
    const savedPasskeyId = localStorage.getItem("passkeyId");

    if (savedPrimary) setPrimarySafeAddress(savedPrimary);
    if (savedNested) setNestedSafeAddress(savedNested);
    if (savedPasskey) setPasskeyAddress(savedPasskey);
    if (savedPasskeyId) setPasskeyId(savedPasskeyId);

    if (savedNested) fetchData(savedNested);
  }, []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const addLog = (msg: string, type: 'info' | 'success' | 'error' | 'warning' = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { msg, type, timestamp }]);
    if (type === 'error' || type === 'success') setShowTerminal(true);
  };

  // --- ACTIONS (Simplified logic for UI Demo) ---

  const handleConnect = async () => {
    try {
      setLoading(true);
      addLog("Connecting to Phantom...", 'info');
      const client = await connectPhantom();
      if (!client.account) throw new Error("No account returned");
      setWalletClient(client);
      setEoaAddress(client.account.address);
      addLog(`Connected: ${client.account.address}`, 'success');
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  const createPrimarySafe = async () => {
    if (!walletClient || !eoaAddress) return;
    try {
      setLoading(true);
      addLog("Initializing Primary Safe (ERC-4337)...", 'info');
      let salt = localStorage.getItem("primarySafeSalt");
      if (!salt) {
        salt = BigInt(Date.now()).toString();
        localStorage.setItem("primarySafeSalt", salt);
      }
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1", saltNonce: BigInt(salt),
      });
      const address = safeAccount.address;
      setPrimarySafeAddress(address);
      localStorage.setItem("primarySafeAddress", address);
      addLog(`Primary Safe Address: ${address}`, 'success');
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  const createNestedSafe = async () => {
    if (!walletClient || !primarySafeAddress || !eoaAddress) return;
    try {
      setLoading(true);
      addLog("Generating Nested Safe Payload...", 'info');
      const primarySalt = localStorage.getItem("primarySafeSalt") || "0";
      let nestedSalt = localStorage.getItem("nestedSafeSalt");
      if (!nestedSalt) { nestedSalt = Date.now().toString(); localStorage.setItem("nestedSafeSalt", nestedSalt); }

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1", address: primarySafeAddress as Hex, saltNonce: BigInt(primarySalt)
      });

      const smartAccountClient = createSmartAccountClient({
        account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      const provider = (window as any).phantom?.ethereum || (window as any).ethereum;
      const safeAccountConfig: SafeAccountConfig = { owners: [primarySafeAddress], threshold: 1 };
      const protocolKit = await Safe.init({ provider, signer: eoaAddress, predictedSafe: { safeAccountConfig, safeDeploymentConfig: { saltNonce: nestedSalt } } });
      const predictedAddr = await protocolKit.getAddress();
      const deploymentTx = await protocolKit.createSafeDeploymentTransaction();

      addLog(`Sending UserOp via Pimlico (Sponsored)...`, 'info');
      const txHash = await smartAccountClient.sendTransaction({ to: deploymentTx.to as Hex, value: BigInt(deploymentTx.value), data: deploymentTx.data as Hex });

      setNestedSafeAddress(predictedAddr);
      localStorage.setItem("nestedSafeAddress", predictedAddr);
      addLog(`Success! Nested Safe Deployed: ${predictedAddr}`, 'success');
      fetchData(predictedAddr);
    } catch (e: any) { addLog(`Failed: ${e.message}`, 'error'); } finally { setLoading(false); }
  };

  const verifyOwnership = async () => {
    if (!nestedSafeAddress || !primarySafeAddress || !eoaAddress) return;
    try {
      setLoading(true);
      addLog("Verifying Chain of Ownership...", "info");
      const provider = (window as any).phantom?.ethereum || (window as any).ethereum;

      const primarySafeInstance = await Safe.init({ provider, safeAddress: primarySafeAddress });
      const primaryOwners = await primarySafeInstance.getOwners();
      if (!primaryOwners.some(o => o.toLowerCase() === eoaAddress.toLowerCase())) throw new Error("EOA not owner of Primary");

      const nestedSafeInstance = await Safe.init({ provider, safeAddress: nestedSafeAddress });
      const nestedOwners = await nestedSafeInstance.getOwners();
      if (!nestedOwners.some(o => o.toLowerCase() === primarySafeAddress.toLowerCase())) throw new Error("Primary Safe not owner of Nested");

      addLog("✅ Full Ownership Verified.", "success");
      setIsVerified(true);
    } catch (e: any) { addLog(`Verification Error: ${e.message}`, "error"); } finally { setLoading(false); }
  };

  const fetchData = async (address: string) => {
    if (!address) return;
    try {
      setIsRefreshing(true);
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const eth = await publicClient.getBalance({ address: address as Hex });
      setEthBalance(formatEther(eth));
      try {
        const usdc = await publicClient.readContract({ address: USDC_ADDRESS, abi: ERC20_ABI, functionName: "balanceOf", args: [address as Hex] });
        setUsdcBalance(formatUnits(usdc, 6));
      } catch (e) { setUsdcBalance("0"); }
      try {
        const owners = await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getOwners" });
        const threshold = await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getThreshold" });
        setNestedOwners(Array.from(owners));
        setNestedThreshold(Number(threshold));
      } catch (e) { }
      addLog("Data refreshed.", 'info');
    } catch (e) { console.error(e); } finally { setIsRefreshing(false); }
  };

  const executeOnNestedSafe = async (targetContract: string, valueWei: bigint, callData: Hex, description: string) => {
    if (!walletClient || !primarySafeAddress || !nestedSafeAddress) return;
    try {
      setLoading(true);
      const signerName = selectedSigner === 'phantom' ? "Phantom" : "Passkey";
      addLog(`${description} via ${signerName}...`, 'info');

      let ownerAccount;
      if (selectedSigner === 'phantom') {
        ownerAccount = walletClient;
      } else {
        if (!passkeyId) throw new Error("No passkey ID found.");
        addLog("Authenticate with Biometrics...", 'warning');
        if (!(await authenticatePasskey(passkeyId))) throw new Error("Biometric failed");
        ownerAccount = privateKeyToAccount(localStorage.getItem("passkey_priv") as Hex);
      }

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [ownerAccount], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1", address: primarySafeAddress as Hex,
      });

      const smartAccountClient = createSmartAccountClient({
        account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      const r = pad(primarySafeAddress as Hex, { size: 32 });
      const s = pad("0x0", { size: 32 });
      const v = "01";
      const signatures = `${r}${s.slice(2)}${v}` as Hex;

      const nestedSafeCallData = encodeFunctionData({
        abi: SAFE_ABI, functionName: "execTransaction",
        args: [targetContract as Hex, valueWei, callData, 0, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", signatures]
      });

      const txHash = await smartAccountClient.sendTransaction({ to: nestedSafeAddress as Hex, value: 0n, data: nestedSafeCallData });
      addLog(`Executed! Hash: ${txHash}`, 'success');
      setTimeout(() => fetchData(nestedSafeAddress), 4000);
    } catch (e: any) { addLog(`Execution Failed: ${e.message}`, 'error'); } finally { setLoading(false); }
  };

  const handleSendEth = async () => {
    if (!sendAmount || !recipient) return;
    await executeOnNestedSafe(recipient, parseEther(sendAmount), "0x", `Sending ${sendAmount} ETH`);
  };

  const handleAddNestedOwner = async () => {
    if (!newOwnerInput || newThresholdInput < 1) return;
    const addOwnerData = encodeFunctionData({ abi: SAFE_ABI, functionName: "addOwnerWithThreshold", args: [newOwnerInput as Hex, BigInt(newThresholdInput)] });
    await executeOnNestedSafe(nestedSafeAddress, 0n, addOwnerData, `Adding owner ${newOwnerInput.slice(0, 6)}...`);
    setNewOwnerInput("");
  };

  const addPasskeySigner = async () => {
    try {
      setLoading(true);
      const newCredId = await registerPasskey("SafeOwner");
      setPasskeyId(newCredId); localStorage.setItem("passkeyId", newCredId);
      let privKey = localStorage.getItem("passkey_priv") as Hex | null;
      if (!privKey) { privKey = generatePrivateKey(); localStorage.setItem("passkey_priv", privKey); }
      const account = privateKeyToAccount(privKey);
      setPasskeyAddress(account.address); localStorage.setItem("passkeyAddress", account.address);
      addLog("Passkey added to device.", 'success');
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  // --- RENDER ---

  const isDashboardMode = !!nestedSafeAddress;

  return (
    <>
      <div className="app-container">
        <header className="header">
          <div className="header-badge">Base Sepolia Testnet</div>
          <h1>Nested Safe Engine</h1>
          {!isDashboardMode && <p style={{ color: 'var(--text-secondary)' }}>Initialize your ERC-4337 Account Abstraction Structure</p>}
        </header>

        {/* --- ONBOARDING / SETUP MODE --- */}
        {!isDashboardMode && (
          <div className="setup-container">
            <StepCard
              title="1. Connect Phantom"
              desc="Connect your browser wallet to act as the root signer."
              isActive={!eoaAddress}
              isDone={!!eoaAddress}
              actionLabel="Connect Wallet"
              onAction={handleConnect}
              address={eoaAddress}
              Icon={Icons.Wallet}
              loading={loading}
            />
            <StepCard
              title="2. Initialize Primary Safe"
              desc="Generate the deterministic address for your Primary Safe."
              isActive={!!eoaAddress && !primarySafeAddress}
              isDone={!!primarySafeAddress}
              isDisabled={!eoaAddress}
              actionLabel="Initialize Safe"
              onAction={createPrimarySafe}
              address={primarySafeAddress}
              Icon={Icons.Safe}
              loading={loading}
            />
            <StepCard
              title="3. Deploy Nested Safe"
              desc="Deploy the child Safe controlled by the Primary Safe."
              isActive={!!primarySafeAddress}
              isDisabled={!primarySafeAddress}
              actionLabel="Deploy Sponsored"
              onAction={createNestedSafe}
              Icon={Icons.Nested}
              loading={loading}
            />
          </div>
        )}

        {/* --- DASHBOARD MODE --- */}
        {isDashboardMode && (
          <div className="dashboard-container">

            {/* SIDEBAR */}
            <div className="info-card">
              <div className="balance-display">

                {/* Header with Refresh Button */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', marginBottom: '0.5rem' }}>
                  <span className="balance-label" style={{ margin: 0 }}>Total Balance</span>
                  <button
                    className="refresh-btn"
                    onClick={() => fetchData(nestedSafeAddress)}
                    disabled={isRefreshing}
                    title="Refresh Balance"
                  >
                    <div className={isRefreshing ? "spin-active" : ""}>
                      <Icons.Refresh />
                    </div>
                  </button>
                </div>

                <span className="balance-amount">{ethBalance} ETH</span>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.9rem' }}>{usdcBalance} USDC</span>
              </div>

              <div className="verification-status">
                <Icons.Check />
                <span>
                  {isVerified ? "Chain Verified" : "Verification Pending"}
                </span>
              </div>

              {!isVerified && (
                <button className="action-btn secondary" onClick={verifyOwnership} style={{ marginBottom: '1rem' }}>
                  Run Verification
                </button>
              )}

              <div style={{ borderTop: '1px solid var(--border)', paddingTop: '1.5rem' }}>
                <span className="balance-label" style={{ display: 'block', marginBottom: '0.5rem' }}>Signer Config</span>
                {!passkeyAddress ? (
                  <button className="action-btn secondary" onClick={addPasskeySigner} disabled={loading} style={{ fontSize: '0.85rem' }}>
                    <Icons.Fingerprint /> Enable Passkey
                  </button>
                ) : (
                  <div style={{ fontSize: '0.85rem', color: 'var(--success)' }}>
                    <Icons.Check /> Passkey Active
                  </div>
                )}
              </div>
            </div>

            {/* MAIN PANEL */}
            <div className="main-panel">
              <div className="tabs-header">
                <button className={`tab-btn ${activeTab === 'transfer' ? 'active' : ''}`} onClick={() => setActiveTab('transfer')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', justifyContent: 'center' }}>
                    <Icons.Send /> Transfer
                  </div>
                </button>
                <button className={`tab-btn ${activeTab === 'owners' ? 'active' : ''}`} onClick={() => setActiveTab('owners')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', justifyContent: 'center' }}>
                    <Icons.Safe /> Owners
                  </div>
                </button>
                <button className={`tab-btn ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', justifyContent: 'center' }}>
                    <Icons.Settings /> Settings
                  </div>
                </button>
              </div>

              <div className="panel-content">
                {/* TRANSFER TAB */}
                {activeTab === 'transfer' && (
                  <div>
                    <div className="input-group">
                      <label>Select Signer Method</label>
                      <div className="signer-toggle">
                        <button className={`signer-opt ${selectedSigner === 'phantom' ? 'active' : ''}`} onClick={() => setSelectedSigner('phantom')}>
                          Phantom Wallet
                        </button>
                        <button
                          className={`signer-opt ${selectedSigner === 'passkey' ? 'active' : ''}`}
                          onClick={() => setSelectedSigner('passkey')}
                          disabled={!passkeyAddress}
                          title={!passkeyAddress ? "Setup Passkey first" : ""}
                        >
                          Biometric Passkey
                        </button>
                      </div>
                    </div>

                    <div className="input-group">
                      <label>Recipient Address</label>
                      <input placeholder="0x..." value={recipient} onChange={e => setRecipient(e.target.value)} />
                    </div>

                    <div className="input-group">
                      <label>Amount (ETH)</label>
                      <input type="number" placeholder="0.0" value={sendAmount} onChange={e => setSendAmount(e.target.value)} />
                    </div>

                    <button className="action-btn" onClick={handleSendEth} disabled={loading}>
                      {loading ? "Processing..." : "Sign & Send Transaction"}
                    </button>
                  </div>
                )}

                {/* OWNERS TAB */}
                {activeTab === 'owners' && (
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                      <h4 style={{ margin: 0 }}>Active Owners ({nestedThreshold}/{nestedOwners.length})</h4>
                      <button onClick={() => fetchData(nestedSafeAddress)} className="copy-icon" style={{ color: isRefreshing ? 'var(--primary)' : '' }}>
                        <Icons.Refresh />
                      </button>
                    </div>

                    <div style={{ opacity: isRefreshing ? 0.5 : 1, transition: 'opacity 0.2s' }}>
                      {nestedOwners.map(owner => (
                        <div key={owner} className="owner-row">
                          <span>{owner}</span>
                          {owner.toLowerCase() === primarySafeAddress.toLowerCase() && <span className="tag">Primary Safe</span>}
                        </div>
                      ))}
                    </div>

                    <div style={{ marginTop: '2rem', borderTop: '1px solid var(--border)', paddingTop: '1rem' }}>
                      <h4 style={{ margin: '0 0 1rem 0' }}>Add New Owner</h4>
                      <div style={{ display: 'flex', gap: '10px' }}>
                        <input placeholder="Address" value={newOwnerInput} onChange={e => setNewOwnerInput(e.target.value)} style={{ flex: 2 }} />
                        <input type="number" placeholder="Thresh" value={newThresholdInput} onChange={e => setNewThresholdInput(parseInt(e.target.value))} style={{ width: '80px' }} />
                      </div>
                      <button className="action-btn secondary" onClick={handleAddNestedOwner} disabled={loading} style={{ marginTop: '1rem' }}>
                        Add Owner
                      </button>
                    </div>
                  </div>
                )}

                {/* SETTINGS TAB */}
                {activeTab === 'settings' && (
                  <div>
                    <h3>Nested Safe Configuration</h3>
                    <div className="address-pill" style={{ justifyContent: 'flex-start', gap: '1rem' }}>
                      <span style={{ color: 'var(--text-dim)' }}>Address:</span>
                      <span>{nestedSafeAddress}</span>
                      <button className="copy-icon" onClick={() => navigator.clipboard.writeText(nestedSafeAddress)}><Icons.Copy /></button>
                    </div>

                    <div style={{ marginTop: '1.5rem' }}>
                      <a href={`https://sepolia.basescan.org/address/${nestedSafeAddress}`} target="_blank" rel="noreferrer" style={{ color: 'var(--primary)', textDecoration: 'none' }}>
                        View on Block Explorer &rarr;
                      </a>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* --- COLLAPSIBLE LOGS DRAWER --- */}
      <div className="terminal-drawer" style={{ transform: showTerminal ? 'translateY(0)' : 'translateY(100%) translateY(-45px)' }}>
        <div className="terminal-header" onClick={() => setShowTerminal(!showTerminal)}>
          <div className="terminal-title">
            <span className={`status-indicator ${loading ? 'online' : ''}`} style={{ background: loading ? 'var(--warning)' : 'var(--success)' }}></span>
            System Logs {loading ? "(Processing...)" : ""}
          </div>
          {showTerminal ? <Icons.ChevronDown /> : <Icons.ChevronUp />}
        </div>
        <div className="terminal-content">
          {logs.map((l, i) => (
            <div key={i} className={`log-entry ${l.type}`}>
              <span>[{l.timestamp}]</span>
              <span>{l.msg}</span>
            </div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>
    </>
  );
};

export default App;