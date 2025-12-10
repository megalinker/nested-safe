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
  "function addOwnerWithThreshold(address owner, uint256 _threshold) public"
]);

const ERC20_ABI = parseAbi([
  "function balanceOf(address owner) view returns (uint256)"
]);

// --- ICONS ---
const WalletIcon = () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M20 7h-9" /><path d="M14 17H5" /><circle cx="17" cy="17" r="3" /><path d="M7 7V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2h3a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-3" /></svg>;
const SafeIcon = () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>;
const NestedIcon = () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>;
const VerifyIcon = () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>;
const CheckIcon = () => <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="3" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5" /></svg>;
const CopyIcon = () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>;
const LinkIcon = () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg>;
const DashboardIcon = () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></svg>;
const RefreshIcon = () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>;
const KeyIcon = () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" /></svg>;

interface LogEntry {
  msg: string;
  type: 'info' | 'success' | 'error' | 'warning';
  timestamp: string;
}

const StepCard = ({
  step, title, desc, isActive, isDone, isDisabled, actionLabel, onAction, address, Icon, extraAction, children, loading
}: any) => {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className={`step-card ${isActive ? 'active' : ''} ${isDone ? 'success' : ''} ${isDisabled ? 'disabled' : ''}`}>
      <div className="step-indicator">
        {isDone ? <CheckIcon /> : step}
      </div>
      <div className="step-content">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 className="step-title">{title}</h3>
          {Icon && <div style={{ color: 'var(--text-muted)' }}><Icon /></div>}
        </div>
        <p className="step-desc">{desc}</p>

        {address && (
          <div className="address-box">
            <span>{address.slice(0, 8)}...{address.slice(-6)}</span>
            <button className="copy-btn" onClick={() => copyToClipboard(address)} title="Copy"><CopyIcon /></button>
          </div>
        )}

        {children}

        <div style={{ display: 'flex', gap: '10px', marginTop: '0.5rem' }}>
          {!isDone && onAction && (
            <button className="action-btn" onClick={onAction} disabled={loading || isDisabled}>
              {loading && isActive ? "Processing..." : actionLabel}
            </button>
          )}
          {extraAction}
        </div>
      </div>
    </div>
  );
};

// --- MAIN APP COMPONENT ---

const App: React.FC = () => {
  const [walletClient, setWalletClient] = useState<WalletClient | null>(null);
  const [eoaAddress, setEoaAddress] = useState<string>("");
  const [primarySafeAddress, setPrimarySafeAddress] = useState<string>("");
  const [nestedSafeAddress, setNestedSafeAddress] = useState<string>("");
  const [passkeyAddress, setPasskeyAddress] = useState<string>("");
  const [passkeyId, setPasskeyId] = useState<string>(""); // Store the browser ID
  const [isVerified, setIsVerified] = useState(false);

  // Dashboard State
  const [ethBalance, setEthBalance] = useState("0");
  const [usdcBalance, setUsdcBalance] = useState("0");
  const [sendAmount, setSendAmount] = useState("");
  const [recipient, setRecipient] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Signer Selection
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

    if (savedNested) fetchBalances(savedNested);
  }, []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const addLog = (msg: string, type: 'info' | 'success' | 'error' | 'warning' = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { msg, type, timestamp }]);
  };

  // --- ACTIONS ---

  const handleConnect = async () => {
    try {
      setLoading(true);
      addLog("Connecting to Phantom...", 'info');
      const client = await connectPhantom();
      if (!client.account) throw new Error("No account returned");

      setWalletClient(client);
      setEoaAddress(client.account.address);
      addLog(`Connected: ${client.account.address}`, 'success');
    } catch (e: any) {
      addLog(e.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const createPrimarySafe = async () => {
    if (!walletClient || !eoaAddress) return;
    try {
      setLoading(true);
      addLog("Initializing Primary Safe (ERC-4337)...", 'info');

      // 1. Get or Generate a random salt for the Primary Safe
      let salt = localStorage.getItem("primarySafeSalt");
      if (!salt) {
        salt = BigInt(Date.now()).toString(); // Use timestamp as unique salt
        localStorage.setItem("primarySafeSalt", salt);
      }

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient,
        owners: [walletClient],
        entryPoint: { address: entryPoint07Address, version: "0.7" },
        version: "1.4.1",
        saltNonce: BigInt(salt),
      });

      const address = safeAccount.address;
      setPrimarySafeAddress(address);
      localStorage.setItem("primarySafeAddress", address);
      addLog(`Primary Safe Address Calculated: ${address}`, 'success');
    } catch (e: any) {
      addLog(e.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const createNestedSafe = async () => {
    if (!walletClient || !primarySafeAddress || !eoaAddress) return;
    try {
      setLoading(true);
      addLog("Generating Nested Safe Payload...", 'info');

      // 1. Re-initialize Primary Safe to ensure we are using the correct signer context
      // We need to fetch the primary salt to reconstruct the 4337 account wrapper correctly
      const primarySalt = localStorage.getItem("primarySafeSalt") || "0";

      // 2. Get or Generate a random salt for the Nested Safe
      let nestedSalt = localStorage.getItem("nestedSafeSalt");
      if (!nestedSalt) {
        nestedSalt = Date.now().toString(); // Timestamp string
        localStorage.setItem("nestedSafeSalt", nestedSalt);
      }

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({
        transport: http(PIMLICO_URL),
        entryPoint: { address: entryPoint07Address, version: "0.7" },
      });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient,
        owners: [walletClient],
        entryPoint: { address: entryPoint07Address, version: "0.7" },
        version: "1.4.1",
        address: primarySafeAddress as Hex,
        saltNonce: BigInt(primarySalt)
      });

      const smartAccountClient = createSmartAccountClient({
        account: safeAccount,
        chain: baseSepolia,
        bundlerTransport: http(PIMLICO_URL),
        paymaster: pimlicoClient,
        userOperation: {
          estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast,
        },
      });

      const provider = (window as any).phantom?.ethereum || (window as any).ethereum;
      const safeAccountConfig: SafeAccountConfig = { owners: [primarySafeAddress], threshold: 1 };

      const protocolKit = await Safe.init({
        provider,
        signer: eoaAddress,
        predictedSafe: {
          safeAccountConfig,
          safeDeploymentConfig: {
            saltNonce: nestedSalt
          }
        }
      });

      const predictedAddr = await protocolKit.getAddress();
      const deploymentTx = await protocolKit.createSafeDeploymentTransaction();

      addLog(`Sending UserOp via Pimlico (Sponsored)...`, 'info');
      const txHash = await smartAccountClient.sendTransaction({
        to: deploymentTx.to as Hex,
        value: BigInt(deploymentTx.value),
        data: deploymentTx.data as Hex,
      });

      setNestedSafeAddress(predictedAddr);
      localStorage.setItem("nestedSafeAddress", predictedAddr);
      addLog(`Success! UserOp Hash: ${txHash}`, 'success');
      addLog(`Nested Safe: ${predictedAddr}`, 'success');
      fetchBalances(predictedAddr);
    } catch (e: any) {
      console.error(e);
      addLog(`Failed: ${e.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const verifyOwnership = async () => {
    if (!nestedSafeAddress || !primarySafeAddress || !eoaAddress) return;
    try {
      setLoading(true);
      setIsVerified(false);
      const provider = (window as any).phantom?.ethereum || (window as any).ethereum;
      addLog("1. Verifying EOA -> Primary Safe...", "info");
      const primarySafeInstance = await Safe.init({ provider, safeAddress: primarySafeAddress });
      const primaryOwners = await primarySafeInstance.getOwners();
      if (!primaryOwners.some(o => o.toLowerCase() === eoaAddress.toLowerCase())) throw new Error("EOA not owner of Primary");
      addLog("✅ Confirmed: You own the Primary Safe.", "success");
      addLog("2. Verifying Primary Safe -> Nested Safe...", "info");
      const nestedSafeInstance = await Safe.init({ provider, safeAddress: nestedSafeAddress });
      const nestedOwners = await nestedSafeInstance.getOwners();
      if (!nestedOwners.some(o => o.toLowerCase() === primarySafeAddress.toLowerCase())) throw new Error("Primary Safe not owner of Nested");
      addLog("✅ Confirmed: Primary Safe owns the Nested Safe.", "success");
      setIsVerified(true);
    } catch (e: any) {
      addLog(`Verification Error: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const fetchBalances = async (address: string) => {
    try {
      setIsRefreshing(true);
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const eth = await publicClient.getBalance({ address: address as Hex });
      setEthBalance(formatEther(eth));

      try {
        const usdc = await publicClient.readContract({
          address: USDC_ADDRESS,
          abi: ERC20_ABI,
          functionName: "balanceOf",
          args: [address as Hex]
        });
        setUsdcBalance(formatUnits(usdc, 6));
      } catch (e) {
        setUsdcBalance("0");
      }
      addLog("Balances updated.", 'info');
    } catch (e) {
      console.error("Balance fetch failed", e);
    } finally {
      setIsRefreshing(false);
    }
  };

  // --- ACTIONS WITH REAL PASSKEY PROMPTS ---

  const addPasskeyOwner = async () => {
    if (!walletClient || !primarySafeAddress) return;
    try {
      setLoading(true);
      addLog("Prompting browser for Passkey creation...", 'warning');

      // 1. Trigger Native Passkey Creation (FaceID/TouchID)
      const newCredId = await registerPasskey("SafeOwner");
      // Store the Credential ID to look it up later
      setPasskeyId(newCredId);
      localStorage.setItem("passkeyId", newCredId);
      addLog("Passkey Created via Browser!", 'success');

      // 2. Generate Signer Key
      // (Note: In a full prod app, you'd use the P256 key from the passkey directly. 
      //  Here we gate a local key with the passkey prompt to ensure valid UX)
      let privKey = localStorage.getItem("passkey_priv") as Hex | null;
      if (!privKey) {
        privKey = generatePrivateKey();
        localStorage.setItem("passkey_priv", privKey);
      }
      const account = privateKeyToAccount(privKey);
      const newOwner = account.address;
      addLog(`Generated Safe Signer: ${newOwner}`, 'info');

      // 3. Add Owner on Chain
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({
        transport: http(PIMLICO_URL),
        entryPoint: { address: entryPoint07Address, version: "0.7" },
      });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient,
        owners: [walletClient],
        entryPoint: { address: entryPoint07Address, version: "0.7" },
        version: "1.4.1",
        address: primarySafeAddress as Hex,
      });

      const smartAccountClient = createSmartAccountClient({
        account: safeAccount,
        chain: baseSepolia,
        bundlerTransport: http(PIMLICO_URL),
        paymaster: pimlicoClient,
        userOperation: {
          estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast,
        },
      });

      const addOwnerData = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "addOwnerWithThreshold",
        args: [newOwner, 1n]
      });

      addLog("Signing with Phantom to add new owner...", 'info');
      const txHash = await smartAccountClient.sendTransaction({
        to: primarySafeAddress as Hex,
        value: 0n,
        data: addOwnerData,
      });

      addLog(`Owner Added! Tx: ${txHash}`, 'success');
      setPasskeyAddress(newOwner);
      localStorage.setItem("passkeyAddress", newOwner);

    } catch (e: any) {
      console.error(e);
      addLog(`Add Owner Failed: ${e.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const sendFromNestedSafe = async () => {
    if (!walletClient || !primarySafeAddress || !nestedSafeAddress) return;
    try {
      if (!sendAmount || !recipient) throw new Error("Enter amount and recipient");
      setLoading(true);

      const signerName = selectedSigner === 'phantom' ? "Phantom" : "Passkey";
      addLog(`Preparing to send ${sendAmount} ETH using ${signerName}...`, 'info');

      // --- PASSKEY GATE ---
      let ownerAccount;
      if (selectedSigner === 'phantom') {
        ownerAccount = walletClient;
      } else {
        // Trigger Native Browser Prompt
        if (!passkeyId) throw new Error("No passkey ID found");
        addLog("Please authenticate with FaceID/TouchID...", 'warning');

        // This halts execution until user touches sensor
        const isAuthenticated = await authenticatePasskey(passkeyId);

        if (!isAuthenticated) throw new Error("Biometric verification failed");
        addLog("Biometric verified!", 'success');

        const privKey = localStorage.getItem("passkey_priv") as Hex;
        ownerAccount = privateKeyToAccount(privKey);
      }

      // --- EXECUTE TRANSACTION ---
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({
        transport: http(PIMLICO_URL),
        entryPoint: { address: entryPoint07Address, version: "0.7" },
      });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient,
        owners: [ownerAccount],
        entryPoint: { address: entryPoint07Address, version: "0.7" },
        version: "1.4.1",
        address: primarySafeAddress as Hex,
      });

      const smartAccountClient = createSmartAccountClient({
        account: safeAccount,
        chain: baseSepolia,
        bundlerTransport: http(PIMLICO_URL),
        paymaster: pimlicoClient,
        userOperation: {
          estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast,
        },
      });

      const r = pad(primarySafeAddress as Hex, { size: 32 });
      const s = pad("0x0", { size: 32 });
      const v = "01";
      const signatures = `${r}${s.slice(2)}${v}` as Hex;

      const nestedSafeCallData = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "execTransaction",
        args: [
          recipient as Hex,
          parseEther(sendAmount),
          "0x",
          0,
          0n, 0n, 0n,
          "0x0000000000000000000000000000000000000000",
          "0x0000000000000000000000000000000000000000",
          signatures
        ]
      });

      addLog(`Authorizing via Primary Safe (${signerName})...`, 'info');

      const txHash = await smartAccountClient.sendTransaction({
        to: nestedSafeAddress as Hex,
        value: 0n,
        data: nestedSafeCallData,
      });

      addLog(`Transaction Sent! Hash: ${txHash}`, 'success');
      setTimeout(() => fetchBalances(nestedSafeAddress), 5000);

    } catch (e: any) {
      console.error(e);
      addLog(`Send Failed: ${e.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>Nested Safe Engine</h1>
        <p>Base Sepolia • 4337 • Pimlico Sponsored</p>
      </header>
      <div className="steps-container">
        <StepCard
          step={1}
          title="Connect Phantom"
          desc="Link your Phantom wallet to act as the signer."
          isActive={!eoaAddress}
          isDone={!!eoaAddress}
          isDisabled={false}
          actionLabel="Connect Wallet"
          onAction={handleConnect}
          address={eoaAddress}
          Icon={WalletIcon}
          loading={loading}
        />
        <StepCard
          step={2}
          title="Initialize Primary Safe"
          desc="Generate the 4337 Safe address."
          isActive={!!eoaAddress && !primarySafeAddress}
          isDone={!!primarySafeAddress}
          isDisabled={!eoaAddress}
          actionLabel="Initialize Safe"
          onAction={createPrimarySafe}
          address={primarySafeAddress}
          Icon={SafeIcon}
          loading={loading}
        />
        <StepCard
          step={3}
          title="Deploy Nested Safe"
          desc="Primary Safe deploys the Nested Safe via Pimlico."
          isActive={!!primarySafeAddress && !nestedSafeAddress}
          isDone={!!nestedSafeAddress}
          isDisabled={!primarySafeAddress}
          actionLabel="Deploy Sponsored"
          onAction={createNestedSafe}
          address={nestedSafeAddress}
          Icon={NestedIcon}
          loading={loading}
        />

        <StepCard
          step={4}
          title="Full Chain Verification"
          desc="Verify ownership chain: EOA -> Primary -> Nested."
          isActive={!!nestedSafeAddress && !isVerified}
          isDone={isVerified}
          isDisabled={!nestedSafeAddress}
          actionLabel="Run Verification"
          onAction={verifyOwnership}
          Icon={VerifyIcon}
          loading={loading}
          extraAction={
            nestedSafeAddress ? (
              <a
                href={`https://sepolia.basescan.org/address/${nestedSafeAddress}#readProxyContract`}
                target="_blank"
                rel="noreferrer"
                className="action-btn"
                style={{ textDecoration: 'none', background: 'var(--surface-hover)', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                View on Basescan <LinkIcon />
              </a>
            ) : null
          }
        />

        {/* Step 5: Dashboard */}
        {nestedSafeAddress && (
          <StepCard
            step={5}
            title="Nested Safe Dashboard"
            desc="Manage assets in your Nested Safe."
            isActive={true}
            isDone={false}
            isDisabled={false}
            Icon={DashboardIcon}
            loading={loading}
            extraAction={
              <button
                className="action-btn"
                onClick={() => fetchBalances(nestedSafeAddress)}
                disabled={isRefreshing}
                style={{ background: 'var(--surface-hover)', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                {isRefreshing ? "Refreshing..." : "Refresh"} <RefreshIcon />
              </button>
            }
          >
            {/* Signer Management Section */}
            <div style={{ margin: '1rem 0', padding: '1rem', border: '1px solid var(--border-color)', borderRadius: '8px', background: 'rgba(255,255,255,0.02)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h4 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <KeyIcon /> Signer Settings
                </h4>
                {!passkeyAddress ? (
                  <button
                    className="action-btn"
                    onClick={addPasskeyOwner}
                    disabled={loading}
                    style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                  >
                    Add Passkey / Device Key
                  </button>
                ) : (
                  <span style={{ fontSize: '0.8rem', color: 'var(--success-color)' }}>
                    Passkey Active: {passkeyAddress.slice(0, 6)}...
                  </span>
                )}
              </div>
            </div>

            <div className="dashboard-grid">
              <div className="balance-item">
                <div className="balance-label">ETH Balance</div>
                <div className="balance-value">{ethBalance} ETH</div>
              </div>
              <div className="balance-item">
                <div className="balance-label">USDC Balance</div>
                <div className="balance-value">{usdcBalance} USDC</div>
              </div>
            </div>

            <div className="transfer-box">
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <h4 style={{ margin: 0 }}>Transfer ETH</h4>

                {/* Signer Toggle */}
                <div style={{ display: 'flex', gap: '0.5rem', background: 'var(--bg-color)', padding: '2px', borderRadius: '6px' }}>
                  <button
                    onClick={() => setSelectedSigner('phantom')}
                    style={{
                      border: 'none',
                      background: selectedSigner === 'phantom' ? 'var(--primary-color)' : 'transparent',
                      color: selectedSigner === 'phantom' ? 'white' : 'var(--text-muted)',
                      borderRadius: '4px',
                      padding: '4px 8px',
                      cursor: 'pointer',
                      fontSize: '0.8rem'
                    }}
                  >
                    Phantom
                  </button>
                  <button
                    onClick={() => setSelectedSigner('passkey')}
                    disabled={!passkeyAddress}
                    style={{
                      border: 'none',
                      background: selectedSigner === 'passkey' ? 'var(--primary-color)' : 'transparent',
                      color: !passkeyAddress ? 'rgba(255,255,255,0.2)' : (selectedSigner === 'passkey' ? 'white' : 'var(--text-muted)'),
                      borderRadius: '4px',
                      padding: '4px 8px',
                      cursor: !passkeyAddress ? 'not-allowed' : 'pointer',
                      fontSize: '0.8rem'
                    }}
                  >
                    Passkey
                  </button>
                </div>
              </div>

              <div className="input-row">
                <input
                  placeholder="Amount (ETH)"
                  value={sendAmount}
                  onChange={e => setSendAmount(e.target.value)}
                  type="number"
                />
                <input
                  placeholder="Recipient Address (0x...)"
                  value={recipient}
                  onChange={e => setRecipient(e.target.value)}
                />
              </div>
              <button
                className="action-btn"
                onClick={sendFromNestedSafe}
                disabled={loading}
                style={{ width: '100%', marginTop: '10px' }}
              >
                {loading ? "Processing..." : `Sign with ${selectedSigner === 'phantom' ? 'Phantom' : 'Passkey'} & Send`}
              </button>
            </div>
          </StepCard>
        )}
      </div>

      <div className="terminal">
        {logs.length === 0 && <span style={{ opacity: 0.5 }}>System logs will appear here...</span>}
        {logs.map((l, i) => (
          <div key={i} className={`log-entry ${l.type}`}>
            [{l.timestamp}] {l.msg}
          </div>
        ))}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
};

export default App;