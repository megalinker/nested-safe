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
  formatUnits,
  concat
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
const SAFE_TX_SERVICE_URL = "https://safe-transaction-base-sepolia.safe.global/api/v1";
const USDC_ADDRESS = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

// --- RHINESTONE ADDRESSES ---
const SAFE_7579_ADAPTER_ADDRESS = "0x7579f2AD53b01c3D8779Fe17928e0D48885B0003";
const SMART_SESSIONS_VALIDATOR_ADDRESS = "0x00000000008bdaba73cd9815d79069c247eb4bda";

// Storage slot for Safe Fallback Handler
const FALLBACK_HANDLER_STORAGE_SLOT = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";

const SAFE_ABI = parseAbi([
  "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool success)",
  "function addOwnerWithThreshold(address owner, uint256 _threshold) public",
  "function changeThreshold(uint256 _threshold) public",
  "function approveHash(bytes32 hashToApprove) public",
  "function enableModule(address module) public",
  "function setFallbackHandler(address handler) public",
  "function isModuleEnabled(address module) view returns (bool)",
  "function getOwners() view returns (address[])",
  "function getThreshold() view returns (uint256)",
  "function approvedHashes(address owner, bytes32 hash) view returns (uint256)",
  "function nonce() view returns (uint256)",
  "function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)"
]);

const ADAPTER_7579_ABI = parseAbi([
  "struct ModuleInit { address module; bytes initData; uint256 moduleType; }",
  "struct RegistryInit { address registry; address[] attesters; uint8 threshold; }",
  "function initializeAccount(ModuleInit[] calldata modules, RegistryInit calldata registryInit) external",
  "function isModuleInstalled(uint256 moduleType, address module, bytes additionalContext) external view returns (bool)"
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
  ChevronDown: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9" /></svg>,
  ExternalLink: () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg>,
  Module: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>,
  Bug: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="1" y="1" width="22" height="22" rx="4" ry="4" /><path d="M16 3v5" /><path d="M8 3v5" /><path d="M3 11h18" /></svg>
};

// --- TYPES ---

interface StoredSafe { address: string; salt: string; name: string; }
interface LogEntry { msg: string; type: 'info' | 'success' | 'error'; timestamp: string; }

interface Transfer {
  type: string;
  value: string;
  tokenAddress: string | null;
  tokenInfo: any;
  from: string;
  to: string;
}

interface SafeTx {
  txType: 'MULTISIG_TRANSACTION' | 'ETHEREUM_TRANSACTION' | 'MODULE_TRANSACTION';
  executionDate: string;
  to: string;
  value: string;
  data: string | null;
  isSuccessful?: boolean;
  transactionHash?: string;
  from?: string;
  transfers?: Transfer[];
}

interface QueuedTx {
  safeAddress: string;
  hash: string;
  to: string;
  value: string;
  data: string;
  operation: 0 | 1; // 0 = Call, 1 = DelegateCall
  nonce: number;
  description: string;
}

// --- COMPONENTS ---

const SafeListItem = ({ safe, isSelected, onClick, type, balanceInfo, onRefresh }: {
  safe: StoredSafe,
  isSelected: boolean,
  onClick: () => void,
  type: 'parent' | 'nested',
  balanceInfo?: { eth: string | null, usdc: string | null },
  onRefresh?: () => void
}) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(safe.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const gradient = type === 'parent'
    ? `linear-gradient(135deg, #${safe.address.slice(2, 8)}, #${safe.address.slice(-6)})`
    : `linear-gradient(135deg, #10b981, #0ea5e9)`;

  return (
    <div className={`safe-card ${isSelected ? 'selected' : ''}`} onClick={onClick}>
      <div className="safe-card-header" style={{ justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div className="safe-avatar" style={{ background: gradient }}></div>
          <div className="safe-name">{safe.name}</div>
        </div>
        {type === 'nested' && isSelected && onRefresh && (
          <button className="icon-btn" onClick={(e) => { e.stopPropagation(); onRefresh(); }} title="Refresh Balance">
            <Icons.Refresh />
          </button>
        )}
      </div>

      <div className="safe-meta">
        <span className="safe-address">{safe.address.slice(0, 6)}...{safe.address.slice(-4)}</span>
        <button className="icon-btn" onClick={handleCopy} title="Copy Address">
          {copied ? <Icons.Check /> : <Icons.Copy />}
        </button>
      </div>

      {type === 'nested' && balanceInfo && (
        <div style={{ marginTop: '12px', fontSize: '0.85rem', color: 'var(--text-secondary)', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>ETH</span>
            <span style={{ color: 'var(--text-main)', fontWeight: '500' }}>
              {balanceInfo.eth !== null ? balanceInfo.eth : <span style={{ opacity: 0.5 }}>...</span>}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>USDC</span>
            <span style={{ color: 'var(--text-main)', fontWeight: '500' }}>
              {balanceInfo.usdc !== null ? balanceInfo.usdc : <span style={{ opacity: 0.5 }}>...</span>}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

// --- MAIN APP ---

const App: React.FC = () => {
  // State
  const [walletClient, setWalletClient] = useState<WalletClient | null>(null);
  const [eoaAddress, setEoaAddress] = useState<string>("");

  const [mySafes, setMySafes] = useState<StoredSafe[]>([]);
  const [myNestedSafes, setMyNestedSafes] = useState<StoredSafe[]>([]);

  const [selectedSafeAddr, setSelectedSafeAddr] = useState<string>("");
  const [selectedNestedSafeAddr, setSelectedNestedSafeAddr] = useState<string>("");

  const [activeTab, setActiveTab] = useState<'transfer' | 'owners' | 'queue' | 'history' | 'settings'>('transfer');

  // Data State
  const [nestedOwners, setNestedOwners] = useState<string[]>([]);
  const [nestedThreshold, setNestedThreshold] = useState<number>(0);
  const [nestedNonce, setNestedNonce] = useState<number>(0);
  const [ethBalance, setEthBalance] = useState<string | null>(null);
  const [usdcBalance, setUsdcBalance] = useState<string | null>(null);
  const [txHistory, setTxHistory] = useState<SafeTx[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Module State
  const [is7579AdapterEnabled, setIs7579AdapterEnabled] = useState<boolean>(false);
  const [currentFallbackHandler, setCurrentFallbackHandler] = useState<string>("0x");
  const [isValidatorInstalled, setIsValidatorInstalled] = useState<boolean>(false);

  // Queue State
  const [queuedTxs, setQueuedTxs] = useState<QueuedTx[]>([]);
  const queueRef = useRef<QueuedTx[]>([]);

  const [approvalsMap, setApprovalsMap] = useState<Record<string, string[]>>({});

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Inputs
  const [recipient, setRecipient] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [newOwnerInput, setNewOwnerInput] = useState("");
  const [newThresholdInput, setNewThresholdInput] = useState<number>(1);

  // --- INITIALIZATION ---

  useEffect(() => {
    const savedSafes = localStorage.getItem("mySafes");
    if (savedSafes) {
      const parsed = JSON.parse(savedSafes);
      setMySafes(parsed);
      if (parsed.length > 0) setSelectedSafeAddr(parsed[0].address);
    }

    const savedNestedList = localStorage.getItem("myNestedSafes");
    if (savedNestedList) {
      const parsed = JSON.parse(savedNestedList);
      setMyNestedSafes(parsed);
      if (parsed.length > 0) {
        setSelectedNestedSafeAddr(parsed[0].address);
        fetchData(parsed[0].address);
      }
    } else {
      const oldNested = localStorage.getItem("nestedSafeAddress");
      if (oldNested) {
        const migrated: StoredSafe = { address: oldNested, salt: "0", name: "Legacy Safe" };
        setMyNestedSafes([migrated]);
        setSelectedNestedSafeAddr(oldNested);
        fetchData(oldNested);
      }
    }

    const storedQueue = localStorage.getItem("localTxQueue");
    if (storedQueue) {
      const parsedQueue = JSON.parse(storedQueue);
      setQueuedTxs(parsedQueue);
      queueRef.current = parsedQueue; // Sync Ref
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'history' && selectedNestedSafeAddr) {
      fetchHistory(selectedNestedSafeAddr);
    }
    if (activeTab === 'queue' && selectedNestedSafeAddr) {
      checkQueueApprovals();
    }
  }, [activeTab, selectedNestedSafeAddr, queuedTxs]);

  const isCurrentSafeOwner = useMemo(() => {
    if (!selectedSafeAddr || nestedOwners.length === 0) return false;
    return nestedOwners.some(o => o.toLowerCase() === selectedSafeAddr.toLowerCase());
  }, [selectedSafeAddr, nestedOwners]);

  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  const addLog = (msg: string, type: 'info' | 'success' | 'error' = 'info') => {
    setLogs(prev => [...prev, { msg, type, timestamp: new Date().toLocaleTimeString() }]);
  };

  const getClient = async (): Promise<WalletClient | null> => {
    if (walletClient && walletClient.account) return walletClient;
    try {
      addLog("Connecting wallet...", "info");
      const client = await connectPhantom();
      if (!client.account) throw new Error("Wallet connected but no account found.");
      setWalletClient(client);
      setEoaAddress(client.account.address);
      return client;
    } catch (e: any) {
      addLog(`Wallet connection failed: ${e.message}`, "error");
      return null;
    }
  };

  const handleConnect = async () => {
    setLoading(true);
    await getClient();
    setLoading(false);
  };

  // --- ACTIONS ---

  const createParentSafe = async () => {
    const client = await getClient();
    if (!client) return;
    try {
      setLoading(true);
      const safeIndex = mySafes.length + 1;
      const salt = BigInt(Date.now()).toString();
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [client], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1", saltNonce: BigInt(salt),
      });
      const newSafe: StoredSafe = { address: safeAccount.address, salt, name: `Parent Safe ${safeIndex}` };
      const updated = [...mySafes, newSafe];
      setMySafes(updated);
      setSelectedSafeAddr(newSafe.address);
      localStorage.setItem("mySafes", JSON.stringify(updated));
      addLog(`Created ${newSafe.name}`, 'success');
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  const createNestedSafe = async () => {
    const client = await getClient();
    if (!client) return;
    const currentParent = mySafes.find(s => s.address === selectedSafeAddr);
    if (!selectedSafeAddr || !currentParent) return;

    if (!window.confirm(`Deploy a new Nested Safe owned by "${currentParent.name}"?`)) return;

    try {
      setLoading(true);
      const nestedSalt = Date.now().toString();
      const safeIndex = myNestedSafes.length + 1;
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [client], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
        address: currentParent.address as Hex, saltNonce: BigInt(currentParent.salt)
      });

      const smartAccountClient = createSmartAccountClient({
        account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      const provider = (window as any).phantom?.ethereum || (window as any).ethereum;
      const protocolKit = await Safe.init({
        provider, signer: client.account!.address, predictedSafe: { safeAccountConfig: { owners: [selectedSafeAddr], threshold: 1 }, safeDeploymentConfig: { saltNonce: nestedSalt } }
      });

      const deploymentTx = await protocolKit.createSafeDeploymentTransaction();
      await smartAccountClient.sendTransaction({ to: deploymentTx.to as Hex, value: BigInt(deploymentTx.value), data: deploymentTx.data as Hex });

      const addr = await protocolKit.getAddress();
      const newNested: StoredSafe = { address: addr, salt: nestedSalt, name: `Nested Safe ${safeIndex}` };
      const updatedList = [...myNestedSafes, newNested];
      setMyNestedSafes(updatedList);
      setSelectedNestedSafeAddr(addr);
      localStorage.setItem("myNestedSafes", JSON.stringify(updatedList));
      addLog(`Nested Safe Deployed: ${addr}`, 'success');
      fetchData(addr);
    } catch (e: any) { addLog(e.message, 'error'); } finally { setLoading(false); }
  };

  const fetchData = async (address: string) => {
    if (!address) return;
    setLoading(true);
    const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });

    try {
      const eth = await publicClient.getBalance({ address: address as Hex });
      setEthBalance(formatEther(eth));
      const usdc = await publicClient.readContract({ address: USDC_ADDRESS, abi: ERC20_ABI, functionName: "balanceOf", args: [address as Hex] });
      setUsdcBalance(formatUnits(usdc, 6));
      const owners = await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getOwners" });
      setNestedOwners(Array.from(owners));
      const thresh = await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getThreshold" });
      setNestedThreshold(Number(thresh));
      setNewThresholdInput(Number(thresh));

      const nonce = await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "nonce" });
      setNestedNonce(Number(nonce));

      const isEnabled = await publicClient.readContract({
        address: address as Hex,
        abi: SAFE_ABI,
        functionName: "isModuleEnabled",
        args: [SAFE_7579_ADAPTER_ADDRESS]
      });
      setIs7579AdapterEnabled(isEnabled);

      // Fetch Fallback Handler via Storage
      const fallbackHandler = await publicClient.getStorageAt({
        address: address as Hex,
        slot: FALLBACK_HANDLER_STORAGE_SLOT as Hex
      });
      const handlerAddress = fallbackHandler ? `0x${fallbackHandler.slice(-40)}` : "0x";
      setCurrentFallbackHandler(handlerAddress);

      // Attempt to check if validator is installed. 
      // Since 'isModuleInstalled' on the adapter requires msg.sender to be the Safe,
      // we can't accurately query this via simple readContract from the frontend without simulation.
      // However, if we assume the user followed the steps, we can optimistically set this if the Adapter is enabled & fallback is set.
      // For a robust app, we would use a read-only call simulation with state overrides.
      if (isEnabled && handlerAddress.toLowerCase() === SAFE_7579_ADAPTER_ADDRESS.toLowerCase()) {
        // Logic to determine if "Step 3" was executed. For now, rely on session/local state or user flow.
        // setIsValidatorInstalled(true); // Can't definitively check on-chain easily
      }

    } catch { }
    setLoading(false);
  };

  const fetchHistory = async (address: string) => {
    setLoadingHistory(true);
    try {
      const response = await fetch(`${SAFE_TX_SERVICE_URL}/safes/${address}/all-transactions/?ordering=-timestamp&limit=20`);
      if (!response.ok) throw new Error("History fetch failed");
      const data = await response.json();
      setTxHistory(data.results || []);
    } catch (e) {
      console.error(e);
      setTxHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleRefreshQueue = async () => {
    addLog("Refreshing Queue & Nonce...", "info");
    await fetchData(selectedNestedSafeAddr);
    await checkQueueApprovals();
  };

  // --- MULTI-SIG LOGIC ---

  const getSafeTxHash = async (to: string, val: bigint, data: Hex, operation: 0 | 1, nonceOffset = 0) => {
    const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
    const currentNonce = await publicClient.readContract({ address: selectedNestedSafeAddr as Hex, abi: SAFE_ABI, functionName: "nonce" });
    const targetNonce = Number(currentNonce) + nonceOffset;

    // Hash includes operation type
    const hash = await publicClient.readContract({
      address: selectedNestedSafeAddr as Hex,
      abi: SAFE_ABI,
      functionName: "getTransactionHash",
      args: [to as Hex, val, data, operation, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", BigInt(targetNonce)]
    });
    return { hash, nonce: targetNonce };
  };

  const proposeTransaction = async (to: string, val: bigint, data: Hex, description: string, nonceOffset = 0, operation: 0 | 1 = 0) => {
    try {
      setLoading(true);
      const { hash, nonce } = await getSafeTxHash(to, val, data, operation, nonceOffset);

      const newTx: QueuedTx = {
        safeAddress: selectedNestedSafeAddr,
        hash,
        to,
        value: val.toString(),
        data,
        operation, // Store operation type
        nonce,
        description
      };

      const currentQueue = queueRef.current;

      if (currentQueue.some(t => t.hash === hash)) {
        addLog(`Transaction ${description} already in queue.`, "info");
      } else {
        const updatedQueue = [...currentQueue, newTx];
        queueRef.current = updatedQueue;
        setQueuedTxs(updatedQueue);
        localStorage.setItem("localTxQueue", JSON.stringify(updatedQueue));
        addLog(`Proposed: ${description} (Nonce ${nonce})`, "success");
      }

      setActiveTab('queue');
    } catch (e: any) {
      addLog(`Proposal failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  // --- RHINESTONE MODULE LOGIC ---

  const handleInstallSmartSession = async () => {
    if (!isCurrentSafeOwner) {
      addLog("Only owner can install modules", "error");
      return;
    }

    try {
      setLoading(true);
      let offset = 0;

      // 1. Enable 7579 Adapter as Module (Call)
      if (!is7579AdapterEnabled) {
        const enableData = encodeFunctionData({
          abi: SAFE_ABI,
          functionName: "enableModule",
          args: [SAFE_7579_ADAPTER_ADDRESS]
        });
        await proposeTransaction(
          selectedNestedSafeAddr, // Call self
          0n,
          enableData,
          "1. Enable Safe 7579 Adapter",
          offset,
          0 // Call
        );
        offset++;
      }

      // 2. Set Adapter as Fallback Handler (Call)
      const isFallbackSet = currentFallbackHandler.toLowerCase() === SAFE_7579_ADAPTER_ADDRESS.toLowerCase();

      if (!isFallbackSet) {
        const fallbackData = encodeFunctionData({
          abi: SAFE_ABI,
          functionName: "setFallbackHandler",
          args: [SAFE_7579_ADAPTER_ADDRESS]
        });
        await proposeTransaction(
          selectedNestedSafeAddr, // Call self
          0n,
          fallbackData,
          "2. Set 7579 Adapter as Fallback Handler",
          offset,
          0 // Call
        );
        offset++;
      }

      // 3. Initialize Adapter & Install Validator via CALL (Op 0)
      // CRITICAL: Use Call (Op 0) to Adapter. Append SAFE ADDRESS to emulate 2771 msg.sender.

      // Only propose this if previous steps are done (or if we are chaining them now).
      // Since we check the bools above, we only propose Step 3 if we are proposing steps 1 & 2 or if they are done.

      if (walletClient?.account) {
        // Build the init call data
        const initData = encodeFunctionData({
          abi: ADAPTER_7579_ABI,
          functionName: "initializeAccount",
          args: [
            [{
              module: SMART_SESSIONS_VALIDATOR_ADDRESS,
              initData: "0x",
              moduleType: 1n
            }],
            {
              registry: "0x0000000000000000000000000000000000000000",
              attesters: [],
              threshold: 0
            }
          ]
        });

        // Append SAFE address (20 bytes) to the calldata
        // This satisfies `onlyEntryPointOrSelf` in the Adapter, as `_msgSender()` will read the appended address.
        const paddedAddress = selectedNestedSafeAddr.slice(2);
        const dataWithContext = concat([initData, `0x${paddedAddress}` as Hex]);

        await proposeTransaction(
          SAFE_7579_ADAPTER_ADDRESS, // Call the Adapter Directly
          0n,
          dataWithContext, // Use payload with appended SAFE ADDRESS
          "3. Init Adapter & Install Validator",
          offset,
          0 // Call (Operation 0)
        );

        // Assume success locally for UI update after execution
        setIsValidatorInstalled(true);
      } else {
        addLog("Error: Wallet not connected.", "error");
      }

      addLog("Transactions added to Queue.", "success");

    } catch (e: any) {
      addLog(`Failed to propose module installation: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const approveTxHash = async (hash: string) => {
    const client = await getClient();
    if (!client || !selectedSafeAddr) return;

    try {
      setLoading(true);
      const parent = mySafes.find(s => s.address === selectedSafeAddr);
      if (!parent) return;

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [client], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
        address: parent.address as Hex, saltNonce: BigInt(parent.salt)
      });

      const smartClient = createSmartAccountClient({
        account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      const callData = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "approveHash",
        args: [hash as Hex]
      });

      const txHash = await smartClient.sendTransaction({
        to: selectedNestedSafeAddr as Hex,
        value: 0n,
        data: callData
      });

      addLog(`Approved Hash! TX: ${txHash}`, "success");
      setTimeout(() => handleRefreshQueue(), 4000);
    } catch (e: any) {
      addLog(`Approval Failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const checkQueueApprovals = async () => {
    if (!selectedNestedSafeAddr) return;
    const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
    const newMap: Record<string, string[]> = {};

    const relevantTxs = queuedTxs.filter(t =>
      !t.safeAddress ||
      t.safeAddress.toLowerCase() === selectedNestedSafeAddr.toLowerCase()
    );

    for (const tx of relevantTxs) {
      if (tx.nonce < nestedNonce) continue;

      const approvedBy: string[] = [];
      for (const owner of nestedOwners) {
        const isApproved = await publicClient.readContract({
          address: selectedNestedSafeAddr as Hex,
          abi: SAFE_ABI,
          functionName: "approvedHashes",
          args: [owner as Hex, tx.hash as Hex]
        });
        if (isApproved === 1n) approvedBy.push(owner);
      }
      newMap[tx.hash] = approvedBy;
    }
    setApprovalsMap(newMap);
  };

  const executeQueuedTx = async (tx: QueuedTx) => {
    const client = await getClient();
    if (!client || !selectedSafeAddr) return;

    try {
      setLoading(true);
      const parent = mySafes.find(s => s.address === selectedSafeAddr);
      if (!parent) return;

      const sortedOwners = [...nestedOwners].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));

      let signatures = "0x";

      for (const owner of sortedOwners) {
        const approvedList = approvalsMap[tx.hash] || [];
        const isApproved = approvedList.some(o => o.toLowerCase() === owner.toLowerCase());
        const isCurrentSigner = owner.toLowerCase() === parent.address.toLowerCase();

        if (isApproved || isCurrentSigner) {
          signatures += pad(owner as Hex, { size: 32 }).slice(2);
          signatures += pad("0x0", { size: 32 }).slice(2);
          signatures += "01";
        }
      }

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [client], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
        address: parent.address as Hex, saltNonce: BigInt(parent.salt)
      });

      const smartClient = createSmartAccountClient({
        account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      const execData = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "execTransaction",
        args: [
          tx.to as Hex,
          BigInt(tx.value),
          tx.data as Hex,
          tx.operation, // USE THE CORRECT OPERATION TYPE (0 or 1)
          0n, 0n, 0n,
          "0x0000000000000000000000000000000000000000",
          "0x0000000000000000000000000000000000000000",
          signatures as Hex
        ]
      });

      const hash = await smartClient.sendTransaction({
        to: selectedNestedSafeAddr as Hex,
        value: 0n,
        data: execData
      });

      addLog(`Execution Sent! TX: ${hash}`, "success");

      const newQueue = queuedTxs.filter(t => t.hash !== tx.hash);
      setQueuedTxs(newQueue);
      queueRef.current = newQueue;
      localStorage.setItem("localTxQueue", JSON.stringify(newQueue));

      setTimeout(() => {
        fetchData(selectedNestedSafeAddr);
        setActiveTab('history');
      }, 4000);

    } catch (e: any) {
      addLog(`Execution Failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleAddOwner = async () => {
    if (!newOwnerInput) return;
    const data = encodeFunctionData({ abi: SAFE_ABI, functionName: "addOwnerWithThreshold", args: [newOwnerInput as Hex, 1n] });
    await proposeTransaction(selectedNestedSafeAddr, 0n, data, `Add Owner: ${newOwnerInput.slice(0, 6)}...`, 0, 0);
    setNewOwnerInput("");
  };

  const handleUpdateThreshold = async () => {
    if (newThresholdInput < 1) return;
    const data = encodeFunctionData({ abi: SAFE_ABI, functionName: "changeThreshold", args: [BigInt(newThresholdInput)] });
    await proposeTransaction(selectedNestedSafeAddr, 0n, data, `Change Threshold to ${newThresholdInput}`, 0, 0);
  };

  const debugClearQueue = () => {
    setQueuedTxs([]);
    queueRef.current = [];
    localStorage.removeItem("localTxQueue");
    addLog("Queue cleared via Debug", "info");
  };

  const isDashboard = myNestedSafes.length > 0;

  const currentSafeQueue = queuedTxs.filter(t => {
    if (!selectedNestedSafeAddr) return false;
    return t.safeAddress && t.safeAddress.toLowerCase() === selectedNestedSafeAddr.toLowerCase();
  });

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
          <div className="sidebar">
            <div>
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
                  />
                ))}
              </div>
            </div>

            <hr style={{ width: '100%', borderColor: 'var(--border)', margin: '1rem 0' }} />

            <div>
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
                    onClick={() => {
                      setEthBalance(null);
                      setUsdcBalance(null);
                      setNestedOwners([]);
                      setNestedThreshold(0);
                      setTxHistory([]);
                      setSelectedNestedSafeAddr(safe.address);
                      fetchData(safe.address);
                    }}
                    type="nested"
                    onRefresh={() => {
                      fetchData(safe.address);
                      if (activeTab === 'history') fetchHistory(safe.address);
                    }}
                    balanceInfo={selectedNestedSafeAddr === safe.address ? {
                      eth: ethBalance !== null ? parseFloat(ethBalance).toFixed(4) : null,
                      usdc: usdcBalance !== null ? parseFloat(usdcBalance).toFixed(2) : null
                    } : undefined}
                  />
                ))}
              </div>
            </div>
          </div>

          <div className="main-panel">
            <div className="panel-header">
              <button className={`tab-btn ${activeTab === 'transfer' ? 'active' : ''}`} onClick={() => setActiveTab('transfer')}>Transfer</button>
              <button className={`tab-btn ${activeTab === 'owners' ? 'active' : ''}`} onClick={() => setActiveTab('owners')}>Owners</button>
              <button className={`tab-btn ${activeTab === 'queue' ? 'active' : ''}`} onClick={() => setActiveTab('queue')}>
                Queue {currentSafeQueue.filter(t => t.nonce >= nestedNonce).length > 0 && <span className="header-badge" style={{ background: 'var(--primary)', border: 'none', marginLeft: '6px' }}>{currentSafeQueue.filter(t => t.nonce >= nestedNonce).length}</span>}
              </button>
              <button className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`} onClick={() => setActiveTab('history')}>History</button>
              <button className={`tab-btn ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}>Settings</button>
            </div>

            <div className="panel-content">
              {!isCurrentSafeOwner && (
                <div style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24', padding: '10px', borderRadius: '8px', marginBottom: '20px', fontSize: '0.9rem', display: 'flex', gap: '10px' }}>
                  <span>⚠️ The selected Parent Safe is NOT an owner. Transactions cannot be initiated.</span>
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
                  <button className="action-btn" onClick={() => proposeTransaction(recipient, parseEther(sendAmount), "0x", `Transfer ${sendAmount} ETH`)} disabled={loading || !isCurrentSafeOwner}>
                    {nestedThreshold > 1 ? `Create Proposal (${nestedThreshold} sigs needed)` : "Execute Transaction"}
                  </button>
                </>
              )}

              {activeTab === 'queue' && (
                <div>
                  <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                    <span>Pending Transactions (Next Nonce: {nestedNonce})</span>
                    <button onClick={handleRefreshQueue} className="icon-btn" title="Force Refresh Queue & Nonce"><Icons.Refresh /></button>
                  </div>

                  {currentSafeQueue.filter(t => t.nonce >= nestedNonce).length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>No pending transactions for this Safe.</div>
                  ) : (
                    currentSafeQueue.filter(t => t.nonce >= nestedNonce).sort((a, b) => a.nonce - b.nonce).map(tx => {
                      const approvals = approvalsMap[tx.hash] || [];
                      const hasSigned = approvals.some(o => o.toLowerCase() === selectedSafeAddr.toLowerCase());

                      const potentialCount = approvals.length + (hasSigned ? 0 : 1);
                      const readyToExec = potentialCount >= nestedThreshold;
                      const isNext = tx.nonce === nestedNonce;

                      return (
                        <div key={tx.hash} style={{ background: 'var(--surface-1)', border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem', marginBottom: '1rem', opacity: isNext ? 1 : 0.6 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '10px' }}>
                            <div style={{ fontWeight: '600' }}>{tx.description}</div>
                            <div className="header-badge" style={{ background: approvals.length >= nestedThreshold ? 'var(--success)' : 'var(--surface-3)', color: 'white' }}>
                              Nonce {tx.nonce}
                            </div>
                          </div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1rem', fontFamily: 'monospace' }}>
                            Hash: {tx.hash.slice(0, 10)}...{tx.hash.slice(-8)}
                          </div>

                          <div style={{ display: 'flex', gap: '10px' }}>
                            {!hasSigned && (
                              <button className="action-btn secondary" onClick={() => approveTxHash(tx.hash)} disabled={loading || !isCurrentSafeOwner}>
                                Sign (Approve)
                              </button>
                            )}

                            {readyToExec && isNext && (
                              <button className="action-btn" onClick={() => executeQueuedTx(tx)} disabled={loading || !isCurrentSafeOwner}>
                                Execute Transaction
                              </button>
                            )}
                            {(!isNext) && <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', alignSelf: 'center' }}>Waiting for previous nonce...</span>}
                          </div>
                        </div>
                      );
                    })
                  )}

                  {queuedTxs.length > 0 && <div style={{ textAlign: 'center', marginTop: '2rem' }}>
                    <button className="action-btn small secondary" style={{ width: 'auto', display: 'inline-block' }} onClick={debugClearQueue}>
                      Debug: Clear Queue LocalStorage
                    </button>
                  </div>}
                </div>
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
                  </div>

                  <div className="input-group" style={{ marginTop: '1rem' }}>
                    <label>Add External Owner Address</label>
                    <div style={{ display: 'flex', gap: '10px' }}>
                      <input value={newOwnerInput} onChange={e => setNewOwnerInput(e.target.value)} placeholder="0x..." />
                      <button className="action-btn small" onClick={handleAddOwner} disabled={loading || !isCurrentSafeOwner}>Propose Add</button>
                    </div>
                  </div>

                  <hr style={{ margin: '2rem 0', borderColor: 'var(--border)' }} />
                  <div className="section-label">Security Threshold</div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--surface-1)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
                    <div>
                      <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Current Policy</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: '600' }}>
                        {nestedThreshold} out of {nestedOwners.length} signatures required
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <input
                        type="number"
                        min="1"
                        max={nestedOwners.length}
                        value={newThresholdInput}
                        onChange={(e) => setNewThresholdInput(parseInt(e.target.value))}
                        style={{ width: '60px' }}
                      />
                      <button className="action-btn small" onClick={handleUpdateThreshold} disabled={loading || !isCurrentSafeOwner}>
                        Propose Update
                      </button>
                    </div>
                  </div>
                </>
              )}

              {activeTab === 'history' && (
                <div>
                  <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Recent Transactions</span>
                    <button onClick={() => fetchHistory(selectedNestedSafeAddr)} className="icon-btn"><Icons.Refresh /></button>
                  </div>

                  {loadingHistory ? (
                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', textAlign: 'center', marginTop: '2rem' }}>Loading history...</div>
                  ) : txHistory.length === 0 ? (
                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', textAlign: 'center', marginTop: '2rem' }}>No transactions found.</div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {txHistory.map((tx, i) => {
                        const isIncoming = tx.txType === 'ETHEREUM_TRANSACTION';

                        // --- DEDUPLICATION LOGIC ---
                        let valueBigInt = BigInt(0);

                        if (isIncoming && tx.transfers) {
                          const seen = new Set<string>();
                          tx.transfers.forEach(t => {
                            if (t.type === 'ETHER_TRANSFER') {
                              // Deduplicate based on exact match of Value+From+To
                              const key = `${t.value}-${t.from}-${t.to}`;
                              if (!seen.has(key)) {
                                valueBigInt += BigInt(t.value);
                                seen.add(key);
                              }
                            }
                          });
                        } else if (tx.value) {
                          valueBigInt = BigInt(tx.value);
                        }

                        if (isIncoming && valueBigInt === 0n) return null;

                        const amount = formatEther(valueBigInt);
                        const date = new Date(tx.executionDate).toLocaleDateString();

                        let label = isIncoming ? "Received ETH" : "Executed TX";
                        const counterParty = isIncoming ? tx.from : tx.to;
                        const matchedSafe = mySafes.find(s => s.address.toLowerCase() === counterParty?.toLowerCase()) ||
                          myNestedSafes.find(s => s.address.toLowerCase() === counterParty?.toLowerCase());

                        return (
                          <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px', background: 'var(--surface-1)', borderRadius: '8px', borderLeft: isIncoming ? '4px solid var(--success)' : '4px solid var(--primary)' }}>
                            <div>
                              <div style={{ fontWeight: '600', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                {label}
                                {matchedSafe && <span className="owner-tag" style={{ background: 'rgba(255,255,255,0.1)', color: 'white' }}>{matchedSafe.name}</span>}
                              </div>
                              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{date}</div>
                            </div>
                            <div style={{ textAlign: 'right' }}>
                              <div style={{ fontWeight: '600' }}>{amount} ETH</div>
                              {tx.transactionHash && (
                                <a href={`https://sepolia.basescan.org/tx/${tx.transactionHash}`} target="_blank" rel="noreferrer" style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px', justifyContent: 'flex-end' }}>
                                  Explorer <Icons.ExternalLink />
                                </a>
                              )}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'settings' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>

                  {/* --- NEW RHINESTONE MODULE SECTION --- */}
                  <div>
                    <h3 style={{ margin: '0 0 1rem 0' }}>Rhinestone Modules</h3>

                    {/* Fallback Handler Status */}
                    <div style={{ marginBottom: '1rem', padding: '12px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span>Fallback Handler:</span>
                        <span style={{ fontFamily: 'monospace' }}>{currentFallbackHandler}</span>
                      </div>
                      {currentFallbackHandler.toLowerCase() === SAFE_7579_ADAPTER_ADDRESS.toLowerCase() ?
                        <span style={{ color: 'var(--success)' }}>✓ Safe 7579 Adapter Active</span> :
                        <span style={{ color: '#fbbf24' }}>⚠ Standard Safe Handler (Upgrade Needed)</span>
                      }

                      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px' }}>
                        <span>Validator Status:</span>
                        <span>{isValidatorInstalled || (is7579AdapterEnabled && currentFallbackHandler.toLowerCase() === SAFE_7579_ADAPTER_ADDRESS.toLowerCase() && isValidatorInstalled) ? "Installed" : "Not Installed"}</span>
                      </div>
                    </div>

                    <div style={{
                      background: 'var(--surface-1)',
                      border: '1px solid var(--border)',
                      borderRadius: '8px',
                      padding: '1.5rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '1.5rem'
                    }}>
                      <div style={{
                        width: '40px', height: '40px',
                        background: 'rgba(99, 102, 241, 0.1)',
                        color: 'var(--primary)',
                        borderRadius: '8px',
                        display: 'flex', alignItems: 'center', justifyContent: 'center'
                      }}>
                        <Icons.Module />
                      </div>

                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: '600', marginBottom: '4px' }}>Smart Sessions</div>
                        <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                          Enables session keys and automated transactions via ERC-7579.
                        </div>
                      </div>

                      {!(isValidatorInstalled || (is7579AdapterEnabled && currentFallbackHandler.toLowerCase() === SAFE_7579_ADAPTER_ADDRESS.toLowerCase() && isValidatorInstalled)) && <button
                        className="action-btn small"
                        onClick={handleInstallSmartSession}
                        disabled={loading || !isCurrentSafeOwner}
                        style={{ width: 'auto' }}
                      >
                        Install Module
                      </button>}

                      {(isValidatorInstalled || (is7579AdapterEnabled && currentFallbackHandler.toLowerCase() === SAFE_7579_ADAPTER_ADDRESS.toLowerCase() && isValidatorInstalled)) && <div className="header-badge" style={{ background: 'var(--success)', color: 'white' }}>Installed</div>}
                    </div>
                  </div>

                  <hr style={{ borderColor: 'var(--border)' }} />

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