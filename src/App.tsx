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
  parseUnits,
  concat,
  type Address,
  toHex,
  hashTypedData,
  encodePacked,
  size
} from "viem";
import { baseSepolia } from "viem/chains";
import { entryPoint07Address } from "viem/account-abstraction";
import { createSmartAccountClient } from "permissionless";
import { toSafeSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import Safe, { type PasskeyArgType } from "@safe-global/protocol-kit";

import { connectPhantom } from "./utils/phantom";
import "./App.css";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createAllowanceSessionStruct, createSessionStruct, USDC_ADDRESS } from "./utils/smartSessions";
import { getPermissionId, getSafe7579SessionAccount } from "./utils/safe7579";
import { createPasskey, loadPasskeys, storePasskey } from "./utils/passkeys";
import { executePasskeyTransaction, getSafeInfo } from "./utils/safePasskeyClient";

// --- LOGGING HELPER ---
const consoleLog = (stage: string, message: string, data?: any) => {
  const labelStyle = "background: #4f46e5; color: #fff; padding: 2px 6px; border-radius: 4px; font-weight: bold;";
  const msgStyle = "font-weight: bold; color: #4f46e5;";

  console.groupCollapsed(`%c${stage}%c ${message}`, labelStyle, msgStyle);
  if (data) {
    console.log(
      JSON.stringify(
        data,
        (_, v) => (typeof v === "bigint" ? v.toString() + "n" : v),
        2
      )
    );
  }
  console.groupEnd();
};

// --- CONFIG ---
const PIMLICO_API_KEY = import.meta.env.VITE_PIMLICO_API_KEY;
const PIMLICO_URL = `https://api.pimlico.io/v2/base-sepolia/rpc?apikey=${PIMLICO_API_KEY}`;
const PUBLIC_RPC = "https://sepolia.base.org";
const SAFE_TX_SERVICE_URL = "https://safe-transaction-base-sepolia.safe.global/api/v1";

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

// Updated ERC20 ABI with 'as const'
const ERC20_ABI = parseAbi([
  "function balanceOf(address owner) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)"
] as const);

// --- SMART SESSION CONFIG ---
const ENABLE_SESSIONS_ABI = parseAbi([
  "struct PolicyData { address policy; bytes initData; }",
  "struct ERC7739Context { bytes32 appDomainSeparator; string[] contentName; }",
  "struct ERC7739Data { ERC7739Context[] allowedERC7739Content; PolicyData[] erc1271Policies; }",
  "struct ActionData { bytes4 actionTargetSelector; address actionTarget; PolicyData[] actionPolicies; }",
  "struct Session { address sessionValidator; bytes sessionValidatorInitData; bytes32 salt; PolicyData[] userOpPolicies; ERC7739Data erc7739Policies; ActionData[] actions; bool permitERC4337Paymaster; }",
  "function enableSessions(Session[] calldata sessions) external returns (bytes32[])",
  "function isPermissionEnabled(bytes32 permissionId, address account) external view returns (bool)",
  "function removeSession(bytes32 permissionId) external"
]);

const MULTI_SEND_ADDRESS = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526";

const MULTI_SEND_ABI = parseAbi([
  "function multiSend(bytes transactions) external"
]);

/**
 * Encodes a batch of transactions for the Safe MultiSend contract
 */
const encodeMultiSend = (txs: { to: string; value: bigint; data: string; operation: number }[]) => {
  return encodeFunctionData({
    abi: MULTI_SEND_ABI,
    functionName: "multiSend",
    args: [
      concat(
        txs.map((tx) =>
          encodePacked(
            ["uint8", "address", "uint256", "uint256", "bytes"],
            [
              tx.operation,         // 0 for Call, 1 for DelegateCall
              tx.to as Address,
              tx.value,
              BigInt(size(tx.data as Hex)), // Helper to get byte length
              tx.data as Hex,
            ]
          )
        )
      ),
    ],
  });
};

// --- ICONS ---
const Icons = {
  Wallet: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M20 7h-9" /><path d="M14 17H5" /><circle cx="17" cy="17" r="3" /><path d="M7 7V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2h3a2 2 0 0 1 2 2v2h3a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-3" /></svg>,
  Safe: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>,
  Nested: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>,
  Check: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="3" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5" /></svg>,
  Copy: () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>,
  Refresh: () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>,
  Plus: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>,
  ChevronDown: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9" /></svg>,
  ExternalLink: () => <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg>,
  Module: () => <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>,
  Bug: () => <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="1" y="1" width="22" height="22" rx="4" ry="4" /><path d="M16 3v5" /><path d="M8 3v5" /><path d="M3 11h18" /></svg>,
  Key: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="7.5" cy="15.5" r="5.5" /><path d="m21 2-9.6 9.6" /><path d="m15.5 7.5 3 3L22 7l-3-3" /></svg>,
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

// Token Constants
const TOKENS = {
  ETH: { symbol: 'ETH', decimals: 18, isNative: true },
  USDC: { symbol: 'USDC', decimals: 6, isNative: false, address: USDC_ADDRESS }
};

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
  const [loginMethod, setLoginMethod] = useState<'phantom' | 'passkey' | null>(null);
  const [activePasskey, setActivePasskey] = useState<PasskeyArgType | null>(null);
  const [storedPasskeys, setStoredPasskeys] = useState<PasskeyArgType[]>([]);

  const [mySafes, setMySafes] = useState<StoredSafe[]>([]);
  const [myNestedSafes, setMyNestedSafes] = useState<StoredSafe[]>([]);

  const [selectedSafeAddr, setSelectedSafeAddr] = useState<string>("");
  const [selectedNestedSafeAddr, setSelectedNestedSafeAddr] = useState<string>("");

  const [activeTab, setActiveTab] = useState<'transfer' | 'scheduled' | 'allowances' | 'owners' | 'queue' | 'history' | 'settings'>('transfer');

  // Token Selection State
  const [selectedToken, setSelectedToken] = useState<'ETH' | 'USDC'>('ETH');

  // Data State
  const [nestedOwners, setNestedOwners] = useState<string[]>([]);
  const [nestedThreshold, setNestedThreshold] = useState<number>(0);
  const [nestedNonce, setNestedNonce] = useState<number>(0);
  const [ethBalance, setEthBalance] = useState<string | null>(null);
  const [usdcBalance, setUsdcBalance] = useState<string | null>(null);
  const [txHistory, setTxHistory] = useState<SafeTx[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

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

  // Allowances State
  const [allowanceAmount, setAllowanceAmount] = useState("");
  const [allowanceUsage, setAllowanceUsage] = useState("1");
  const [allowanceStart, setAllowanceStart] = useState("");
  const [myAllowances, setMyAllowances] = useState<any[]>([]);

  const [signerMode, setSignerMode] = useState<'main' | 'session'>('main');
  const [activeSession, setActiveSession] = useState<any | null>(null);

  // Scheduled Transfer State
  const [scheduleRecipient, setScheduleRecipient] = useState("");
  const [scheduleAmount, setScheduleAmount] = useState("");
  const [hasStoredSchedule, setHasStoredSchedule] = useState(false);
  const [scheduledInfo, setScheduledInfo] = useState<{ target: string, amount: string } | null>(null);
  const [scheduleDate, setScheduleDate] = useState<string>("");

  const [isSessionEnabledOnChain, setIsSessionEnabledOnChain] = useState(false);

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

    setStoredPasskeys(loadPasskeys());
  }, []);

  useEffect(() => {
    if (selectedNestedSafeAddr) {
      fetchData(selectedNestedSafeAddr);
    }
  }, [selectedSafeAddr]);

  // Check for existing schedule on load
  useEffect(() => {
    const stored = localStorage.getItem("scheduled_session");
    if (stored) {
      const data = JSON.parse(stored);
      setHasStoredSchedule(true);
      setScheduledInfo({ target: data.target, amount: data.amount });
      // Check on-chain status immediately
      if (data.permissionId && selectedNestedSafeAddr) {
        checkSessionStatus(selectedNestedSafeAddr, data.permissionId);
      }
    }
  }, [selectedNestedSafeAddr]);

  useEffect(() => {
    const stored = localStorage.getItem("my_allowances");
    if (stored) setMyAllowances(JSON.parse(stored));
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
    // Debugging the ownership check
    if (!selectedSafeAddr) {
      console.log("OWNER-CHECK: Failed. No selectedParentAddr.");
      return false;
    }
    if (nestedOwners.length === 0) {
      console.log("OWNER-CHECK: Failed. Nested owners list is empty.");
      return false;
    }

    const match = nestedOwners.some(o => o.toLowerCase() === selectedSafeAddr.toLowerCase());

    console.log(`OWNER-CHECK: ${match ? "PASS" : "FAIL"}`, {
      parent: selectedSafeAddr,
      nestedOwners: nestedOwners,
      matchFound: match
    });

    return match;
  }, [selectedSafeAddr, nestedOwners]);

  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  const timePreviews = useMemo(() => {
    if (!scheduleDate) return null;
    const d = new Date(scheduleDate);
    if (isNaN(d.getTime())) return null;

    const options: Intl.DateTimeFormatOptions = {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: true
    };

    return {
      local: d.toLocaleString(undefined, options),
      utc: d.toLocaleString('en-GB', { ...options, timeZone: 'UTC' }) + " UTC",
      est: d.toLocaleString('en-US', { ...options, timeZone: 'America/New_York' }) + " EST",
      unix: Math.floor(d.getTime() / 1000)
    };
  }, [scheduleDate]);

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

  const handleConnectPhantom = async () => {
    setLoading(true);
    const client = await getClient();
    if (client) {
      setLoginMethod('phantom');
    }
    setLoading(false);
  };

  const handleConnectPasskey = async (passkey: PasskeyArgType) => {
    setLoading(true);
    try {
      const info = await getSafeInfo(passkey);
      setActivePasskey(passkey);
      setEoaAddress(info.address); // The EOA equivalent is the Safe 4337 address
      setLoginMethod('passkey');

      // Automatically add this Passkey Safe as a "Parent Safe" if not exists
      const exists = mySafes.find(s => s.address.toLowerCase() === info.address.toLowerCase());
      if (!exists) {
        const newSafe: StoredSafe = { address: info.address, salt: "PASSKEY", name: "Passkey Parent" };
        const updated = [...mySafes, newSafe];
        setMySafes(updated);
        localStorage.setItem("mySafes", JSON.stringify(updated));
        setSelectedSafeAddr(info.address);
      } else {
        setSelectedSafeAddr(info.address);
      }
      addLog(`Logged in with Passkey Safe: ${info.address}`, 'success');
    } catch (e: any) {
      addLog(`Passkey Login Failed: ${e.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNewPasskey = async () => {
    try {
      setLoading(true);
      const pk = await createPasskey();
      storePasskey(pk);
      setStoredPasskeys(loadPasskeys());
      await handleConnectPasskey(pk);
    } catch (e: any) {
      addLog(e.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  // --- ACTIONS ---

  const checkSessionStatus = async (account: string, permissionId: string) => {
    try {
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const isEnabled = await publicClient.readContract({
        address: SMART_SESSIONS_VALIDATOR_ADDRESS,
        abi: ENABLE_SESSIONS_ABI,
        functionName: "isPermissionEnabled",
        args: [permissionId as Hex, account as Address]
      });
      setIsSessionEnabledOnChain(isEnabled);
      if (isEnabled) consoleLog("SESSION-CHECK", "Session is Enabled on-chain");
      else consoleLog("SESSION-CHECK", "Session NOT enabled yet");
    } catch (e) {
      console.error("Failed to check session status", e);
    }
  };

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
    // 1. Get the Current Parent Safe
    const currentParent = mySafes.find(s => s.address === selectedSafeAddr);
    if (!selectedSafeAddr || !currentParent) return;

    if (!window.confirm(`Deploy a new Nested Safe owned by "${currentParent.name}"?`)) return;

    try {
      setLoading(true);
      const nestedSalt = Date.now().toString();
      const safeIndex = myNestedSafes.length + 1;

      // 2. Predict the New Safe Address
      // Use Phantom provider if available, otherwise use Public RPC (for Passkeys)
      const provider = loginMethod === 'phantom'
        ? ((window as any).phantom?.ethereum || (window as any).ethereum)
        : PUBLIC_RPC;

      // Ensure we have a valid signer address string for the SDK to init
      const signerAddr = (loginMethod === 'phantom' && walletClient?.account)
        ? walletClient.account.address
        : selectedSafeAddr;

      const protocolKit = await Safe.init({
        provider,
        signer: signerAddr,
        predictedSafe: {
          safeAccountConfig: { owners: [selectedSafeAddr], threshold: 1 },
          safeDeploymentConfig: { saltNonce: nestedSalt }
        }
      });

      const predictedAddr = await protocolKit.getAddress();

      // 3. Deploy (Phantom) or Track (Passkey)
      if (loginMethod === 'phantom') {
        // Connect Wallet to sign the deployment
        const client = await getClient();
        if (!client) return;

        const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

        // Initialize Parent Smart Account to execute the deployment tx
        const safeAccount = await toSafeSmartAccount({
          client: publicClient,
          owners: [client],
          entryPoint: { address: entryPoint07Address, version: "0.7" },
          version: "1.4.1",
          address: currentParent.address as Hex,
          saltNonce: BigInt(currentParent.salt) // Safe here because Phantom safes use numeric salts
        });

        const smartAccountClient = createSmartAccountClient({
          account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
          userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
        });

        // Create Deployment Transaction via Safe Factory
        const deploymentTx = await protocolKit.createSafeDeploymentTransaction();

        // Send via Parent Safe
        await smartAccountClient.sendTransaction({
          to: deploymentTx.to as Hex,
          value: BigInt(deploymentTx.value),
          data: deploymentTx.data as Hex
        });

        addLog(`Nested Safe Deployed: ${predictedAddr}`, 'success');

      } else {
        // Passkey Mode: Counterfactual / Lazy Deployment
        // Since we don't have an easy way to construct the factory call via the Relay Kit in this demo flow,
        // we will treat it as counterfactual. It will be deployed when you first send assets to it and execute a tx.
        addLog("Note: Nested Safe is Counterfactual (will deploy on first usage)", 'info');
      }

      // 4. Save to Local State
      const newNested: StoredSafe = { address: predictedAddr, salt: nestedSalt, name: `Nested Safe ${safeIndex}` };
      const updatedList = [...myNestedSafes, newNested];
      setMyNestedSafes(updatedList);
      setSelectedNestedSafeAddr(predictedAddr);
      localStorage.setItem("myNestedSafes", JSON.stringify(updatedList));

      fetchData(predictedAddr);

    } catch (e: any) {
      addLog(e.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const fetchData = async (address: string) => {
    if (!address) return;

    consoleLog("FETCH", `Fetching data for Nested Safe: ${address}`);

    const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });

    try {
      // 1. Balances
      const eth = await publicClient.getBalance({ address: address as Hex });
      setEthBalance(formatEther(eth));
      const usdc = await publicClient.readContract({ address: USDC_ADDRESS, abi: ERC20_ABI, functionName: "balanceOf", args: [address as Hex] });
      setUsdcBalance(formatUnits(usdc, 6));

      try {
        // 2. Owners & Threshold
        consoleLog("FETCH", "Reading owners...");
        const owners = await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getOwners" });
        setNestedOwners(Array.from(owners));

        const thresh = await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "getThreshold" });
        setNestedThreshold(Number(thresh));

        setNestedNonce(Number(await publicClient.readContract({ address: address as Hex, abi: SAFE_ABI, functionName: "nonce" })));

        // NEW: If there is a stored session, check its specific status
        const stored = localStorage.getItem("scheduled_session");
        if (stored) {
          const { permissionId } = JSON.parse(stored);
          if (permissionId) {
            await checkSessionStatus(address, permissionId);
          }
        }

      } catch (e) {
        consoleLog("FETCH", "Contract read failed (likely counterfactual)");

        // Counterfactual Fallback Logic
        if (selectedSafeAddr) {
          setNestedOwners([selectedSafeAddr]);
          setNestedThreshold(1);
        } else {
          setNestedOwners([]);
          setNestedThreshold(0);
        }
        setNestedNonce(0);
      }

    } catch (e: any) {
      consoleLog("FETCH", "General error", e);
    }
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

  const handleCreateSchedule = async () => {
    if (!scheduleRecipient || !scheduleAmount || !selectedNestedSafeAddr || !timePreviews) {
      addLog("Missing fields or invalid date", "error");
      return;
    }
    setLoading(true);

    try {
      addLog(`Checking on-chain status for ${selectedNestedSafeAddr.slice(0, 8)}...`, "info");

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const targetSafe = selectedNestedSafeAddr as Address;
      const adapterAddr = SAFE_7579_ADAPTER_ADDRESS.toLowerCase();

      // 1. PERFORM ON-CHAIN CHECKS
      const [isModuleEnabled, rawFallback] = await Promise.all([
        publicClient.readContract({
          address: targetSafe,
          abi: SAFE_ABI,
          functionName: "isModuleEnabled",
          args: [SAFE_7579_ADAPTER_ADDRESS]
        }).catch(() => false),
        publicClient.getStorageAt({
          address: targetSafe,
          slot: FALLBACK_HANDLER_STORAGE_SLOT as Hex
        }).catch(() => "0x")
      ]);

      const currentFallback = rawFallback && rawFallback !== "0x"
        ? `0x${rawFallback.slice(-40)}`.toLowerCase()
        : "0x";

      console.log("--- 7579 Status Check ---");
      console.log("Module Enabled:", isModuleEnabled);
      console.log("Fallback Match:", currentFallback === adapterAddr);

      const batch: { to: string; value: bigint; data: string; operation: number }[] = [];

      // 2. ONLY ADD SETUP STEPS IF THE MODULE IS NOT ENABLED
      // If isModuleEnabled is true, initializeAccount has already been called and MUST NOT be called again.
      if (!isModuleEnabled) {
        addLog("Bundling first-time 7579 setup...", "info");

        // A. Enable Module
        batch.push({
          to: targetSafe, value: 0n, operation: 0,
          data: encodeFunctionData({ abi: SAFE_ABI, functionName: "enableModule", args: [SAFE_7579_ADAPTER_ADDRESS] })
        });

        // B. Initialize Adapter (This maps the Safe to the Validator in the Adapter)
        const initData = encodeFunctionData({
          abi: ADAPTER_7579_ABI,
          functionName: "initializeAccount",
          args: [
            [{ module: SMART_SESSIONS_VALIDATOR_ADDRESS, initData: "0x", moduleType: 1n }],
            { registry: "0x0000000000000000000000000000000000000000", attesters: [], threshold: 0 }
          ]
        });
        batch.push({
          to: SAFE_7579_ADAPTER_ADDRESS, value: 0n, operation: 0,
          data: concat([initData, targetSafe])
        });
      }

      // C. Ensure Fallback Handler is set (Separate from module enable check for safety)
      if (currentFallback !== adapterAddr) {
        batch.push({
          to: targetSafe, value: 0n, operation: 0,
          data: encodeFunctionData({ abi: SAFE_ABI, functionName: "setFallbackHandler", args: [SAFE_7579_ADAPTER_ADDRESS] })
        });
      }

      // 3. PREPARE THE NEW SESSION (Always required)
      const privateKey = generatePrivateKey();
      const sessionOwner = privateKeyToAccount(privateKey);
      const salt = pad(toHex(Date.now()), { size: 32 }) as Hex;

      const session = selectedToken === 'ETH'
        ? createSessionStruct(sessionOwner.address, scheduleRecipient as Address, "0xFFFFFFFF", parseEther(scheduleAmount), salt, timePreviews.unix)
        : createSessionStruct(sessionOwner.address, USDC_ADDRESS as Address, "0xa9059cbb", 0n, salt, timePreviews.unix);

      const expectedId = getPermissionId(session);

      batch.push({
        to: SMART_SESSIONS_VALIDATOR_ADDRESS, value: 0n, operation: 0,
        data: encodeFunctionData({
          abi: ENABLE_SESSIONS_ABI,
          functionName: "enableSessions",
          args: [[session]]
        })
      });

      // 4. PROPOSE
      if (batch.length > 1) {
        // MultiSend if we have setup steps + enableSession
        await proposeTransaction(MULTI_SEND_ADDRESS, 0n, encodeMultiSend(batch), `Setup 7579 + Enable ${selectedToken} Session`, 0, 1);
      } else {
        // Single call if only enableSession is needed
        await proposeTransaction(SMART_SESSIONS_VALIDATOR_ADDRESS, 0n, batch[0].data as Hex, `Enable ${selectedToken} Session`, 0, 0);
      }

      localStorage.setItem("scheduled_session", JSON.stringify({
        privateKey, session, target: scheduleRecipient, amount: scheduleAmount,
        token: selectedToken, permissionId: expectedId, startDate: timePreviews.local
      }));

      setHasStoredSchedule(true);
      setScheduledInfo({ target: scheduleRecipient, amount: scheduleAmount });
      setActiveTab('queue');
      addLog("Session proposal created!", "success");

    } catch (e: any) {
      addLog(`Proposal failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleExecuteSchedule = async () => {
    const stored = localStorage.getItem("scheduled_session");
    if (!stored) return;

    setLoading(true);
    try {
      const { privateKey, session, target, amount, token, permissionId: storedId } = JSON.parse(stored);

      consoleLog("SESSION-EXEC", "Retrieved Session from Storage", {
        storedId,
        target,
        amount,
        token
      });

      const sessionOwner = privateKeyToAccount(privateKey);
      const currentId = getPermissionId(session);

      if (storedId && currentId !== storedId) {
        throw new Error("Session ID mismatch. Please clear schedule and try again.");
      }

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await getSafe7579SessionAccount(
        publicClient,
        selectedNestedSafeAddr as Hex,
        session,
        async (hash) => (sessionOwner as any).sign({ hash })
      );

      const smartClient = createSmartAccountClient({
        account: safeAccount,
        chain: baseSepolia,
        bundlerTransport: http(PIMLICO_URL),
        paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      addLog(`Executing ${token} via Smart Session...`, "info");

      let executionPayload;

      if (token === 'USDC') {
        const decimals = TOKENS.USDC.decimals;
        const value = parseUnits(amount, decimals);
        // Build ERC20 Transfer Call
        const calldata = encodeFunctionData({
          abi: ERC20_ABI,
          functionName: "transfer",
          args: [target as Address, value]
        });

        executionPayload = {
          to: USDC_ADDRESS as Address,
          value: 0n,
          data: calldata
        };
      } else {
        // Native ETH Transfer
        executionPayload = {
          to: target as Address,
          value: parseEther(amount),
          data: "0x" as Hex
        };
      }

      consoleLog("SESSION-EXEC", "Sending UserOp (Execution)", executionPayload);

      const hash = await smartClient.sendTransaction(executionPayload);

      consoleLog("SESSION-EXEC", "Execution Result", { hash });

      addLog(`Schedule Executed! TX: ${hash}`, "success");
      handleClearSchedule();

    } catch (e: any) {
      const msg = e.message || "";
      if (msg.includes("AA22") || msg.includes("expired") || msg.includes("not due")) {
        const date = JSON.parse(localStorage.getItem("scheduled_session") || "{}").startDate;
        addLog(`Policy Restriction: This transfer is not valid yet.`, "info");
        addLog(`Please wait until: ${date}`, "info");
      } else {
        addLog(`Execution Failed: ${e.message}`, "error");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleClearSchedule = () => {
    localStorage.removeItem("scheduled_session");
    setHasStoredSchedule(false);
    setScheduledInfo(null);
    setIsSessionEnabledOnChain(false);
    addLog("Local schedule data cleared", "info");
  };

  const handleRevokeSessionOnChain = async () => {
    const stored = localStorage.getItem("scheduled_session");
    if (!stored || !selectedNestedSafeAddr) return;

    const { permissionId } = JSON.parse(stored);
    if (!permissionId) {
      addLog("No Permission ID found to revoke.", "error");
      return;
    }

    try {
      setLoading(true);
      addLog("Proposing session revocation...", "info");

      // 1. Encode the call to the Validator
      const data = encodeFunctionData({
        abi: ENABLE_SESSIONS_ABI,
        functionName: "removeSession",
        args: [permissionId as Hex]
      });

      // 2. Propose the transaction (Nested Safe calls the Validator)
      // We send this to the queue just like a transfer or owner change
      await proposeTransaction(
        SMART_SESSIONS_VALIDATOR_ADDRESS,
        0n,
        data,
        `Revoke Smart Session: ${permissionId.slice(0, 10)}...`
      );

      addLog("Revocation proposal created. Check the Queue to sign and execute.", "success");
      setActiveTab('queue');
    } catch (e: any) {
      addLog(`Revocation failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleCreateAllowance = async () => {
    if (!allowanceAmount || !allowanceStart || !selectedNestedSafeAddr) {
      addLog("Please fill in amount and start date", "error");
      return;
    }

    setLoading(true);

    try {
      // 1. Setup Ephemeral Signer
      const pk = generatePrivateKey();
      const sessionOwner = privateKeyToAccount(pk);
      const salt = pad(toHex(Date.now()), { size: 32 }) as Hex;
      const startUnix = Math.floor(new Date(allowanceStart).getTime() / 1000);
      const usageCount = allowanceUsage ? parseInt(allowanceUsage) : 10;

      // 2. Format Token Details
      const isNative = selectedToken === 'ETH';
      const amountRaw = isNative
        ? parseEther(allowanceAmount)
        : parseUnits(allowanceAmount, 6);
      const tokenAddr = isNative
        ? "0x0000000000000000000000000000000000000000" as Address
        : USDC_ADDRESS as Address;

      // 3. CREATE THE STRUCT USING THE HELPER
      const session = createAllowanceSessionStruct(
        sessionOwner.address,
        tokenAddr,
        amountRaw,
        usageCount,
        startUnix,
        salt
      );

      // 4. Propose to Queue
      const data = encodeFunctionData({
        abi: ENABLE_SESSIONS_ABI,
        functionName: "enableSessions",
        args: [[session]]
      });

      const permissionId = getPermissionId(session);

      await proposeTransaction(
        SMART_SESSIONS_VALIDATOR_ADDRESS,
        0n,
        data,
        `Enable ${allowanceAmount} ${selectedToken} Allowance (Limit: ${usageCount} Tx)`
      );

      // 5. Store Metadata Locally
      const newAllowance = {
        permissionId,
        privateKey: pk,
        amount: allowanceAmount,
        token: selectedToken,
        usage: usageCount,
        start: allowanceStart,
        session
      };

      const updated = [...myAllowances, newAllowance];
      setMyAllowances(updated);
      localStorage.setItem("my_allowances", JSON.stringify(updated));

      addLog("Allowance proposed to Queue!", "success");
      setActiveTab('queue');

    } catch (e: any) {
      addLog(`Creation failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleSessionSpend = async () => {
    if (!activeSession || !recipient || !sendAmount) return;
    setLoading(true);

    try {
      const { privateKey, session, token, permissionId } = activeSession;
      const sessionOwner = privateKeyToAccount(privateKey);

      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await getSafe7579SessionAccount(
        publicClient,
        selectedNestedSafeAddr as Hex,
        session,
        async (hash) => (sessionOwner as any).sign({ hash })
      );

      const smartClient = createSmartAccountClient({
        account: safeAccount,
        chain: baseSepolia,
        bundlerTransport: http(PIMLICO_URL),
        paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      let tx;
      if (token === 'USDC') {
        tx = {
          to: USDC_ADDRESS as Address,
          value: 0n,
          data: encodeFunctionData({
            abi: ERC20_ABI,
            functionName: "transfer",
            args: [recipient as Address, parseUnits(sendAmount, 6)]
          })
        };
      } else {
        tx = { to: recipient as Address, value: parseEther(sendAmount), data: "0x" as Hex };
      }

      addLog(`Spending ${sendAmount} ${token} via Session Key...`, "info");
      const hash = await smartClient.sendTransaction(tx);
      addLog(`Success! UserOp Hash: ${hash}`, "success");

      // --- FIX STARTS HERE: Post-Spend Cleanup ---

      // 1. Immediately switch the UI back to the Main Account signer
      setSignerMode('main');
      setActiveSession(null);

      // 2. Update the local allowance list (Decrement usage or remove)
      const updatedAllowances = myAllowances.map(al => {
        if (al.permissionId === permissionId) {
          const currentUsage = parseInt(al.usage || "1");
          return { ...al, usage: (currentUsage - 1).toString() };
        }
        return al;
      }).filter(al => parseInt(al.usage) > 0); // Remove if no usage left

      // 3. Save updated list to state and storage
      setMyAllowances(updatedAllowances);
      localStorage.setItem("my_allowances", JSON.stringify(updatedAllowances));

      addLog(updatedAllowances.find(a => a.permissionId === permissionId)
        ? "Allowance updated (Usage count reduced)."
        : "One-use key consumed and removed from sidebar.", "info");

      // 4. Refresh balances
      setTimeout(() => fetchData(selectedNestedSafeAddr), 4000);

    } catch (e: any) {
      addLog(`Spend failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  // --- MULTI-SIG LOGIC ---

  const getSafeTxHash = async (to: string, val: bigint, data: Hex, operation: 0 | 1, nonceOffset = 0) => {
    const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });

    let currentNonce = 0n;
    try {
      currentNonce = await publicClient.readContract({ address: selectedNestedSafeAddr as Hex, abi: SAFE_ABI, functionName: "nonce" });
    } catch (e) {
      consoleLog("TX-HASH", "Could not read nonce (Safe likely undeployed). Defaulting to 0.");
      currentNonce = 0n;
    }

    const targetNonce = Number(currentNonce) + nonceOffset;

    try {
      // Try on-chain calculation first (works for deployed safes)
      const hash = await publicClient.readContract({
        address: selectedNestedSafeAddr as Hex,
        abi: SAFE_ABI,
        functionName: "getTransactionHash",
        args: [to as Hex, val, data, operation, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", BigInt(targetNonce)]
      });
      return { hash, nonce: targetNonce };
    } catch (e) {
      consoleLog("TX-HASH", "On-chain hash calc failed. Calculating off-chain...");

      // Fallback: Calculate Hash Off-chain (EIP-712) for Counterfactual Safes
      const domain = {
        chainId: baseSepolia.id,
        verifyingContract: selectedNestedSafeAddr as Hex,
      };

      const types = {
        SafeTx: [
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'data', type: 'bytes' },
          { name: 'operation', type: 'uint8' },
          { name: 'safeTxGas', type: 'uint256' },
          { name: 'baseGas', type: 'uint256' },
          { name: 'gasPrice', type: 'uint256' },
          { name: 'gasToken', type: 'address' },
          { name: 'refundReceiver', type: 'address' },
          { name: 'nonce', type: 'uint256' },
        ],
      };

      const message = {
        to: to as Hex,
        value: val,
        data: data,
        operation: operation,
        safeTxGas: 0n,
        baseGas: 0n,
        gasPrice: 0n,
        gasToken: "0x0000000000000000000000000000000000000000" as Hex,
        refundReceiver: "0x0000000000000000000000000000000000000000" as Hex,
        nonce: BigInt(targetNonce),
      };

      const hash = await hashTypedData({
        domain,
        types,
        primaryType: 'SafeTx',
        message
      });

      return { hash, nonce: targetNonce };
    }
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

  const approveTxHash = async (hash: string) => {
    if (!selectedSafeAddr) return;

    try {
      setLoading(true);

      // 1. Prepare the call data for the Nested Safe
      const approveData = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "approveHash",
        args: [hash as Hex]
      });

      let txHash;

      // 2. Branch based on Login Method
      if (loginMethod === 'phantom' && walletClient) {
        // --- OPTION A: PHANTOM (Permissionless.js) ---

        const parent = mySafes.find(s => s.address === selectedSafeAddr);
        if (!parent) throw new Error("Parent Safe info not found");

        const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });
        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

        // Initialize the Parent Safe Smart Account
        const safeAccount = await toSafeSmartAccount({
          client: publicClient,
          owners: [walletClient], // Phantom Signer
          entryPoint: { address: entryPoint07Address, version: "0.7" },
          version: "1.4.1",
          address: parent.address as Hex,
          saltNonce: BigInt(parent.salt)
        });

        const smartClient = createSmartAccountClient({
          account: safeAccount,
          chain: baseSepolia,
          bundlerTransport: http(PIMLICO_URL),
          paymaster: pimlicoClient,
          userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
        });

        // Send transaction from Parent Safe -> Nested Safe
        txHash = await smartClient.sendTransaction({
          to: selectedNestedSafeAddr as Hex,
          value: 0n,
          data: approveData
        });

      } else if (loginMethod === 'passkey' && activePasskey) {
        // --- OPTION B: PASSKEY (Safe SDK / Relay Kit) ---

        // Construct the transaction object for the Relay Kit
        const txData = {
          to: selectedNestedSafeAddr,
          value: '0',
          data: approveData
        };

        // Use our helper to sign (WebAuthn) and submit (Pimlico)
        txHash = await executePasskeyTransaction(activePasskey, [txData]);

      } else {
        throw new Error("No active wallet or passkey found.");
      }

      addLog(`Approved Hash! TX: ${txHash}`, "success");

      // Refresh the queue after a short delay to allow indexing
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
        try {
          const isApproved = await publicClient.readContract({
            address: selectedNestedSafeAddr as Hex,
            abi: SAFE_ABI,
            functionName: "approvedHashes",
            args: [owner as Hex, tx.hash as Hex]
          });
          if (isApproved === 1n) approvedBy.push(owner);
        } catch (e) {
          // Ignore read errors (undeployed safe)
        }
      }
      newMap[tx.hash] = approvedBy;
    }
    setApprovalsMap(newMap);
  };

  const executeQueuedTx = async (tx: QueuedTx) => {
    if (!selectedSafeAddr || !selectedNestedSafeAddr) return;

    try {
      setLoading(true);
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http(PUBLIC_RPC) });

      // 1. Check if Nested Safe is deployed
      const code = await publicClient.getBytecode({ address: selectedNestedSafeAddr as Hex });
      const isDeployed = code && code !== "0x";

      // 2. Construct Signatures
      // We need signatures for the threshold. 
      // Since we are the Parent Safe (Owner), we can provide a Pre-Validated Signature (Type 1) for ourselves.

      const sortedOwners = [...nestedOwners].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
      let signatures = "0x";

      for (const owner of sortedOwners) {
        let isApproved = 0n;

        // Condition A: On-chain Approval (for other owners or deployed safe)
        if (isDeployed) {
          try {
            isApproved = await publicClient.readContract({
              address: selectedNestedSafeAddr as Hex,
              abi: SAFE_ABI,
              functionName: "approvedHashes",
              args: [owner as Hex, tx.hash as Hex]
            });
          } catch (e) { /* Ignore read errors */ }
        }

        // Condition B: Implicit Approval (Current Signer/Parent Safe)
        // If the owner is US (the Parent Safe), we are executing the tx, so we implicitly sign it.
        const isCurrentParent = owner.toLowerCase() === selectedSafeAddr.toLowerCase();

        if (isApproved === 1n || isCurrentParent) {
          // Pre-Validated Signature Format (r=Owner, s=0, v=1)
          signatures += pad(owner as Hex, { size: 32 }).slice(2);
          signatures += pad("0x0", { size: 32 }).slice(2);
          signatures += "01";
        }
      }

      // 3. Prepare Execution Data
      const execData = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "execTransaction",
        args: [
          tx.to as Hex, BigInt(tx.value), tx.data as Hex, tx.operation,
          0n, 0n, 0n,
          "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000",
          signatures as Hex
        ]
      });

      // 4. Build Batch (Deploy + Execute)
      const txsToExecute = [];

      if (!isDeployed) {
        const nestedSafeInfo = myNestedSafes.find(s => s.address === selectedNestedSafeAddr);
        if (nestedSafeInfo) {
          addLog("Nested Safe is undeployed. Adding deployment to batch...", "info");

          const provider = loginMethod === 'phantom'
            ? ((window as any).phantom?.ethereum || (window as any).ethereum)
            : PUBLIC_RPC;

          // We use selectedSafeAddr as signer just to satisfy the SDK init requirements for prediction
          const protocolKit = await Safe.init({
            provider,
            signer: selectedSafeAddr,
            predictedSafe: {
              safeAccountConfig: { owners: [selectedSafeAddr], threshold: 1 },
              safeDeploymentConfig: { saltNonce: nestedSafeInfo.salt }
            }
          });

          const deployTx = await protocolKit.createSafeDeploymentTransaction();
          txsToExecute.push({
            to: deployTx.to,
            value: deployTx.value,
            data: deployTx.data
          });
        }
      }

      txsToExecute.push({
        to: selectedNestedSafeAddr,
        value: '0',
        data: execData
      });

      let txHash;

      // 5. Submit Batch
      if (loginMethod === 'phantom' && walletClient) {
        const parent = mySafes.find(s => s.address === selectedSafeAddr);
        if (!parent) throw new Error("Parent Safe info not found");

        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

        const safeAccount = await toSafeSmartAccount({
          client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
          address: parent.address as Hex, saltNonce: BigInt(parent.salt)
        });

        const smartClient = createSmartAccountClient({
          account: safeAccount, chain: baseSepolia, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
          userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
        });

        const userOpHash = await smartClient.sendUserOperation({
          calls: txsToExecute.map(t => ({
            to: t.to as Hex,
            value: BigInt(t.value),
            data: t.data as Hex
          }))
        });
        txHash = userOpHash;

      } else if (loginMethod === 'passkey' && activePasskey) {
        txHash = await executePasskeyTransaction(activePasskey, txsToExecute);
      }

      addLog(`Execution Sent! TX: ${txHash}`, "success");

      // 6. Cleanup Queue
      const newQueue = queuedTxs.filter(t => t.hash !== tx.hash);
      setQueuedTxs(newQueue);
      queueRef.current = newQueue;
      localStorage.setItem("localTxQueue", JSON.stringify(newQueue));

      setTimeout(() => {
        fetchData(selectedNestedSafeAddr);
        setActiveTab('history');
      }, 5000);

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

  // Helper Component: Token Selector
  const TokenSelector = () => (
    <div style={{ display: 'flex', gap: '8px', marginBottom: '1rem' }}>
      {(['ETH', 'USDC'] as const).map(t => (
        <button
          key={t}
          onClick={() => { setSelectedToken(t); setSendAmount(""); setScheduleAmount(""); }}
          className="chip"
          style={{
            borderColor: selectedToken === t ? 'var(--primary)' : 'var(--border)',
            background: selectedToken === t ? 'rgba(99, 102, 241, 0.1)' : 'transparent',
            color: selectedToken === t ? 'white' : 'var(--text-secondary)'
          }}
        >
          {t}
        </button>
      ))}
    </div>
  );

  const isDashboard = loginMethod !== null;

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
        /* --- ONBOARDING / SETUP VIEW --- */
        <div className="setup-container">
          <div className={`step-card ${!loginMethod ? 'active' : 'success'}`}>
            <div className="step-icon"><Icons.Key /></div>
            <div style={{ width: '100%' }}>
              <h3>1. Login Method</h3>
              {!loginMethod ? (
                <div style={{ display: 'flex', gap: '10px', marginTop: '10px', flexDirection: 'column' }}>
                  <div style={{ display: 'flex', gap: '10px' }}>
                    <button className="action-btn" onClick={handleConnectPhantom} disabled={loading}>
                      <Icons.Wallet /> Phantom Wallet
                    </button>
                    <button className="action-btn" style={{ background: '#0ea5e9' }} onClick={handleCreateNewPasskey} disabled={loading}>
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
                  <button className="icon-btn" onClick={() => window.location.reload()} title="Logout"><Icons.Refresh /></button>
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
      ) : (
        /* --- MAIN DASHBOARD VIEW --- */
        <div className="dashboard-container">
          <div className="sidebar">
            <div style={{ flex: 1 }}>
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

              <hr style={{ width: '100%', borderColor: 'var(--border)', margin: '1.5rem 0' }} />
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
                      addLog(`Signer switched to Allowance Key: ${al.permissionId.slice(0, 8)}`, 'info');
                    }}
                  >
                    🔑 Key: {al.amount} {al.token} ({al.usage} left)
                  </button>
                ))}
              </div>
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

            <div style={{ marginTop: '2rem', paddingTop: '1rem', borderTop: '1px solid var(--border)' }}>
              <button
                className="action-btn secondary small"
                style={{ width: '100%', opacity: 0.6, fontSize: '0.75rem' }}
                onClick={() => {
                  if (window.confirm("This will clear all local safes and passkeys. Continue?")) {
                    localStorage.clear();
                    window.location.reload();
                  }
                }}
              >
                Reset Application
              </button>
            </div>
          </div>

          <div className="main-panel">
            <div className="panel-header">
              <button className={`tab-btn ${activeTab === 'transfer' ? 'active' : ''}`} onClick={() => setActiveTab('transfer')}>Transfer</button>
              <button className={`tab-btn ${activeTab === 'scheduled' ? 'active' : ''}`} onClick={() => setActiveTab('scheduled')}>Scheduled</button>
              <button className={`tab-btn ${activeTab === 'allowances' ? 'active' : ''}`} onClick={() => setActiveTab('allowances')}>Allowances</button>
              <button className={`tab-btn ${activeTab === 'owners' ? 'active' : ''}`} onClick={() => setActiveTab('owners')}>Owners</button>
              <button className={`tab-btn ${activeTab === 'queue' ? 'active' : ''}`} onClick={() => setActiveTab('queue')}>
                Queue {currentSafeQueue.filter(t => t.nonce >= nestedNonce).length > 0 && <span className="header-badge" style={{ background: 'var(--primary)', border: 'none', marginLeft: '6px' }}>{currentSafeQueue.filter(t => t.nonce >= nestedNonce).length}</span>}
              </button>
              <button className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`} onClick={() => setActiveTab('history')}>History</button>
            </div>

            <div className="panel-content">
              {!isCurrentSafeOwner && (
                <div style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24', padding: '10px', borderRadius: '8px', marginBottom: '20px', fontSize: '0.9rem', display: 'flex', gap: '10px' }}>
                  <span>⚠️ The selected Parent Safe is NOT an owner. Transactions cannot be initiated.</span>
                </div>
              )}

              {/* --- TRANSFER TAB --- */}
              {activeTab === 'transfer' && (
                <>
                  <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>{signerMode === 'session' ? "Make Transfer (Session Mode)" : "Make Transfer"}</span>
                    {signerMode === 'session' && (
                      <span style={{ color: 'var(--success)', fontSize: '0.7rem', fontWeight: 'bold' }}>
                        USING SESSION KEY
                      </span>
                    )}
                  </div>

                  {/* Token Selector logic */}
                  <TokenSelector />

                  {/* Warning if the selected token in UI doesn't match what the key is authorized for */}
                  {signerMode === 'session' && selectedToken !== activeSession.token && (
                    <div style={{
                      background: 'rgba(239, 68, 68, 0.1)',
                      color: '#f87171',
                      padding: '10px',
                      borderRadius: '8px',
                      marginBottom: '15px',
                      fontSize: '0.85rem',
                      border: '1px solid rgba(239, 68, 68, 0.2)'
                    }}>
                      ⚠️ This session key is authorized for <strong>{activeSession.token}</strong>,
                      but you have <strong>{selectedToken}</strong> selected.
                    </div>
                  )}

                  <div className="input-group">
                    <label>Recipient Address</label>
                    <input placeholder="0x..." value={recipient} onChange={e => setRecipient(e.target.value)} />
                  </div>

                  <div className="input-group">
                    <label>Amount ({selectedToken})</label>
                    <input type="number" placeholder="0.0" value={sendAmount} onChange={e => setSendAmount(e.target.value)} />
                  </div>

                  <button
                    className="action-btn"
                    style={{
                      background: signerMode === 'session' ? 'var(--success)' : 'var(--primary)',
                      boxShadow: signerMode === 'session' ? '0 0 20px rgba(16, 185, 129, 0.2)' : 'none'
                    }}
                    onClick={() => {
                      if (!sendAmount || !recipient) return;

                      if (signerMode === 'session') {
                        // --- SESSION EXECUTION ---
                        if (selectedToken !== activeSession.token) {
                          addLog(`Cannot spend ${selectedToken}: Key is only for ${activeSession.token}`, 'error');
                          return;
                        }
                        handleSessionSpend(); // This is the new direct-execution function
                      } else {
                        // --- MULTISIG PROPOSAL ---
                        if (selectedToken === 'ETH') {
                          proposeTransaction(recipient, parseEther(sendAmount), "0x", `Transfer ${sendAmount} ETH`);
                        } else {
                          const amount = parseUnits(sendAmount, 6);
                          const data = encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [recipient as Address, amount] });
                          proposeTransaction(USDC_ADDRESS, 0n, data, `Transfer ${sendAmount} USDC`);
                        }
                      }
                    }}
                    disabled={loading || (signerMode === 'main' && !isCurrentSafeOwner)}
                  >
                    {signerMode === 'session'
                      ? `Spend via Allowance (${activeSession.token})`
                      : nestedThreshold > 1
                        ? `Create Proposal (${nestedThreshold} sigs needed)`
                        : "Execute Transaction"
                    }
                  </button>

                  {signerMode === 'session' && (
                    <div style={{ marginTop: '15px', padding: '10px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      <strong>Current Session Limits:</strong><br />
                      • Max Spend: {activeSession.amount} {activeSession.token}<br />
                      • Max Txs: {activeSession.usage}<br />
                      • Permission ID: <span style={{ fontFamily: 'monospace' }}>{activeSession.permissionId.slice(0, 16)}...</span>
                    </div>
                  )}
                </>
              )}

              {/* --- SCHEDULED TAB --- */}
              {activeTab === 'scheduled' && (
                <div>
                  <div className="section-label">Scheduled Transfer (Smart Session)</div>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                    Create a one-time session key that activates at a specific time.
                  </p>

                  {!hasStoredSchedule ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      <TokenSelector />
                      <div className="input-group">
                        <label>Recipient Address</label>
                        <input placeholder="0x..." value={scheduleRecipient} onChange={e => setScheduleRecipient(e.target.value)} />
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                        <div className="input-group">
                          <label>Amount ({selectedToken})</label>
                          <input type="number" placeholder="0.0" value={scheduleAmount} onChange={e => setScheduleAmount(e.target.value)} />
                        </div>
                        <div className="input-group">
                          <label>Activation Time (Local)</label>
                          <input type="datetime-local" value={scheduleDate} onChange={e => setScheduleDate(e.target.value)} style={{ colorScheme: 'dark' }} />
                        </div>
                      </div>

                      <button className="action-btn" onClick={handleCreateSchedule} disabled={loading || !isCurrentSafeOwner || !scheduleDate}>
                        Create Schedule Proposal
                      </button>
                    </div>
                  ) : (
                    <div style={{ background: 'var(--surface-1)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '1rem' }}>
                        <div style={{ color: isSessionEnabledOnChain ? 'var(--success)' : '#fbbf24' }}>
                          {isSessionEnabledOnChain ? <Icons.Check /> : <Icons.Refresh />}
                        </div>
                        <h3 style={{ margin: 0, fontSize: '1rem' }}>
                          {isSessionEnabledOnChain ? "Session Key Active" : "Waiting for Setup Approval"}
                        </h3>
                      </div>
                      <div style={{ fontSize: '0.9rem', marginBottom: '1rem' }}>
                        <div><strong>Recipient:</strong> {scheduledInfo?.target}</div>
                        <div><strong>Amount:</strong> {scheduledInfo?.amount} {JSON.parse(localStorage.getItem("scheduled_session") || "{}").token}</div>
                      </div>

                      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        <button className="action-btn" onClick={handleExecuteSchedule} disabled={loading || !isSessionEnabledOnChain}>
                          Execute Now
                        </button>
                        {isSessionEnabledOnChain && (
                          <button className="action-btn" style={{ background: '#ef4444' }} onClick={handleRevokeSessionOnChain} disabled={loading || !isCurrentSafeOwner}>
                            Revoke On-Chain
                          </button>
                        )}
                        <button className="action-btn secondary" onClick={() => fetchData(selectedNestedSafeAddr)} disabled={loading}>
                          Check Status
                        </button>
                        <button className="action-btn secondary" onClick={handleClearSchedule} disabled={loading}>
                          Clear Local Data
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* --- ALLOWANCES TAB --- */}
              {activeTab === 'allowances' && (
                <div>
                  <div className="section-label">Smart Allowances (Spending + Usage Limits)</div>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                    Grant restricted access to your Safe. Use <strong>ValueLimitPolicy</strong> for ETH and <strong>ERC20SpendingLimitPolicy</strong> for USDC.
                  </p>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <TokenSelector />

                    <div className="input-group">
                      <label>Total Spending Allowance ({selectedToken})</label>
                      <input type="number" value={allowanceAmount} onChange={e => setAllowanceAmount(e.target.value)} placeholder="0.0" />
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                      <div className="input-group">
                        <label>Max Transactions (Usage Limit)</label>
                        <input type="number" value={allowanceUsage} onChange={e => setAllowanceUsage(e.target.value)} placeholder="e.g. 5" />
                      </div>
                      <div className="input-group">
                        <label>Key Active From</label>
                        <input type="datetime-local" value={allowanceStart} onChange={e => setAllowanceStart(e.target.value)} style={{ colorScheme: 'dark' }} />
                      </div>
                    </div>

                    <button className="action-btn" onClick={handleCreateAllowance} disabled={loading || !isCurrentSafeOwner || !allowanceStart || !allowanceAmount}>
                      Propose Allowance Key
                    </button>
                  </div>

                  <div className="section-label" style={{ marginTop: '2.5rem' }}>Locally Stored Allowance Keys</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {myAllowances.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>No active allowance keys.</div>
                    ) : (
                      myAllowances.map((al, i) => (
                        <div key={i} className="owner-row" style={{ borderLeft: '3px solid var(--primary)' }}>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: '600' }}>{al.amount} {al.token} Total Cap</div>
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                              Usage: Max {al.usage || 'N/A'} Tx | ID: {al.permissionId.slice(0, 14)}...
                            </div>
                          </div>
                          <button className="action-btn secondary small" onClick={() => addLog("To spend: Select this key as signer and use Transfer tab.", "info")}>Spend</button>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* --- QUEUE TAB --- */}
              {activeTab === 'queue' && (
                <div>
                  <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                    <span>Pending Transactions (Next Nonce: {nestedNonce})</span>
                    <button onClick={handleRefreshQueue} className="icon-btn" title="Force Refresh"><Icons.Refresh /></button>
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
                            {!hasSigned && <button className="action-btn secondary" onClick={() => approveTxHash(tx.hash)} disabled={loading || !isCurrentSafeOwner}>Sign (Approve)</button>}
                            {readyToExec && isNext && <button className="action-btn" onClick={() => executeQueuedTx(tx)} disabled={loading || !isCurrentSafeOwner}>Execute Transaction</button>}
                            {(!isNext) && <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', alignSelf: 'center' }}>Waiting for previous nonce...</span>}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* --- OWNERS TAB --- */}
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
                      <div style={{ fontSize: '1.1rem', fontWeight: '600' }}>{nestedThreshold} out of {nestedOwners.length} signatures</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <input type="number" min="1" max={nestedOwners.length} value={newThresholdInput} onChange={(e) => setNewThresholdInput(parseInt(e.target.value))} style={{ width: '60px' }} />
                      <button className="action-btn small" onClick={handleUpdateThreshold} disabled={loading || !isCurrentSafeOwner}>Update</button>
                    </div>
                  </div>
                </>
              )}

              {/* --- HISTORY TAB --- */}
              {activeTab === 'history' && (
                <div>
                  <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Recent Transactions</span>
                    <button onClick={() => fetchHistory(selectedNestedSafeAddr)} className="icon-btn"><Icons.Refresh /></button>
                  </div>
                  {loadingHistory ? (
                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', textAlign: 'center', marginTop: '2rem' }}>Loading...</div>
                  ) : txHistory.length === 0 ? (
                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', textAlign: 'center', marginTop: '2rem' }}>No history found.</div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {txHistory.map((tx, i) => {
                        const isIncoming = tx.txType === 'ETHEREUM_TRANSACTION';
                        const val = formatEther(BigInt(tx.value || 0));
                        if (isIncoming && val === "0") return null;
                        return (
                          <div key={i} className="owner-row" style={{ borderLeft: isIncoming ? '4px solid var(--success)' : '4px solid var(--primary)', padding: '12px' }}>
                            <div>
                              <div style={{ fontWeight: '600', fontSize: '0.9rem' }}>{isIncoming ? "Received ETH" : "Executed TX"}</div>
                              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{new Date(tx.executionDate).toLocaleDateString()}</div>
                            </div>
                            <div style={{ textAlign: 'right' }}>
                              <div style={{ fontWeight: '600' }}>{val} ETH</div>
                              {tx.transactionHash && <a href={`https://sepolia.basescan.org/tx/${tx.transactionHash}`} target="_blank" rel="noreferrer" style={{ fontSize: '0.75rem', color: 'var(--primary)', textDecoration: 'none' }}>Explorer <Icons.ExternalLink /></a>}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TERMINAL DRAWER */}
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