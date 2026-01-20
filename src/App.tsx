import React, { useEffect, useState, useRef, useMemo } from "react";
import {
  createPublicClient, http, type WalletClient, type Hex,
  encodeFunctionData, pad, parseEther, formatEther,
  formatUnits, parseUnits, concat, type Address, toHex,
  hashTypedData, encodePacked, size
} from "viem";
import { SAFE_ABI, ADAPTER_7579_ABI, ERC20_ABI, ENABLE_SESSIONS_ABI, PERIODIC_POLICY_ABI, MULTI_SEND_ABI } from "./abis";
import type { StoredSafe, LogEntry, SafeTx, QueuedTx } from "./types";
import { entryPoint07Address } from "viem/account-abstraction";
import { createSmartAccountClient } from "permissionless";
import { toSafeSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import Safe, { type PasskeyArgType } from "@safe-global/protocol-kit";
import { Icons } from "./components/shared/Icons";
import { SafeListItem } from "./components/shared/SafeListItem";
import { TerminalDrawer } from "./components/shared/TerminalDrawer";
import { TokenSelector } from "./components/shared/TokenSelector";

// --- Thirdweb Imports ---
import {
  ConnectButton,
  useActiveAccount,
  useDisconnect,
  useActiveWallet
} from "thirdweb/react";
import { defineChain } from "thirdweb";
import { base, baseSepolia } from "thirdweb/chains";
import { viemAdapter } from "thirdweb/adapters/viem";
import { client } from "./utils/thirdweb";

import "./App.css";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { calculateConfigId, createAllowanceSessionStruct, createSessionStruct } from "./utils/smartSessions";
import { getPermissionId, getSafe7579SessionAccount } from "./utils/safe7579";
import { createPasskey, loadPasskeys, storePasskey } from "./utils/passkeys";
import { executePasskeyTransaction, getSafeInfo, getSafe4337Pack } from "./utils/safePasskeyClient";
import {
  ACTIVE_CHAIN,
  BUNDLER_URL,
  NETWORK,
  RPC_URL,
  USDC_ADDRESS,
  PERIODIC_ERC20_POLICY,
  SMART_SESSIONS_VALIDATOR_ADDRESS,
  SAFE_7579_ADAPTER_ADDRESS,
  MULTI_SEND_ADDRESS
} from "./config";

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

const formatError = (error: any): string => {
  const msg = error?.message || JSON.stringify(error);

  // Smart Account (Entrypoint) Revert Codes
  if (msg.includes("AA23")) {
    if (msg.includes("0xacfdb444") || msg.includes("0xd1f90918")) {
      return "⛔ Policy Violation: Usage limit exceeded or time window not active.";
    }
    if (msg.includes("AA22")) {
      return "⚠️ Session Expired: The validity period for this key has ended.";
    }
    return "❌ Transaction Refused: The Smart Session policy rejected this action.";
  }

  if (msg.includes("AA21")) return "💸 Paymaster Error: Not enough funds to sponsor gas.";
  if (msg.includes("AA10")) return "❌ Sender Created: The account is already deployed.";

  // Fallback for short messages
  if (msg.length < 100) return `Error: ${msg}`;

  return "Unknown Error (Check console)";
};

// --- CONFIG ---
const PIMLICO_URL = BUNDLER_URL;
const PUBLIC_RPC = RPC_URL;
const SAFE_TX_SERVICE_URL = NETWORK === 'mainnet'
  ? "https://safe-transaction-base.safe.global/api/v1"
  : "https://safe-transaction-base-sepolia.safe.global/api/v1";

// Storage slot for Safe Fallback Handler
const FALLBACK_HANDLER_STORAGE_SLOT = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";

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

// Token Constants
const TOKENS = {
  ETH: { symbol: 'ETH', decimals: 18, isNative: true },
  USDC: { symbol: 'USDC', decimals: 6, isNative: false, address: USDC_ADDRESS }
};

// --- MAIN APP ---

const App: React.FC = () => {
  const [walletClient, setWalletClient] = useState<WalletClient | null>(null);
  const [eoaAddress, setEoaAddress] = useState<string>("");
  const [loginMethod, setLoginMethod] = useState<'thirdweb' | 'passkey' | null>(null);
  const [activePasskey, setActivePasskey] = useState<PasskeyArgType | null>(null);
  const [storedPasskeys, setStoredPasskeys] = useState<PasskeyArgType[]>([]);

  // Thirdweb Hooks
  const thirdwebAccount = useActiveAccount();
  const thirdwebWallet = useActiveWallet();
  const { disconnect } = useDisconnect();

  // Define active chain for Thirdweb components
  const activeChain = NETWORK === 'mainnet' ? base : baseSepolia;

  // --- THIRDWEB INTEGRATION ---
  useEffect(() => {
    if (thirdwebAccount) {
      // Convert Thirdweb account to Viem Client
      const viemClient = viemAdapter.walletClient.toViem({
        client,
        chain: defineChain(activeChain.id),
        account: thirdwebAccount
      });

      // Cast to fix type mismatch
      setWalletClient(viemClient as unknown as WalletClient);
      setEoaAddress(thirdwebAccount.address);
      setLoginMethod('thirdweb');
      addLog(`Wallet Connected: ${thirdwebAccount.address.slice(0, 6)}...`, "success");
    } else {
      if (loginMethod === 'thirdweb') {
        setWalletClient(null);
        setEoaAddress("");
        setLoginMethod(null);
      }
    }
  }, [thirdwebAccount, loginMethod, activeChain.id]);

  const [mySafes, setMySafes] = useState<StoredSafe[]>([]);
  const [myNestedSafes, setMyNestedSafes] = useState<StoredSafe[]>([]);

  const [selectedSafeAddr, setSelectedSafeAddr] = useState<string>("");
  const [selectedNestedSafeAddr, setSelectedNestedSafeAddr] = useState<string>("");

  // Parent Safe Management State
  const [isParentSettingsOpen, setIsParentSettingsOpen] = useState(false);
  const [parentOwners, setParentOwners] = useState<string[]>([]);
  const [newParentOwnerInput, setNewParentOwnerInput] = useState("");

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

  // Inputs
  const [recipient, setRecipient] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [newOwnerInput, setNewOwnerInput] = useState("");
  const [newThresholdInput, setNewThresholdInput] = useState<number>(1);

  // Allowances State
  const [allowanceHolder, setAllowanceHolder] = useState<string>("");
  const [allowanceAmount, setAllowanceAmount] = useState("");
  const [allowanceName, setAllowanceName] = useState("");
  const [allowanceStart, setAllowanceStart] = useState("");
  const [allowanceInterval, setAllowanceInterval] = useState<string>("1");
  const [allowanceUnit, setAllowanceUnit] = useState<'minutes' | 'hours' | 'days'>('minutes');
  const [myAllowances, setMyAllowances] = useState<any[]>([]);

  // Scan / Audit State
  const [zombieAllowances, setZombieAllowances] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState(false);

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
    if (!selectedSafeAddr || nestedOwners.length === 0) return false;
    return nestedOwners.some(o => o.toLowerCase() === selectedSafeAddr.toLowerCase());
  }, [selectedSafeAddr, nestedOwners]);

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

  const handleLogout = async () => {
    if (loginMethod === 'thirdweb' && thirdwebWallet) {
      await disconnect(thirdwebWallet);
    }
    setWalletClient(null);
    setEoaAddress("");
    setActivePasskey(null);
    setLoginMethod(null);
    // Note: We deliberately do NOT clear 'mySafes' or 'myNestedSafes' 
    // so the user retains their list of Safes when they log back in.
    addLog("Logged out. Please sign in again.", "info");
  };

  const fetchParentOwners = async (address: string) => {
    try {
      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
      const owners = await publicClient.readContract({
        address: address as Hex,
        abi: SAFE_ABI,
        functionName: "getOwners"
      });
      setParentOwners(Array.from(owners));
    } catch (e) {
      console.error("Failed to fetch parent owners", e);
    }
  };

  const handleOpenParentSettings = () => {
    if (selectedSafeAddr) {
      fetchParentOwners(selectedSafeAddr);
      setIsParentSettingsOpen(true);
    }
  };

  const handleAddSignerToParent = async () => {
    if (!newParentOwnerInput || !selectedSafeAddr) return;

    try {
      setLoading(true);

      // 1. Encode Data: Add Owner, keep threshold at 1
      const data = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "addOwnerWithThreshold",
        args: [newParentOwnerInput as Hex, 1n]
      });

      let txHash;

      // 2. Execute based on Login Method
      if (loginMethod === 'thirdweb' && walletClient) {
        // Init Client for Parent Safe
        const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });
        const parentInfo = mySafes.find(s => s.address === selectedSafeAddr);

        const safeAccount = await toSafeSmartAccount({
          client: publicClient,
          owners: [walletClient],
          entryPoint: { address: entryPoint07Address, version: "0.7" },
          version: "1.4.1",
          address: selectedSafeAddr as Hex,
          saltNonce: parentInfo ? BigInt(parentInfo.salt) : 0n
        });

        const smartClient = createSmartAccountClient({
          account: safeAccount,
          chain: ACTIVE_CHAIN,
          bundlerTransport: http(PIMLICO_URL),
          paymaster: pimlicoClient,
          userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
        });

        // Send Self-Transaction to add owner
        txHash = await smartClient.sendTransaction({
          to: selectedSafeAddr as Hex,
          value: 0n,
          data: data
        });

      } else if (loginMethod === 'passkey' && activePasskey) {

        // Passkey Mode: Safe4337Pack targets itself by default
        const tx = {
          to: selectedSafeAddr,
          value: '0',
          data: data
        };

        txHash = await executePasskeyTransaction(activePasskey, [tx]);
      }

      addLog(`Signer Added! TX: ${txHash}`, "success");
      setNewParentOwnerInput("");

      // Refresh list after short delay
      setTimeout(() => fetchParentOwners(selectedSafeAddr), 4000);

    } catch (e: any) {
      addLog(`Failed to add signer: ${formatError(e)}`, "error");
    } finally {
      setLoading(false);
    }
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
      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
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
    if (!walletClient) return;
    try {
      setLoading(true);
      const safeIndex = mySafes.length + 1;
      const salt = BigInt(Date.now()).toString();
      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
      const safeAccount = await toSafeSmartAccount({
        client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1", saltNonce: BigInt(salt),
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
      // Ensure we have a valid signer address string for the SDK to init
      const signerAddr = (loginMethod === 'thirdweb' && walletClient?.account)
        ? walletClient.account.address
        : selectedSafeAddr;

      const protocolKit = await Safe.init({
        provider: RPC_URL,
        signer: signerAddr,
        predictedSafe: {
          safeAccountConfig: { owners: [selectedSafeAddr], threshold: 1 },
          safeDeploymentConfig: { saltNonce: nestedSalt }
        }
      });

      const predictedAddr = await protocolKit.getAddress();

      // 3. Deploy (Thirdweb) or Track (Passkey)
      if (loginMethod === 'thirdweb' && walletClient) {

        const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

        // Initialize Parent Smart Account to execute the deployment tx
        const safeAccount = await toSafeSmartAccount({
          client: publicClient,
          owners: [walletClient],
          entryPoint: { address: entryPoint07Address, version: "0.7" },
          version: "1.4.1",
          address: currentParent.address as Hex,
          saltNonce: BigInt(currentParent.salt) // Safe here because Thirdweb safes use numeric salts
        });

        const smartAccountClient = createSmartAccountClient({
          account: safeAccount, chain: ACTIVE_CHAIN, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
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

    const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });

    try {
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

      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
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

      const batch: { to: string; value: bigint; data: string; operation: number }[] = [];

      // 2. ONLY ADD SETUP STEPS IF THE MODULE IS NOT ENABLED
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
        await proposeTransaction(MULTI_SEND_ADDRESS, 0n, encodeMultiSend(batch), `Setup 7579 + Enable ${selectedToken} Session`, 0, 1);
      } else {
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

      const sessionOwner = privateKeyToAccount(privateKey);
      const currentId = getPermissionId(session);

      if (storedId && currentId !== storedId) {
        throw new Error("Session ID mismatch. Please clear schedule and try again.");
      }

      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await getSafe7579SessionAccount(
        publicClient,
        selectedNestedSafeAddr as Hex,
        session,
        async (hash) => (sessionOwner as any).sign({ hash })
      );

      const smartClient = createSmartAccountClient({
        account: safeAccount,
        chain: ACTIVE_CHAIN,
        bundlerTransport: http(PIMLICO_URL),
        paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      addLog(`Executing ${token} via Smart Session...`, "info");

      let executionPayload;

      if (token === 'USDC') {
        const decimals = TOKENS.USDC.decimals;
        const value = parseUnits(amount, decimals);
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
        executionPayload = {
          to: target as Address,
          value: parseEther(amount),
          data: "0x" as Hex
        };
      }

      const hash = await smartClient.sendTransaction(executionPayload);

      addLog(`Schedule Executed! TX: ${hash}`, "success");
      handleClearSchedule();

    } catch (e: any) {
      const niceMessage = formatError(e);
      addLog(niceMessage, "error");
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

      const data = encodeFunctionData({
        abi: ENABLE_SESSIONS_ABI,
        functionName: "removeSession",
        args: [permissionId as Hex]
      });

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

  // --- ALLOWANCE LOGIC ---

  const handleCreateAllowance = async () => {
    if (!allowanceAmount || !allowanceStart || !selectedNestedSafeAddr || !allowanceHolder) {
      addLog("Please fill in amount, start date, and select a holder.", "error");
      return;
    }

    if (selectedToken === 'ETH') {
      addLog("Recurring allowances only support USDC in this demo.", "error");
      return;
    }

    setLoading(true);

    try {
      // --- 1. SETUP / CHECKS ---
      addLog(`Checking on-chain status for ${selectedNestedSafeAddr.slice(0, 8)}...`, "info");

      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
      const targetSafe = selectedNestedSafeAddr as Address;
      const adapterAddr = SAFE_7579_ADAPTER_ADDRESS.toLowerCase();

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

      const batch: { to: string; value: bigint; data: string; operation: number }[] = [];

      // Only add setup steps if needed
      if (!isModuleEnabled) {
        addLog("Bundling first-time 7579 setup...", "info");
        batch.push({
          to: targetSafe, value: 0n, operation: 0,
          data: encodeFunctionData({ abi: SAFE_ABI, functionName: "enableModule", args: [SAFE_7579_ADAPTER_ADDRESS] })
        });

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

      if (currentFallback !== adapterAddr) {
        addLog("Updating Fallback Handler...", "info");
        batch.push({
          to: targetSafe, value: 0n, operation: 0,
          data: encodeFunctionData({ abi: SAFE_ABI, functionName: "setFallbackHandler", args: [SAFE_7579_ADAPTER_ADDRESS] })
        });
      }

      // --- 2. PREPARE SESSION ---
      const sessionOwnerAddress = allowanceHolder as Address;

      const salt = pad(toHex(Date.now()), { size: 32 }) as Hex;
      const startUnix = Math.floor(new Date(allowanceStart).getTime() / 1000);

      const val = parseInt(allowanceInterval);
      if (isNaN(val) || val <= 0) throw new Error("Invalid interval");

      let refillSeconds = 0;
      if (allowanceUnit === 'minutes') refillSeconds = val * 60;
      if (allowanceUnit === 'hours') refillSeconds = val * 3600;
      if (allowanceUnit === 'days') refillSeconds = val * 86400;

      const amountRaw = parseUnits(allowanceAmount, 6); // Assuming USDC
      const tokenAddr = USDC_ADDRESS as Address;
      const finalName = allowanceName || "Untitled Budget";

      const session = createAllowanceSessionStruct(
        sessionOwnerAddress,
        tokenAddr,
        amountRaw,
        startUnix,
        salt,
        refillSeconds,
        finalName,
        allowanceHolder as Address,
        pad("0x0", { size: 32 })
      );

      const enableData = encodeFunctionData({
        abi: ENABLE_SESSIONS_ABI,
        functionName: "enableSessions",
        args: [[session]]
      });

      batch.push({
        to: SMART_SESSIONS_VALIDATOR_ADDRESS, value: 0n, operation: 0,
        data: enableData
      });

      const permissionId = getPermissionId(session);

      const configId = calculateConfigId(
        selectedNestedSafeAddr as Address,
        permissionId,
        tokenAddr
      );

      // --- 3. PROPOSE ---
      const description = `Enable ${finalName}: ${allowanceAmount} ${selectedToken}`;

      if (batch.length > 1) {
        await proposeTransaction(MULTI_SEND_ADDRESS, 0n, encodeMultiSend(batch), `Setup 7579 + ${description}`, 0, 1);
      } else {
        await proposeTransaction(SMART_SESSIONS_VALIDATOR_ADDRESS, 0n, enableData, description, 0, 0);
      }

      const newAllowance = {
        permissionId,
        configId,
        signerAddress: allowanceHolder,
        name: finalName,
        amount: allowanceAmount,
        token: selectedToken,
        start: allowanceStart,
        session,
        type: 'recurring',
        interval: `${allowanceInterval} ${allowanceUnit}`
      };

      const updated = [...myAllowances, newAllowance];
      setMyAllowances(updated);
      localStorage.setItem("my_allowances", JSON.stringify(updated));

      addLog("Recurring Budget proposed!", "success");
      setAllowanceName("");
      setActiveTab('queue');

    } catch (e: any) {
      addLog(`Creation failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleCreateLinkedSchedule = async (parentAllowance: any) => {
    if (!parentAllowance.configId) {
      alert("Error: No Config ID found on parent allowance.");
      return;
    }

    setLoading(true);
    try {
      // 1. Setup the Ephemeral Key
      const ephemeralKey = generatePrivateKey();
      const ephemeralAccount = privateKeyToAccount(ephemeralKey);
      const salt = pad(toHex(Date.now()), { size: 32 }) as Hex;

      // 2. Schedule for 1 hour from now (Simulated)
      const startUnix = Math.floor(Date.now() / 1000); // Executable immediately for this test

      // 3. Create Session with POINTER
      // We pass the parent's configId as the last argument
      const session = createAllowanceSessionStruct(
        ephemeralAccount.address, // The Ephemeral Key is the signer
        USDC_ADDRESS as Address,
        parseUnits("10", 6), // Spending 10 USDC
        startUnix,
        salt,
        3600, // Interval doesn't really matter for a one-time schedule
        "Scheduled Payment",
        parentAllowance.holder, // Keep the same holder for record keeping
        parentAllowance.configId // <--- THE MAGIC POINTER
      );

      // 4. Enable this session on-chain
      // Note: In a real app, the User would sign this userOp. 
      // Here, we assume the connected wallet is authorizing this schedule.
      const enableData = encodeFunctionData({
        abi: ENABLE_SESSIONS_ABI,
        functionName: "enableSessions",
        args: [[session]]
      });

      await proposeTransaction(
        SMART_SESSIONS_VALIDATOR_ADDRESS,
        0n,
        enableData,
        `Schedule 10 USDC (Linked to ${parentAllowance.name})`
      );

      // 5. Save to local storage so we can execute it
      const scheduleData = {
        privateKey: ephemeralKey, // We store the ephemeral private key
        session,
        token: 'USDC',
        permissionId: getPermissionId(session),
        amount: "10"
      };

      // We'll just hijack the 'activeSession' state to let you execute it immediately for the test
      setSignerMode('session');
      setActiveSession(scheduleData); // Load it into the "Transfer" tab context
      setActiveTab('transfer');

      addLog("Linked Schedule Created! Go to Transfer tab to execute.", "success");

    } catch (e: any) {
      addLog(e.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleCheckSpecific = async (allowance: any) => {
    try {
      addLog(`🔍 Debugging Allowance: ${allowance.name}...`, "info");
      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });

      const recalculatedConfigId = calculateConfigId(
        selectedNestedSafeAddr as Address,
        allowance.permissionId,
        USDC_ADDRESS as Address
      );

      console.log("DEBUG-CONFIG", {
        storedConfigId: allowance.configId,
        recalculated: recalculatedConfigId,
        permissionId: allowance.permissionId,
        account: selectedNestedSafeAddr,
        token: USDC_ADDRESS
      });

      if (recalculatedConfigId !== allowance.configId) {
        addLog("⚠️ Config ID Mismatch! The app may have stored an invalid ID.", "error");
      }

      const data = await publicClient.readContract({
        address: PERIODIC_ERC20_POLICY as Address,
        abi: PERIODIC_POLICY_ABI,
        functionName: "getAllowance",
        args: [
          selectedNestedSafeAddr as Address,
          recalculatedConfigId,
          USDC_ADDRESS as Address
        ]
      });

      console.log("DEBUG-ONCHAIN", data);

      if (data.limit === 0n && !data.isDeleted) {
        addLog("❌ Policy returned Empty Data (Limit 0). The Config ID might be wrong, or initialization failed.", "error");
      } else {
        const holderText = data.holder === "0x0000000000000000000000000000000000000000" ? "None" : `${data.holder.slice(0, 6)}...`;
        addLog(`✅ Data Found! Limit: ${formatUnits(data.limit, 6)} | Spent: ${formatUnits(data.amountSpent, 6)} | Holder: ${holderText}`, "success");

        const now = Math.floor(Date.now() / 1000);
        const elapsed = now - Number(data.lastRefill);
        const interval = Number(data.refillInterval);
        addLog(`⏱ Time Status: Last Refill ${new Date(Number(data.lastRefill) * 1000).toLocaleTimeString()} | Interval: ${interval}s | Elapsed: ${elapsed}s`, "info");
      }

    } catch (e: any) {
      console.error(e);
      addLog(`Fetch failed: ${e.message}`, "error");
    }
  };

  const handleScanAllowances = async () => {
    if (!selectedNestedSafeAddr) return;
    setIsScanning(true);
    setZombieAllowances([]);

    try {
      addLog("Scanning blockchain for active allowances...", "info");
      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });

      // Call the View Function on the V3 Policy
      const onChainAllowances = await publicClient.readContract({
        address: PERIODIC_ERC20_POLICY as Address,
        abi: PERIODIC_POLICY_ABI,
        functionName: "getAllowances",
        args: [selectedNestedSafeAddr as Address]
      });

      console.log("🔍 RAW ALLOWANCES FROM CHAIN:", onChainAllowances);
      consoleLog("SCAN", "Raw Data", onChainAllowances);

      const zombies: any[] = [];

      for (const allowance of onChainAllowances) {
        // Simple heuristic to detect if we own it: match name and amount
        const isControllable = myAllowances.some(local =>
          local.amount === formatUnits(allowance.limit, 6) &&
          local.name === allowance.name
        );

        zombies.push({
          ...allowance,
          formattedLimit: formatUnits(allowance.limit, 6),
          formattedSpent: formatUnits(allowance.amountSpent, 6),
          isControllable
        });
      }

      setZombieAllowances(zombies);
      addLog(`Scan complete. Found ${zombies.length} allowances.`, "success");

    } catch (e: any) {
      addLog(`Scan failed: ${e.message}. Is the module enabled?`, "error");
    } finally {
      setIsScanning(false);
    }
  };

  const handleCleanUpAllowance = async (configId: string, tokenAddress: string) => {
    if (!selectedNestedSafeAddr) return;
    if (!window.confirm("This will permanently disable this allowance record on-chain. Continue?")) return;

    setLoading(true);
    try {
      const data = encodeFunctionData({
        abi: PERIODIC_POLICY_ABI,
        functionName: "revokeAllowance",
        args: [configId as Hex, tokenAddress as Address]
      });

      await proposeTransaction(
        PERIODIC_ERC20_POLICY,
        0n,
        data,
        `Clean up Allowance Record (${configId.slice(0, 6)}...)`
      );

      addLog("Cleanup proposal created! Check Queue.", "success");
      setActiveTab('queue');
    } catch (e: any) {
      addLog(`Cleanup failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeAllowance = async (allowance: any) => {
    if (!selectedNestedSafeAddr || !allowance.permissionId) return;

    if (!window.confirm("Are you sure you want to revoke this key on-chain?")) return;

    setLoading(true);
    try {
      // 1. Encode the call to removeSession
      const data = encodeFunctionData({
        abi: ENABLE_SESSIONS_ABI,
        functionName: "removeSession",
        args: [allowance.permissionId as Hex]
      });

      // 2. Propose the transaction to the Queue
      await proposeTransaction(
        SMART_SESSIONS_VALIDATOR_ADDRESS,
        0n,
        data,
        `Revoke Key: ${allowance.permissionId.slice(0, 8)}...`
      );

      // 3. Cleanup Local State immediately
      const updated = myAllowances.filter(a => a.permissionId !== allowance.permissionId);
      setMyAllowances(updated);
      localStorage.setItem("my_allowances", JSON.stringify(updated));

      // If this was the active signer, reset mode
      if (activeSession?.permissionId === allowance.permissionId) {
        setSignerMode('main');
        setActiveSession(null);
      }

      addLog("Revocation proposed to Queue. Key removed from local list.", "success");
      setActiveTab('queue');

    } catch (e: any) {
      addLog(`Revocation failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleSessionSpend = async () => {
    if (!activeSession || !recipient || !sendAmount) return;
    setLoading(true);

    try {
      const { privateKey, session, token, signerAddress, holder } = activeSession;
      const requiredSigner = (signerAddress || holder) as string;

      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });

      let signerCallback: ((hash: Hex) => Promise<Hex>) | undefined;

      if (privateKey) {
        // --- CASE A: AUTOMATED / SCHEDULED (Ephemeral Key) ---
        const localAccount = privateKeyToAccount(privateKey);
        signerCallback = async (hash: Hex) => localAccount.sign({ hash });
      } else {
        // --- CASE B: USER-BOUND (Interactive) ---
        const currentAddr = loginMethod === 'thirdweb' ? walletClient?.account?.address : eoaAddress;
        if (!currentAddr) throw new Error("No wallet connected");

        // 1. IS HOLDER == CONNECTED WALLET? (Direct EOA)
        if (currentAddr.toLowerCase() === requiredSigner.toLowerCase()) {
          if (loginMethod === 'thirdweb' && walletClient) {
            signerCallback = async (hash: Hex) => {
              addLog("Requesting signature from wallet...", "info");
              return await walletClient.signMessage({
                account: currentAddr as Address,
                message: { raw: hash }
              });
            };
          } else if (loginMethod === 'passkey' && activePasskey) {
            // Passkey Mode: Use Safe4337Pack Protocol Kit to sign the hash
            signerCallback = async (hash: Hex) => {
              addLog("Requesting Direct Passkey signature...", "info");
              const safe4337Pack = await getSafe4337Pack(activePasskey);

              // 1. Get the WebAuthn Signer Address (Owner of the Parent Safe)
              const owners = await safe4337Pack.protocolKit.getOwners();
              const webAuthnSignerAddress = owners[0] as Address;
              consoleLog("SIGNER", "WebAuthn Shared Signer Address", webAuthnSignerAddress);

              // 2. Calculate the EIP-712 SafeMessage hash for the Parent Safe
              // The Parent Safe (currentAddr) is the one validating the signature.
              const safeMessageHash = hashTypedData({
                domain: {
                  chainId: ACTIVE_CHAIN.id,
                  verifyingContract: currentAddr as Address // The Parent Safe
                },
                types: { SafeMessage: [{ name: 'message', type: 'bytes' }] },
                primaryType: 'SafeMessage',
                message: { message: hash } // Raw UserOpHash
              });

              consoleLog("SIGNER", "Direct SafeMessage Hash (Challenge)", safeMessageHash);

              // 3. Sign hash to get RAW WebAuthn data
              const sigResult = await safe4337Pack.protocolKit.signHash(safeMessageHash);
              const rawWebAuthnSig = sigResult.data as Hex;
              consoleLog("SIGNER", "Raw WebAuthn Signature", rawWebAuthnSig);

              // 4. Wrap into Parent Safe Contract Signature Format (v=0)
              // [r=Owner] [s=Offset] [v=0] [len] [data]
              const r_auth = pad(webAuthnSignerAddress, { size: 32 });
              const s_auth = pad(toHex(65), { size: 32 });
              const v_auth = "0x00";
              const len_auth = pad(toHex(size(rawWebAuthnSig)), { size: 32 });

              const innerSigData = encodePacked(
                ['bytes32', 'bytes32', 'bytes1', 'bytes32', 'bytes'],
                [r_auth, s_auth, v_auth, len_auth, rawWebAuthnSig]
              );

              consoleLog("SIGNER", "Inner Signature (Parent Safe)", innerSigData);

              // 5. Wrap THIS signature for the Nested Safe (Layer 3).
              // [r=ParentSafe] [s=Offset] [v=0] [len] [innerSigData]

              const r = pad(currentAddr as Hex, { size: 32 }); // r = Parent Safe Address
              const s = pad(toHex(65), { size: 32 });
              const v = "0x00";

              const len = pad(toHex(size(innerSigData)), { size: 32 });

              const wrappedSignature = encodePacked(
                ['bytes32', 'bytes32', 'bytes1', 'bytes32', 'bytes'],
                [r, s, v, len, innerSigData]
              );

              consoleLog("SIGNER", "Final Wrapped Signature", wrappedSignature);
              return wrappedSignature;
            };
          } else {
            throw new Error("Direct Passkey signing logic pending.");
          }
        }
        // 2. IS HOLDER == A PARENT SAFE? (Smart Contract Signer)
        else {
          const parentSafe = mySafes.find(s => s.address.toLowerCase() === requiredSigner.toLowerCase());

          if (parentSafe) {
            const code = await publicClient.getBytecode({ address: requiredSigner as Address });
            if (!code || code === '0x') {
              throw new Error(`Parent Safe (${parentSafe.name}) is NOT deployed on-chain yet. Please switch to it and send a transaction first.`);
            }

            if (loginMethod === 'thirdweb' && walletClient) {
              signerCallback = async (hash: Hex) => {
                addLog(`Requesting signature on behalf of Safe ${parentSafe.name}...`, "info");
                return await walletClient.signTypedData({
                  account: currentAddr as Address,
                  domain: {
                    chainId: ACTIVE_CHAIN.id,
                    verifyingContract: requiredSigner as Address
                  },
                  types: {
                    SafeMessage: [{ name: 'message', type: 'bytes' }]
                  },
                  primaryType: 'SafeMessage',
                  message: { message: hash }
                });
              };
            } else if (loginMethod === 'passkey') {
              throw new Error("Cross-signing for other Safes is not currently supported with Passkeys in this demo.");
            } else {
              throw new Error(`Wrong Wallet! Connected: ${currentAddr.slice(0, 6)}... | Required: ${requiredSigner.slice(0, 6)}...`);
            }
          }
        }
      }

      // 2. Critical Check: Ensure we have a signer before proceeding
      if (!signerCallback) {
        throw new Error("Could not determine a valid signer method for this session.");
      }

      // --- CLIENT SETUP & EXECUTION ---
      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

      const safeAccount = await getSafe7579SessionAccount(
        publicClient,
        selectedNestedSafeAddr as Hex,
        session,
        signerCallback
      );

      const smartClient = createSmartAccountClient({
        account: safeAccount,
        chain: ACTIVE_CHAIN,
        bundlerTransport: http(PIMLICO_URL),
        paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      let tx;
      if (token === 'USDC') {
        tx = {
          to: USDC_ADDRESS as Address,
          value: 0n,
          data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [recipient as Address, parseUnits(sendAmount, 6)] })
        };
      } else {
        tx = { to: recipient as Address, value: parseEther(sendAmount), data: "0x" as Hex };
      }

      addLog(`Spending ${sendAmount} ${token} via Session Key...`, "info");
      const userOpHash = await smartClient.sendTransaction(tx);
      addLog(`Success! UserOp Hash: ${userOpHash}`, "success");

      setSignerMode('main');
      setActiveSession(null);
      setTimeout(() => fetchData(selectedNestedSafeAddr), 4000);

    } catch (e: any) {
      console.error(e);
      addLog(formatError(e), "error");
    } finally {
      setLoading(false);
    }
  };

  // --- MULTI-SIG LOGIC ---

  const getSafeTxHash = async (to: string, val: bigint, data: Hex, operation: 0 | 1, nonceOffset = 0) => {
    const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });

    let currentNonce = 0n;
    try {
      currentNonce = await publicClient.readContract({ address: selectedNestedSafeAddr as Hex, abi: SAFE_ABI, functionName: "nonce" });
    } catch (e) {
      consoleLog("TX-HASH", "Could not read nonce (Safe likely undeployed). Defaulting to 0.");
      currentNonce = 0n;
    }

    const targetNonce = Number(currentNonce) + nonceOffset;

    try {
      const hash = await publicClient.readContract({
        address: selectedNestedSafeAddr as Hex,
        abi: SAFE_ABI,
        functionName: "getTransactionHash",
        args: [to as Hex, val, data, operation, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", BigInt(targetNonce)]
      });
      return { hash, nonce: targetNonce };
    } catch (e) {
      // Fallback: Off-chain hash (EIP-712) for counterfactual
      const domain = { chainId: ACTIVE_CHAIN.id, verifyingContract: selectedNestedSafeAddr as Hex };
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
        to: to as Hex, value: val, data: data, operation, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n,
        gasToken: "0x0000000000000000000000000000000000000000" as Hex,
        refundReceiver: "0x0000000000000000000000000000000000000000" as Hex,
        nonce: BigInt(targetNonce),
      };
      const hash = await hashTypedData({ domain, types, primaryType: 'SafeTx', message });
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
        operation,
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
      const approveData = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "approveHash",
        args: [hash as Hex]
      });

      let txHash;

      if (loginMethod === 'thirdweb' && walletClient) {
        const parent = mySafes.find(s => s.address === selectedSafeAddr);
        if (!parent) throw new Error("Parent Safe info not found");

        const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

        const safeAccount = await toSafeSmartAccount({
          client: publicClient,
          owners: [walletClient],
          entryPoint: { address: entryPoint07Address, version: "0.7" },
          version: "1.4.1",
          address: parent.address as Hex,
          saltNonce: BigInt(parent.salt)
        });

        const smartClient = createSmartAccountClient({
          account: safeAccount,
          chain: ACTIVE_CHAIN,
          bundlerTransport: http(PIMLICO_URL),
          paymaster: pimlicoClient,
          userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
        });

        txHash = await smartClient.sendTransaction({
          to: selectedNestedSafeAddr as Hex,
          value: 0n,
          data: approveData
        });

      } else if (loginMethod === 'passkey' && activePasskey) {
        const txData = {
          to: selectedNestedSafeAddr,
          value: '0',
          data: approveData
        };
        txHash = await executePasskeyTransaction(activePasskey, [txData]);
      } else {
        throw new Error("No active wallet found.");
      }

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
    const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
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
        } catch (e) { }
      }
      newMap[tx.hash] = approvedBy;
    }
    setApprovalsMap(newMap);
  };

  const executeQueuedTx = async (tx: QueuedTx) => {
    if (!selectedSafeAddr || !selectedNestedSafeAddr) return;

    try {
      setLoading(true);
      const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });

      const code = await publicClient.getBytecode({ address: selectedNestedSafeAddr as Hex });
      const isDeployed = code && code !== "0x";

      const sortedOwners = [...nestedOwners].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
      let signatures = "0x";

      for (const owner of sortedOwners) {
        let isApproved = 0n;
        if (isDeployed) {
          try {
            isApproved = await publicClient.readContract({
              address: selectedNestedSafeAddr as Hex,
              abi: SAFE_ABI,
              functionName: "approvedHashes",
              args: [owner as Hex, tx.hash as Hex]
            });
          } catch (e) { }
        }

        const isCurrentParent = owner.toLowerCase() === selectedSafeAddr.toLowerCase();

        if (isApproved === 1n || isCurrentParent) {
          signatures += pad(owner as Hex, { size: 32 }).slice(2);
          signatures += pad("0x0", { size: 32 }).slice(2);
          signatures += "01";
        }
      }

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

      const txsToExecute = [];

      if (!isDeployed) {
        const nestedSafeInfo = myNestedSafes.find(s => s.address === selectedNestedSafeAddr);
        if (nestedSafeInfo) {
          addLog("Nested Safe is undeployed. Adding deployment to batch...", "info");

          // Use prediction logic
          const protocolKit = await Safe.init({
            provider: RPC_URL,
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

      if (loginMethod === 'thirdweb' && walletClient) {
        const parent = mySafes.find(s => s.address === selectedSafeAddr);
        if (!parent) throw new Error("Parent Safe info not found");

        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

        const safeAccount = await toSafeSmartAccount({
          client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
          address: parent.address as Hex, saltNonce: BigInt(parent.salt)
        });

        const smartClient = createSmartAccountClient({
          account: safeAccount, chain: ACTIVE_CHAIN, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
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

  const handleAddOwner = async (addressOverride?: string) => {
    const ownerToAdd = addressOverride || newOwnerInput;
    if (!ownerToAdd) return;
    const data = encodeFunctionData({ abi: SAFE_ABI, functionName: "addOwnerWithThreshold", args: [ownerToAdd as Hex, 1n] });
    await proposeTransaction(selectedNestedSafeAddr, 0n, data, `Add Owner: ${ownerToAdd.slice(0, 6)}...`, 0, 0);
    setNewOwnerInput("");
  };

  const handleUpdateThreshold = async () => {
    if (newThresholdInput < 1) return;
    const data = encodeFunctionData({ abi: SAFE_ABI, functionName: "changeThreshold", args: [BigInt(newThresholdInput)] });
    await proposeTransaction(selectedNestedSafeAddr, 0n, data, `Change Threshold to ${newThresholdInput}`, 0, 0);
  };

  const isDashboard = loginMethod !== null;

  const currentSafeQueue = queuedTxs.filter(t => {
    if (!selectedNestedSafeAddr) return false;
    return t.safeAddress && t.safeAddress.toLowerCase() === selectedNestedSafeAddr.toLowerCase();
  });

  return (
    <div className="app-container">
      <header className="header">
        <span className="header-badge">
          {NETWORK === 'mainnet' ? 'Base Mainnet' : 'Base Sepolia'}
        </span>
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
                    onSettings={handleOpenParentSettings}
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
                    🔑 {al.name || "Key"} ({al.amount} {al.token})
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
                  <TokenSelector
                    selectedToken={selectedToken}
                    onSelect={(t) => {
                      setSelectedToken(t);
                      setSendAmount("");
                      setScheduleAmount("");
                    }}
                  />

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
                      <TokenSelector
                        selectedToken={selectedToken}
                        onSelect={(t) => {
                          setSelectedToken(t);
                          setSendAmount("");
                          setScheduleAmount("");
                        }}
                      />
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
                  <div className="section-label">Recurring Budgets</div>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                    Create a standing allowance that resets automatically over time.
                  </p>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <TokenSelector
                      selectedToken={selectedToken}
                      onSelect={(t) => {
                        setSelectedToken(t);
                        setSendAmount("");
                        setScheduleAmount("");
                      }}
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
                          {/* 1. Name and Badges */}
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontWeight: 'bold' }}>{z.name}</span>
                            {!z.isActive && <span className="header-badge" style={{ background: '#52525b' }}>ARCHIVED</span>}
                            {z.isActive && !z.isControllable && <span className="header-badge" style={{ background: '#f59e0b', color: 'black' }}>READ ONLY</span>}
                          </div>

                          {/* 2. Spent Amount */}
                          <div style={{ fontSize: '0.85rem', marginTop: '4px' }}>
                            <span style={{ color: 'var(--text-secondary)' }}>Spent:</span> {z.formattedSpent} / {z.formattedLimit} USDC
                          </div>

                          {/* 3. Holder Info */}
                          <div style={{ fontSize: '0.85rem', marginTop: '4px' }}>
                            <span style={{ color: 'var(--text-secondary)' }}>Holder:</span> {z.holder.slice(0, 6)}...{z.holder.slice(-4)}
                          </div>

                          {/* 4. Config ID */}
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px', fontFamily: 'monospace' }}>
                            ConfigID: {z.configId.slice(0, 10)}...
                          </div>
                        </div>

                        {/* Right side buttons */}
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
                      const signedCount = approvals.length;
                      const readyToExec = signedCount >= nestedThreshold;
                      const isNext = tx.nonce === nestedNonce;

                      return (
                        <div key={tx.hash} style={{ background: 'var(--surface-1)', border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem', marginBottom: '1rem', opacity: isNext ? 1 : 0.6 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '10px' }}>
                            <div style={{ fontWeight: '600' }}>{tx.description}</div>
                            <div className="header-badge" style={{ background: readyToExec ? 'var(--success)' : 'var(--surface-3)', color: 'white' }}>
                              Nonce {tx.nonce}
                            </div>
                          </div>

                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1rem', fontFamily: 'monospace' }}>
                            Hash: {tx.hash.slice(0, 10)}...{tx.hash.slice(-8)}
                          </div>

                          <div style={{ background: 'var(--surface-2)', padding: '10px', borderRadius: '6px', marginBottom: '1rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '0.8rem' }}>
                              <span style={{ color: 'var(--text-secondary)' }}>Confirmations</span>
                              <span style={{ fontWeight: '600', color: readyToExec ? 'var(--success)' : 'var(--text-main)' }}>
                                {signedCount} / {nestedThreshold}
                              </span>
                            </div>

                            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                              {approvals.length > 0 ? (
                                approvals.map(signer => {
                                  const isMe = signer.toLowerCase() === selectedSafeAddr.toLowerCase();
                                  return (
                                    <div key={signer} style={{
                                      display: 'flex', alignItems: 'center', gap: '6px',
                                      background: 'rgba(255,255,255,0.05)', border: isMe ? '1px solid var(--primary)' : '1px solid var(--border)',
                                      padding: '4px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'JetBrains Mono'
                                    }}>
                                      {isMe && <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--primary)' }}></span>}
                                      {signer.slice(0, 6)}...{signer.slice(-4)}
                                      {isMe && <span style={{ fontWeight: 'bold', color: 'var(--primary)' }}>(You)</span>}
                                    </div>
                                  );
                                })
                              ) : (
                                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                                  No signatures yet
                                </span>
                              )}
                            </div>
                          </div>

                          <div style={{ display: 'flex', gap: '10px' }}>
                            {!hasSigned && (
                              <button className="action-btn secondary" onClick={() => approveTxHash(tx.hash)} disabled={loading || !isCurrentSafeOwner}>
                                <Icons.Check /> Sign (Approve)
                              </button>
                            )}
                            {(readyToExec || (!hasSigned && (signedCount + 1) >= nestedThreshold)) && isNext && (
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
                              {tx.transactionHash && (
                                <a
                                  href={`${ACTIVE_CHAIN.blockExplorers?.default.url}/tx/${tx.transactionHash}`}
                                  target="_blank"
                                  rel="noreferrer"
                                  style={{ fontSize: '0.75rem', color: 'var(--primary)', textDecoration: 'none' }}
                                >
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
            </div>
          </div>
        </div>
      )}

      <TerminalDrawer
        logs={logs}
        loading={loading}
        onClear={() => setLogs([])}
      />

      {/* PARENT SETTINGS MODAL */}
      {isParentSettingsOpen && (
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
              <button className="icon-btn" onClick={() => setIsParentSettingsOpen(false)}>✕</button>
            </div>

            <div className="section-label">Current Owners</div>
            <div style={{ maxHeight: '200px', overflowY: 'auto', marginBottom: '1.5rem', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {parentOwners.map(owner => (
                <div key={owner} style={{
                  background: 'var(--surface-1)', padding: '10px', borderRadius: '6px',
                  fontFamily: 'JetBrains Mono', fontSize: '0.85rem', border: '1px solid var(--border)'
                }}>
                  {owner}
                  {eoaAddress && owner.toLowerCase() === eoaAddress.toLowerCase() &&
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
                value={newParentOwnerInput}
                onChange={(e) => setNewParentOwnerInput(e.target.value)}
              />
            </div>

            <button
              className="action-btn"
              onClick={handleAddSignerToParent}
              disabled={loading || !newParentOwnerInput}
            >
              Add Signer
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;