import React, { useEffect, useState, useRef, useMemo } from "react";
import {
  createPublicClient, http, type WalletClient, type Hex,
  encodeFunctionData, pad, parseEther,
  formatUnits, parseUnits, concat, type Address, toHex,
  hashTypedData, encodePacked, size
} from "viem";
import { SAFE_ABI, ERC20_ABI, ENABLE_SESSIONS_ABI, PERIODIC_POLICY_ABI, MULTI_SEND_ABI } from "./abis";
import type { StoredSafe, LogEntry, QueuedTx } from "./types";
import { entryPoint07Address } from "viem/account-abstraction";
import { createSmartAccountClient } from "permissionless";
import { toSafeSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import Safe, { type PasskeyArgType } from "@safe-global/protocol-kit";

// --- Components ---
import { Onboarding } from "./components/Onboarding";
import { Sidebar } from "./components/layout/Sidebar";
import { ParentSettingsModal } from "./components/modals/ParentSettingsModal";
import { TerminalDrawer } from "./components/shared/TerminalDrawer";

// --- Tabs ---
import { HistoryTab } from "./components/dashboard/HistoryTab";
import { QueueTab } from "./components/dashboard/QueueTab";
import { OwnersTab } from "./components/dashboard/OwnersTab";
import { TransferTab } from "./components/dashboard/TransferTab";
import { ScheduledTab } from "./components/dashboard/ScheduledTab";
import { AllowancesTab } from "./components/dashboard/AllowancesTab";

// --- Hooks & Utils ---
import { useSafeData } from "./hooks/useSafeData";
import {
  useActiveAccount,
  useDisconnect,
  useActiveWallet
} from "thirdweb/react";
import { defineChain } from "thirdweb";
import { base, baseSepolia } from "thirdweb/chains";
import { viemAdapter } from "thirdweb/adapters/viem";
import { client } from "./utils/thirdweb";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { calculateConfigId, createAllowanceSessionStruct } from "./utils/smartSessions";
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
  MULTI_SEND_ADDRESS
} from "./config";
import { prepareAllowanceProposal, prepareCleanupAllowance, prepareRevokeAllowance, prepareScheduleProposal } from "./services/sessionProposalService";
import { executeAutomatedSchedule } from "./services/sessionExecutionService";
import { scanOnChainAllowances } from "./services/sessionAuditService";

import "./App.css";

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

  if (msg.length < 100) return `Error: ${msg}`;
  return "Unknown Error (Check console)";
};

// --- CONFIG ---
const PIMLICO_URL = BUNDLER_URL;
const PUBLIC_RPC = RPC_URL;

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
              tx.operation,
              tx.to as Address,
              tx.value,
              BigInt(size(tx.data as Hex)),
              tx.data as Hex,
            ]
          )
        )
      ),
    ],
  });
};

// --- MAIN APP ---

const App: React.FC = () => {
  // 1. Auth State
  const [walletClient, setWalletClient] = useState<WalletClient | null>(null);
  const [eoaAddress, setEoaAddress] = useState<string>("");
  const [loginMethod, setLoginMethod] = useState<'thirdweb' | 'passkey' | null>(null);
  const [activePasskey, setActivePasskey] = useState<PasskeyArgType | null>(null);
  const [storedPasskeys, setStoredPasskeys] = useState<PasskeyArgType[]>([]);

  // Thirdweb
  const thirdwebAccount = useActiveAccount();
  const thirdwebWallet = useActiveWallet();
  const { disconnect } = useDisconnect();
  const activeChain = NETWORK === 'mainnet' ? base : baseSepolia;

  // 2. Navigation & Safe State
  const [mySafes, setMySafes] = useState<StoredSafe[]>([]);
  const [myNestedSafes, setMyNestedSafes] = useState<StoredSafe[]>([]);

  const [selectedSafeAddr, setSelectedSafeAddr] = useState<string>("");
  const [selectedNestedSafeAddr, setSelectedNestedSafeAddr] = useState<string>("");

  const [activeTab, setActiveTab] = useState<'transfer' | 'scheduled' | 'allowances' | 'owners' | 'queue' | 'history' | 'settings'>('transfer');

  // 3. Extracted Data Hook
  // Replaces manual fetching of balances, owners, history, and nonce for the nested safe
  const nestedSafeData = useSafeData(selectedNestedSafeAddr, selectedSafeAddr);

  // 4. Modal & Settings State
  const [isParentSettingsOpen, setIsParentSettingsOpen] = useState(false);
  const [parentOwners, setParentOwners] = useState<string[]>([]);
  const [newParentOwnerInput, setNewParentOwnerInput] = useState("");

  // 5. Transaction/Form State
  const [selectedToken, setSelectedToken] = useState<'ETH' | 'USDC'>('ETH');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);

  // Inputs
  const [recipient, setRecipient] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [newOwnerInput, setNewOwnerInput] = useState("");
  const [newThresholdInput, setNewThresholdInput] = useState<number>(1);

  // Queue State
  const [queuedTxs, setQueuedTxs] = useState<QueuedTx[]>([]);
  const queueRef = useRef<QueuedTx[]>([]);
  const [approvalsMap, setApprovalsMap] = useState<Record<string, string[]>>({});

  // Allowances State
  const [allowanceHolder, setAllowanceHolder] = useState<string>("");
  const [allowanceAmount, setAllowanceAmount] = useState("");
  const [allowanceName, setAllowanceName] = useState("");
  const [allowanceStart, setAllowanceStart] = useState("");
  const [allowanceInterval, setAllowanceInterval] = useState<string>("1");
  const [allowanceUnit, setAllowanceUnit] = useState<'minutes' | 'hours' | 'days'>('minutes');
  const [myAllowances, setMyAllowances] = useState<any[]>([]);
  const [zombieAllowances, setZombieAllowances] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  // Session State
  const [signerMode, setSignerMode] = useState<'main' | 'session'>('main');
  const [activeSession, setActiveSession] = useState<any | null>(null);

  // Schedule State
  const [scheduleRecipient, setScheduleRecipient] = useState("");
  const [scheduleAmount, setScheduleAmount] = useState("");
  const [hasStoredSchedule, setHasStoredSchedule] = useState(false);
  const [scheduledInfo, setScheduledInfo] = useState<{ target: string, amount: string } | null>(null);
  const [scheduleDate, setScheduleDate] = useState<string>("");
  const [isSessionEnabledOnChain, setIsSessionEnabledOnChain] = useState(false);

  // --- EFFECTS ---

  useEffect(() => {
    if (thirdwebAccount) {
      const viemClient = viemAdapter.walletClient.toViem({
        client,
        chain: defineChain(activeChain.id),
        account: thirdwebAccount
      });
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
      if (parsed.length > 0) setSelectedNestedSafeAddr(parsed[0].address);
    } else {
      const oldNested = localStorage.getItem("nestedSafeAddress");
      if (oldNested) {
        const migrated: StoredSafe = { address: oldNested, salt: "0", name: "Legacy Safe" };
        setMyNestedSafes([migrated]);
        setSelectedNestedSafeAddr(oldNested);
      }
    }

    const storedQueue = localStorage.getItem("localTxQueue");
    if (storedQueue) {
      const parsedQueue = JSON.parse(storedQueue);
      setQueuedTxs(parsedQueue);
      queueRef.current = parsedQueue;
    }

    setStoredPasskeys(loadPasskeys());

    const storedAllowances = localStorage.getItem("my_allowances");
    if (storedAllowances) setMyAllowances(JSON.parse(storedAllowances));
  }, []);

  // Check for existing schedule on load/switch
  useEffect(() => {
    const stored = localStorage.getItem("scheduled_session");
    if (stored) {
      const data = JSON.parse(stored);
      setHasStoredSchedule(true);
      setScheduledInfo({ target: data.target, amount: data.amount });
      if (data.permissionId && selectedNestedSafeAddr) {
        checkSessionStatus(selectedNestedSafeAddr, data.permissionId);
      }
    }
  }, [selectedNestedSafeAddr]);

  // Hook into data fetcher for History
  useEffect(() => {
    if (activeTab === 'history' && selectedNestedSafeAddr) {
      nestedSafeData.fetchHistory();
    }
    if (activeTab === 'queue' && selectedNestedSafeAddr) {
      checkQueueApprovals();
    }
  }, [activeTab, selectedNestedSafeAddr, queuedTxs]);


  const isCurrentSafeOwner = useMemo(() => {
    if (!selectedSafeAddr || nestedSafeData.owners.length === 0) return false;
    return nestedSafeData.owners.some(o => o.toLowerCase() === selectedSafeAddr.toLowerCase());
  }, [selectedSafeAddr, nestedSafeData.owners]);

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

  // --- HELPERS ---

  const addLog = (msg: string, type: 'info' | 'success' | 'error' = 'info') => {
    setLogs(prev => [...prev, { msg, type, timestamp: new Date().toLocaleTimeString() }]);
  };

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
    } catch (e) {
      console.error("Failed to check session status", e);
    }
  };

  // --- HANDLERS: AUTH & SETUP ---

  const handleLogout = async () => {
    if (loginMethod === 'thirdweb' && thirdwebWallet) {
      await disconnect(thirdwebWallet);
    }
    setWalletClient(null);
    setEoaAddress("");
    setActivePasskey(null);
    setLoginMethod(null);
    addLog("Logged out. Please sign in again.", "info");
  };

  const handleReset = () => {
    if (window.confirm("This will clear all local safes and passkeys. Continue?")) {
      localStorage.clear();
      window.location.reload();
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

  const handleConnectPasskey = async (passkey: PasskeyArgType) => {
    setLoading(true);
    try {
      const info = await getSafeInfo(passkey);
      setActivePasskey(passkey);
      setEoaAddress(info.address);
      setLoginMethod('passkey');

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
    const currentParent = mySafes.find(s => s.address === selectedSafeAddr);
    if (!selectedSafeAddr || !currentParent) return;
    if (!window.confirm(`Deploy a new Nested Safe owned by "${currentParent.name}"?`)) return;

    try {
      setLoading(true);
      const nestedSalt = Date.now().toString();
      const safeIndex = myNestedSafes.length + 1;
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

      if (loginMethod === 'thirdweb' && walletClient) {
        const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });

        const safeAccount = await toSafeSmartAccount({
          client: publicClient,
          owners: [walletClient],
          entryPoint: { address: entryPoint07Address, version: "0.7" },
          version: "1.4.1",
          address: currentParent.address as Hex,
          saltNonce: BigInt(currentParent.salt)
        });

        const smartAccountClient = createSmartAccountClient({
          account: safeAccount, chain: ACTIVE_CHAIN, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
          userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
        });

        const deploymentTx = await protocolKit.createSafeDeploymentTransaction();
        await smartAccountClient.sendTransaction({
          to: deploymentTx.to as Hex,
          value: BigInt(deploymentTx.value),
          data: deploymentTx.data as Hex
        });
        addLog(`Nested Safe Deployed: ${predictedAddr}`, 'success');
      } else {
        addLog("Note: Nested Safe is Counterfactual (will deploy on first usage)", 'info');
      }

      const newNested: StoredSafe = { address: predictedAddr, salt: nestedSalt, name: `Nested Safe ${safeIndex}` };
      const updatedList = [...myNestedSafes, newNested];
      setMyNestedSafes(updatedList);
      setSelectedNestedSafeAddr(predictedAddr);
      localStorage.setItem("myNestedSafes", JSON.stringify(updatedList));

      // Trigger data refresh
      nestedSafeData.fetchData();

    } catch (e: any) {
      addLog(e.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  // --- HANDLERS: PARENT SAFE SETTINGS ---

  const handleOpenParentSettings = async () => {
    if (selectedSafeAddr) {
      try {
        const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
        const owners = await publicClient.readContract({
          address: selectedSafeAddr as Hex, abi: SAFE_ABI, functionName: "getOwners"
        });
        setParentOwners(Array.from(owners));
        setIsParentSettingsOpen(true);
      } catch (e) {
        console.error("Failed to fetch parent owners", e);
      }
    }
  };

  const handleAddSignerToParent = async () => {
    if (!newParentOwnerInput || !selectedSafeAddr) return;
    try {
      setLoading(true);
      const data = encodeFunctionData({
        abi: SAFE_ABI,
        functionName: "addOwnerWithThreshold",
        args: [newParentOwnerInput as Hex, 1n]
      });

      let txHash;
      if (loginMethod === 'thirdweb' && walletClient) {
        const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });
        const parentInfo = mySafes.find(s => s.address === selectedSafeAddr);

        const safeAccount = await toSafeSmartAccount({
          client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
          address: selectedSafeAddr as Hex, saltNonce: parentInfo ? BigInt(parentInfo.salt) : 0n
        });

        const smartClient = createSmartAccountClient({
          account: safeAccount, chain: ACTIVE_CHAIN, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
          userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
        });

        txHash = await smartClient.sendTransaction({ to: selectedSafeAddr as Hex, value: 0n, data: data });

      } else if (loginMethod === 'passkey' && activePasskey) {
        const tx = { to: selectedSafeAddr, value: '0', data: data };
        txHash = await executePasskeyTransaction(activePasskey, [tx]);
      }

      addLog(`Signer Added! TX: ${txHash}`, "success");
      setNewParentOwnerInput("");
      setTimeout(() => handleOpenParentSettings(), 4000);

    } catch (e: any) {
      addLog(`Failed to add signer: ${formatError(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };


  // --- HANDLERS: TRANSACTION PROPOSAL & QUEUE ---

  const getSafeTxHash = async (to: string, val: bigint, data: Hex, operation: 0 | 1, nonceOffset = 0) => {
    const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
    let currentNonce = 0n;
    try {
      currentNonce = await publicClient.readContract({ address: selectedNestedSafeAddr as Hex, abi: SAFE_ABI, functionName: "nonce" });
    } catch { currentNonce = 0n; }

    const targetNonce = Number(currentNonce) + nonceOffset;

    try {
      const hash = await publicClient.readContract({
        address: selectedNestedSafeAddr as Hex, abi: SAFE_ABI, functionName: "getTransactionHash",
        args: [to as Hex, val, data, operation, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", BigInt(targetNonce)]
      });
      return { hash, nonce: targetNonce };
    } catch {
      // Counterfactual Fallback
      const domain = { chainId: ACTIVE_CHAIN.id, verifyingContract: selectedNestedSafeAddr as Hex };
      const types = {
        SafeTx: [
          { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' },
          { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
          { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' },
          { name: 'nonce', type: 'uint256' },
        ],
      };
      const message = {
        to: to as Hex, value: val, data: data, operation, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n,
        gasToken: "0x0000000000000000000000000000000000000000" as Hex, refundReceiver: "0x0000000000000000000000000000000000000000" as Hex,
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
        safeAddress: selectedNestedSafeAddr, hash, to, value: val.toString(), data, operation, nonce, description
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
      const approveData = encodeFunctionData({ abi: SAFE_ABI, functionName: "approveHash", args: [hash as Hex] });
      let txHash;

      if (loginMethod === 'thirdweb' && walletClient) {
        const parent = mySafes.find(s => s.address === selectedSafeAddr);
        if (!parent) throw new Error("Parent Safe info not found");
        const publicClient = createPublicClient({ chain: ACTIVE_CHAIN, transport: http(PUBLIC_RPC) });
        const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });
        const safeAccount = await toSafeSmartAccount({
          client: publicClient, owners: [walletClient], entryPoint: { address: entryPoint07Address, version: "0.7" }, version: "1.4.1",
          address: parent.address as Hex, saltNonce: BigInt(parent.salt)
        });
        const smartClient = createSmartAccountClient({
          account: safeAccount, chain: ACTIVE_CHAIN, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
          userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
        });
        txHash = await smartClient.sendTransaction({ to: selectedNestedSafeAddr as Hex, value: 0n, data: approveData });
      } else if (loginMethod === 'passkey' && activePasskey) {
        const txData = { to: selectedNestedSafeAddr, value: '0', data: approveData };
        txHash = await executePasskeyTransaction(activePasskey, [txData]);
      } else {
        throw new Error("No active wallet found.");
      }
      addLog(`Approved Hash! TX: ${txHash}`, "success");
      setTimeout(() => checkQueueApprovals(), 4000);
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
    const relevantTxs = queuedTxs.filter(t => !t.safeAddress || t.safeAddress.toLowerCase() === selectedNestedSafeAddr.toLowerCase());

    for (const tx of relevantTxs) {
      if (tx.nonce < nestedSafeData.nonce) continue;
      const approvedBy: string[] = [];
      for (const owner of nestedSafeData.owners) {
        try {
          const isApproved = await publicClient.readContract({
            address: selectedNestedSafeAddr as Hex, abi: SAFE_ABI, functionName: "approvedHashes", args: [owner as Hex, tx.hash as Hex]
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
      const sortedOwners = [...nestedSafeData.owners].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
      let signatures = "0x";

      for (const owner of sortedOwners) {
        let isApproved = 0n;
        if (isDeployed) {
          try {
            isApproved = await publicClient.readContract({
              address: selectedNestedSafeAddr as Hex, abi: SAFE_ABI, functionName: "approvedHashes", args: [owner as Hex, tx.hash as Hex]
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
        abi: SAFE_ABI, functionName: "execTransaction",
        args: [tx.to as Hex, BigInt(tx.value), tx.data as Hex, tx.operation, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", signatures as Hex]
      });

      const txsToExecute = [];
      if (!isDeployed) {
        const nestedSafeInfo = myNestedSafes.find(s => s.address === selectedNestedSafeAddr);
        if (nestedSafeInfo) {
          addLog("Nested Safe is undeployed. Adding deployment to batch...", "info");
          const protocolKit = await Safe.init({
            provider: RPC_URL, signer: selectedSafeAddr,
            predictedSafe: { safeAccountConfig: { owners: [selectedSafeAddr], threshold: 1 }, safeDeploymentConfig: { saltNonce: nestedSafeInfo.salt } }
          });
          const deployTx = await protocolKit.createSafeDeploymentTransaction();
          txsToExecute.push({ to: deployTx.to, value: deployTx.value, data: deployTx.data });
        }
      }
      txsToExecute.push({ to: selectedNestedSafeAddr, value: '0', data: execData });

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
          calls: txsToExecute.map(t => ({ to: t.to as Hex, value: BigInt(t.value), data: t.data as Hex }))
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
        nestedSafeData.fetchData();
        setActiveTab('history');
      }, 5000);

    } catch (e: any) {
      addLog(`Execution Failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  // --- HANDLERS: SCHEDULED & SESSIONS ---

  const handleCreateSchedule = async () => {
    if (!scheduleRecipient || !scheduleAmount || !selectedNestedSafeAddr || !timePreviews) {
      addLog("Missing fields or invalid date", "error");
      return;
    }
    setLoading(true);
    try {
      addLog(`Preparing schedule proposal...`, "info");
      const { batch, log, storageData } = await prepareScheduleProposal(
        selectedNestedSafeAddr, scheduleRecipient, scheduleAmount, selectedToken, timePreviews.unix
      );
      log.forEach(l => addLog(l, "info"));
      const description = `Setup 7579 + Enable ${selectedToken} Session`;
      if (batch.length > 1) await proposeTransaction(MULTI_SEND_ADDRESS, 0n, encodeMultiSend(batch), description, 0, 1);
      else await proposeTransaction(batch[0].to, 0n, batch[0].data, description, 0, 0);

      localStorage.setItem("scheduled_session", JSON.stringify(storageData));
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
      const data = JSON.parse(stored);
      addLog(`Executing ${data.token} via Smart Session...`, "info");
      const hash = await executeAutomatedSchedule(selectedNestedSafeAddr, data);
      addLog(`Schedule Executed! TX: ${hash}`, "success");
      handleClearSchedule();
    } catch (e: any) {
      addLog(formatError(e), "error");
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
    try {
      setLoading(true);
      const data = encodeFunctionData({ abi: ENABLE_SESSIONS_ABI, functionName: "removeSession", args: [permissionId as Hex] });
      await proposeTransaction(SMART_SESSIONS_VALIDATOR_ADDRESS, 0n, data, `Revoke Smart Session: ${permissionId.slice(0, 10)}...`);
      addLog("Revocation proposal created.", "success");
      setActiveTab('queue');
    } catch (e: any) {
      addLog(`Revocation failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  // --- HANDLERS: ALLOWANCES ---

  const handleCreateAllowance = async () => {
    if (!allowanceAmount || !allowanceStart || !selectedNestedSafeAddr || !allowanceHolder) {
      addLog("Please fill in amount, start date, and select a holder.", "error");
      return;
    }
    setLoading(true);
    try {
      const { batch, log, localData } = await prepareAllowanceProposal(
        selectedNestedSafeAddr, allowanceHolder, allowanceAmount, selectedToken, allowanceName, allowanceStart, allowanceInterval, allowanceUnit
      );
      log.forEach(l => addLog(l, "info"));
      const description = `Setup 7579 + Enable Budget: ${allowanceName}`;
      if (batch.length > 1) await proposeTransaction(MULTI_SEND_ADDRESS, 0n, encodeMultiSend(batch), description, 0, 1);
      else await proposeTransaction(batch[0].to, 0n, batch[0].data, description, 0, 0);

      const updated = [...myAllowances, localData];
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
      const ephemeralKey = generatePrivateKey();
      const ephemeralAccount = privateKeyToAccount(ephemeralKey);
      const salt = pad(toHex(Date.now()), { size: 32 }) as Hex;
      const startUnix = Math.floor(Date.now() / 1000);
      const session = createAllowanceSessionStruct(
        ephemeralAccount.address, USDC_ADDRESS as Address, parseUnits("10", 6), startUnix, salt, 3600, "Scheduled Payment", parentAllowance.holder, parentAllowance.configId
      );
      const enableData = encodeFunctionData({ abi: ENABLE_SESSIONS_ABI, functionName: "enableSessions", args: [[session]] });
      await proposeTransaction(SMART_SESSIONS_VALIDATOR_ADDRESS, 0n, enableData, `Schedule 10 USDC (Linked to ${parentAllowance.name})`);

      const scheduleData = { privateKey: ephemeralKey, session, token: 'USDC', permissionId: getPermissionId(session), amount: "10" };
      setSignerMode('session');
      setActiveSession(scheduleData);
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
      const recalculatedConfigId = calculateConfigId(selectedNestedSafeAddr as Address, allowance.permissionId, USDC_ADDRESS as Address);

      const data = await publicClient.readContract({
        address: PERIODIC_ERC20_POLICY as Address, abi: PERIODIC_POLICY_ABI, functionName: "getAllowance", args: [selectedNestedSafeAddr as Address, recalculatedConfigId, USDC_ADDRESS as Address]
      });

      if (data.limit === 0n && !data.isDeleted) {
        addLog("❌ Policy returned Empty Data (Limit 0). The Config ID might be wrong.", "error");
      } else {
        const holderText = data.holder === "0x0000000000000000000000000000000000000000" ? "None" : `${data.holder.slice(0, 6)}...`;
        addLog(`✅ Data Found! Limit: ${formatUnits(data.limit, 6)} | Spent: ${formatUnits(data.amountSpent, 6)} | Holder: ${holderText}`, "success");
      }
    } catch (e: any) {
      addLog(`Fetch failed: ${e.message}`, "error");
    }
  };

  const handleScanAllowances = async () => {
    if (!selectedNestedSafeAddr) return;
    setIsScanning(true);
    setZombieAllowances([]);
    try {
      addLog("Scanning blockchain for active allowances...", "info");
      const zombies = await scanOnChainAllowances(selectedNestedSafeAddr, myAllowances);
      setZombieAllowances(zombies);
      addLog(`Scan complete. Found ${zombies.length} allowances.`, "success");
    } catch (e: any) {
      addLog(`Scan failed: ${e.message}`, "error");
    } finally {
      setIsScanning(false);
    }
  };

  const handleCleanUpAllowance = async (configId: string, tokenAddress: string) => {
    if (!window.confirm("Disable on-chain?")) return;
    setLoading(true);
    try {
      const tx = prepareCleanupAllowance(configId, tokenAddress);
      await proposeTransaction(tx.to, tx.value, tx.data, `Clean up Record ${configId.slice(0, 6)}...`);
      addLog("Cleanup proposal created!", "success");
      setActiveTab('queue');
    } catch (e: any) {
      addLog(`Cleanup failed: ${e.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeAllowance = async (allowance: any) => {
    if (!window.confirm("Revoke this key on-chain?")) return;
    setLoading(true);
    try {
      const tx = prepareRevokeAllowance(allowance.permissionId);
      await proposeTransaction(tx.to, tx.value, tx.data, `Revoke Key: ${allowance.permissionId.slice(0, 6)}...`);
      const updated = myAllowances.filter(a => a.permissionId !== allowance.permissionId);
      setMyAllowances(updated);
      localStorage.setItem("my_allowances", JSON.stringify(updated));
      if (activeSession?.permissionId === allowance.permissionId) {
        setSignerMode('main');
        setActiveSession(null);
      }
      addLog("Revocation proposed.", "success");
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
        const localAccount = privateKeyToAccount(privateKey);
        signerCallback = async (hash: Hex) => localAccount.sign({ hash });
      } else {
        const currentAddr = loginMethod === 'thirdweb' ? walletClient?.account?.address : eoaAddress;
        if (!currentAddr) throw new Error("No wallet connected");

        if (currentAddr.toLowerCase() === requiredSigner.toLowerCase()) {
          if (loginMethod === 'thirdweb' && walletClient) {
            signerCallback = async (hash: Hex) => {
              addLog("Requesting signature from wallet...", "info");
              return await walletClient.signMessage({ account: currentAddr as Address, message: { raw: hash } });
            };
          } else if (loginMethod === 'passkey' && activePasskey) {
            signerCallback = async (hash: Hex) => {
              addLog("Requesting Direct Passkey signature...", "info");
              const safe4337Pack = await getSafe4337Pack(activePasskey);
              const owners = await safe4337Pack.protocolKit.getOwners();
              const webAuthnSignerAddress = owners[0] as Address;

              const safeMessageHash = hashTypedData({
                domain: { chainId: ACTIVE_CHAIN.id, verifyingContract: currentAddr as Address },
                types: { SafeMessage: [{ name: 'message', type: 'bytes' }] },
                primaryType: 'SafeMessage',
                message: { message: hash }
              });

              const sigResult = await safe4337Pack.protocolKit.signHash(safeMessageHash);
              const rawWebAuthnSig = sigResult.data as Hex;

              const r_auth = pad(webAuthnSignerAddress, { size: 32 });
              const s_auth = pad(toHex(65), { size: 32 });
              const v_auth = "0x00";
              const len_auth = pad(toHex(size(rawWebAuthnSig)), { size: 32 });
              const innerSigData = encodePacked(['bytes32', 'bytes32', 'bytes1', 'bytes32', 'bytes'], [r_auth, s_auth, v_auth, len_auth, rawWebAuthnSig]);

              const r = pad(currentAddr as Hex, { size: 32 });
              const s = pad(toHex(65), { size: 32 });
              const v = "0x00";
              const len = pad(toHex(size(innerSigData)), { size: 32 });

              return encodePacked(['bytes32', 'bytes32', 'bytes1', 'bytes32', 'bytes'], [r, s, v, len, innerSigData]);
            };
          }
        } else {
          const parentSafe = mySafes.find(s => s.address.toLowerCase() === requiredSigner.toLowerCase());
          if (parentSafe) {
            if (loginMethod === 'thirdweb' && walletClient) {
              signerCallback = async (hash: Hex) => {
                addLog(`Requesting signature on behalf of Safe ${parentSafe.name}...`, "info");
                return await walletClient.signTypedData({
                  account: currentAddr as Address,
                  domain: { chainId: ACTIVE_CHAIN.id, verifyingContract: requiredSigner as Address },
                  types: { SafeMessage: [{ name: 'message', type: 'bytes' }] },
                  primaryType: 'SafeMessage',
                  message: { message: hash }
                });
              };
            }
          }
        }
      }

      if (!signerCallback) throw new Error("Could not determine a valid signer method for this session.");

      const pimlicoClient = createPimlicoClient({ transport: http(PIMLICO_URL), entryPoint: { address: entryPoint07Address, version: "0.7" } });
      const safeAccount = await getSafe7579SessionAccount(publicClient, selectedNestedSafeAddr as Hex, session, signerCallback);
      const smartClient = createSmartAccountClient({
        account: safeAccount, chain: ACTIVE_CHAIN, bundlerTransport: http(PIMLICO_URL), paymaster: pimlicoClient,
        userOperation: { estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast },
      });

      let tx;
      if (token === 'USDC') {
        tx = { to: USDC_ADDRESS as Address, value: 0n, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [recipient as Address, parseUnits(sendAmount, 6)] }) };
      } else {
        tx = { to: recipient as Address, value: parseEther(sendAmount), data: "0x" as Hex };
      }

      addLog(`Spending ${sendAmount} ${token} via Session Key...`, "info");
      const userOpHash = await smartClient.sendTransaction(tx);
      addLog(`Success! UserOp Hash: ${userOpHash}`, "success");
      setSignerMode('main');
      setActiveSession(null);
      setTimeout(() => nestedSafeData.fetchData(), 4000);

    } catch (e: any) {
      // --- DEBUGGING ---
      console.error("SESSION SPEND ERROR:", e); // <--- THIS WILL SHOW THE ERROR IN CONSOLE

      // Check for specific Viem/Pimlico error details
      if (e.cause) console.error("Error Cause:", e.cause);
      if (e.details) console.error("Error Details:", e.details);

      addLog(formatError(e), "error");
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

  return (
    <div className="app-container">
      <header className="header">
        <span className="header-badge">
          {NETWORK === 'mainnet' ? 'Base Mainnet' : 'Base Sepolia'}
        </span>
        <h1>Nested Safe Engine</h1>
      </header>

      {!isDashboard ? (
        <Onboarding
          loginMethod={loginMethod}
          eoaAddress={eoaAddress}
          storedPasskeys={storedPasskeys}
          mySafes={mySafes}
          loading={loading}
          activeChain={activeChain}
          handleCreateNewPasskey={handleCreateNewPasskey}
          handleConnectPasskey={handleConnectPasskey}
          createParentSafe={createParentSafe}
          createNestedSafe={createNestedSafe}
        />
      ) : (
        <div className="dashboard-container">
          {/* Extracted Sidebar */}
          <Sidebar
            mySafes={mySafes}
            myNestedSafes={myNestedSafes}
            selectedSafeAddr={selectedSafeAddr}
            setSelectedSafeAddr={setSelectedSafeAddr}
            selectedNestedSafeAddr={selectedNestedSafeAddr}
            setSelectedNestedSafeAddr={(addr) => {
              setSelectedNestedSafeAddr(addr);
              setActiveTab('transfer');
            }}
            createParentSafe={createParentSafe}
            createNestedSafe={createNestedSafe}
            handleLogout={handleLogout}
            handleReset={handleReset}
            handleOpenParentSettings={handleOpenParentSettings}
            ethBalance={nestedSafeData.ethBalance}
            usdcBalance={nestedSafeData.usdcBalance}
            signerMode={signerMode}
            setSignerMode={setSignerMode}
            activeSession={activeSession}
            setActiveSession={setActiveSession}
            myAllowances={myAllowances}
            refreshNestedSafe={nestedSafeData.fetchData}
          />

          <div className="main-panel">
            <div className="panel-header">
              <button className={`tab-btn ${activeTab === 'transfer' ? 'active' : ''}`} onClick={() => setActiveTab('transfer')}>Transfer</button>
              <button className={`tab-btn ${activeTab === 'scheduled' ? 'active' : ''}`} onClick={() => setActiveTab('scheduled')}>Scheduled</button>
              <button className={`tab-btn ${activeTab === 'allowances' ? 'active' : ''}`} onClick={() => setActiveTab('allowances')}>Allowances</button>
              <button className={`tab-btn ${activeTab === 'owners' ? 'active' : ''}`} onClick={() => setActiveTab('owners')}>Owners</button>
              <button className={`tab-btn ${activeTab === 'queue' ? 'active' : ''}`} onClick={() => setActiveTab('queue')}>
                Queue {queuedTxs.filter(t => t.safeAddress && t.safeAddress.toLowerCase() === selectedNestedSafeAddr.toLowerCase() && t.nonce >= nestedSafeData.nonce).length > 0 && <span className="header-badge" style={{ background: 'var(--primary)', border: 'none', marginLeft: '6px' }}>{queuedTxs.filter(t => t.safeAddress && t.safeAddress.toLowerCase() === selectedNestedSafeAddr.toLowerCase() && t.nonce >= nestedSafeData.nonce).length}</span>}
              </button>
              <button className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`} onClick={() => setActiveTab('history')}>History</button>
            </div>

            <div className="panel-content">
              {!isCurrentSafeOwner && (
                <div style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24', padding: '10px', borderRadius: '8px', marginBottom: '20px', fontSize: '0.9rem', display: 'flex', gap: '10px' }}>
                  <span>⚠️ The selected Parent Safe is NOT an owner. Transactions cannot be initiated.</span>
                </div>
              )}

              {activeTab === 'transfer' && (
                <TransferTab
                  signerMode={signerMode}
                  activeSession={activeSession}
                  selectedToken={selectedToken}
                  setSelectedToken={setSelectedToken}
                  recipient={recipient}
                  setRecipient={setRecipient}
                  sendAmount={sendAmount}
                  setSendAmount={setSendAmount}
                  setScheduleAmount={setScheduleAmount}
                  loading={loading}
                  isCurrentSafeOwner={isCurrentSafeOwner}
                  nestedThreshold={nestedSafeData.threshold}
                  handleSessionSpend={handleSessionSpend}
                  proposeTransaction={proposeTransaction}
                  addLog={addLog}
                />
              )}

              {activeTab === 'scheduled' && (
                <ScheduledTab
                  hasStoredSchedule={hasStoredSchedule}
                  scheduledInfo={scheduledInfo}
                  isSessionEnabledOnChain={isSessionEnabledOnChain}
                  selectedToken={selectedToken}
                  setSelectedToken={setSelectedToken}
                  scheduleRecipient={scheduleRecipient}
                  setScheduleRecipient={setScheduleRecipient}
                  scheduleAmount={scheduleAmount}
                  setScheduleAmount={setScheduleAmount}
                  scheduleDate={scheduleDate}
                  setScheduleDate={setScheduleDate}
                  setSendAmount={setSendAmount}
                  loading={loading}
                  isCurrentSafeOwner={isCurrentSafeOwner}
                  selectedNestedSafeAddr={selectedNestedSafeAddr}
                  handleCreateSchedule={handleCreateSchedule}
                  handleExecuteSchedule={handleExecuteSchedule}
                  handleRevokeSessionOnChain={handleRevokeSessionOnChain}
                  fetchData={nestedSafeData.fetchData}
                  handleClearSchedule={handleClearSchedule}
                />
              )}

              {activeTab === 'allowances' && (
                <AllowancesTab
                  selectedToken={selectedToken}
                  setSelectedToken={setSelectedToken}
                  allowanceName={allowanceName}
                  setAllowanceName={setAllowanceName}
                  allowanceAmount={allowanceAmount}
                  setAllowanceAmount={setAllowanceAmount}
                  allowanceInterval={allowanceInterval}
                  setAllowanceInterval={setAllowanceInterval}
                  allowanceUnit={allowanceUnit}
                  setAllowanceUnit={setAllowanceUnit}
                  allowanceStart={allowanceStart}
                  setAllowanceStart={setAllowanceStart}
                  allowanceHolder={allowanceHolder}
                  setAllowanceHolder={setAllowanceHolder}
                  nestedOwners={nestedSafeData.owners}
                  mySafes={mySafes}
                  myAllowances={myAllowances}
                  zombieAllowances={zombieAllowances}
                  loading={loading}
                  isScanning={isScanning}
                  isCurrentSafeOwner={isCurrentSafeOwner}
                  selectedNestedSafeAddr={selectedNestedSafeAddr}
                  setSendAmount={setSendAmount}
                  setScheduleAmount={setScheduleAmount}
                  setSignerMode={setSignerMode}
                  setActiveSession={setActiveSession}
                  setActiveTab={setActiveTab}
                  addLog={addLog}
                  handleCreateAllowance={handleCreateAllowance}
                  handleCreateLinkedSchedule={handleCreateLinkedSchedule}
                  handleCheckSpecific={handleCheckSpecific}
                  handleRevokeAllowance={handleRevokeAllowance}
                  handleScanAllowances={handleScanAllowances}
                  handleCleanUpAllowance={handleCleanUpAllowance}
                />
              )}

              {activeTab === 'queue' && (
                <QueueTab
                  queuedTxs={queuedTxs}
                  nestedNonce={nestedSafeData.nonce}
                  nestedThreshold={nestedSafeData.threshold}
                  approvalsMap={approvalsMap}
                  selectedSafeAddr={selectedSafeAddr}
                  selectedNestedSafeAddr={selectedNestedSafeAddr}
                  isCurrentSafeOwner={isCurrentSafeOwner}
                  loading={loading}
                  handleRefreshQueue={async () => {
                    await nestedSafeData.fetchData();
                    checkQueueApprovals();
                  }}
                  approveTxHash={approveTxHash}
                  executeQueuedTx={executeQueuedTx}
                />
              )}

              {activeTab === 'owners' && (
                <OwnersTab
                  nestedOwners={nestedSafeData.owners}
                  mySafes={mySafes}
                  nestedThreshold={nestedSafeData.threshold}
                  loading={loading}
                  isCurrentSafeOwner={isCurrentSafeOwner}
                  handleAddOwner={handleAddOwner}
                  handleUpdateThreshold={handleUpdateThreshold}
                  newThresholdInput={newThresholdInput}
                  setNewThresholdInput={setNewThresholdInput}
                  newOwnerInput={newOwnerInput}
                  setNewOwnerInput={setNewOwnerInput}
                />
              )}

              {activeTab === 'history' && (
                <HistoryTab
                  txHistory={nestedSafeData.history}
                  loadingHistory={nestedSafeData.loadingHistory}
                  fetchHistory={nestedSafeData.fetchHistory}
                  selectedNestedSafeAddr={selectedNestedSafeAddr}
                />
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

      {/* Extracted Modal */}
      <ParentSettingsModal
        isOpen={isParentSettingsOpen}
        onClose={() => setIsParentSettingsOpen(false)}
        parentOwners={parentOwners}
        currentEoa={loginMethod === 'thirdweb' ? walletClient?.account?.address || "" : eoaAddress}
        newOwnerInput={newParentOwnerInput}
        setNewOwnerInput={setNewParentOwnerInput}
        onAddSigner={handleAddSignerToParent}
        loading={loading}
      />
    </div>
  );
};

export default App;