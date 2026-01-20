import { parseAbi } from "viem";

export const SAFE_ABI = parseAbi([
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

export const ADAPTER_7579_ABI = parseAbi([
    "struct ModuleInit { address module; bytes initData; uint256 moduleType; }",
    "struct RegistryInit { address registry; address[] attesters; uint8 threshold; }",
    "function initializeAccount(ModuleInit[] calldata modules, RegistryInit calldata registryInit) external",
    "function isModuleInstalled(uint256 moduleType, address module, bytes additionalContext) external view returns (bool)"
]);

// Updated ERC20 ABI with 'as const'
export const ERC20_ABI = parseAbi([
    "function balanceOf(address owner) view returns (uint256)",
    "function transfer(address to, uint256 amount) returns (bool)"
] as const);

// --- SMART SESSION CONFIG ---
export const ENABLE_SESSIONS_ABI = parseAbi([
    "struct PolicyData { address policy; bytes initData; }",
    "struct ERC7739Context { bytes32 appDomainSeparator; string[] contentName; }",
    "struct ERC7739Data { ERC7739Context[] allowedERC7739Content; PolicyData[] erc1271Policies; }",
    "struct ActionData { bytes4 actionTargetSelector; address actionTarget; PolicyData[] actionPolicies; }",
    "struct Session { address sessionValidator; bytes sessionValidatorInitData; bytes32 salt; PolicyData[] userOpPolicies; ERC7739Data erc7739Policies; ActionData[] actions; bool permitERC4337Paymaster; }",
    "function enableSessions(Session[] calldata sessions) external returns (bytes32[])",
    "function isPermissionEnabled(bytes32 permissionId, address account) external view returns (bool)",
    "function removeSession(bytes32 permissionId) external"
]);

// --- PERIODIC POLICY V3 ABI ---
export const PERIODIC_POLICY_ABI = parseAbi([
    "struct TokenPolicyData { address holder; uint256 limit; uint256 refillInterval; uint256 amountSpent; uint48 lastRefill; string name; bool isDeleted; }",
    "struct AllowanceInfo { bytes32 configId; address token; address holder; uint256 limit; uint256 refillInterval; uint256 amountSpent; uint48 lastRefill; string name; bool isActive; bytes32 linkedParent; }",
    "function getAllowances(address account) external view returns (AllowanceInfo[] memory)",
    "function revokeAllowance(bytes32 configId, address token) external",
    "function getAllowance(address account, bytes32 configId, address token) external view returns (TokenPolicyData memory)"
]);

export const MULTI_SEND_ABI = parseAbi([
    "function multiSend(bytes transactions) external"
]);