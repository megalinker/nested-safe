import {
    encodeAbiParameters,
    keccak256,
    encodePacked,
    type Hex,
    type Address,
    parseAbi
} from "viem";

// --- Constants ---
export const OWNABLE_VALIDATOR_ADDRESS = "0x000000000013fdb5234e4e3162a810f54d9f7e98";

export const VALUE_LIMIT_POLICY = "0x730DA93267E7E513e932301B47F2ac7D062abC83";
export const USAGE_LIMIT_POLICY = "0x1F34eF8311345A3A4a4566aF321b313052F51493";
export const SUDO_POLICY = "0x0000003111cD8e92337C100F22B7A9dbf8DEE301";

// --- ABI ---
export const ERC7579_EXECUTE_ABI = parseAbi([
    "function execute(bytes32 mode, bytes calldata executionCalldata) external payable"
]);

// --- Helpers ---

export const encodePolicy = (type: 'value' | 'usage' | 'sudo', limit?: bigint): { policy: Address; initData: Hex } => {
    if (type === 'sudo') return { policy: SUDO_POLICY as Address, initData: "0x" };
    if (type === 'value') return { policy: VALUE_LIMIT_POLICY as Address, initData: encodeAbiParameters([{ type: 'uint256' }], [limit!]) };
    if (type === 'usage') return { policy: USAGE_LIMIT_POLICY as Address, initData: encodePacked(['uint128'], [limit!]) };
    return { policy: "0x0000000000000000000000000000000000000000", initData: "0x" };
};

export const getPermissionId = (session: any): Hex => {
    return keccak256(encodeAbiParameters(
        [{ type: 'address' }, { type: 'bytes' }, { type: 'bytes32' }],
        [session.sessionValidator, session.sessionValidatorInitData, session.salt]
    ));
};

export const createSessionStruct = (
    sessionOwner: Address,
    targetContract: Address, // For ETH: Recipient. For USDC: USDC_ADDR
    selector: Hex,           // For ETH: 0xFFFFFFFF. For USDC: 0xa9059cbb
    nativeValueLimit: bigint,// Only applies to ETH value
    salt: Hex
) => {

    // 1. Build Policies
    const policiesList = [];

    // Always limit usage to 1 time for this demo
    policiesList.push(encodePolicy('usage', 1n));

    // If sending ETH (native), add value limit. 
    // If sending USDC, native value is 0, so we can skip or set to 0.
    if (nativeValueLimit > 0n) {
        policiesList.push(encodePolicy('value', nativeValueLimit));
    }

    // Sort policies by address (required by 7579)
    const policies = policiesList.sort((a, b) => a.policy.toLowerCase().localeCompare(b.policy.toLowerCase()));

    // Sudo policy for Paymaster compatibility
    const userOpPolicies = [
        encodePolicy('sudo')
    ];

    return {
        sessionValidator: OWNABLE_VALIDATOR_ADDRESS as Address,
        sessionValidatorInitData: encodeAbiParameters(
            [{ name: 'threshold', type: 'uint256' }, { name: 'owners', type: 'address[]' }],
            [1n, [sessionOwner]]
        ),
        salt: salt,
        userOpPolicies: userOpPolicies,
        erc7739Policies: { allowedERC7739Content: [], erc1271Policies: [] },
        actions: [{
            actionTarget: targetContract,
            actionTargetSelector: selector,
            actionPolicies: policies
        }],
        permitERC4337Paymaster: true
    };
};