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

export const createSessionStruct = (sessionOwner: Address, targetAddress: Address, amountWei: bigint, salt: Hex) => {
    // FIX: Policies MUST be sorted by address for the Validator to store/retrieve them correctly.
    const policies = [
        encodePolicy('value', amountWei),
        encodePolicy('usage', 1n)
    ].sort((a, b) => a.policy.toLowerCase().localeCompare(b.policy.toLowerCase()));

    // FIX: Add a Sudo policy to userOpPolicies to allow Paymasters (minPolicies=1 requirement)
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
            actionTarget: targetAddress,
            // FIX: Use 0xFFFFFFFF for native ETH transfers (matches IdLib.VALUE_SELECTOR)
            actionTargetSelector: "0xFFFFFFFF" as Hex,
            actionPolicies: policies 
        }],
        permitERC4337Paymaster: true
    };
};