//--- File: src/utils/smartSessions.ts ---

import {
    encodeAbiParameters,
    keccak256,
    encodePacked,
    type Hex,
    type Address,
    parseAbi,
    toHex,
    encodeFunctionData,
    pad,
    hexToBytes
} from "viem";

// --- Constants ---
export const OWNABLE_VALIDATOR_ADDRESS = "0x000000000013fdb5234e4e3162a810f54d9f7e98";
export const SMART_SESSIONS_VALIDATOR_ADDRESS = "0x00000000008bdaba73cd9815d79069c247eb4bda";
export const SAFE_7579_ADAPTER_ADDRESS = "0x7579f2AD53b01c3D8779Fe17928e0D48885B0003";

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

export const encodeSmartSessionSignature = (permissionId: Hex, signature: Hex): Hex => {
    // Mode 0x00 = USE session
    return encodePacked(['bytes1', 'bytes32', 'bytes'], ['0x00', permissionId, signature]);
};

/**
 * Packs a signature for the Safe 7579 Adapter.
 * Format: [ValidatorAddr (32)][Offset (32)][v=0 (1)][Length (32)][Data...]
 */
export const packSafe7579Signature = (validator: Address, signature: Hex): Hex => {
    const validatorPadded = pad(validator, { size: 32 });

    // Safe expects 's' to be the offset to the dynamic bytes relative to the start of the signatures.
    // r(32) + s(32) + v(1) = 65 bytes. So offset is 65 (0x41).
    const sValue = pad(toHex(65), { size: 32 });
    const vValue = "0x00";

    // Manual encoding of dynamic bytes: [Length (32 bytes)] + [Data (raw bytes)]
    // We use hexToBytes to get accurate byte length of the signature string
    const sigBytes = hexToBytes(signature);
    const length = pad(toHex(sigBytes.length), { size: 32 });
    const dynamicPart = encodePacked(['bytes32', 'bytes'], [length as Hex, signature]);

    return encodePacked(
        ['bytes32', 'bytes32', 'bytes1', 'bytes'],
        [validatorPadded, sValue as Hex, vValue, dynamicPart]
    );
};

export const encode7579Call = (to: Address, value: bigint, data: Hex): Hex => {
    // Single Call Mode (0x00...)
    const mode = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const calldataInner = encodePacked(['address', 'uint256', 'bytes'], [to, value, data]);

    return encodeFunctionData({
        abi: ERC7579_EXECUTE_ABI,
        functionName: "execute",
        args: [mode, calldataInner]
    });
};

export const createSessionStruct = (sessionOwner: Address, targetAddress: Address, amountWei: bigint, salt: Hex) => {
    return {
        sessionValidator: OWNABLE_VALIDATOR_ADDRESS as Address,
        sessionValidatorInitData: encodeAbiParameters(
            [{ name: 'threshold', type: 'uint256' }, { name: 'owners', type: 'address[]' }],
            [1n, [sessionOwner]]
        ),
        salt: salt,
        userOpPolicies: [],
        erc7739Policies: { allowedERC7739Content: [], erc1271Policies: [] },
        actions: [{
            actionTarget: targetAddress,
            actionTargetSelector: "0x00000000" as Hex,
            actionPolicies: [encodePolicy('value', amountWei), encodePolicy('usage', 1n)]
        }],
        permitERC4337Paymaster: true
    };
};