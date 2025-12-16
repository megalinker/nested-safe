//--- File: src/utils/safe7579.ts ---

import {
    type Address,
    type Hex,
    type PublicClient,
    encodeFunctionData,
    encodePacked,
    concat,
    parseAbi,
    keccak256,
    encodeAbiParameters,
    pad,
} from "viem";
import {
    toSmartAccount,
    type SmartAccount,
    entryPoint07Address,
    entryPoint07Abi,
    getUserOperationHash
} from "viem/account-abstraction";

// --- Constants ---
export const OWNABLE_VALIDATOR_ADDRESS = "0x000000000013fdb5234e4e3162a810f54d9f7e98";
export const SMART_SESSIONS_VALIDATOR_ADDRESS = "0x00000000008bdaba73cd9815d79069c247eb4bda";

// --- ABIs ---
const EXECUTE_ABI = parseAbi([
    "function execute(bytes32 mode, bytes calldata executionCalldata) external payable"
]);

const NONCE_ABI = parseAbi([
    "function getNonce(address sender, uint192 key) view returns (uint256)"
]);

// --- Helpers ---

export const encodePolicy = (type: 'value' | 'usage' | 'sudo', limit?: bigint | string): { policy: Address; initData: Hex } => {
    const VALUE_LIMIT_POLICY = "0x730DA93267E7E513e932301B47F2ac7D062abC83";
    const USAGE_LIMIT_POLICY = "0x1F34eF8311345A3A4a4566aF321b313052F51493";
    const SUDO_POLICY = "0x0000003111cD8e92337C100F22B7A9dbf8DEE301";

    if (type === 'sudo') return { policy: SUDO_POLICY as Address, initData: "0x" };

    const limitBn = BigInt(limit!);

    if (type === 'value') return { policy: VALUE_LIMIT_POLICY as Address, initData: encodeAbiParameters([{ type: 'uint256' }], [limitBn]) };
    if (type === 'usage') return { policy: USAGE_LIMIT_POLICY as Address, initData: encodePacked(['uint128'], [limitBn]) };
    return { policy: "0x0000000000000000000000000000000000000000", initData: "0x" };
};

export const getPermissionId = (session: any): Hex => {
    return keccak256(encodeAbiParameters(
        [{ type: 'address' }, { type: 'bytes' }, { type: 'bytes32' }],
        [session.sessionValidator, session.sessionValidatorInitData, session.salt]
    ));
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

// FIX: Simplified Packing for Safe 7579 Adapter
// [Validator Address (32 bytes)] + [Inner Signature]
const packSafe7579Signature = (validator: Address, signature: Hex): Hex => {
    const validatorPadded = pad(validator, { size: 32 });
    return encodePacked(['bytes32', 'bytes'], [validatorPadded, signature]);
};

// --- CUSTOM CLIENT IMPLEMENTATION ---

export async function getSafe7579SessionAccount(
    client: PublicClient<any, any>, // Use <any, any> to avoid strict transaction type mismatch
    safeAddress: Address,
    session: any,
    signUserOp: (hash: Hex) => Promise<Hex>
): Promise<SmartAccount> {

    const permissionId = getPermissionId(session);

    // Helper to wrap signature in 7579 Smart Session format
    // Mode 0x00 = USE
    const encodeSmartSessionSig = (sig: Hex) => encodePacked(['bytes1', 'bytes32', 'bytes'], ['0x00', permissionId, sig]);

    return toSmartAccount({
        client,
        entryPoint: {
            abi: entryPoint07Abi,
            address: entryPoint07Address,
            version: "0.7",
        },

        async getAddress() {
            return safeAddress;
        },

        // Override Nonce: Use Validator Address as Key (2D Nonce)
        async getNonce() {
            const key = concat([
                SMART_SESSIONS_VALIDATOR_ADDRESS as Address,
                "0x00000000" // Pad to 24 bytes (uint192)
            ]);
            return await client.readContract({
                address: entryPoint07Address,
                abi: NONCE_ABI,
                functionName: "getNonce",
                args: [safeAddress, BigInt(key)]
            });
        },

        // Override EncodeCalls: Use ERC-7579 `execute`
        async encodeCalls(calls) {
            const call = calls[0];
            const mode = "0x0000000000000000000000000000000000000000000000000000000000000000"; // Single Call
            const calldata = encodePacked(['address', 'uint256', 'bytes'], [call.to, call.value || 0n, call.data || "0x"]);

            return encodeFunctionData({
                abi: EXECUTE_ABI,
                functionName: "execute",
                args: [mode as Hex, calldata]
            });
        },

        // Override SignUserOperation
        async signUserOperation(userOp) {
            const { chainId = client.chain!.id, ...op } = userOp;
            const hash = getUserOperationHash({
                userOperation: {
                    ...op,
                    sender: safeAddress,
                    signature: "0x"
                },
                entryPointAddress: entryPoint07Address,
                entryPointVersion: "0.7",
                chainId: chainId
            });

            const signature = await signUserOp(hash);
            const smartSessionSig = encodeSmartSessionSig(signature);

            // FIX: Wrap with simple Safe Adapter format
            return packSafe7579Signature(SMART_SESSIONS_VALIDATOR_ADDRESS, smartSessionSig);
        },

        // Override StubSignature
        async getStubSignature() {
            const dummySig = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1c" as Hex;
            const smartSessionSig = encodeSmartSessionSig(dummySig);
            return packSafe7579Signature(SMART_SESSIONS_VALIDATOR_ADDRESS, smartSessionSig);
        },

        // --- Implement Missing Required Methods ---

        async getFactoryArgs() {
            return { factory: undefined, factoryData: undefined };
        },

        async signMessage({ message }) {
            throw new Error("signMessage not implemented for Session Key Client");
        },

        async signTypedData(typedData) {
            throw new Error("signTypedData not implemented for Session Key Client");
        }
    });
}