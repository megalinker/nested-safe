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
} from "viem";
import {
    toSmartAccount,
    type SmartAccount,
    entryPoint07Address,
    entryPoint07Abi,
    getUserOperationHash
} from "viem/account-abstraction";
import { SMART_SESSIONS_VALIDATOR_ADDRESS } from "../config";

// --- ABIs ---
const EXECUTE_ABI = parseAbi([
    "function execute(bytes32 mode, bytes calldata executionCalldata) external payable"
]);

const NONCE_ABI = parseAbi([
    "function getNonce(address sender, uint192 key) view returns (uint256)"
]);

// --- Helpers ---

export const getPermissionId = (session: any): Hex => {
    return keccak256(encodeAbiParameters(
        [{ type: 'address' }, { type: 'bytes' }, { type: 'bytes32' }],
        [session.sessionValidator, session.sessionValidatorInitData, session.salt]
    ));
};

// --- CUSTOM CLIENT IMPLEMENTATION ---

export async function getSafe7579SessionAccount(
    client: PublicClient<any, any>,
    safeAddress: Address,
    session: any,
    signUserOp: (hash: Hex) => Promise<Hex>
): Promise<SmartAccount> {

    const permissionId = getPermissionId(session);

    // Mode 0x00 = USE session.
    // Format: [Mode (1 byte)] + [PermissionId (32 bytes)] + [Signature]
    // The Safe Adapter reads the validator from the Nonce, so we don't need to wrap this further.
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

        // Override Nonce: Key includes the Validator Address.
        // This tells the Safe 7579 Adapter which module to validate against.
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

        async encodeCalls(calls) {
            const call = calls[0];
            const mode = "0x0000000000000000000000000000000000000000000000000000000000000000"; // Single Call

            // Ensure call.to is defined, otherwise throw or handle it. 
            // In a session execution, 'to' MUST be the target.
            if (!call.to) throw new Error("Missing 'to' in call");

            const calldata = encodePacked(['address', 'uint256', 'bytes'], [call.to, call.value || 0n, call.data || "0x"]);

            return encodeFunctionData({
                abi: EXECUTE_ABI,
                functionName: "execute",
                args: [mode as Hex, calldata]
            });
        },

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
            return encodeSmartSessionSig(signature);
        },

        async getStubSignature() {
            // FIX: Use a mathematically valid ECDSA signature for the stub.
            // All 0xff causes ecrecover to revert/fail hard in some validators.
            // r = 1, s = 1, v = 27 (0x1b)
            const dummySig = "0x000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000011b" as Hex;
            return encodeSmartSessionSig(dummySig);
        },

        async getFactoryArgs() {
            return { factory: undefined, factoryData: undefined };
        },

        async signMessage() { throw new Error("Not implemented"); },
        async signTypedData() { throw new Error("Not implemented"); }
    });
}