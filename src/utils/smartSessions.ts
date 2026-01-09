import {
    encodeAbiParameters,
    keccak256,
    encodePacked,
    type Hex,
    type Address,
} from "viem";
import {
    OWNABLE_VALIDATOR_ADDRESS,
    VALUE_LIMIT_POLICY,
    USAGE_LIMIT_POLICY,
    SUDO_POLICY,
    TIME_FRAME_POLICY,
    PERIODIC_ERC20_POLICY
} from "../config";

export const encodePolicy = (type: 'value' | 'usage' | 'sudo' | 'time', limit?: bigint, validAfter?: number): { policy: Address; initData: Hex } => {
    if (type === 'sudo') return { policy: SUDO_POLICY as Address, initData: "0x" };
    if (type === 'value') return { policy: VALUE_LIMIT_POLICY as Address, initData: encodeAbiParameters([{ type: 'uint256' }], [limit!]) };
    if (type === 'usage') return { policy: USAGE_LIMIT_POLICY as Address, initData: encodePacked(['uint128'], [limit!]) };

    if (type === 'time') {
        return {
            policy: TIME_FRAME_POLICY as Address,
            initData: encodePacked(
                ['uint128', 'uint128'],
                [0n, BigInt(validAfter || 0)]
            )
        };
    }
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
    targetContract: Address,
    selector: Hex,
    nativeValueLimit: bigint,
    salt: Hex,
    validAfterUnix: number
) => {
    const policiesList = [];
    policiesList.push(encodePolicy('usage', 1n));
    if (nativeValueLimit > 0n) {
        policiesList.push(encodePolicy('value', nativeValueLimit));
    }

    const policies = policiesList.sort((a, b) => a.policy.toLowerCase().localeCompare(b.policy.toLowerCase()));

    const userOpPolicies = [
        encodePolicy('sudo'),
        encodePolicy('time', 0n, validAfterUnix)
    ].sort((a, b) => a.policy.toLowerCase().localeCompare(b.policy.toLowerCase()));

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

export const createAllowanceSessionStruct = (
    sessionOwner: Address,
    tokenAddress: Address,
    amount: bigint,
    startUnix: number,
    salt: Hex,
    refillInterval: number,
    allowanceName: string
) => {
    if (tokenAddress === "0x0000000000000000000000000000000000000000") {
        throw new Error("Recurring Allowances currently only support ERC20 tokens (USDC), not Native ETH.");
    }

    if (refillInterval <= 0) {
        throw new Error("Interval must be greater than 0 for recurring allowances.");
    }

    const policies = [];

    policies.push({
        policy: PERIODIC_ERC20_POLICY as Address,
        initData: encodeAbiParameters(
            [
                { type: 'address[]' }, 
                { type: 'uint256[]' }, 
                { type: 'uint256[]' },
                { type: 'string[]' }
            ],
            [
                [tokenAddress], 
                [amount], 
                [BigInt(refillInterval)],
                [allowanceName]
            ]
        )
    });

    const sortedActionPolicies = policies.sort((a, b) => a.policy.toLowerCase().localeCompare(b.policy.toLowerCase()));

    return {
        sessionValidator: OWNABLE_VALIDATOR_ADDRESS as Address,
        sessionValidatorInitData: encodeAbiParameters(
            [{ name: 'threshold', type: 'uint256' }, { name: 'owners', type: 'address[]' }],
            [1n, [sessionOwner]]
        ),
        salt,
        userOpPolicies: [
            encodePolicy('sudo'),
            encodePolicy('time', 0n, startUnix)
        ].sort((a, b) => a.policy.toLowerCase().localeCompare(b.policy.toLowerCase())),
        erc7739Policies: { allowedERC7739Content: [], erc1271Policies: [] },
        actions: [{
            actionTarget: tokenAddress,
            actionTargetSelector: "0xa9059cbb" as Hex, // ERC20 transfer
            actionPolicies: sortedActionPolicies
        }],
        permitERC4337Paymaster: true
    };
};