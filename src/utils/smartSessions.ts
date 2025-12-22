import {
    encodeAbiParameters,
    keccak256,
    encodePacked,
    type Hex,
    type Address,
} from "viem";

export const OWNABLE_VALIDATOR_ADDRESS = "0x000000000013fdb5234e4e3162a810f54d9f7e98";
export const VALUE_LIMIT_POLICY = "0x730DA93267E7E513e932301B47F2ac7D062abC83";
export const USAGE_LIMIT_POLICY = "0x1F34eF8311345A3A4a4566aF321b313052F51493";
export const SUDO_POLICY = "0x0000003111cD8e92337C100F22B7A9dbf8DEE301";
export const TIME_FRAME_POLICY = "0x8177451511dE0577b911C254E9551D981C26dc72";
export const ERC20_SPENDING_LIMIT_POLICY = "0x00000088D48cF102A8Cdb0137A9b173f957c6343"; 
export const USDC_ADDRESS = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

export const encodePolicy = (type: 'value' | 'usage' | 'sudo' | 'time', limit?: bigint, validAfter?: number): { policy: Address; initData: Hex } => {
    if (type === 'sudo') return { policy: SUDO_POLICY as Address, initData: "0x" };
    if (type === 'value') return { policy: VALUE_LIMIT_POLICY as Address, initData: encodeAbiParameters([{ type: 'uint256' }], [limit!]) };
    if (type === 'usage') return { policy: USAGE_LIMIT_POLICY as Address, initData: encodePacked(['uint128'], [limit!]) };

    if (type === 'time') {
        /**
         * TimeFramePolicy.sol logic: 
         * validUntil = uint48(uint128(bytes16(initData[0:16])))
         * validAfter = uint48(uint128(bytes16(initData[16:32])))
         */
        return {
            policy: TIME_FRAME_POLICY as Address,
            initData: encodePacked(
                ['uint128', 'uint128'],
                [0n, BigInt(validAfter || 0)] // validUntil = 0 (never), validAfter = start time
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
    validAfterUnix: number // Added timestamp
) => {
    const policiesList = [];
    policiesList.push(encodePolicy('usage', 1n));
    if (nativeValueLimit > 0n) {
        policiesList.push(encodePolicy('value', nativeValueLimit));
    }

    // Sort action policies
    const policies = policiesList.sort((a, b) => a.policy.toLowerCase().localeCompare(b.policy.toLowerCase()));

    // UserOp policies: Sudo + Time Frame restriction
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
    tokenAddress: Address, // Use address(0) for Native ETH
    amount: bigint,
    usageLimit: number,
    startUnix: number,
    salt: Hex
) => {
    const isNative = tokenAddress === "0x0000000000000000000000000000000000000000";
    const policies = [];

    // 1. Add the correct Value/Spending Policy
    if (isNative) {
        policies.push({
            policy: VALUE_LIMIT_POLICY as Address,
            initData: encodeAbiParameters([{ type: 'uint256' }], [amount]) // 32 bytes uint256
        });
    } else {
        policies.push({
            policy: ERC20_SPENDING_LIMIT_POLICY as Address,
            initData: encodeAbiParameters(
                [{ type: 'address[]' }, { type: 'uint256[]' }],
                [[tokenAddress], [amount]]
            )
        });
    }

    // 2. Add Usage Limit (Max transaction count)
    policies.push({
        policy: USAGE_LIMIT_POLICY as Address,
        initData: encodePacked(['uint128'], [BigInt(usageLimit)])
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
            actionTarget: isNative ? "0x0000000000000000000000000000000000000000" : tokenAddress,
            actionTargetSelector: isNative ? "0xFFFFFFFF" : "0xa9059cbb" as Hex,
            actionPolicies: sortedActionPolicies
        }],
        permitERC4337Paymaster: true
    };
};