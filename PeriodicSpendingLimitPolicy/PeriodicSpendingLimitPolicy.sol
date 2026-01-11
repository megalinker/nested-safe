// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// --- Interfaces & Types ---

type ConfigId is bytes32;

interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface IPolicy is IERC165 {
    event PolicySet(ConfigId id, address multiplexer, address account);
    event AllowanceRevoked(ConfigId id, address token, address account);
    event AllowanceLinked(ConfigId childId, ConfigId parentId, address account);

    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    ) external;
}

interface IActionPolicy is IPolicy {
    function checkAction(
        ConfigId id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (uint256);
}

// --- Main Contract ---

contract PeriodicSpendingLimitPolicy is IActionPolicy {
    struct TokenPolicyData {
        address holder;
        uint256 limit;
        uint256 refillInterval; // In seconds
        uint256 amountSpent;
        uint48 lastRefill;
        string name;
        bool isDeleted;
    }

    struct AllowanceInfo {
        ConfigId configId;
        address token;
        address holder;
        uint256 limit;
        uint256 refillInterval;
        uint256 amountSpent;
        uint48 lastRefill;
        string name;
        bool isActive;
        ConfigId linkedParent;
    }

    // Mapping: ConfigId -> Multiplexer -> Token -> Account -> Data
    mapping(ConfigId id => mapping(address multiplexer => mapping(address token => mapping(address account => TokenPolicyData))))
        internal $policyData;

    mapping(ConfigId => ConfigId) internal $pointers;

    // Trackers for enumeration
    mapping(address account => ConfigId[]) internal $accountConfigs;
    mapping(ConfigId id => address[]) internal $configTokens;

    function supportsInterface(
        bytes4 interfaceID
    ) external pure override returns (bool) {
        return
            interfaceID == 0x01ffc9a7 ||
            interfaceID == 0x05c00895 ||
            interfaceID == type(IPolicy).interfaceId ||
            interfaceID == type(IActionPolicy).interfaceId;
    }

    /**
     * Init Data Format:
     * abi.encode(
     *   address[] tokens,
     *   uint256[] limits,
     *   uint256[] refillIntervals,
     *   address[] holders,
     *   string[] names,
     *   bytes32 parentConfigId
     * )
     */
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    ) external {
        (
            address[] memory tokens,
            uint256[] memory limits,
            uint256[] memory intervals,
            address[] memory holders,
            string[] memory names,
            bytes32 parentConfigId
        ) = abi.decode(
                initData,
                (address[], uint256[], uint256[], address[], string[], bytes32)
            );

        require(tokens.length == holders.length, "Length mismatch");

        $accountConfigs[account].push(configId);

        // --- POINTER LOGIC ---
        // If a parent ID is provided, we link this config to the parent.
        // We do NOT initialize storage for this configId, because we will read from the parent's storage.
        if (parentConfigId != bytes32(0)) {
            $pointers[configId] = ConfigId.wrap(parentConfigId);
            emit AllowanceLinked(
                configId,
                ConfigId.wrap(parentConfigId),
                account
            );

            for (uint256 i = 0; i < tokens.length; i++) {
                $configTokens[configId].push(tokens[i]);
            }
            return;
        }

        // --- NORMAL INITIALIZATION ---
        for (uint256 i = 0; i < tokens.length; i++) {
            TokenPolicyData storage $ = $policyData[configId][msg.sender][
                tokens[i]
            ][account];

            $.holder = holders[i];
            $.limit = limits[i];
            $.refillInterval = intervals[i];
            $.amountSpent = 0;
            $.lastRefill = uint48(block.timestamp);
            $.name = names[i];
            $.isDeleted = false;

            $configTokens[configId].push(tokens[i]);
        }
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    // Revoke Function ---
    // Only the Smart Account itself can call this to clean up its own storage
    function revokeAllowance(ConfigId configId, address token) external {
        // Rhinestone Validator.
        address multiplexer = 0x00000000008bDABA73cD9815d79069c247Eb4bDA;

        ConfigId effectiveId = $pointers[configId];
        if (ConfigId.unwrap(effectiveId) == bytes32(0)) {
            effectiveId = configId;
        }

        TokenPolicyData storage $ = $policyData[effectiveId][multiplexer][
            token
        ][msg.sender];

        // Mark as deleted
        $.isDeleted = true;

        // Reset limit to 0
        $.limit = 0;

        // Clear holder
        $.holder = address(0);

        emit AllowanceRevoked(effectiveId, token, msg.sender);
    }

    function checkAction(
        ConfigId id,
        address account,
        address target, // The Token Address
        uint256 value,
        bytes calldata callData
    ) external override returns (uint256) {
        if (value != 0) return 1; // VALIDATION_FAILED

        // 1. Decode Amount from Transfer
        // transfer(address,uint256) selector is 0xa9059cbb
        if (bytes4(callData[0:4]) != 0xa9059cbb) {
            return 1; // FAILED: Only support transfer
        }

        uint256 amount;
        // Decode 2nd arg (amount). Skip 4 bytes selector + 32 bytes address
        (, amount) = abi.decode(callData[4:], (address, uint256));

        // --- POINTER RESOLUTION ---
        // If this ConfigId points to another, switch to the parent ID
        ConfigId effectiveId = $pointers[id];
        if (ConfigId.unwrap(effectiveId) == bytes32(0)) {
            effectiveId = id;
        }

        TokenPolicyData storage $ = $policyData[effectiveId][msg.sender][
            target
        ][account];

        // --- Check Deleted Status ---
        if ($.isDeleted) return 1; // VALIDATION_FAILED if deleted

        // 2. Strict Window Refill Logic
        // Calculate how much time passed since the last refill
        uint256 elapsed = block.timestamp - $.lastRefill;

        if (elapsed >= $.refillInterval) {
            $.amountSpent = 0;
            // Align refill to the original schedule
            $.lastRefill += uint48(elapsed - (elapsed % $.refillInterval));
        }

        // 3. Check Limit
        if ($.amountSpent + amount > $.limit) {
            return 1; // VALIDATION_FAILED
        }

        $.amountSpent += amount;
        return 0; // VALIDATION_SUCCESS
    }

    function getAllowance(
        address account,
        bytes32 configId,
        address token
    ) external view returns (TokenPolicyData memory) {
        // Rhinestone Smart Session Validator
        address multiplexer = 0x00000000008bDABA73cD9815d79069c247Eb4bDA;

        // Resolve Pointer
        ConfigId effectiveId = $pointers[ConfigId.wrap(configId)];
        if (ConfigId.unwrap(effectiveId) == bytes32(0)) {
            effectiveId = ConfigId.wrap(configId);
        }

        return $policyData[effectiveId][multiplexer][token][account];
    }

    function getAllowances(
        address account
    ) external view returns (AllowanceInfo[] memory) {
        ConfigId[] memory configs = $accountConfigs[account];

        uint256 totalCount = 0;
        for (uint256 i = 0; i < configs.length; i++) {
            totalCount += $configTokens[configs[i]].length;
        }

        AllowanceInfo[] memory results = new AllowanceInfo[](totalCount);
        uint256 currentIndex = 0;

        for (uint256 i = 0; i < configs.length; i++) {
            currentIndex = _processConfig(
                account,
                configs[i],
                results,
                currentIndex
            );
        }

        assembly {
            mstore(results, currentIndex)
        }

        return results;
    }

    function _processConfig(
        address account,
        ConfigId cId,
        AllowanceInfo[] memory results,
        uint256 currentIndex
    ) internal view returns (uint256) {
        ConfigId parentId = $pointers[cId];
        ConfigId effectiveId = ConfigId.unwrap(parentId) != bytes32(0)
            ? parentId
            : cId;

        address[] memory tokens = $configTokens[cId];
        address multiplexer = 0x00000000008bDABA73cD9815d79069c247Eb4bDA;

        for (uint256 j = 0; j < tokens.length; j++) {
            address token = tokens[j];
            TokenPolicyData storage data = $policyData[effectiveId][
                multiplexer
            ][token][account];

            if (data.limit > 0 || data.isDeleted) {
                results[currentIndex] = AllowanceInfo({
                    configId: cId,
                    token: token,
                    holder: data.holder,
                    limit: data.limit,
                    refillInterval: data.refillInterval,
                    amountSpent: data.amountSpent,
                    lastRefill: data.lastRefill,
                    name: data.name,
                    isActive: !data.isDeleted,
                    linkedParent: parentId
                });
                currentIndex++;
            }
        }
        return currentIndex;
    }
}
