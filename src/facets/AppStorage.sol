/// @title LibAccountConfigStorage
/// @author Brendon Paul
/// @notice Storage layout and structs for AccountConfig diamond. All facets read/write this storage at a fixed slot.
/// @notice Mappings using uint256 are always keccak256 of whatever is being mapped.
/// @notice Each struct contains a keccak256 that matches the mapping to prove existence of the struct.

// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {
    EnumerableSet
} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

library AppStorage {
    using EnumerableSet for EnumerableSet.UintSet;
    using EnumerableSet for EnumerableSet.AddressSet;

    bytes32 constant ACCOUNT_CONFIG_STORAGE_POSITION =
        keccak256("com.litprotocol.accountconfig.storage");

    uint256 internal constant WALLET_PATH_TAG =
        uint256(uint96(bytes12("lit-wallet:1")));
    uint256 internal constant WALLET_PATH_TAG_SHIFT = 160;

    error AccountDoesNotExist(uint256 apiKeyHash);
    error NoAccountAccess(uint256 apiKeyHash, address sender);
    error AccountAlreadyExists(uint256 apiKeyHash);
    error GroupDoesNotExist(uint256 apiKeyHash, uint256 groupId);
    error PkpDoesNotExist(uint256 apiKeyHash, uint256 groupId, address pkpId);
    error ActionDoesNotExist(
        uint256 apiKeyHash,
        uint256 groupId,
        uint256 cidHash
    );
    error UsageApiKeyDoesNotExist(uint256 apiKeyHash, uint256 usageApiKeyHash);
    error InsufficientBalance(uint256 apiKeyHash, uint256 amount);
    error OnlyApiPayer(address caller);
    error OnlyApiPayerOrPricingOperator(address caller);
    error OnlyApiPayerOrOwner(address caller);
    error NotMasterAccount(uint256 apiKeyHash);
    error NotAllowedToCreateGroup(uint256 apiKeyHash);
    error NotAllowedToDeleteGroup(uint256 apiKeyHash);
    error NotAllowedToCreatePkp(uint256 apiKeyHash);
    error NotAllowedToAddPkpToGroup(uint256 apiKeyHash, uint256 groupId);
    error NotAllowedToRemovePkpFromGroup(uint256 apiKeyHash, uint256 groupId);
    error NotAllowedToManageIPFSIdsInGroup(uint256 apiKeyHash, uint256 groupId);
    error UsageApiKeyExpired(uint256 usageApiKeyHash);
    error InvalidRequest(string message);
    error OnlyConfigOperatorOrOwner(address caller);

    struct PkpData {
        uint256 id;
        address pkpId;
        string name;
        string description;
    }

    struct Metadata {
        uint256 id;
        string name;
        string description;
    }

    struct UsageApiKey {
        Metadata metadata;
        uint256 apiKeyHash;
        uint256 expiration;
        uint256 balance;
        EnumerableSet.UintSet executeInGroups;
        bool createGroups;
        bool deleteGroups;
        bool createPKPs;
        EnumerableSet.UintSet manageIPFSIdsInGroups;
        EnumerableSet.UintSet addPkpToGroups;
        EnumerableSet.UintSet removePkpFromGroups;
    }

    struct Group {
        Metadata metadata;
        EnumerableSet.UintSet cidHash;
        EnumerableSet.AddressSet pkpId;
    }

    struct Account {
        UsageApiKey accountApiKey;
        address adminWalletAddress;
        EnumerableSet.UintSet usageApiKeysList;
        mapping(uint256 => UsageApiKey) usageApiKeys;
        EnumerableSet.UintSet groupList;
        mapping(uint256 => Group) groups;
        EnumerableSet.UintSet actionHashesList;
        mapping(uint256 => Metadata) actionMetadata;
        mapping(uint256 => address) pkpIds;
        mapping(address => Metadata) pkpData;
        bool managed;
        uint256 pkpCount;
        uint256 actionCount;
        uint256 groupCount;
        address billingWalletAddress;
    }

    struct AccountConfigStorage {
        mapping(uint256 => Account) accounts;
        mapping(uint256 => uint256) indexToAccountHash;
        mapping(uint256 => uint256) allApiKeyHashesToMaster;
        mapping(uint256 => address) allPkpIds;
        mapping(uint256 => uint256) pricing;
        EnumerableSet.AddressSet api_payers;
        address configOperator;
        address pricingOperator;
        uint256 pkpCount;
        uint256 accountCount;
        address adminApiPayerAccount;
        uint256 requestedApiPayerCount;
        uint256 rebalanceAmount;
        EnumerableSet.StringSet nodeConfigurationKeys;
        mapping(string => string) nodeConfigurationValues;
        uint256 serverTriggerValue;
        mapping(address => uint256) pkpIdToOwnerMaster;
        mapping(uint256 => uint256) pathToOwnerMaster;
    }

    function getStorage()
        internal
        pure
        returns (AccountConfigStorage storage s)
    {
        bytes32 position = ACCOUNT_CONFIG_STORAGE_POSITION;
        assembly {
            s.slot := position
        }
    }

    function accountExistsAndIsMutable(
        uint256 apiKeyHash,
        address sender
    ) internal view returns (bool) {
        AccountConfigStorage storage s = getStorage();
        uint256 masterAccountApiKeyHash = s.allApiKeyHashesToMaster[apiKeyHash];
        if (masterAccountApiKeyHash == 0) {
            return false;
        }
        Account storage account = s.accounts[masterAccountApiKeyHash];
        if (account.accountApiKey.apiKeyHash != masterAccountApiKeyHash)
            return false;
        if (s.api_payers.contains(sender) && account.managed == true)
            return true;
        return account.adminWalletAddress == sender;
    }

    function groupExists(
        uint256 accountApiKeyHash,
        uint256 groupId
    ) internal view returns (bool) {
        if (groupId == 0) return false;
        AccountConfigStorage storage s = getStorage();
        Account storage account = s.accounts[accountApiKeyHash];
        Group storage group = account.groups[groupId];
        return group.metadata.id == groupId;
    }

    function revertIfNoAccountAccess(
        uint256 accountApiKeyHash,
        address sender
    ) internal view {
        if (!accountExistsAndIsMutable(accountApiKeyHash, sender)) {
            revert NoAccountAccess(accountApiKeyHash, sender);
        }
    }

    function revertIfGroupDoesNotExist(
        uint256 accountApiKeyHash,
        uint256 groupId
    ) internal view {
        if (!groupExists(accountApiKeyHash, groupId)) {
            revert GroupDoesNotExist(accountApiKeyHash, groupId);
        }
    }

    function checkIfApiPayerOrPricingOperator(
        AccountConfigStorage storage s,
        address caller
    ) internal view {
        if (!s.api_payers.contains(caller) && caller != s.pricingOperator) {
            revert OnlyApiPayerOrPricingOperator(caller);
        }
    }
}
