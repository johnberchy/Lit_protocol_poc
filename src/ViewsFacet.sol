/// @title AccountConfigViews
/// @author Brendon Paul
/// @notice View (read-only) functions for AccountConfig diamond.

// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {
    EnumerableSet
} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {AppStorage} from "./AppStorage.sol";

contract ViewsFacet {
    using EnumerableSet for EnumerableSet.UintSet;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.StringSet;

    struct UsageApiKeyReturn {
        AppStorage.Metadata metadata;
        uint256 apiKeyHash;
        uint256 expiration;
        uint256 balance;
        uint256[] executeInGroups;
        bool createGroups;
        bool deleteGroups;
        bool createPKPs;
        uint256[] manageIPFSIdsInGroups;
        uint256[] addPkpToGroups;
        uint256[] removePkpFromGroups;
    }

    struct GroupReturn {
        AppStorage.Metadata metadata;
        uint256[] cidHash;
        address[] pkpId;
    }

    struct KeyValueReturn {
        string key;
        string value;
    }

    function adminApiPayerAccount() public view returns (address) {
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        return s.adminApiPayerAccount;
    }

    function api_payers() public view returns (address[] memory) {
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        return s.api_payers.values();
    }

    function pricingOperator() public view returns (address) {
        return AppStorage.getStorage().pricingOperator;
    }

    function configOperator() public view returns (address) {
        return AppStorage.getStorage().configOperator;
    }

    function pkpCount() public view returns (uint256) {
        return AppStorage.getStorage().pkpCount;
    }
    function accountCount() public view returns (uint256) {
        return AppStorage.getStorage().accountCount;
    }
    function indexToAccountHashAt(uint256 index) public view returns (uint256) {
        return AppStorage.getStorage().indexToAccountHash[index];
    }
    function allPkpIdsAt(uint256 index) public view returns (address) {
        return AppStorage.getStorage().allPkpIds[index];
    }
    function pricingAt(uint256 index) public view returns (uint256) {
        return AppStorage.getStorage().pricing[index];
    }

    function apiPayerCount() public view returns (uint256) {
        return AppStorage.getStorage().api_payers.length();
    }
    function requestedApiPayerCount() public view returns (uint256) {
        return AppStorage.getStorage().requestedApiPayerCount;
    }

    function rebalanceAmount() public view returns (uint256) {
        return AppStorage.getStorage().rebalanceAmount;
    }

    function nodeConfigurationKeys() public view returns (string[] memory) {
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        return s.nodeConfigurationKeys.values();
    }
    function nodeConfigurationValue(
        string memory key
    ) public view returns (string memory) {
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        return s.nodeConfigurationValues[key];
    }

    function nodeConfigurationValues()
        public
        view
        returns (KeyValueReturn[] memory)
    {
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        uint256 length = s.nodeConfigurationKeys.length();
        KeyValueReturn[] memory values = new KeyValueReturn[](length);
        for (uint256 i = 0; i < length; i++) {
            values[i] = KeyValueReturn(
                s.nodeConfigurationKeys.at(i),
                s.nodeConfigurationValues[s.nodeConfigurationKeys.at(i)]
            );
        }
        return values;
    }

    function accountExistsAndIsMutable(
        uint256 apiKeyHash
    ) public view returns (bool) {
        return AppStorage.accountExistsAndIsMutable(apiKeyHash, msg.sender);
    }

    function isAccountManaged(uint256 apiKeyHash) public view returns (bool) {
        return getReadOnlyAccount(apiKeyHash).managed;
    }

    function getAccountWalletAddress(
        uint256 apiKeyHash
    ) public view returns (address) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        return account.adminWalletAddress;
    }

    function getBillingWalletAddress(
        uint256 apiKeyHash
    ) public view returns (address) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        if (account.billingWalletAddress == address(0)) {
            return account.adminWalletAddress;
        }
        return account.billingWalletAddress;
    }

    function getWalletDerivation(
        uint256 apiKeyHash,
        address walletAddress
    ) public view returns (uint256) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        uint256 derivation = account.pkpData[walletAddress].id;
        if (derivation == 0) {
            return 0;
        }
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        uint256 resolvedMaster = s.allApiKeyHashesToMaster[apiKeyHash];
        uint256 owner = s.pkpIdToOwnerMaster[walletAddress];
        if (owner != resolvedMaster) {
            revert AppStorage.InvalidRequest("PKP owned by another account");
        }
        uint256 pathOwner = s.pathToOwnerMaster[derivation];
        if (pathOwner != resolvedMaster) {
            revert AppStorage.InvalidRequest("derivation path owned by another account");
        }
        return derivation;
    }

    function getPkpOwnerMaster(address pkpId) public view returns (uint256) {
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        return s.pkpIdToOwnerMaster[pkpId];
    }

    function getPathOwnerMaster(
        uint256 derivationPath
    ) public view returns (uint256) {
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        return s.pathToOwnerMaster[derivationPath];
    }

    function listApiKeys(
        uint256 accountApiKeyHash,
        uint256 pageNumber,
        uint256 pageSize
    ) public view returns (UsageApiKeyReturn[] memory) {
        AppStorage.Account storage account = getReadOnlyAccount(
            accountApiKeyHash
        );
        uint256 totalLength = account.usageApiKeysList.length();
        (uint256 startIndex, uint256 pageLength) = getPageStartAndLength(
            totalLength,
            pageNumber,
            pageSize
        );
        UsageApiKeyReturn[] memory pageApiKeys = new UsageApiKeyReturn[](
            pageLength
        );
        for (uint256 i = 0; i < pageLength; i++) {
            uint256 usageApiKeyHash = account.usageApiKeysList.at(
                startIndex + i
            );
            pageApiKeys[i] = UsageApiKeyReturn(
                account.usageApiKeys[usageApiKeyHash].metadata,
                account.usageApiKeys[usageApiKeyHash].apiKeyHash,
                account.usageApiKeys[usageApiKeyHash].expiration,
                account.usageApiKeys[usageApiKeyHash].balance,
                account.usageApiKeys[usageApiKeyHash].executeInGroups.values(),
                account.usageApiKeys[usageApiKeyHash].createGroups,
                account.usageApiKeys[usageApiKeyHash].deleteGroups,
                account.usageApiKeys[usageApiKeyHash].createPKPs,
                account
                    .usageApiKeys[usageApiKeyHash]
                    .manageIPFSIdsInGroups
                    .values(),
                account.usageApiKeys[usageApiKeyHash].addPkpToGroups.values(),
                account
                    .usageApiKeys[usageApiKeyHash]
                    .removePkpFromGroups
                    .values()
            );
        }
        return pageApiKeys;
    }

    function listGroups(
        uint256 accountApiKeyHash,
        uint256 pageNumber,
        uint256 pageSize
    ) public view returns (AppStorage.Metadata[] memory) {
        AppStorage.Account storage account = getReadOnlyAccount(
            accountApiKeyHash
        );
        uint256 totalLength = account.groupList.length();
        (uint256 startIndex, uint256 pageLength) = getPageStartAndLength(
            totalLength,
            pageNumber,
            pageSize
        );
        AppStorage.Metadata[] memory pageMetadata = new AppStorage.Metadata[](
            pageLength
        );
        for (uint256 i = 0; i < pageLength; i++) {
            pageMetadata[i] = account
                .groups[account.groupList.at(startIndex + i)]
                .metadata;
        }
        return pageMetadata;
    }

    function listGroupContents(
        uint256 accountApiKeyHash,
        uint256 groupId
    ) public view returns (GroupReturn memory) {
        AppStorage.Account storage account = getReadOnlyAccount(
            accountApiKeyHash
        );

        GroupReturn memory groupReturn = GroupReturn(
            account.groups[groupId].metadata,
            account.groups[groupId].cidHash.values(),
            account.groups[groupId].pkpId.values()
        );
        return groupReturn;
    }

    function listPkps(
        uint256 accountApiKeyHash,
        uint256 pageNumber,
        uint256 pageSize
    ) public view returns (AppStorage.PkpData[] memory) {
        AppStorage.Account storage account = getReadOnlyAccount(
            accountApiKeyHash
        );
        (uint256 startIndex, uint256 pageLength) = getPageStartAndLength(
            account.pkpCount,
            pageNumber,
            pageSize
        );

        AppStorage.PkpData[] memory pagePkpData = new AppStorage.PkpData[](
            pageLength
        );
        for (uint256 i = 0; i < pageLength; i++) {
            address walletAddress = account.pkpIds[startIndex + i];
            pagePkpData[i].pkpId = walletAddress;
            pagePkpData[i].name = account.pkpData[walletAddress].name;
            pagePkpData[i].description = account
                .pkpData[walletAddress]
                .description;
        }
        return pagePkpData;
    }

    function listWalletsInGroup(
        uint256 accountApiKeyHash,
        uint256 groupId,
        uint256 pageNumber,
        uint256 pageSize
    ) public view returns (AppStorage.PkpData[] memory) {
        AppStorage.Account storage account = getReadOnlyAccount(
            accountApiKeyHash
        );
        AppStorage.Group storage group = account.groups[groupId];
        (uint256 startIndex, uint256 pageLength) = getPageStartAndLength(
            group.pkpId.length(),
            pageNumber,
            pageSize
        );
        AppStorage.PkpData[] memory pagePkpData = new AppStorage.PkpData[](
            pageLength
        );
        for (uint256 i = 0; i < pageLength; i++) {
            address walletAddress = group.pkpId.at(startIndex + i);
            pagePkpData[i].pkpId = walletAddress;
            pagePkpData[i].name = account.pkpData[walletAddress].name;
            pagePkpData[i].description = account
                .pkpData[walletAddress]
                .description;
        }
        return pagePkpData;
    }

    function listActions(
        uint256 accountApiKeyHash,
        uint256 pageNumber,
        uint256 pageSize
    ) public view returns (AppStorage.Metadata[] memory) {
        AppStorage.Account storage account = getReadOnlyAccount(
            accountApiKeyHash
        );
        (uint256 startIndex, uint256 pageLength) = getPageStartAndLength(
            account.actionHashesList.length(),
            pageNumber,
            pageSize
        );

        AppStorage.Metadata[] memory pageMetadata = new AppStorage.Metadata[](
            pageLength
        );

        for (uint256 i = 0; i < pageLength; i++) {
            pageMetadata[i] = account.actionMetadata[
                account.actionHashesList.at(startIndex + i)
            ];
        }
        return pageMetadata;
    }

    function listActionsInGroup(
        uint256 accountApiKeyHash,
        uint256 groupId,
        uint256 pageNumber,
        uint256 pageSize
    ) public view returns (AppStorage.Metadata[] memory) {
        AppStorage.Account storage account = getReadOnlyAccount(
            accountApiKeyHash
        );
        AppStorage.Group storage group = account.groups[groupId];
        uint256 totalLength = group.cidHash.length();
        (uint256 startIndex, uint256 pageLength) = getPageStartAndLength(
            totalLength,
            pageNumber,
            pageSize
        );

        AppStorage.Metadata[] memory pageMetadata = new AppStorage.Metadata[](
            pageLength
        );
        for (uint256 i = 0; i < pageLength; i++) {
            pageMetadata[i] = account.actionMetadata[
                group.cidHash.at(startIndex + i)
            ];
        }
        return pageMetadata;
    }

    function getPageStartAndLength(
        uint256 totalLength,
        uint256 pageNumber,
        uint256 pageSize
    ) internal pure returns (uint256, uint256) {
        if (pageSize > totalLength) {
            pageSize = totalLength;
            pageNumber = 0;
        }
        uint256 startIndex = pageNumber * pageSize;
        if (startIndex >= totalLength) {
            return (0, 0);
        }
        uint256 endIndex = startIndex + pageSize;
        if (endIndex > totalLength) endIndex = totalLength;
        return (startIndex, endIndex - startIndex);
    }

    function getReadOnlyAccount(
        uint256 apiKeyHash
    ) internal view returns (AppStorage.Account storage) {
        AppStorage.AccountConfigStorage storage s = AppStorage.getStorage();
        uint256 masterAccountApiKeyHash = s.allApiKeyHashesToMaster[apiKeyHash];
        if (masterAccountApiKeyHash == 0) {
            revert AppStorage.AccountDoesNotExist(apiKeyHash);
        }
        AppStorage.Account storage account = s.accounts[
            masterAccountApiKeyHash
        ];
        return account;
    }

    function _isExpired(
        AppStorage.UsageApiKey storage usageApiKey
    ) internal view returns (bool) {
        return
            usageApiKey.expiration != 0 &&
            block.timestamp >= usageApiKey.expiration;
    }

    function canExecuteAction(
        uint256 apiKeyHash,
        uint256 cidHash
    ) public view returns (bool) {
        return canExecuteActionFast(apiKeyHash, cidHash);
    }

    function canUseWalletInAction(
        uint256 apiKeyHash,
        uint256 cidHash,
        address walletAddress
    ) public view returns (bool) {
        uint256[] memory groupIds = groupIdsForActionAndWallet(
            apiKeyHash,
            cidHash,
            walletAddress
        );
        return apiKeyCanExecuteForAnyGroup(apiKeyHash, groupIds);
    }

    function apiKeyCanExecuteForAnyGroup(
        uint256 apiKeyHash,
        uint256[] memory groupIds
    ) public view returns (bool) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        AppStorage.UsageApiKey storage usageApiKey = account.usageApiKeys[
            apiKeyHash
        ];

        if (_isExpired(usageApiKey)) {
            return false;
        }

        if (usageApiKey.executeInGroups.contains(0)) {
            return groupIds.length > 0;
        }

        for (uint256 i = 0; i < groupIds.length; i++) {
            if (usageApiKey.executeInGroups.contains(groupIds[i])) {
                return true;
            }
        }
        return false;
    }

    function groupIdsForAction(
        uint256 apiKeyHash,
        uint256 cidHash
    ) public view returns (uint256[] memory) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        uint256[] memory groupIds = new uint256[](account.groupList.length());
        uint256 groupCount = 0;
        for (uint256 i = 0; i < account.groupList.length(); i++) {
            AppStorage.Group storage group = account.groups[
                account.groupList.at(i)
            ];
            if (group.cidHash.contains(cidHash) || group.cidHash.contains(0)) {
                groupIds[groupCount] = account.groupList.at(i);
                groupCount++;
            }
        }
        uint256[] memory returnGroups = new uint256[](groupCount);
        for (uint256 i = 0; i < groupCount; i++) {
            returnGroups[i] = groupIds[i];
        }
        return returnGroups;
    }

    function groupIdsForActionAndWallet(
        uint256 apiKeyHash,
        uint256 cidHash,
        address walletAddress
    ) public view returns (uint256[] memory) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        uint256[] memory groupIds = new uint256[](account.groupList.length());
        uint256 groupCount = 0;
        for (uint256 i = 0; i < account.groupList.length(); i++) {
            AppStorage.Group storage group = account.groups[
                account.groupList.at(i)
            ];
            if (
                (group.cidHash.contains(cidHash) ||
                    group.cidHash.contains(0)) &&
                (group.pkpId.contains(walletAddress) ||
                    group.pkpId.contains(address(0)))
            ) {
                groupIds[groupCount] = account.groupList.at(i);
                groupCount++;
            }
        }
        uint256[] memory returnGroups = new uint256[](groupCount);
        for (uint256 i = 0; i < groupCount; i++) {
            returnGroups[i] = groupIds[i];
        }
        return returnGroups;
    }

    function canExecuteActionFast(
        uint256 apiKeyHash,
        uint256 cidHash
    ) public view returns (bool) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        AppStorage.UsageApiKey storage usageApiKey = account.usageApiKeys[
            apiKeyHash
        ];

        if (_isExpired(usageApiKey)) {
            return false;
        }

        if (usageApiKey.executeInGroups.contains(0)) {
            return true;
        }

        uint256 len = account.groupList.length();
        for (uint256 i = 0; i < len; i++) {
            uint256 groupId = account.groupList.at(i);
            AppStorage.Group storage group = account.groups[groupId];
            if (
                (group.cidHash.contains(cidHash) ||
                    group.cidHash.contains(0)) &&
                usageApiKey.executeInGroups.contains(groupId)
            ) {
                return true;
            }
        }
        return false;
    }

    function canUseWalletInActionFast(
        uint256 apiKeyHash,
        uint256 cidHash,
        address walletAddress
    ) public view returns (bool) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        AppStorage.UsageApiKey storage usageApiKey = account.usageApiKeys[
            apiKeyHash
        ];

        if (_isExpired(usageApiKey)) {
            return false;
        }

        bool isWildcard = usageApiKey.executeInGroups.contains(0);

        uint256 len = account.groupList.length();
        for (uint256 i = 0; i < len; i++) {
            uint256 groupId = account.groupList.at(i);
            AppStorage.Group storage group = account.groups[groupId];
            if (
                (group.cidHash.contains(cidHash) ||
                    group.cidHash.contains(0)) &&
                (group.pkpId.contains(walletAddress) ||
                    group.pkpId.contains(address(0))) &&
                (isWildcard || usageApiKey.executeInGroups.contains(groupId))
            ) {
                return true;
            }
        }
        return false;
    }

    function canExecuteActionAndUseWallet(
        uint256 apiKeyHash,
        uint256 cidHash,
        address walletAddress
    ) public view returns (bool canExecute, bool canUseWallet) {
        AppStorage.Account storage account = getReadOnlyAccount(apiKeyHash);
        AppStorage.UsageApiKey storage usageApiKey = account.usageApiKeys[
            apiKeyHash
        ];

        if (_isExpired(usageApiKey)) {
            return (false, false);
        }

        bool isWildcard = usageApiKey.executeInGroups.contains(0);
        canExecute = isWildcard;

        uint256 len = account.groupList.length();
        for (uint256 i = 0; i < len; i++) {
            if (canExecute && canUseWallet) break;

            uint256 groupId = account.groupList.at(i);
            AppStorage.Group storage group = account.groups[groupId];

            bool cidMatch = group.cidHash.contains(cidHash) ||
                group.cidHash.contains(0);
            if (!cidMatch) continue;

            bool groupPermitted = isWildcard ||
                usageApiKey.executeInGroups.contains(groupId);
            if (!groupPermitted) continue;

            canExecute = true;

            if (!canUseWallet) {
                if (
                    group.pkpId.contains(walletAddress) ||
                    group.pkpId.contains(address(0))
                ) {
                    canUseWallet = true;
                }
            }
        }
    }
}
