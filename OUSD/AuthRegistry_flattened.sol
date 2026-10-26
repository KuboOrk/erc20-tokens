// SPDX-License-Identifier: MIT
// v0.8.30+commit.73712a01 
// Optimization: no
// EvmVersion: prague
// -------------------------
// 1. deploy AuthRegistry.sol
// 2. deploy ReserveLedger.sol
// 3. deploy StablecoinTemplateV3
// -------------------------

// File: OUSD/auth-registry/src/IAuthRegistry.sol


pragma solidity ^0.8.12;

interface IAuthRegistry {

    /*//////////////////////////////////////////////////////////////
                         GENERAL POLICY STORAGE
    //////////////////////////////////////////////////////////////*/

    enum PolicyType {
        WHITELIST,
        BLACKLIST
    }

    struct PolicyData {
        PolicyType policyType;
        address admin;
        uint64 parentPolicyId;
        bool parentPolicyIdIsSet;
    }

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error Unauthorized();
    error IncompatiblePolicyType();
    error PolicyDoesNotExist();
    error ArrayLengthMismatch();
    error InvalidParentPolicyId();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event PolicyAdminUpdated(
        uint64 indexed policyId, address indexed updater, address indexed admin
    );
    event PolicyCreated(uint64 indexed policyId, address indexed updater, PolicyType policyType);
    event WhitelistUpdated(
        uint64 indexed policyId, address indexed updater, address indexed account, bool allowed
    );
    event BlacklistUpdated(
        uint64 indexed policyId, address indexed updater, address indexed account, bool restricted
    );
    event ParentPolicyUpdated(
        uint64 indexed policyId, address indexed updater, uint64 indexed parentPolicyId, bool set
    );

    /*//////////////////////////////////////////////////////////////
                        GENERAL POLICY QUERYING
    //////////////////////////////////////////////////////////////*/

    function isAuthorized(uint64 policyId, address user) external view returns (bool);

}

// File: OUSD/auth-registry/src/AuthRegistry.sol


pragma solidity ^0.8.13;


/**
 * @title AuthRegistry
 * @notice A registry for managing whitelist and blacklist authorization policies, and checking
 *         authorization for accounts according to those policies.
 */
contract AuthRegistry is IAuthRegistry {

    uint64 public policyIdCounter = 2; // Skip special policies (documented in isAuthorized).

    mapping(uint64 => PolicyData) public policyData;

    /*//////////////////////////////////////////////////////////////
                      POLICY TYPE-SPECIFIC STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint64 => mapping(address => bool)) internal policySet;

    /*//////////////////////////////////////////////////////////////
                      GENERAL POLICY ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    function createPolicy(address admin, PolicyType policyType)
        public
        returns (uint64 newPolicyId)
    {
        policyData[newPolicyId = policyIdCounter++] = PolicyData({
            policyType: policyType, admin: admin, parentPolicyId: 0, parentPolicyIdIsSet: false
        });

        emit PolicyCreated(newPolicyId, msg.sender, policyType);
        emit PolicyAdminUpdated(newPolicyId, msg.sender, admin);
    }

    function createPolicy(address admin, PolicyType policyType, uint64 parentPolicyId)
        public
        returns (uint64 newPolicyId)
    {
        newPolicyId = policyIdCounter++;
        _validateParentPolicy(policyType, newPolicyId, parentPolicyId);

        policyData[newPolicyId] = PolicyData({
            policyType: policyType,
            admin: admin,
            parentPolicyId: parentPolicyId,
            parentPolicyIdIsSet: true
        });

        emit PolicyCreated(newPolicyId, msg.sender, policyType);
        emit PolicyAdminUpdated(newPolicyId, msg.sender, admin);
        emit ParentPolicyUpdated(newPolicyId, msg.sender, parentPolicyId, true);
    }

    function createPolicy(address admin, PolicyType policyType, address[] memory accounts)
        public
        returns (uint64 newPolicyId)
    {
        newPolicyId = policyIdCounter++;

        policyData[newPolicyId] = PolicyData({
            policyType: policyType, admin: admin, parentPolicyId: 0, parentPolicyIdIsSet: false
        });

        // Set the initial policy set.
        for (uint256 i = 0; i < accounts.length; i++) {
            policySet[newPolicyId][accounts[i]] = true;

            if (policyType == PolicyType.WHITELIST) {
                emit WhitelistUpdated(newPolicyId, msg.sender, accounts[i], true);
            } else {
                emit BlacklistUpdated(newPolicyId, msg.sender, accounts[i], true);
            }
        }

        emit PolicyCreated(newPolicyId, msg.sender, policyType);
        emit PolicyAdminUpdated(newPolicyId, msg.sender, admin);
    }

    function createPolicy(
        address admin,
        PolicyType policyType,
        uint64 parentPolicyId,
        address[] memory accounts
    ) public returns (uint64 newPolicyId) {
        newPolicyId = policyIdCounter++;

        _validateParentPolicy(policyType, newPolicyId, parentPolicyId);

        policyData[newPolicyId] = PolicyData({
            policyType: policyType,
            admin: admin,
            parentPolicyId: parentPolicyId,
            parentPolicyIdIsSet: true
        });

        // Set the initial policy set.
        for (uint256 i = 0; i < accounts.length; i++) {
            policySet[newPolicyId][accounts[i]] = true;

            if (policyType == PolicyType.WHITELIST) {
                emit WhitelistUpdated(newPolicyId, msg.sender, accounts[i], true);
            } else {
                emit BlacklistUpdated(newPolicyId, msg.sender, accounts[i], true);
            }
        }

        emit PolicyCreated(newPolicyId, msg.sender, policyType);
        emit PolicyAdminUpdated(newPolicyId, msg.sender, admin);
        emit ParentPolicyUpdated(newPolicyId, msg.sender, parentPolicyId, true);
    }

    function setPolicyAdmin(uint64 policyId, address admin) external {
        require(policyData[policyId].admin == msg.sender, Unauthorized());

        policyData[policyId].admin = admin;

        emit PolicyAdminUpdated(policyId, msg.sender, admin);
    }

    function modifyParentPolicy(uint64 policyId, uint64 parentPolicyId, bool setting) external {
        require(policyData[policyId].admin == msg.sender, Unauthorized());

        if (setting) {
            _validateParentPolicy(policyData[policyId].policyType, policyId, parentPolicyId);
            policyData[policyId].parentPolicyId = parentPolicyId;
            policyData[policyId].parentPolicyIdIsSet = true;
        } else {
            policyData[policyId].parentPolicyId = 0;
            policyData[policyId].parentPolicyIdIsSet = false;
        }

        emit ParentPolicyUpdated(policyId, msg.sender, parentPolicyId, setting);
    }

    /*//////////////////////////////////////////////////////////////
                   POLICY TYPE-SPECIFIC ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    function modifyPolicyWhitelist(uint64 policyId, address account, bool allowed) external {
        _modifyPolicyWhitelist(policyId, account, allowed);
    }

    function modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) external {
        _modifyPolicyBlacklist(policyId, account, restricted);
    }

    function batchModifyPolicyWhitelist(uint64 policyId, address[] calldata accounts, bool allowed)
        external
    {
        for (uint256 i = 0; i < accounts.length; i++) {
            _modifyPolicyWhitelist(policyId, accounts[i], allowed);
        }
    }

    function batchModifyPolicyBlacklist(
        uint64 policyId,
        address[] calldata accounts,
        bool restricted
    ) external {
        for (uint256 i = 0; i < accounts.length; i++) {
            _modifyPolicyBlacklist(policyId, accounts[i], restricted);
        }
    }

    /*//////////////////////////////////////////////////////////////
                        GENERAL POLICY QUERYING
    //////////////////////////////////////////////////////////////*/

    function isAuthorized(uint64 policyId, address user) public view override returns (bool) {
        PolicyData memory data = policyData[policyId];

        if (policyId < 2) {
            // policyId == 0 is the "always-reject" policy.
            // policyId == 1 is the "always-allow" policy.
            return policyId == 1;
        }

        bool policySetForUser = policySet[policyId][user];

        if (policySetForUser) {
            return data.policyType == PolicyType.WHITELIST;
        }

        if (data.parentPolicyIdIsSet) {
            return isAuthorized(data.parentPolicyId, user);
        }

        return data.policyType == PolicyType.BLACKLIST;
    }

    /*//////////////////////////////////////////////////////////////
                        Internal Functions
    //////////////////////////////////////////////////////////////*/

    function _modifyPolicyWhitelist(uint64 policyId, address account, bool allowed) internal {
        PolicyData memory data = policyData[policyId];

        require(data.admin == msg.sender, Unauthorized());
        require(data.policyType == PolicyType.WHITELIST, IncompatiblePolicyType());

        policySet[policyId][account] = allowed;

        emit WhitelistUpdated(policyId, msg.sender, account, allowed);
    }

    function _modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) internal {
        PolicyData memory data = policyData[policyId];

        require(data.admin == msg.sender, Unauthorized());
        require(data.policyType == PolicyType.BLACKLIST, IncompatiblePolicyType());

        policySet[policyId][account] = restricted;

        emit BlacklistUpdated(policyId, msg.sender, account, restricted);
    }

    function _validateParentPolicy(PolicyType policyType, uint64 policyId, uint64 parentPolicyId)
        internal
        view
    {
        require(parentPolicyId >= 2, InvalidParentPolicyId());

        require(
            parentPolicyId < policyIdCounter && parentPolicyId != policyId, InvalidParentPolicyId()
        );
        require(policyData[parentPolicyId].policyType == policyType, InvalidParentPolicyId());
    }

}
