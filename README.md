# StarZip Contracts

Smart contracts for the StarZip platform — a token launchpad, fixed-supply store-token
issuance system, non-custodial trade settlement layer, and an ERC-4337 smart-account stack.

This repository is a self-contained package prepared for external security audit. It
compiles and runs its full test suite standalone (`npm install && npm test`).

## Audit Scope

The following contracts are the subject of the audit:

| Contract | Path | Proxy | Role |
| --- | --- | --- | --- |
| `LaunchpadV1` | `contracts/launchpad/LaunchpadV1.sol` | UUPS | Token launchpad: investor participation (USDT), fund split, per-launchpad vesting, finalize / cancel / timeout refund |
| `TokenFactory` | `contracts/token/TokenFactory.sol` | UUPS | Issues fixed-supply store tokens; 3-bucket allocation (launchpad escrow / liquidity reserve / owner vesting); deploys vesting wallets |
| `ERC20V1` | `contracts/token/ERC20V1.sol` | Beacon | The issued store token: fixed supply (cap locked at issuance), blacklist/pause with platform-infrastructure exemptions |
| `TradeSettlementV1` | `contracts/trade/TradeSettlementV1.sol` | UUPS | Non-custodial settlement for an off-chain order book: signature-gated debits, session keys, self-withdrawals |
| `TokenVestingWallet` | `contracts/vesting/TokenVestingWallet.sol` | Beacon/clone | Per-token owner-allocation vesting wallet (ERC-7201 namespaced storage) |
| `StarzipWallet` | `contracts/wallet/StarzipWallet.sol` | Beacon/clone | ERC-4337 smart account (P256/passkey + owner sentinel; social-recovery-ready layout) |
| `VerifyingPaymaster` | `contracts/wallet/VerifyingPaymaster.sol` | — | ERC-4337 paymaster: sponsorship budgets/caps, timestamp-free validation |
| `StarzipWalletFactory` | `contracts/wallet/StarzipWalletFactory.sol` | — | Deterministic account factory for `StarzipWallet` |

Supporting infrastructure also included (shared by the above): `contracts/UpgradeableBeacon.sol`,
`contracts/ERC1967Proxy.sol`.

### Not in audit scope (test-only support)

The following are test scaffolding, present only so the audit team can compile and run the
suite. They are **not** deployed to production and are not part of the review:

- `contracts/USDT.sol` — an 18-decimal ERC-20 stand-in for the real stablecoin used in tests.
- `contracts/mocks/*` — mock EntryPoint, ERC-721/1155/1271 tokens, gas probe, and adversarial
  contracts used by negative tests.

## Architecture

- **Upgradeability.** `LaunchpadV1`, `TokenFactory`, and `TradeSettlementV1` are UUPS proxies
  with request → delay → execute upgrade timelocks. `ERC20V1` and `TokenVestingWallet` are
  deployed behind beacons/clones. `StarzipWallet` is an ERC-4337 account deployed by
  `StarzipWalletFactory`.
- **Fixed-supply store tokens.** `TokenFactory.issueToken` mints the full supply and locks the
  `ERC20V1` cap to that amount in the same transaction; there is no post-issuance mint path.
- **Non-custodial settlement.** In `TradeSettlementV1`, every balance debit is authorized by the
  debited account's EIP-712 signature or a registered session key. The operator is a pure relayer
  and cannot move user funds unilaterally. Direct self-withdrawals are always available (exempt
  from pause). The unsigned net-delta settlement path is disabled by default.

## Tech Stack

- Solidity `0.8.30`, EVM target **Cancun**, `viaIR` enabled, optimizer runs `200`
- OpenZeppelin Contracts / Contracts-Upgradeable `v5.5.0`
- `@account-abstraction/contracts` `0.8.0` (EntryPoint v0.8)
- Hardhat `3.x`, viem, TypeScript
- Target chain: **opBNB** (chainId 204)

## Build & Test

```bash
npm install
npm run compile     # hardhat compile
npm test            # hardhat test — full suite (307 tests)
npm run lint        # solhint
```

## Trust Model & Assumptions

- **Privileged ownership is a multisig behind a timelock in production.** UUPS proxy owners and
  beacon owners are expected to be a multisig; the code additionally timelocks upgrades and the
  most sensitive setters. Several immediate owner setters remain and are assumed to be operated by
  an honest multisig.
- **`TradeSettlementV1` custody.** The non-custodial guarantee holds for the signature-gated
  order-settlement path and self-withdrawals under an assumed-compromised *operator*. It is
  conditional on an honest *owner* (e.g. enabling the net-delta path or delisting a token are
  owner powers).
- **Store-token controls.** `ERC20V1` grants the issuing business blacklist/pause powers for
  compliance; platform-infrastructure addresses (launchpad, factory, vesting wallet, settlement)
  are exempted so distributions to end users cannot be blocked.
