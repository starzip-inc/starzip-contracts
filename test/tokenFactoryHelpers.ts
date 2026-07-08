/**
 * Shared test helpers for the 3-bucket `TokenFactory` / `LaunchpadV1` issuance flow
 * (LAUNCHPAD escrow, LIQUIDITY_RESERVE, OWNER_VESTING wallet;
 * the original design's OCT bucket was removed as part of the fixed-supply finalization).
 * Centralizes the boilerplate every consumer fixture needs:
 *   1. Deploy ERC20V1 beacon + TokenVestingWallet beacon + TokenFactory proxy.
 *   2. Configure allocation guides for all 3 buckets (2-day timelock, propose+execute).
 *   3. Configure `linkedLaunchpad` (2-day timelock, propose+execute).
 *   4. Sign + submit the 14-field `IssuePermit` (adds the 6 ratio fields +
 *      `linkedLaunchpad` on top of the original 7-field permit).
 *
 * Any test that only needs "a token exists, business holds a spendable balance" (ERC20V1,
 * Security, TradeSettlement* fixtures) should route LIQUIDITY_RESERVE to a neutral EOA
 * (never `businessAccount` — the factory's self-deal guard rejects that) and then forward
 * the proceeds to `businessAccount` with a plain `transfer`, mirroring the old "business
 * receives ~90%" assumption those test bodies were written against.
 */
import { encodeFunctionData, parseEventLogs, getAddress, type Hex, type Address } from "viem";
import { signTypedData } from "viem/accounts";
import { getConnection, time } from "./helpers.js";

export const ALLOCATION_GUIDE_DELAY = 2n * 24n * 60n * 60n; // 2 days
export const CONFIG_DELAY = 2n * 24n * 60n * 60n; // 2 days

// Within [MIN_OWNER_VESTING_DURATION=30d, MAX_OWNER_VESTING_DURATION=3650d].
export const DEFAULT_OWNER_VESTING_DURATION = 365n * 24n * 60n * 60n;

export const BUCKET_LAUNCHPAD = 0;
export const BUCKET_LIQUIDITY_RESERVE = 1;
export const BUCKET_OWNER_VESTING = 2;

/** Propose + advance + execute an allocation guide for a single bucket. */
export async function setAllocationGuide(
  tokenFactory: any,
  owner: any,
  bucket: number,
  minBp: number | bigint,
  maxBp: number | bigint,
): Promise<void> {
  await tokenFactory.write.proposeAllocationGuide([bucket, minBp, maxBp], {
    account: owner.account,
  });
  await time.increase(ALLOCATION_GUIDE_DELAY);
  await tokenFactory.write.executeAllocationGuide([bucket], { account: owner.account });
}

/**
 * Configure permissive guides for all 3 buckets (wide ranges) so callers can pick any
 * bp split summing to 10000. LIQUIDITY_RESERVE respects the 1bp floor
 * (`LIQUIDITY_RESERVE_MIN_BP_FLOOR`).
 */
export async function configureDefaultAllocationGuides(
  tokenFactory: any,
  owner: any,
): Promise<void> {
  await tokenFactory.write.proposeAllocationGuide([BUCKET_LAUNCHPAD, 0, 10000], {
    account: owner.account,
  });
  await tokenFactory.write.proposeAllocationGuide([BUCKET_LIQUIDITY_RESERVE, 1, 10000], {
    account: owner.account,
  });
  await tokenFactory.write.proposeAllocationGuide([BUCKET_OWNER_VESTING, 0, 10000], {
    account: owner.account,
  });
  await time.increase(ALLOCATION_GUIDE_DELAY);
  await tokenFactory.write.executeAllocationGuide([BUCKET_LAUNCHPAD], { account: owner.account });
  await tokenFactory.write.executeAllocationGuide([BUCKET_LIQUIDITY_RESERVE], {
    account: owner.account,
  });
  await tokenFactory.write.executeAllocationGuide([BUCKET_OWNER_VESTING], {
    account: owner.account,
  });
}

/** Propose + advance + execute the `linkedLaunchpad` pointer. */
export async function setLinkedLaunchpad(
  tokenFactory: any,
  owner: any,
  launchpadAddress: Address,
): Promise<void> {
  await tokenFactory.write.proposeLinkedLaunchpadChange([launchpadAddress], {
    account: owner.account,
  });
  await time.increase(CONFIG_DELAY);
  await tokenFactory.write.executeLinkedLaunchpadChange([], { account: owner.account });
}

/** Propose + advance + execute the escrow reclaim timeout. */
export async function setEscrowTimeout(
  tokenFactory: any,
  owner: any,
  seconds: bigint,
): Promise<void> {
  await tokenFactory.write.proposeEscrowTimeoutChange([seconds], { account: owner.account });
  await time.increase(CONFIG_DELAY);
  await tokenFactory.write.executeEscrowTimeoutChange([], { account: owner.account });
}

/** Deploy ERC20V1 beacon + TokenVestingWallet beacon + the TokenFactory proxy. */
export async function deployTokenFactoryCore(
  viem: any,
  deployer: any,
  platformTreasuryAddress: Address,
  permitSignerAddress: Address,
): Promise<{
  erc20Impl: any;
  erc20Beacon: any;
  vestingWalletImpl: any;
  vestingWalletBeacon: any;
  tokenFactoryImpl: any;
  tokenFactory: any;
}> {
  const erc20Impl = await viem.deployContract("ERC20V1", []);
  const erc20Beacon = await viem.deployContract("UpgradeableBeacon", [
    erc20Impl.address,
    deployer.account.address,
  ]);

  const vestingWalletImpl = await viem.deployContract("TokenVestingWallet", []);
  const vestingWalletBeacon = await viem.deployContract("UpgradeableBeacon", [
    vestingWalletImpl.address,
    deployer.account.address,
  ]);

  const tokenFactoryImpl = await viem.deployContract("TokenFactory", []);
  const initData = encodeFunctionData({
    abi: tokenFactoryImpl.abi,
    functionName: "initialize",
    args: [
      erc20Beacon.address,
      platformTreasuryAddress,
      permitSignerAddress,
      vestingWalletBeacon.address,
    ],
  });
  const tokenFactoryProxy = await viem.deployContract("ERC1967Proxy", [
    tokenFactoryImpl.address,
    initData,
  ]);
  const tokenFactory = await viem.getContractAt("TokenFactory", tokenFactoryProxy.address);

  return {
    erc20Impl,
    erc20Beacon,
    vestingWalletImpl,
    vestingWalletBeacon,
    tokenFactoryImpl,
    tokenFactory,
  };
}

export type Ratios = {
  launchpadBp: bigint;
  liquidityBp: bigint;
  ownerBp: bigint;
  liquidityRecipient: Address;
  ownerVestingCliff: bigint;
  ownerVestingDuration: bigint;
};

export function buildRatios(input: {
  launchpadBp: number | bigint;
  liquidityBp: number | bigint;
  ownerBp: number | bigint;
  liquidityRecipient: Address;
  ownerVestingCliff?: bigint;
  ownerVestingDuration?: bigint;
}): Ratios {
  return {
    launchpadBp: BigInt(input.launchpadBp),
    liquidityBp: BigInt(input.liquidityBp),
    ownerBp: BigInt(input.ownerBp),
    liquidityRecipient: input.liquidityRecipient,
    ownerVestingCliff: input.ownerVestingCliff ?? 0n,
    ownerVestingDuration: input.ownerVestingDuration ?? DEFAULT_OWNER_VESTING_DURATION,
  };
}

/** Sign the 14-field `IssuePermit` (adds ratio fields + `linkedLaunchpad`). */
export async function signIssuePermit(params: {
  privateKey: Hex;
  chainId: number;
  verifyingContract: Address;
  businessAccount: Address;
  name: string;
  symbol: string;
  totalSupply: bigint;
  contractURI: string;
  ratios: Ratios;
  linkedLaunchpad: Address;
  nonce: bigint;
  deadline: bigint;
}): Promise<Hex> {
  return signTypedData({
    privateKey: params.privateKey,
    domain: {
      name: "TokenFactory",
      version: "1",
      chainId: params.chainId,
      verifyingContract: params.verifyingContract,
    },
    types: {
      IssuePermit: [
        { name: "businessAccount", type: "address" },
        { name: "name", type: "string" },
        { name: "symbol", type: "string" },
        { name: "totalSupply", type: "uint256" },
        { name: "contractURI", type: "string" },
        { name: "launchpadBp", type: "uint16" },
        { name: "liquidityBp", type: "uint16" },
        { name: "ownerBp", type: "uint16" },
        { name: "liquidityRecipient", type: "address" },
        { name: "ownerVestingCliff", type: "uint64" },
        { name: "ownerVestingDuration", type: "uint64" },
        { name: "linkedLaunchpad", type: "address" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    },
    primaryType: "IssuePermit",
    message: {
      businessAccount: params.businessAccount,
      name: params.name,
      symbol: params.symbol,
      totalSupply: params.totalSupply,
      contractURI: params.contractURI,
      launchpadBp: params.ratios.launchpadBp,
      liquidityBp: params.ratios.liquidityBp,
      ownerBp: params.ratios.ownerBp,
      liquidityRecipient: params.ratios.liquidityRecipient,
      ownerVestingCliff: params.ratios.ownerVestingCliff,
      ownerVestingDuration: params.ratios.ownerVestingDuration,
      linkedLaunchpad: params.linkedLaunchpad,
      nonce: params.nonce,
      deadline: params.deadline,
    },
  });
}

/**
 * Sign + submit `issueToken`. Returns the tx hash plus the resolved token/vesting-wallet
 * addresses (parsed from the `TokenIssued` event).
 */
export async function issueTokenWithRatios(params: {
  tokenFactory: any;
  business: any;
  publicClient: any;
  chainId: number;
  permitPrivateKey: Hex;
  linkedLaunchpad: Address;
  name: string;
  symbol: string;
  totalSupply: bigint;
  contractURI?: string;
  ratios: Ratios;
  deadline?: bigint;
}): Promise<{ hash: Hex; tokenAddress: Address; vestingWallet: Address }> {
  const { tokenFactory, business, publicClient, chainId, permitPrivateKey, linkedLaunchpad } =
    params;
  const contractURI = params.contractURI ?? "";
  const deadline = params.deadline ?? (await time.latest()) + 3600n;
  const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;

  const signature = await signIssuePermit({
    privateKey: permitPrivateKey,
    chainId,
    verifyingContract: tokenFactory.address,
    businessAccount: business.account.address,
    name: params.name,
    symbol: params.symbol,
    totalSupply: params.totalSupply,
    contractURI,
    ratios: params.ratios,
    linkedLaunchpad,
    nonce,
    deadline,
  });

  const hash = await tokenFactory.write.issueToken(
    [
      params.name,
      params.symbol,
      params.totalSupply,
      contractURI,
      params.ratios,
      deadline,
      signature,
    ],
    { account: business.account },
  );
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const issued = parseEventLogs({
    abi: tokenFactory.abi,
    logs: receipt.logs,
    eventName: "TokenIssued",
  });
  const tokenAddress = getAddress((issued[0] as any).args.tokenAddress as Address);
  const vestingWallet = getAddress((issued[0] as any).args.vestingWallet as Address);

  return { hash, tokenAddress, vestingWallet };
}

/**
 * One-call convenience: deploy the TokenFactory core, wire permissive allocation guides
 * + a `linkedLaunchpad` placeholder (any contract address — tests that don't exercise
 * escrow/vesting-trigger never call it), then issue a single token whose LIQUIDITY_RESERVE
 * bucket is routed to `neutralRecipient` and immediately forwarded to `business` so it
 * ends up holding the full non-escrowed supply (mirrors the "business holds
 * ~90% immediately" assumption most consumer fixtures were written against — the
 * self-deal guard blocks routing LIQUIDITY_RESERVE directly to `businessAccount`).
 *
 * `neutralRecipient` must be a wallet client the caller controls (its `.account` signs
 * the forwarding transfer) — typically the deployer/owner wallet.
 */
export async function deploySimpleTokenFixture(params: {
  viem: any;
  deployer: any;
  business: any;
  neutralRecipient: any;
  publicClient: any;
  chainId: number;
  permitPrivateKey: Hex;
  permitSignerAddress: Address;
  platformTreasuryAddress: Address;
  totalSupply: bigint;
  name: string;
  symbol: string;
  /** Defaults to the freshly-deployed `erc20Beacon` (a real contract address — fine as a
   *  placeholder since these tests never exercise escrow/vesting-trigger). */
  linkedLaunchpadPlaceholder?: Address;
}) {
  const core = await deployTokenFactoryCore(
    params.viem,
    params.deployer,
    params.platformTreasuryAddress,
    params.permitSignerAddress,
  );

  const linkedLaunchpadPlaceholder = params.linkedLaunchpadPlaceholder ?? core.erc20Beacon.address;
  await configureDefaultAllocationGuides(core.tokenFactory, params.deployer);
  await setLinkedLaunchpad(core.tokenFactory, params.deployer, linkedLaunchpadPlaceholder);

  const ratios = buildRatios({
    launchpadBp: 0,
    liquidityBp: 10000,
    ownerBp: 0,
    liquidityRecipient: params.neutralRecipient.account.address,
  });

  const { tokenAddress, vestingWallet } = await issueTokenWithRatios({
    tokenFactory: core.tokenFactory,
    business: params.business,
    publicClient: params.publicClient,
    chainId: params.chainId,
    permitPrivateKey: params.permitPrivateKey,
    linkedLaunchpad: linkedLaunchpadPlaceholder,
    name: params.name,
    symbol: params.symbol,
    totalSupply: params.totalSupply,
    ratios,
  });

  const token = await params.viem.getContractAt("ERC20V1", tokenAddress);

  const forwardAmount = (await token.read.balanceOf([
    params.neutralRecipient.account.address,
  ])) as bigint;
  if (forwardAmount > 0n) {
    await token.write.transfer([params.business.account.address, forwardAmount], {
      account: params.neutralRecipient.account,
    });
  }

  return { ...core, token, tokenAddress, vestingWallet, ratios };
}
