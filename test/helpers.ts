import hre from "hardhat";
import { toFunctionSelector, type AbiError } from "viem";

// Cached network connection to ensure all operations use the same instance
let cachedConnection: Awaited<ReturnType<typeof hre.network.connect>> | null = null;

async function getNetworkConnection() {
  if (!cachedConnection) {
    cachedConnection = await hre.network.connect();
  }
  return cachedConnection;
}

// Connect to network and get helpers
export async function getConnection() {
  return getNetworkConnection();
}

// Helper functions to wrap Hardhat 3 network helpers
export async function loadFixture<T>(fixture: () => Promise<T>): Promise<T> {
  const { networkHelpers } = await getNetworkConnection();
  return networkHelpers.loadFixture(fixture);
}

export const time = {
  async latest(): Promise<bigint> {
    const { networkHelpers } = await getNetworkConnection();
    const result = await networkHelpers.time.latest();
    return BigInt(result);
  },
  async increase(seconds: bigint | number): Promise<bigint> {
    const { networkHelpers } = await getNetworkConnection();
    const result = await networkHelpers.time.increase(BigInt(seconds));
    return BigInt(result);
  },
  async increaseTo(timestamp: bigint | number): Promise<void> {
    const { networkHelpers } = await getNetworkConnection();
    await networkHelpers.time.increaseTo(BigInt(timestamp));
  },
  // Pin the NEXT block's timestamp exactly (does not mine); the next tx lands in that block.
  async setNextBlockTimestamp(timestamp: bigint | number): Promise<void> {
    const { networkHelpers } = await getNetworkConnection();
    await networkHelpers.time.setNextBlockTimestamp(BigInt(timestamp));
  },
};

// Derive the 4-byte selector for a custom error from a viem contract's ABI.
// Returns undefined if the contract/ABI/error cannot be resolved.
function customErrorSelector(contract: unknown, errorName: string): string | undefined {
  const abi = (contract as { abi?: readonly unknown[] } | null | undefined)?.abi;
  if (!Array.isArray(abi)) return undefined;
  const entry = abi.find(
    (item): item is AbiError =>
      typeof item === "object" &&
      item !== null &&
      (item as { type?: string }).type === "error" &&
      (item as { name?: string }).name === errorName,
  );
  if (!entry) return undefined;
  try {
    // `toFunctionSelector` computes selectors from function-shaped ABI items;
    // an error selector uses the same keccak(signature)[:4] scheme, so reshape
    // the error entry as a function to derive its 4-byte selector.
    return toFunctionSelector({
      type: "function",
      name: entry.name,
      inputs: entry.inputs ?? [],
      outputs: [],
      stateMutability: "nonpayable",
    });
  } catch {
    return undefined;
  }
}

// Assertion helpers for viem
export const assertions = {
  async revert(promise: Promise<unknown>): Promise<void> {
    try {
      await promise;
      throw new Error("Expected transaction to revert, but it succeeded");
    } catch (error: unknown) {
      // Check if it's a revert error (not our assertion error)
      if (
        error instanceof Error &&
        error.message === "Expected transaction to revert, but it succeeded"
      ) {
        throw error;
      }
      // Transaction reverted as expected
      return;
    }
  },
  async revertWithCustomError(
    promise: Promise<unknown>,
    contract: unknown,
    errorName: string,
    _args?: unknown[],
  ): Promise<void> {
    try {
      await promise;
      throw new Error(`Expected transaction to revert with ${errorName}, but it succeeded`);
    } catch (error: unknown) {
      // Check if it's our assertion error
      if (error instanceof Error && error.message.startsWith("Expected transaction to revert")) {
        throw error;
      }
      const errorStr = String(error);
      // Primary match: viem decodes and prints the custom error name in the message.
      if (errorStr.includes(errorName)) {
        return;
      }
      // Fallback match: some viem error paths (e.g. gas-estimation failures) only
      // surface the raw 4-byte selector, not the decoded name. Match the selector
      // derived from the contract ABI so the assertion stays SPECIFIC to errorName.
      const selector = customErrorSelector(contract, errorName);
      if (selector && errorStr.toLowerCase().includes(selector.toLowerCase())) {
        return;
      }
      throw new Error(`Expected revert with ${errorName}, but got: ${errorStr.slice(0, 200)}`);
    }
  },
};
