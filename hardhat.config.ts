import { defineConfig } from "hardhat/config";
import HardhatToolboxViem from "@nomicfoundation/hardhat-toolbox-viem";

export default defineConfig({
  plugins: [HardhatToolboxViem],
  solidity: {
    version: "0.8.30",
    settings: {
      viaIR: true,
      evmVersion: "cancun",
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      type: "edr-simulated",
      chainId: 31337,
    },
    localhost: {
      type: "http",
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
    // Fork of live opBNB testnet state. Used by exactly one test (the RIP-7212 P-256 precompile
    // gas floor in `test/StarzipWallet_publicAuditMap.test.ts`), which is `it.skip`-ed unless
    // `OPBNB_TESTNET_ARCHIVE_RPC_URL` is set — so the default `npm test` never touches the network.
    //
    // NOT PINNED BY DEFAULT. The public endpoint is not an archive node: it serves roughly a
    // two-minute window of state and returns `missing trie node` beyond it, so any hardcoded block
    // number is broken within minutes of being written. To pin, supply an archive endpoint in
    // `OPBNB_TESTNET_ARCHIVE_RPC_URL` and a height in `OPBNB_FORK_BLOCK`.
    opbnbTestnetFork: {
      type: "edr-simulated",
      chainId: 5611,
      forking: {
        url: process.env.OPBNB_TESTNET_ARCHIVE_RPC_URL ?? "https://opbnb-testnet-rpc.bnbchain.org",
        ...(process.env.OPBNB_FORK_BLOCK
          ? { blockNumber: Number(process.env.OPBNB_FORK_BLOCK) }
          : {}),
      },
    },
  },
});
