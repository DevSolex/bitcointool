# bitcointool

Bitcoin tools and SPV (Simplified Payment Verification) utilities on Stacks.

This project provides a Clarity smart contract that allows for trustless verification of Bitcoin transactions directly on the Stacks blockchain.

## Features

- **Merkle Proof Verification**: Verify that a transaction is part of a specific Bitcoin block's Merkle tree.
- **Endianness Utilities**: Helper functions to handle Bitcoin's Little-Endian format in Clarity.
- **SPV Integration**: Enables building Bitcoin-aware smart contracts (e.g., cross-chain swaps, Bitcoin-triggered events).

## Contract API

### `verify-tx-inclusion`

Verifies if a transaction hash is included in a block with a given Merkle root and proof.

- `tx-hash-le`: 32-byte buffer (Little-Endian transaction ID).
- `merkle-root-le`: 32-byte buffer (Little-Endian Merkle root from block header).
- `proof`: List of 32-byte hashes (Merkle path).
- `index`: The leaf index in the Merkle tree.

## Development

Requires [Clarinet](https://github.com/hirosystems/clarinet).

```bash
# Check the contract
clarinet check

# Run tests
clarinet test
```
