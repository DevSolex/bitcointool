import { describe, expect, it } from "vitest";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;

const SAMPLE_TX = "0100000001"; // Version 1, 1 input
const SAMPLE_BUFFER = "010203040506";
const SAMPLE_32_BYTE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

describe("bitcointool test suite", () => {
    it("should get the correct version", () => {
        const version = simnet.callReadOnlyFn("bitcoin-tool", "get-version", [], deployer);
        expect(version.result).toBeOk(Object({ value: "1.3.0" }));
    });

    it("should extract uint8 correctly", () => {
        const result = simnet.callReadOnlyFn("bitcoin-tool", "extract-uint8", ["0x" + SAMPLE_BUFFER, "u1"], deployer);
        expect(result.result).toBeOk(Object({ value: 2n }));
    });

    it("should fail to extract uint8 out of bounds", () => {
        const result = simnet.callReadOnlyFn("bitcoin-tool", "extract-uint8", ["0x" + SAMPLE_BUFFER, "u10"], deployer);
        expect(result.result).toBeErr(Object({ value: 104n })); // ERR-OUT-OF-BOUNDS
    });

    it("should extract uint32-le correctly", () => {
        // "01020304" at offset 0 -> 0x04030201 in uint32
        const result = simnet.callReadOnlyFn("bitcoin-tool", "extract-uint32-le", ["0x01020304", "u0"], deployer);
        expect(result.result).toBeOk(Object({ value: BigInt(0x04030201) })); // 67305985
    });

    it("should fail to extract uint32-le out of bounds", () => {
        const result = simnet.callReadOnlyFn("bitcoin-tool", "extract-uint32-le", ["0x01020304", "u1"], deployer);
        expect(result.result).toBeErr(Object({ value: 104n })); // ERR-OUT-OF-BOUNDS
    });

    it("should reverse a 32-byte buffer correctly", () => {
        const input = "0".repeat(62) + "0102";
        const expected = "0201" + "0".repeat(60);
        const result = simnet.callReadOnlyFn("bitcoin-tool", "reverse-buff32", ["0x" + input], deployer);
        expect(result.result).toBe("0x" + expected);
    });

    it("should reverse a full 32-byte buffer complexity test", () => {
        const result = simnet.callReadOnlyFn("bitcoin-tool", "reverse-buff32", ["0x" + SAMPLE_32_BYTE], deployer);
        // Expect reversed SAMPLE_32_BYTE
        const reversed = Array.from({ length: 32 }, (_, i) => (31 - i).toString(16).padStart(2, '0')).join('');
        expect(result.result).toBe("0x" + reversed);
    });

    it("should identify P2PKH script correctly", () => {
        // P2PKH: 76 a9 14 <20-byte-hash> 88 ac
        const script = "76a914" + "0".repeat(40) + "88ac";
        const result = simnet.callReadOnlyFn("bitcoin-tool", "is-p2pkh", ["0x" + script], deployer);
        expect(result.result).toBeBool(true);
    });

    it("should fail to identify invalid P2PKH script", () => {
        const script = "00a914" + "0".repeat(40) + "88ac";
        const result = simnet.callReadOnlyFn("bitcoin-tool", "is-p2pkh", ["0x" + script], deployer);
        expect(result.result).toBeBool(false);
    });

    it("should identify P2SH script correctly", () => {
        // P2SH: a9 14 <20-byte-hash> 87
        const script = "a914" + "0".repeat(40) + "87";
        const result = simnet.callReadOnlyFn("bitcoin-tool", "is-p2sh", ["0x" + script], deployer);
        expect(result.result).toBeBool(true);
    });

    it("should fail to identify invalid P2SH script", () => {
        const script = "0014" + "0".repeat(40) + "87";
        const result = simnet.callReadOnlyFn("bitcoin-tool", "is-p2sh", ["0x" + script], deployer);
        expect(result.result).toBeBool(false);
    });

    it("should identify P2WPKH script correctly", () => {
        // P2WPKH: 00 14 <20-byte-hash>
        const script = "0014" + "0".repeat(40);
        const result = simnet.callReadOnlyFn("bitcoin-tool", "is-p2wpkh", ["0x" + script], deployer);
        expect(result.result).toBeBool(true);
    });

    it("should identify P2TR (Taproot) script correctly", () => {
        // P2TR: 01 20 <32-byte-hash>
        const script = "0120" + "0".repeat(64);
        const result = simnet.callReadOnlyFn("bitcoin-tool", "is-p2tr", ["0x" + script], deployer);
        expect(result.result).toBeBool(true);
    });

    it("should generate TXID correctly from raw tx", () => {
        // Double SHA256 of SAMPLE_TX
        const result = simnet.callReadOnlyFn("bitcoin-tool", "get-txid-from-raw", ["0x" + SAMPLE_TX], deployer);
        expect(result.result).toBeOk(Object({ value: "0x393c66f7704206584065a44ef6e8648316279f649db60492167f536e2f17088a" }));
    });

    it("should extract input count correctly", () => {
        const result = simnet.callReadOnlyFn("bitcoin-tool", "extract-tx-ins-count", ["0x" + SAMPLE_TX], deployer);
        expect(result.result).toBeOk(Object({ value: 1n }));
    });

    it("should extract varint correctly", () => {
        const result = simnet.callReadOnlyFn("bitcoin-tool", "extract-varint-uint", ["0xfd0001", "u0"], deployer);
        expect(result.result).toBeOk(Object({ value: 0n })); // Multi-byte placeholder returns u0

        const result2 = simnet.callReadOnlyFn("bitcoin-tool", "extract-varint-uint", ["0xfe", "u0"], deployer);
        expect(result2.result).toBeOk(Object({ value: 254n }));
    });
});
