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
});
