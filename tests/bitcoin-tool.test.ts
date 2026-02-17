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
});
