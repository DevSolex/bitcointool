import { describe, expect, it } from "vitest";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;

describe("bitcointool test suite", () => {
    it("should get the correct version", () => {
        const version = simnet.callReadOnlyFn("bitcoin-tool", "get-version", [], deployer);
        expect(version.result).toBeOk(Object({ value: "1.3.0" }));
    });
});
