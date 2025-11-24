import { derToPem } from "../src/utils";

describe("derToPem", () => {
  it("should convert a valid DER buffer to PEM format", () => {
    // Sample DER (minimal valid certificate starting bytes, just for test)
    // Real DER is more complex, but for testing the function
    const derBuffer = Buffer.from("3082", "hex"); // Example minimal DER

    const pem = derToPem(derBuffer);
    expect(pem).toContain("-----BEGIN CERTIFICATE-----");
    expect(pem).toContain("-----END CERTIFICATE-----");
    expect(pem).toContain("MII"); // Base64 starts with MII for cert
  });

  it("should throw error for invalid DER buffer", () => {
    const invalidDer = Buffer.alloc(0);
    expect(() => derToPem(invalidDer)).toThrow("Invalid DER buffer");
  });
});
