import { describe, it, expect } from "vitest";
import { buildPlist } from "../src/plist/build.js";
import { parsePlist, sniffPlistFormat } from "../src/plist/parse.js";
import { uuidV5 } from "../src/profile.js";
import { readFile } from "node:fs/promises";
describe("Plist serialization", () => {
  it("preserves data, dates, arrays and numeric values", () => {
    const p = {
      data: Buffer.from([0, 1, 255]),
      date: new Date("2024-01-01T00:00:00Z"),
      list: [1, 0.5, true, "text"],
    };
    expect(parsePlist(Buffer.from(buildPlist(p)))).toEqual(p);
    expect(buildPlist(p)).toContain("<data>");
  });
  it("accepts empty bodies and BOM", () => {
    expect(parsePlist(Buffer.alloc(0))).toBeNull();
    expect(sniffPlistFormat(Buffer.from("\uFEFF  " + buildPlist({})))).toBe(
      "xml",
    );
  });
  it("parses a binary plist fixture", async () => {
    const encoded = await readFile(
      new URL("fixtures/check-out.binary.plist.b64", import.meta.url),
      "utf8",
    );
    const bytes = Buffer.from(encoded.trim(), "base64");
    expect(sniffPlistFormat(bytes)).toBe("binary");
    expect(parsePlist(bytes)).toEqual({
      MessageType: "CheckOut",
      Topic: "com.apple.mgmt.External.00000000-0000-0000-0000-000000000000",
      UDID: "binary-device",
    });
  });
  it("rejects malformed, deeply nested and entity input", () => {
    expect(() => parsePlist(Buffer.from("broken"))).toThrow();
    expect(() =>
      parsePlist(
        Buffer.from(
          "<plist>" + "<array>".repeat(60) + "</array>".repeat(60) + "</plist>",
        ),
      ),
    ).toThrow();
    expect(() =>
      parsePlist(
        Buffer.from(
          '<!DOCTYPE plist [<!ENTITY a "x">]><plist><string>&a;</string></plist>',
        ),
      ),
    ).toThrow();
  });
  it("generates RFC UUIDv5 deterministically", () => {
    expect(uuidV5("www.widgets.com")).toBe(
      "21f7f8de-8051-5b89-8680-0195ef798b6a",
    );
  });
});
