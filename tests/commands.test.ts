import { describe, it, expect } from "vitest";
import { deviceInformation } from "../src/commands/device-information.js";
import {
  buildCommand,
  parseCommandResponse,
} from "../src/commands/registry.js";
describe("Command registry", () => {
  it("accepts absent facts and unknown battery", () => {
    expect(
      deviceInformation.parseResponse({ QueryResponses: { BatteryLevel: -1 } }),
    ).toEqual({ BatteryLevel: -1 });
    expect(deviceInformation.parseResponse({ QueryResponses: {} })).toEqual({});
  });
  it("checks network rights independently", () => {
    expect(() =>
      buildCommand(
        "DeviceInformation",
        { Queries: ["WiFiMAC"] },
        { platform: "ios", access_rights: 16 },
      ),
    ).toThrow("AccessRights");
  });
  it("requires exactly six PIN digits on a Mac", () => {
    for (const PIN of [undefined, "12345", "abcdef", "1234567"])
      expect(() =>
        buildCommand(
          "DeviceLock",
          { PIN },
          { platform: "macos", access_rights: 8191 },
        ),
      ).toThrow();
    expect(
      buildCommand(
        "DeviceLock",
        { PIN: "012345" },
        { platform: "macos", access_rights: 8191 },
      ).PIN,
    ).toBe("012345");
  });
  it("does not send PIN to iOS", () => {
    expect(
      buildCommand(
        "DeviceLock",
        { PIN: "012345" },
        { platform: "ios", access_rights: 8191 },
      ),
    ).toEqual({ RequestType: "DeviceLock" });
  });
  it("parses the three additional response envelopes", () => {
    expect(
      parseCommandResponse("ProfileList", {
        ProfileList: [{ PayloadIdentifier: "test" }],
      }),
    ).toEqual([{ PayloadIdentifier: "test" }]);
    expect(
      parseCommandResponse("SecurityInfo", {
        SecurityInfo: { PasscodePresent: true },
      }),
    ).toEqual({ PasscodePresent: true });
    expect(
      parseCommandResponse("InstalledApplicationList", {
        InstalledApplicationList: [{ Identifier: "com.example.app" }],
      }),
    ).toEqual([{ Identifier: "com.example.app" }]);
  });
});
