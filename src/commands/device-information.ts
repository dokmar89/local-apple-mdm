import { z } from "zod";
import { dict } from "../plist/parse.js";
import type { PlistDict } from "../plist/build.js";
import { AccessRights } from "./access-rights.js";
// Baseline availability is iOS 4 / macOS 10.7 unless overridden below.
// Apple's schema is authoritative; unsupported queries can be omitted in replies.
export const queryMetadata = {
  UDID: ["string", "ios4 macos10.7", 0],
  DeviceName: ["string", "ios4 macos10.7", 16],
  ProductName: ["string", "ios4 macos10.7", 16],
  Model: ["string", "ios4 macos10.7", 16],
  ModelName: ["string", "ios4 macos10.7", 16],
  SerialNumber: ["string", "ios4 macos10.7", 16],
  DeviceCapacity: ["number", "ios4 macos10.7; decimal GB", 16],
  AvailableDeviceCapacity: ["number", "ios4 macos10.7; decimal GB", 16],
  OSVersion: ["string", "ios4 macos10.7", 16],
  BuildVersion: ["string", "ios4 macos10.7", 16],
  OSUpdateSettings: ["dict", "macos10.11", 16],
  BatteryLevel: ["number", "ios4; -1 means unknown", 16],
  IsSupervised: ["boolean", "ios6 macos10.15", 16],
  IsDeviceLocatorServiceEnabled: ["boolean", "ios7 macos10.9", 16],
  IsActivationLockEnabled: ["boolean", "ios7 macos10.9", 16],
  IsCloudBackupEnabled: ["boolean", "ios7", 16],
  PasscodePresent: [
    "boolean",
    "SecurityInfo query, legacy compatibility only",
    1024,
  ],
  DeviceID: [
    "string",
    "platform/version availability unverified; optional",
    16,
  ],
  WiFiMAC: ["string", "ios4 macos10.7", 32],
  BluetoothMAC: ["string", "ios4 macos10.7", 32],
  CurrentCarrierNetwork: ["string", "ios4 cellular", 32],
  IMEI: ["string", "ios4 cellular", 32],
  MEID: ["string", "ios4 cellular", 32],
  PhoneNumber: ["string", "ios4 cellular", 32],
  ICCID: ["string", "ios4 cellular", 32],
  CellularTechnology: ["number", "ios4 cellular", 32],
  ModemFirmwareVersion: ["string", "ios4 cellular", 32],
  IsRoaming: ["boolean", "ios4 cellular", 32],
  CurrentMCC: ["string", "ios4 cellular", 32],
  CurrentMNC: ["string", "ios4 cellular", 32],
} as const;
export type DeviceQuery = keyof typeof queryMetadata;
export interface DeviceInformationParams {
  Queries: DeviceQuery[];
}
type ValueFor<K extends DeviceQuery> =
  (typeof queryMetadata)[K][0] extends "string"
    ? string
    : (typeof queryMetadata)[K][0] extends "number"
      ? number
      : (typeof queryMetadata)[K][0] extends "boolean"
        ? boolean
        : PlistDict;
export type DeviceInformationResult = { [K in DeviceQuery]?: ValueFor<K> };
export const defaultQueries: DeviceQuery[] = [
  "UDID",
  "DeviceName",
  "ProductName",
  "ModelName",
  "SerialNumber",
  "OSVersion",
  "BuildVersion",
  "BatteryLevel",
  "DeviceCapacity",
  "AvailableDeviceCapacity",
  "IsSupervised",
];
export function validateInfo(input: unknown): DeviceInformationParams {
  const parsed = z
    .object({
      Queries: z.array(z.string()).min(1).max(128).default(defaultQueries),
    })
    .strict()
    .parse(input ?? {});
  for (const q of parsed.Queries)
    if (!Object.hasOwn(queryMetadata, q))
      throw new Error(`Unsupported query: ${q}`);
  return { Queries: parsed.Queries as DeviceQuery[] };
}
export function infoRights(params: DeviceInformationParams): number {
  return params.Queries.reduce((mask, q) => mask | queryMetadata[q][2], 0);
}
export const deviceInformation = {
  requestType: "DeviceInformation",
  requiredAccessRights: AccessRights.DeviceInformation,
  build(params: DeviceInformationParams): PlistDict {
    return { RequestType: "DeviceInformation", Queries: params.Queries };
  },
  parseResponse(ack: PlistDict): DeviceInformationResult {
    const q = dict(ack.QueryResponses ?? {});
    const out: Record<string, unknown> = {};
    for (const [key, metadata] of Object.entries(queryMetadata)) {
      const value = q[key];
      if (value === undefined) continue;
      if (metadata[0] === "dict") out[key] = dict(value);
      else if (typeof value !== metadata[0])
        throw new Error(`Invalid ${key} response type`);
      else out[key] = value;
    }
    if (
      typeof out.BatteryLevel === "number" &&
      (out.BatteryLevel < -1 || out.BatteryLevel > 1)
    )
      throw new Error("Invalid BatteryLevel");
    return out as DeviceInformationResult;
  },
};
