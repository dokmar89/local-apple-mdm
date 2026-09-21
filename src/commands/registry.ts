import { z } from "zod";
import type { PlistDict } from "../plist/build.js";
import { dict } from "../plist/parse.js";
import type { Device } from "../db/client.js";
import {
  deviceInformation,
  validateInfo,
  infoRights,
} from "./device-information.js";
import { deviceLock, validateLock } from "./device-lock.js";
import { AccessRights } from "./access-rights.js";
export interface MdmCommand<TParams, TResult> {
  requestType: string;
  requiredAccessRights: number;
  build(params: TParams): PlistDict;
  parseResponse(ack: PlistDict): TResult;
  validate?(params: TParams): void;
}
const noParams = (value: unknown): void => {
  z.object({})
    .strict()
    .parse(value ?? {});
};
const list = (value: unknown): PlistDict[] => {
  if (!Array.isArray(value)) throw new Error("Expected result array");
  return value.map(dict);
};
export const profileList: MdmCommand<Record<string, never>, PlistDict[]> = {
  requestType: "ProfileList",
  requiredAccessRights: AccessRights.InspectProfiles,
  build: () => ({ RequestType: "ProfileList" }),
  parseResponse: (ack) => list(ack.ProfileList ?? []),
};
export const securityInfo: MdmCommand<Record<string, never>, PlistDict> = {
  requestType: "SecurityInfo",
  requiredAccessRights: AccessRights.Security,
  build: () => ({ RequestType: "SecurityInfo" }),
  parseResponse: (ack) => dict(ack.SecurityInfo ?? {}),
};
export const installedApplicationList: MdmCommand<
  Record<string, never>,
  PlistDict[]
> = {
  requestType: "InstalledApplicationList",
  requiredAccessRights: AccessRights.InspectApplications,
  build: () => ({ RequestType: "InstalledApplicationList" }),
  parseResponse: (ack) => list(ack.InstalledApplicationList ?? []),
};
export const registry = {
  DeviceInformation: deviceInformation,
  DeviceLock: deviceLock,
  ProfileList: profileList,
  SecurityInfo: securityInfo,
  InstalledApplicationList: installedApplicationList,
};
export type RequestType = keyof typeof registry;
export function buildCommand(
  requestType: string,
  params: unknown,
  device: Pick<Device, "platform" | "access_rights">,
): PlistDict {
  let payload: PlistDict;
  let rights: number;
  switch (requestType) {
    case "DeviceInformation": {
      const p = validateInfo(params);
      payload = deviceInformation.build(p);
      rights = infoRights(p);
      break;
    }
    case "DeviceLock":
      payload = deviceLock.build(validateLock(params, device.platform));
      rights = AccessRights.DeviceLock;
      break;
    case "ProfileList":
      noParams(params);
      payload = profileList.build({});
      rights = profileList.requiredAccessRights;
      break;
    case "SecurityInfo":
      noParams(params);
      payload = securityInfo.build({});
      rights = securityInfo.requiredAccessRights;
      break;
    case "InstalledApplicationList":
      noParams(params);
      payload = installedApplicationList.build({});
      rights = installedApplicationList.requiredAccessRights;
      break;
    default:
      throw new Error(`Unsupported command: ${requestType}`);
  }
  if ((device.access_rights & rights) !== rights)
    throw new Error(`Profile AccessRights does not permit ${requestType}`);
  return payload;
}
export function parseCommandResponse(
  requestType: string,
  ack: PlistDict,
): unknown {
  if (!Object.hasOwn(registry, requestType))
    throw new Error(`Unsupported command response: ${requestType}`);
  return registry[requestType as RequestType].parseResponse(ack);
}
