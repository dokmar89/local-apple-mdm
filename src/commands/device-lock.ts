import { z } from "zod";
import type { PlistDict } from "../plist/build.js";
import { AccessRights } from "./access-rights.js";
export interface DeviceLockParams {
  Message?: string;
  PhoneNumber?: string;
  PIN?: string;
}
export function validateLock(
  input: unknown,
  platform: "ios" | "macos",
): DeviceLockParams {
  const p = z
    .object({
      Message: z.string().max(1024).optional(),
      PhoneNumber: z.string().max(128).optional(),
      PIN: z
        .string()
        .regex(/^\d{6}$/)
        .optional(),
    })
    .strict()
    .parse(input ?? {});
  // Require an explicit recovery PIN for every Mac in this local test server.
  if (platform === "macos" && !p.PIN)
    throw new Error(
      "macOS DeviceLock requires a six-digit PIN; retain it securely for recovery",
    );
  return platform === "ios"
    ? {
        ...(p.Message ? { Message: p.Message } : {}),
        ...(p.PhoneNumber ? { PhoneNumber: p.PhoneNumber } : {}),
      }
    : p;
}
export const deviceLock = {
  requestType: "DeviceLock",
  requiredAccessRights: AccessRights.DeviceLock,
  build(params: DeviceLockParams): PlistDict {
    return { RequestType: "DeviceLock", ...params };
  },
  parseResponse(ack: PlistDict): { MessageResult?: string } {
    if (
      ack.MessageResult !== undefined &&
      typeof ack.MessageResult !== "string"
    )
      throw new Error("Invalid MessageResult");
    return ack.MessageResult === undefined
      ? {}
      : { MessageResult: ack.MessageResult };
  },
};
