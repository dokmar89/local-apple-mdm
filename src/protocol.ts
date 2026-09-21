import { z } from "zod";
import type { PlistDict } from "./plist/build.js";
const data = z.instanceof(Buffer);
const base = z
  .object({
    MessageType: z.string(),
    Topic: z.string().optional(),
    UDID: z.string().min(1).max(256),
    EnrollmentID: z.string().optional(),
  })
  .passthrough();
export const authenticateSchema = base.extend({
  MessageType: z.literal("Authenticate"),
  Topic: z.string(),
  OSVersion: z.string().optional(),
  BuildVersion: z.string().optional(),
  ProductName: z.string().optional(),
  SerialNumber: z.string().optional(),
  DeviceName: z.string().optional(),
  Model: z.string().optional(),
  Challenge: z.string().optional(),
  IMEI: z.string().optional(),
  MEID: z.string().optional(),
});
export const tokenSchema = base.extend({
  MessageType: z.literal("TokenUpdate"),
  Topic: z.string(),
  Token: data,
  PushMagic: z.string().min(1),
  UnlockToken: data.optional(),
  AwaitingConfiguration: z.boolean().optional(),
  UserID: z.string().optional(),
  UserShortName: z.string().optional(),
  UserLongName: z.string().optional(),
  NotOnConsole: z.boolean().optional(),
});
export type Authenticate = z.infer<typeof authenticateSchema>;
export type TokenUpdate = z.infer<typeof tokenSchema>;
export interface CheckOut {
  MessageType: "CheckOut";
  Topic: string;
  UDID: string;
  EnrollmentID?: string;
}
export interface UserAuthenticate {
  MessageType: "UserAuthenticate";
  UDID: string;
  UserID?: string;
  UserShortName?: string;
  UserLongName?: string;
}
export interface GetBootstrapToken {
  MessageType: "GetBootstrapToken";
  UDID: string;
  AwaitingConfiguration?: boolean;
}
export interface SetBootstrapToken {
  MessageType: "SetBootstrapToken";
  UDID: string;
  BootstrapToken: Buffer;
}
export interface DeclarativeManagement {
  MessageType: "DeclarativeManagement";
  UDID: string;
  Endpoint: string;
  Data?: Buffer;
}
export interface ErrorChainItem {
  ErrorCode: number;
  ErrorDomain: string;
  LocalizedDescription?: string;
  USEnglishDescription?: string;
}
export const errorChainSchema = z.array(
  z.object({
    ErrorCode: z.number().int(),
    ErrorDomain: z.string(),
    LocalizedDescription: z.string().optional(),
    USEnglishDescription: z.string().optional(),
  }),
);
export type ConnectStatus =
  | "Idle"
  | "Acknowledged"
  | "Error"
  | "NotNow"
  | "CommandFormatError";
export interface ConnectMessage {
  UDID: string;
  Status: ConnectStatus;
  CommandUUID?: string;
  ErrorChain?: ErrorChainItem[];
  QueryResponses?: PlistDict;
}
export function json(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    typeof v === "bigint" ? v.toString() : v,
  );
}
