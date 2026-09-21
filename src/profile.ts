import { createHash, X509Certificate } from "node:crypto";
import type { Config } from "./config.js";
import type { PlistDict } from "./plist/build.js";
import { ALL_ACCESS_RIGHTS } from "./commands/access-rights.js";
export type Platform = "ios" | "macos";
export function uuidV5(name: string): string {
  const b = createHash("sha1")
    .update(Buffer.from("6ba7b8109dad11d180b400c04fd430c8", "hex"))
    .update(name)
    .digest()
    .subarray(0, 16);
  b[6] = ((b[6] ?? 0) & 15) | 80;
  b[8] = ((b[8] ?? 0) & 63) | 128;
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
export function makeProfile(
  c: Config,
  device: string,
  platform: Platform,
  root: Buffer,
  p12: Buffer,
  password: string,
): PlistDict {
  if (!/^com\.apple\.mgmt\.External\.[0-9a-f-]{36}$/i.test(c.MDM_TOPIC))
    throw new Error(
      "Set the real MDM push certificate topic before enrollment",
    );
  if (!/^[a-zA-Z0-9._-]+$/.test(device))
    throw new Error("Invalid device identifier");
  const id = `cz.${c.MDM_ORG_NAME.toLowerCase().replace(/[^a-z0-9-]/g, "-")}.mdm.enroll.${device}`;
  // Stable identifiers allow profile replacement without creating another identity.
  const base = (s: string, type: string): PlistDict => ({
    PayloadIdentifier: id + s,
    PayloadUUID: uuidV5(id + s),
    PayloadType: type,
    PayloadVersion: 1,
    PayloadDisplayName: c.MDM_ORG_NAME + " MDM",
  });
  const origin = `https://${c.MDM_HOSTNAME}:${c.MDM_PORT}`;
  return {
    ...base("", "Configuration"),
    PayloadDescription: `Enrollment for ${device}`,
    PayloadOrganization: c.MDM_ORG_NAME,
    PayloadRemovalDisallowed: false,
    ...(platform === "macos" ? { PayloadScope: "System" } : {}),
    PayloadContent: [
      {
        ...base(".root", "com.apple.security.root"),
        PayloadContent: new X509Certificate(root).raw,
        PayloadCertificateFileName: "root-ca.cer",
      },
      {
        ...base(".identity", "com.apple.security.pkcs12"),
        PayloadContent: p12,
        Password: password,
        PayloadCertificateFileName: `${device}.p12`,
      },
      {
        ...base(".mdm", "com.apple.mdm"),
        IdentityCertificateUUID: uuidV5(id + ".identity"),
        Topic: c.MDM_TOPIC,
        ServerURL: origin + "/mdm/connect",
        CheckInURL: origin + "/mdm/checkin",
        CheckOutWhenRemoved: true,
        SignMessage: false,
        UseDevelopmentAPNS: false,
        AccessRights: ALL_ACCESS_RIGHTS,
        ...(platform === "macos"
          ? { ServerCapabilities: ["com.apple.mdm.per-user-connections"] }
          : {}),
      },
    ],
  };
}
