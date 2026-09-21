import https from "node:https";
import { readFile } from "node:fs/promises";
import { loadConfig } from "../src/config.js";
import { buildPlist, type PlistDict } from "../src/plist/build.js";
import { dict, parsePlist } from "../src/plist/parse.js";
async function main(): Promise<void> {
  const c = loadConfig();
  const udid = process.argv[2] ?? "simulator";
  const identity = process.argv[3] ?? "simulator";
  if (!/^[a-zA-Z0-9._-]+$/.test(identity))
    throw new Error("Invalid identity name");
  const [ca, cert, key] = await Promise.all([
    readFile(c.MDM_CA),
    readFile(`ca/${identity}.crt`),
    readFile(`ca/${identity}.key`),
  ]);
  const send = async (path: string, p: PlistDict): Promise<Buffer> =>
    new Promise((resolve, reject) => {
      const body = Buffer.from(buildPlist(p));
      const req = https.request(
        {
          hostname: c.MDM_HOSTNAME,
          port: c.MDM_PORT,
          path,
          method: "PUT",
          ca,
          cert,
          key,
          headers: {
            "content-type": path.endsWith("checkin")
              ? "application/x-apple-aspen-mdm-checkin"
              : "application/x-apple-aspen-mdm",
            "content-length": body.length,
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("error", reject);
          res.on("end", () => {
            const bytes = Buffer.concat(chunks);
            if (res.statusCode !== 200)
              reject(new Error(`HTTP ${res.statusCode}: ${bytes.toString()}`));
            else resolve(bytes);
          });
        },
      );
      req.setTimeout(15_000, () => req.destroy(new Error("Simulator timeout")));
      req.on("error", reject);
      req.end(body);
    });
  if (process.argv.includes("--enroll")) {
    await send("/mdm/checkin", {
      MessageType: "Authenticate",
      UDID: udid,
      Topic: c.MDM_TOPIC,
      ProductName: "iPhone",
      DeviceName: "Simulator",
      OSVersion: "18.0",
    });
    await send("/mdm/checkin", {
      MessageType: "TokenUpdate",
      UDID: udid,
      Topic: c.MDM_TOPIC,
      Token: Buffer.alloc(32, 1),
      PushMagic: "simulator-only",
    });
  }
  let response = await send("/mdm/connect", { UDID: udid, Status: "Idle" });
  while (response.length) {
    const envelope = dict(parsePlist(response)),
      command = dict(envelope.Command);
    console.log("Received", command.RequestType, envelope.CommandUUID);
    if (command.RequestType === "DeviceLock")
      throw new Error(
        "Simulator intentionally cannot claim that a real device was locked",
      );
    const result: PlistDict =
      command.RequestType === "DeviceInformation"
        ? {
            QueryResponses: {
              DeviceName: "Simulator",
              BatteryLevel: -1,
              OSVersion: "18.0",
            },
          }
        : command.RequestType === "ProfileList"
          ? { ProfileList: [] }
          : command.RequestType === "SecurityInfo"
            ? { SecurityInfo: { PasscodePresent: true } }
            : { InstalledApplicationList: [] };
    response = await send("/mdm/connect", {
      UDID: udid,
      Status: "Acknowledged",
      CommandUUID: envelope.CommandUUID as string,
      ...result,
    });
  }
  console.log("Connect session completed (HTTP 200, empty body).");
}
main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exitCode = 1;
});
