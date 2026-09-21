import { parseArgs } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import { api } from "./http-client.js";
const types = {
  info: "DeviceInformation",
  lock: "DeviceLock",
  profiles: "ProfileList",
  security: "SecurityInfo",
  apps: "InstalledApplicationList",
} as const;
async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      queries: { type: "string" },
      message: { type: "string" },
      phone: { type: "string" },
      pin: { type: "string" },
      timeout: { type: "string", default: "120" },
    },
  });
  const [action, udid] = positionals;
  if (!action || !udid || !Object.hasOwn(types, action))
    throw new Error(
      "Usage: npm run mdm -- info|lock|profiles|security|apps <udid> [--queries a,b] [--message text] [--phone number] [--pin 123456] [--timeout seconds]",
    );
  const timeout = Number(values.timeout);
  if (!Number.isFinite(timeout) || timeout < 1)
    throw new Error("Invalid timeout");
  const params = {
    ...(values.queries ? { Queries: values.queries.split(",") } : {}),
    ...(values.message ? { Message: values.message } : {}),
    ...(values.phone ? { PhoneNumber: values.phone } : {}),
    ...(values.pin ? { PIN: values.pin } : {}),
  };
  const queued = (await api(
    `/devices/${encodeURIComponent(udid)}/commands`,
    "POST",
    { requestType: types[action as keyof typeof types], params },
  )) as { uuid: string; push: unknown };
  console.log(`CommandUUID: ${queued.uuid}`);
  console.log("Push:", queued.push);
  const deadline = Date.now() + timeout * 1000;
  while (Date.now() < deadline) {
    const command = (await api(`/commands/${queued.uuid}`)) as {
      status: string;
      result: string | null;
      error_chain: string | null;
    };
    if (command.status === "acknowledged") {
      const result: unknown = command.result ? JSON.parse(command.result) : {};
      console.table(result);
      return;
    }
    if (command.status === "error" || command.status === "expired")
      throw new Error(`${command.status}: ${command.error_chain ?? ""}`);
    await delay(1000);
  }
  throw new Error(
    `Timeout; command ${queued.uuid} remains in the durable queue. Inspect it before enqueueing again.`,
  );
}
main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exitCode = 1;
});
