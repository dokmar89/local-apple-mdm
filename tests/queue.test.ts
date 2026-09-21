import { afterEach, describe, it, expect } from "vitest";
import pino from "pino";
import { Db } from "../src/db/client.js";
import { CommandQueue } from "../src/queue/command-queue.js";
import { handleCheckin } from "../src/http/checkin.route.js";
import { handleConnect } from "../src/http/connect.route.js";
import { loadConfig } from "../src/config.js";
import { buildPlist } from "../src/plist/build.js";
import { dict, parsePlist } from "../src/plist/parse.js";
const peer = {
  cn: "test",
  issuerCn: "Root",
  serialNumber: "1",
  fingerprint256: "AB:CD",
  validTo: "2099-01-01",
};
const config = loadConfig({
  MDM_TOPIC: "com.apple.mgmt.External.00000000-0000-0000-0000-000000000000",
  MDM_API_TOKEN: "a".repeat(32),
  MDM_ENROLL_TOKEN: "b".repeat(32),
});
const log = pino({ level: "silent" });
const databases: Db[] = [];
const raw = (p: Parameters<typeof buildPlist>[0]): Buffer =>
  Buffer.from(buildPlist(p));
async function setup() {
  const db = new Db(":memory:");
  databases.push(db);
  const q = new CommandQueue(db);
  await q.initialize();
  await handleCheckin(
    db,
    config,
    raw({ MessageType: "Authenticate", UDID: "A", Topic: config.MDM_TOPIC }),
    peer,
  );
  await handleCheckin(
    db,
    config,
    raw({
      MessageType: "TokenUpdate",
      UDID: "A",
      Topic: config.MDM_TOPIC,
      Token: Buffer.from("abcd", "hex"),
      PushMagic: "magic",
    }),
    peer,
  );
  return q;
}
afterEach(async () => {
  await Promise.all(databases.splice(0).map((d) => d.close()));
});
describe("Device state", () => {
  it("issues at most one command under concurrent dequeue", async () => {
    const q = await setup();
    await q.enqueue("A", { RequestType: "DeviceInformation" });
    await q.enqueue("A", { RequestType: "ProfileList" });
    const results = await Promise.all(
      Array.from({ length: 8 }, () => q.dequeueNext("A")),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });
  for (const status of [
    "Acknowledged",
    "Error",
    "NotNow",
    "CommandFormatError",
  ])
    it(`handles ${status}`, async () => {
      const q = await setup();
      const uuid = await q.enqueue("A", { RequestType: "DeviceInformation" });
      const next = await q.enqueue("A", { RequestType: "ProfileList" });
      const push = { scheduleRetry: () => {} };
      const sent = dict(
        parsePlist(
          await handleConnect(
            q,
            push,
            raw({ UDID: "A", Status: "Idle" }),
            peer,
            log,
          ),
        ),
      );
      expect(sent.CommandUUID).toBe(uuid);
      const response = await handleConnect(
        q,
        push,
        raw({
          UDID: "A",
          Status: status,
          CommandUUID: uuid,
          ...(status === "Error"
            ? {
                ErrorChain: [{ ErrorCode: 1, ErrorDomain: "MCMDMErrorDomain" }],
              }
            : {}),
        }),
        peer,
        log,
      );
      const stored = await q.db.one<{ status: string }>(
        "SELECT status FROM commands WHERE uuid=?",
        [uuid],
      );
      expect(stored?.status).toBe(
        status === "Acknowledged"
          ? "acknowledged"
          : status === "NotNow"
            ? "queued"
            : "error",
      );
      if (status === "NotNow") expect(response.length).toBe(0);
      else expect(dict(parsePlist(response)).CommandUUID).toBe(next);
    });
  it("rejects another certificate claiming a device", async () => {
    const q = await setup();
    await expect(
      handleConnect(
        q,
        { scheduleRetry: () => {} },
        raw({ UDID: "A", Status: "Idle" }),
        { ...peer, fingerprint256: "OTHER" },
        log,
      ),
    ).rejects.toMatchObject({ status: 403 });
  });
  it("keeps audit after checkout and cancels queued commands", async () => {
    const q = await setup();
    await q.enqueue("A", { RequestType: "DeviceInformation" });
    await handleCheckin(
      q.db,
      config,
      raw({ MessageType: "CheckOut", UDID: "A", Topic: config.MDM_TOPIC }),
      peer,
    );
    expect(
      (await q.db.one<{ status: string }>("SELECT status FROM commands"))
        ?.status,
    ).toBe("expired");
    expect(await q.db.one("SELECT * FROM devices")).toBeDefined();
  });
  it("handles UserAuthenticate, stubs and unknown messages", async () => {
    const q = await setup();
    expect(
      await handleCheckin(
        q.db,
        config,
        raw({ MessageType: "UserAuthenticate", UDID: "A" }),
        peer,
      ),
    ).toBe(410);
    for (const MessageType of [
      "GetBootstrapToken",
      "SetBootstrapToken",
      "DeclarativeManagement",
    ])
      expect(
        await handleCheckin(
          q.db,
          config,
          raw({ MessageType, UDID: "A" }),
          peer,
        ),
      ).toBe(200);
    await expect(
      handleCheckin(
        q.db,
        config,
        raw({ MessageType: "Unknown", UDID: "A" }),
        peer,
      ),
    ).rejects.toMatchObject({ status: 400 });
  });
});
