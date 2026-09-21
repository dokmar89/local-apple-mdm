import { afterAll, beforeAll, describe, it, expect } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { createServer } from "../src/server.js";
import { loadConfig } from "../src/config.js";
import { testPki } from "./pki.js";
import { buildPlist } from "../src/plist/build.js";
import { dict, parsePlist } from "../src/plist/parse.js";
let dir: string,
  app: Awaited<ReturnType<typeof createServer>>,
  pki: Awaited<ReturnType<typeof testPki>>,
  port: number;
const token = "a".repeat(32),
  topic = "com.apple.mgmt.External.00000000-0000-0000-0000-000000000000";
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "mdm-test-"));
  pki = await testPki();
  await Promise.all([
    writeFile(join(dir, "root.crt"), pki.ca),
    writeFile(join(dir, "server.crt"), pki.cert),
    writeFile(join(dir, "server.key"), pki.key),
  ]);
  app = await createServer(
    loadConfig({
      MDM_CA: join(dir, "root.crt"),
      MDM_CERT: join(dir, "server.crt"),
      MDM_KEY: join(dir, "server.key"),
      MDM_DB: join(dir, "db.sqlite"),
      MDM_API_TOKEN: token,
      MDM_ENROLL_TOKEN: "b".repeat(32),
      MDM_TOPIC: topic,
      LOG_LEVEL: "silent",
    }),
  );
  await app.listen({ port: 0, host: "127.0.0.1" });
  port = (app.server.address() as AddressInfo).port;
}, 20_000);
afterAll(async () => {
  await app?.close();
  if (dir) await rm(dir, { recursive: true, force: true });
});
async function request(
  path: string,
  body?: string,
  identity = false,
  api = false,
  method = body ? "PUT" : "GET",
): {} & Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: "127.0.0.1",
        port,
        path,
        method,
        ca: pki.ca,
        ...(identity ? { cert: pki.cert, key: pki.key } : {}),
        headers: {
          ...(body
            ? {
                "content-type": api
                  ? "application/json"
                  : "application/x-apple-aspen-mdm; charset=utf-8",
                "content-length": Buffer.byteLength(body),
              }
            : {}),
          ...(api ? { authorization: `Bearer ${token}` } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (b: Buffer) => chunks.push(b));
        res.on("error", reject);
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }),
        );
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}
describe("Real HTTPS mTLS and full command cycle", () => {
  it("serves public routes and rejects MDM without identity", async () => {
    expect((await request("/healthz")).status).toBe(200);
    expect((await request("/ca")).status).toBe(200);
    expect((await request("/mdm/_ping")).status).toBe(403);
    expect((await request("/mdm/_ping", undefined, true)).status).toBe(200);
    expect((await request("/api/devices")).status).toBe(401);
  });
  it("enrolls, queues through API, delivers and stores a response", async () => {
    const messages: import("../src/plist/build.js").PlistDict[] = [
      {
        MessageType: "Authenticate",
        UDID: "integration",
        Topic: topic,
        ProductName: "iPhone",
      },
      {
        MessageType: "TokenUpdate",
        UDID: "integration",
        Topic: topic,
        Token: Buffer.alloc(32, 1),
        PushMagic: "test",
      },
    ];
    for (const p of messages)
      expect((await request("/mdm/checkin", buildPlist(p), true)).status).toBe(
        200,
      );
    const queued = await request(
      "/api/devices/integration/commands",
      JSON.stringify({ requestType: "DeviceInformation" }),
      false,
      true,
      "POST",
    );
    expect(queued.status).toBe(202);
    const { uuid } = JSON.parse(queued.body.toString()) as { uuid: string };
    const idle = await request(
      "/mdm/connect",
      buildPlist({ UDID: "integration", Status: "Idle" }),
      true,
    );
    expect(dict(parsePlist(idle.body)).CommandUUID).toBe(uuid);
    const ack = await request(
      "/mdm/connect",
      buildPlist({
        UDID: "integration",
        Status: "Acknowledged",
        CommandUUID: uuid,
        QueryResponses: { BatteryLevel: -1, DeviceName: "Integration iPhone" },
      }),
      true,
    );
    expect(ack.status).toBe(200);
    expect(ack.body.length).toBe(0);
    const result = JSON.parse(
      (
        await request("/api/commands/" + uuid, undefined, false, true)
      ).body.toString(),
    ) as { status: string; result: string };
    expect(result.status).toBe("acknowledged");
    expect(JSON.parse(result.result)).toEqual({
      BatteryLevel: -1,
      DeviceName: "Integration iPhone",
    });
  });
});
