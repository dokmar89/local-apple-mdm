import { randomUUID } from "node:crypto";
import type { Db, Device } from "../db/client.js";
import type { PlistDict } from "../plist/build.js";
import { json } from "../protocol.js";
import { buildCommand, parseCommandResponse } from "../commands/registry.js";
import { dict } from "../plist/parse.js";
export interface QueuedCommand {
  uuid: string;
  udid: string;
  request_type: string;
  payload: string;
  status: "queued" | "sent" | "acknowledged" | "error" | "not_now" | "expired";
  priority: number;
  attempts: number;
  created_at: number;
  sent_at: number | null;
  completed_at: number | null;
  expires_at: number;
  result: string | null;
  error_chain: string | null;
}
export class CommandQueue {
  constructor(readonly db: Db) {}
  async initialize(): Promise<void> {
    await this.db.script(`
    CREATE TABLE IF NOT EXISTS commands(uuid TEXT PRIMARY KEY,udid TEXT NOT NULL REFERENCES devices(udid),request_type TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL,priority INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,sent_at INTEGER,completed_at INTEGER,expires_at INTEGER NOT NULL,result TEXT,error_chain TEXT,raw_response BLOB);
    CREATE INDEX IF NOT EXISTS command_device_status_time ON commands(udid,status,created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS one_sent_per_device ON commands(udid) WHERE status='sent';
    CREATE TABLE IF NOT EXISTS connect_events(id INTEGER PRIMARY KEY,udid TEXT,status TEXT,command_uuid TEXT,raw_body BLOB,raw_response BLOB,received_at INTEGER);
    CREATE INDEX IF NOT EXISTS connect_device_time ON connect_events(udid,received_at);
    CREATE TABLE IF NOT EXISTS device_facts(id INTEGER PRIMARY KEY,udid TEXT NOT NULL REFERENCES devices(udid),key TEXT NOT NULL,value TEXT NOT NULL,value_type TEXT NOT NULL,observed_at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS facts_current ON device_facts(udid,key,observed_at DESC,id DESC);
    CREATE VIEW IF NOT EXISTS current_device_facts AS SELECT id,udid,key,value,value_type,observed_at FROM (SELECT *,ROW_NUMBER() OVER(PARTITION BY udid,key ORDER BY observed_at DESC,id DESC) AS rank FROM device_facts) WHERE rank=1;
  `);
  }
  async enqueue(
    udid: string,
    payload: PlistDict,
    ttlMs = 86_400_000,
  ): Promise<string> {
    if (typeof payload.RequestType !== "string")
      throw new Error("RequestType required");
    return this.db.transaction(async () => {
      const device = await this.db.one<Device>(
        "SELECT * FROM devices WHERE udid=?",
        [udid],
      );
      if (!device || device.unenrolled_at || !device.token_updated_at)
        throw new Error("Device is not enrolled");
      const { RequestType, ...params } = payload;
      const validated = buildCommand(RequestType as string, params, device);
      const uuid = randomUUID(),
        now = Date.now();
      await this.db.run(
        "INSERT INTO commands(uuid,udid,request_type,payload,status,created_at,expires_at) VALUES(?,?,?,?,'queued',?,?)",
        [uuid, udid, RequestType as string, json(validated), now, now + ttlMs],
      );
      return uuid;
    });
  }
  async dequeueNext(udid: string): Promise<QueuedCommand | undefined> {
    return this.db.transaction(async () => {
      // A sent command may already have executed. Never blindly expire/reissue a lock.
      await this.db.run(
        "UPDATE commands SET status='expired',completed_at=? WHERE udid=? AND status='queued' AND expires_at<=?",
        [Date.now(), udid, Date.now()],
      );
      if (
        await this.db.one(
          "SELECT uuid FROM commands WHERE udid=? AND status='sent'",
          [udid],
        )
      )
        return undefined;
      // rowid preserves insertion order when multiple enqueues share one millisecond.
      const next = await this.db.one<QueuedCommand>(
        "SELECT * FROM commands WHERE udid=? AND status='queued' ORDER BY created_at,rowid LIMIT 1",
        [udid],
      );
      if (!next) return undefined;
      await this.db.run(
        "UPDATE commands SET status='sent',sent_at=? WHERE uuid=?",
        [Date.now(), next.uuid],
      );
      return { ...next, status: "sent" };
    });
  }
  async complete(
    uuid: string,
    udid: string,
    status: "acknowledged" | "error" | "queued",
    result: unknown,
    errors: unknown,
    raw: Buffer,
  ): Promise<boolean> {
    return this.db.transaction(async () => {
      const active = await this.db.one<QueuedCommand>(
        "SELECT * FROM commands WHERE uuid=? AND udid=? AND status='sent'",
        [uuid, udid],
      );
      if (!active) return false;
      const normalized =
        status === "acknowledged"
          ? parseCommandResponse(active.request_type, dict(result))
          : null;
      await this.db.run(
        "UPDATE commands SET status=?,result=?,error_chain=?,raw_response=?,completed_at=?,attempts=attempts+? WHERE uuid=?",
        [
          status,
          normalized === null ? null : json(normalized),
          errors === null ? null : json(errors),
          raw,
          status === "queued" ? null : Date.now(),
          status === "queued" ? 1 : 0,
          uuid,
        ],
      );
      if (
        status === "acknowledged" &&
        active.request_type === "DeviceInformation"
      ) {
        for (const [key, value] of Object.entries(dict(normalized)))
          await this.db.run(
            "INSERT INTO device_facts(udid,key,value,value_type,observed_at) VALUES(?,?,?,?,?)",
            [
              udid,
              key,
              json(value),
              value instanceof Date
                ? "date"
                : Buffer.isBuffer(value)
                  ? "data"
                  : typeof value,
              Date.now(),
            ],
          );
      }
      return true;
    });
  }
  async markAcknowledged(
    uuid: string,
    udid: string,
    result: unknown,
    raw: Buffer,
  ): Promise<boolean> {
    return this.complete(uuid, udid, "acknowledged", result, null, raw);
  }
  async markError(
    uuid: string,
    udid: string,
    errorChain: unknown,
    raw: Buffer,
  ): Promise<boolean> {
    return this.complete(uuid, udid, "error", null, errorChain, raw);
  }
  async markNotNow(uuid: string, udid: string, raw: Buffer): Promise<boolean> {
    return this.complete(uuid, udid, "queued", null, null, raw);
  }
}
