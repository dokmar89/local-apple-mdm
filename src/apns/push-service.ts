import { setTimeout as delay } from "node:timers/promises";
import type { Logger } from "pino";
import type { Db, Device } from "../db/client.js";
import type { ApnsClient, PushResult } from "./client.js";
export class PushService {
  private pending = new Map<string, Promise<PushResult>>();
  private timers = new Map<string, NodeJS.Timeout>();
  private stopped = false;
  constructor(
    private db: Db,
    private client: ApnsClient | undefined,
    private log: Logger,
  ) {}
  async initialize(): Promise<void> {
    await this.db.script(
      "CREATE TABLE IF NOT EXISTS push_events(id INTEGER PRIMARY KEY,udid TEXT,apns_id TEXT,status INTEGER,reason TEXT,sent_at INTEGER); CREATE INDEX IF NOT EXISTS push_device_time ON push_events(udid,sent_at);",
    );
  }
  pushDevice(udid: string): Promise<PushResult> {
    if (this.stopped) return Promise.reject(new Error("Push service stopped"));
    const existing = this.pending.get(udid);
    if (existing) return existing;
    const job = this.push(udid);
    this.pending.set(udid, job);
    void job.finally(() => this.pending.delete(udid)).catch(() => {});
    return job;
  }
  private async push(udid: string): Promise<PushResult> {
    await delay(250); // A burst of queued commands needs one wakeup, not one push per command.
    const d = await this.db.one<Device>("SELECT * FROM devices WHERE udid=?", [
      udid,
    ]);
    if (
      !d ||
      d.unenrolled_at ||
      d.push_dead_at ||
      !d.push_token_hex ||
      !d.push_magic
    )
      throw new Error("Device has no active push token");
    const result: PushResult = this.client
      ? await this.client.send(d.push_token_hex, d.push_magic)
      : {
          status: 0,
          apnsId: null,
          reason: "PushNotConfigured",
          action: "fail",
        };
    await this.db.run(
      "INSERT INTO push_events(udid,apns_id,status,reason,sent_at) VALUES(?,?,?,?,?)",
      [udid, result.apnsId, result.status, result.reason, Date.now()],
    );
    // A 410 for an older token must not invalidate a newer TokenUpdate.
    if (result.action === "mark-dead")
      await this.db.run(
        "UPDATE devices SET push_dead_at=? WHERE udid=? AND push_token_hex=? AND token_updated_at<=?",
        [
          Date.now(),
          udid,
          d.push_token_hex,
          result.timestamp ?? d.token_updated_at ?? 0,
        ],
      );
    this.log.info({ udid, ...result }, "APNs push result");
    return result;
  }
  scheduleRetry(udid: string, attempt: number): void {
    if (this.stopped || this.timers.has(udid)) return;
    const ms =
      Math.min(30 * 60_000, 30_000 * 2 ** Math.min(attempt, 6)) *
      (0.75 + Math.random() * 0.5);
    const timer = setTimeout(() => {
      this.timers.delete(udid);
      void this.pushDevice(udid).catch((err) =>
        this.log.error({ err, udid }, "Scheduled push failed"),
      );
    }, ms);
    timer.unref();
    this.timers.set(udid, timer);
    this.log.info({ udid, delayMs: Math.round(ms) }, "NotNow wakeup scheduled");
  }
  async close(): Promise<void> {
    this.stopped = true;
    for (const t of this.timers.values()) clearTimeout(t);
    await Promise.allSettled([...this.pending.values()]);
    await this.client?.close();
  }
}
