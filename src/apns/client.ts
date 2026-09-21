import http2, {
  type ClientHttp2Session,
  type ClientHttp2Stream,
} from "node:http2";
import { setTimeout as delay } from "node:timers/promises";
import type { Logger } from "pino";
export enum ApnsReason {
  BadDeviceToken = "BadDeviceToken",
  BadTopic = "BadTopic",
  DeviceTokenNotForTopic = "DeviceTokenNotForTopic",
  Unregistered = "Unregistered",
  TooManyRequests = "TooManyRequests",
  InternalServerError = "InternalServerError",
  ServiceUnavailable = "ServiceUnavailable",
  Shutdown = "Shutdown",
  BadCertificate = "BadCertificate",
  BadCertificateEnvironment = "BadCertificateEnvironment",
  Forbidden = "Forbidden",
  ExpiredProviderToken = "ExpiredProviderToken",
  InvalidProviderToken = "InvalidProviderToken",
  MissingTopic = "MissingTopic",
  TopicDisallowed = "TopicDisallowed",
  PayloadTooLarge = "PayloadTooLarge",
  IdleTimeout = "IdleTimeout",
}
export interface PushResult {
  status: number;
  apnsId: string | null;
  reason: string | null;
  timestamp?: number;
  action: "ok" | "retry" | "mark-dead" | "fail";
}
export function actionFor(status: number): PushResult["action"] {
  return status === 200
    ? "ok"
    : status === 410
      ? "mark-dead"
      : status === 429 || status >= 500 || status === 0
        ? "retry"
        : "fail";
}
interface SessionState {
  session: ClientHttp2Session;
  active: number;
  max: number;
  ready: Promise<void>;
  draining: boolean;
  ping: NodeJS.Timeout;
}
export interface ApnsOptions {
  cert: Buffer;
  key: Buffer;
  topic: string;
  endpoint?: string;
  ca?: Buffer;
  timeoutMs?: number;
  retryLimit?: number;
}
export class ApnsClient {
  private current?: SessionState;
  private sessions = new Set<SessionState>();
  private closed = false;
  private waiters = new Set<() => void>();
  private jobs = new Set<Promise<PushResult>>();
  constructor(
    private options: ApnsOptions,
    private log: Logger,
  ) {}
  private wake(): void {
    for (const wake of this.waiters) wake();
    this.waiters.clear();
  }
  private create(): SessionState {
    const o = this.options;
    // Keep Apple's public trust roots: the local enrollment CA cannot validate APNs.
    const session = http2.connect(
      o.endpoint ?? "https://api.push.apple.com:443",
      { cert: o.cert, key: o.key, ...(o.ca ? { ca: o.ca } : {}) },
    );
    let resolveReady: () => void = () => {};
    let rejectReady: (e: Error) => void = () => {};
    const ready = new Promise<void>((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    const state: SessionState = {
      session,
      active: 0,
      max: 0,
      ready,
      draining: false,
      ping: setInterval(() => {
        if (!session.closed && !session.destroyed && !state.draining)
          session.ping((err) => {
            if (err) {
              this.log.warn({ err }, "APNs ping failed");
              session.destroy(err);
            }
          });
      }, 60_000),
    };
    state.ping.unref();
    this.sessions.add(state);
    const timer = setTimeout(
      () => session.destroy(new Error("APNs connection timeout")),
      o.timeoutMs ?? 15_000,
    );
    session.once("remoteSettings", () => {
      clearTimeout(timer);
      resolveReady();
    });
    session.on("remoteSettings", (settings) => {
      state.max = settings.maxConcurrentStreams ?? 100;
      this.wake();
    });
    session.on("goaway", (code, lastStreamID) => {
      this.log.info({ code, lastStreamID }, "APNs GOAWAY");
      state.draining = true;
      if (this.current === state) this.current = undefined;
      this.wake();
      if (state.active === 0) session.close();
    });
    session.on("error", (err) => {
      rejectReady(err);
      this.log.warn({ err }, "APNs session error");
      state.draining = true;
      if (this.current === state) this.current = undefined;
      this.wake();
    });
    session.on("close", () => {
      clearTimeout(timer);
      clearInterval(state.ping);
      state.draining = true;
      rejectReady(new Error("APNs connection closed"));
      this.sessions.delete(state);
      if (this.current === state) this.current = undefined;
      this.wake();
    });
    return state;
  }
  private async acquire(): Promise<SessionState> {
    const deadline = Date.now() + (this.options.timeoutMs ?? 15_000);
    while (!this.closed) {
      const s = this.current ?? (this.current = this.create());
      await s.ready;
      if (s.draining || s.session.closed || s.session.destroyed) continue;
      if (s.active < s.max) {
        s.active++;
        return s;
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("APNs stream capacity timeout");
      await new Promise<void>((resolve) => {
        const wake = (): void => {
          clearTimeout(t);
          this.waiters.delete(wake);
          resolve();
        };
        const t = setTimeout(wake, remaining);
        this.waiters.add(wake);
      });
    }
    throw new Error("APNs client is closed");
  }
  private async once(token: string, magic: string): Promise<PushResult> {
    const s = await this.acquire();
    try {
      return await new Promise<PushResult>((resolve, reject) => {
        let stream: ClientHttp2Stream;
        try {
          stream = s.session.request({
            ":method": "POST",
            ":path": `/3/device/${token}`,
            "apns-topic": this.options.topic,
            "apns-push-type": "mdm",
            "apns-priority": "10",
            "apns-expiration": String(Math.floor(Date.now() / 1000) + 300),
            "content-type": "application/json",
          });
        } catch (e) {
          reject(e);
          return;
        }
        let status = 0;
        let apnsId: string | null = null;
        let body = "";
        let settled = false;
        const fail = (e: Error): void => {
          if (settled) return;
          settled = true;
          reject(e);
        };
        stream.setTimeout(this.options.timeoutMs ?? 15_000, () => {
          fail(new Error("APNs stream timeout"));
          stream.close(http2.constants.NGHTTP2_CANCEL);
        });
        stream.on("response", (headers) => {
          status = Number(headers[":status"]);
          apnsId =
            typeof headers["apns-id"] === "string" ? headers["apns-id"] : null;
        });
        stream.setEncoding("utf8");
        stream.on("data", (chunk: string) => {
          body += chunk;
          if (body.length > 16_384) {
            fail(new Error("APNs response too large"));
            stream.close(http2.constants.NGHTTP2_CANCEL);
          }
        });
        stream.on("error", fail);
        stream.on("end", () => {
          if (settled) return;
          try {
            const parsed: unknown = body ? JSON.parse(body) : {};
            const p =
              parsed && typeof parsed === "object"
                ? (parsed as Record<string, unknown>)
                : {};
            const result: PushResult = {
              status,
              apnsId,
              reason: typeof p.reason === "string" ? p.reason : null,
              action: actionFor(status),
              ...(typeof p.timestamp === "number"
                ? { timestamp: p.timestamp }
                : {}),
            };
            settled = true;
            resolve(result);
          } catch (e) {
            fail(e instanceof Error ? e : new Error(String(e)));
          }
        });
        stream.on("close", () => {
          if (!settled)
            fail(new Error("APNs stream closed without a response"));
        });
        stream.end(JSON.stringify({ mdm: magic }));
      });
    } finally {
      s.active--;
      this.wake();
      if (s.draining && s.active === 0) s.session.close();
    }
  }
  send(token: string, magic: string): Promise<PushResult> {
    if (!/^(?:[a-f0-9]{2})+$/i.test(token) || !magic)
      return Promise.reject(new Error("Invalid push token or PushMagic"));
    const job = this.sendWithRetry(token, magic);
    this.jobs.add(job);
    void job.finally(() => this.jobs.delete(job)).catch(() => {});
    return job;
  }
  private async sendWithRetry(
    token: string,
    magic: string,
  ): Promise<PushResult> {
    let last: PushResult = {
      status: 0,
      apnsId: null,
      reason: "TransportError",
      action: "retry",
    };
    for (
      let attempt = 0;
      attempt <= (this.options.retryLimit ?? 4);
      attempt++
    ) {
      if (this.closed) throw new Error("APNs client is closed");
      try {
        last = await this.once(token, magic);
      } catch (err) {
        this.log.warn({ err, attempt }, "APNs transport retry");
      }
      if (last.action !== "retry") return last;
      if (attempt < (this.options.retryLimit ?? 4))
        await delay(
          Math.min(30_000, 500 * 2 ** attempt) * (0.5 + Math.random()),
        );
    }
    return last;
  }
  async close(): Promise<void> {
    // Existing pushes finish their retries; the server stops accepting work first.
    await Promise.allSettled([...this.jobs]);
    this.closed = true;
    this.wake();
    await Promise.all(
      [...this.sessions].map(
        (s) =>
          new Promise<void>((resolve) => {
            clearInterval(s.ping);
            const timer = setTimeout(() => s.session.destroy(), 5000);
            s.session.once("close", () => {
              clearTimeout(timer);
              resolve();
            });
            s.session.close();
          }),
      ),
    );
  }
}
