import { Worker } from "node:worker_threads";
import { AsyncLocalStorage } from "node:async_hooks";
export type Parameter = string | number | null | Buffer;
export interface Device {
  udid: string;
  cert_fingerprint: string;
  platform: "ios" | "macos";
  access_rights: number;
  topic: string | null;
  push_token_hex: string | null;
  push_magic: string | null;
  push_dead_at: number | null;
  unenrolled_at: number | null;
  token_updated_at: number | null;
  device_name: string | null;
}
export class Db {
  private worker: Worker;
  private nextId = 0;
  private failed?: Error;
  private pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (error: Error) => void }
  >();
  private tail: Promise<void> = Promise.resolve();
  private scope = new AsyncLocalStorage<boolean>();
  constructor(filename: string) {
    // Compile before running source tests: the synchronous driver lives in an isolated JS worker.
    const url = import.meta.url.endsWith(".ts")
      ? new URL("../../dist/src/db/worker.js", import.meta.url)
      : new URL("./worker.js", import.meta.url);
    this.worker = new Worker(url, { workerData: filename });
    this.worker.on(
      "message",
      (m: { id: number; result: unknown; error?: string }) => {
        const p = this.pending.get(m.id);
        this.pending.delete(m.id);
        if (m.error) p?.reject(new Error(m.error));
        else p?.resolve(m.result);
      },
    );
    const fail = (e: Error): void => {
      this.failed = e;
      for (const p of this.pending.values()) p.reject(e);
      this.pending.clear();
    };
    this.worker.on("error", fail);
    this.worker.on("exit", (code) =>
      fail(new Error(`DB worker exited: ${code}`)),
    );
  }
  private async lock<T>(fn: () => Promise<T>): Promise<T> {
    if (this.scope.getStore()) return fn();
    const prior = this.tail;
    let release: () => void = () => {};
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      return await this.scope.run(true, fn);
    } finally {
      release();
    }
  }
  private async rpc(
    kind: string,
    text = "",
    params: Parameter[] = [],
  ): Promise<unknown> {
    return this.lock(
      () =>
        new Promise((resolve, reject) => {
          if (this.failed) {
            reject(this.failed);
            return;
          }
          const id = ++this.nextId;
          this.pending.set(id, { resolve, reject });
          this.worker.postMessage({ id, kind, text, params });
        }),
    );
  }
  async all<T>(text: string, params: Parameter[] = []): Promise<T[]> {
    return (await this.rpc("query", text, params)) as T[];
  }
  async one<T>(text: string, params: Parameter[] = []): Promise<T | undefined> {
    return (await this.all<T>(text, params))[0];
  }
  async run(text: string, params: Parameter[] = []): Promise<void> {
    await this.rpc("execute", text, params);
  }
  async script(text: string): Promise<void> {
    await this.rpc("script", text);
  }
  async transaction<T>(fn: () => Promise<T>): Promise<T> {
    return this.lock(async () => {
      await this.script("BEGIN IMMEDIATE");
      try {
        const result = await fn();
        await this.script("COMMIT");
        return result;
      } catch (e) {
        await this.script("ROLLBACK");
        throw e;
      }
    });
  }
  async close(): Promise<void> {
    await this.rpc("close");
    await this.worker.terminate();
  }
}
