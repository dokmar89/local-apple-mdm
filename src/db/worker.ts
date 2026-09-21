import { parentPort, workerData } from "node:worker_threads";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { sql } from "drizzle-orm";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import * as schema from "./schema.js";
const filename = workerData as string;
if (filename !== ":memory:")
  mkdirSync(dirname(filename), { recursive: true, mode: 0o700 });
const sqlite = new Database(filename);
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("foreign_keys = ON");
sqlite.pragma("busy_timeout = 5000");
const orm = drizzle(sqlite, { schema });
sqlite.exec(`
CREATE TABLE IF NOT EXISTS devices (
 udid TEXT PRIMARY KEY, serial_number TEXT, device_name TEXT, product_name TEXT, model TEXT, os_version TEXT, build_version TEXT,
 topic TEXT, push_token BLOB, push_token_hex TEXT, push_magic TEXT, unlock_token BLOB, enrollment_id TEXT, cert_fingerprint TEXT NOT NULL,
 awaiting_configuration INTEGER, authenticated_at INTEGER, token_updated_at INTEGER, last_seen_at INTEGER, unenrolled_at INTEGER,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, platform TEXT NOT NULL, access_rights INTEGER NOT NULL, push_dead_at INTEGER);
CREATE INDEX IF NOT EXISTS device_fingerprint ON devices(cert_fingerprint);
CREATE TABLE IF NOT EXISTS checkin_events (id INTEGER PRIMARY KEY, udid TEXT, message_type TEXT, raw_body BLOB, parsed TEXT, received_at INTEGER NOT NULL, peer_cert_cn TEXT, http_status_returned INTEGER);
CREATE INDEX IF NOT EXISTS checkin_device_time ON checkin_events(udid,received_at);
CREATE TABLE IF NOT EXISTS user_channels (id TEXT PRIMARY KEY, udid TEXT NOT NULL REFERENCES devices(udid), user_id TEXT NOT NULL, push_token BLOB, push_magic TEXT, updated_at INTEGER NOT NULL);
`);
interface Message {
  id: number;
  kind: "query" | "execute" | "script" | "close";
  text: string;
  params: (string | number | null | Uint8Array)[];
}
parentPort?.on("message", (m: Message) => {
  try {
    let result: unknown;
    if (m.kind === "close") {
      sqlite.close();
      result = null;
    } else if (m.kind === "script") {
      sqlite.exec(m.text);
      result = null;
    } else {
      // Only trusted source SQL reaches this worker; all values remain bound parameters.
      const fragments = m.text.split("?");
      if (fragments.length !== m.params.length + 1)
        throw new Error("SQL parameter count mismatch");
      const query = sql.empty();
      fragments.forEach((fragment, i) => {
        query.append(sql.raw(fragment));
        if (i < m.params.length) {
          const p = m.params[i];
          query.append(sql`${p instanceof Uint8Array ? Buffer.from(p) : p}`);
        }
      });
      result = m.kind === "query" ? orm.all(query) : orm.run(query);
    }
    parentPort?.postMessage({ id: m.id, result });
    if (m.kind === "close") parentPort?.close();
  } catch (e) {
    parentPort?.postMessage({
      id: m.id,
      error: e instanceof Error ? e.message : String(e),
    });
  }
});
