import https from "node:https";
import { readFile } from "node:fs/promises";
import { loadConfig } from "../src/config.js";
export async function api(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<unknown> {
  const c = loadConfig();
  if (!c.MDM_API_TOKEN) throw new Error("Set MDM_API_TOKEN");
  const ca = await readFile(c.MDM_CA);
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: c.MDM_HOSTNAME,
        port: c.MDM_PORT,
        path: "/api" + path,
        method,
        ca,
        headers: {
          authorization: `Bearer ${c.MDM_API_TOKEN}`,
          ...(payload
            ? {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(payload),
              }
            : {}),
        },
      },
      (res) => {
        let raw = "";
        res.setEncoding("utf8");
        res.on("data", (part: string) => {
          raw += part;
          if (raw.length > 8 * 1024 * 1024)
            req.destroy(new Error("API response too large"));
        });
        res.on("error", reject);
        res.on("end", () => {
          try {
            const result: unknown = raw ? JSON.parse(raw) : null;
            if ((res.statusCode ?? 500) >= 400)
              reject(new Error(`HTTP ${res.statusCode}: ${raw}`));
            else resolve(result);
          } catch (e) {
            reject(e);
          }
        });
      },
    );
    req.setTimeout(90_000, () => req.destroy(new Error("API timeout")));
    req.on("error", reject);
    req.end(payload);
  });
}
