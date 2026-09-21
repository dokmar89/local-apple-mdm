import Fastify from "fastify";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { ZodError } from "zod";
import { loadConfig, type Config } from "./config.js";
import { getPeerIdentity, requireClientCertificate } from "./http/identity.js";
import { enrollRoutes } from "./http/enroll.route.js";
import { checkinRoutes, ProtocolError } from "./http/checkin.route.js";
import { connectRoutes } from "./http/connect.route.js";
import { apiRoutes } from "./http/api.route.js";
import { Db } from "./db/client.js";
import { CommandQueue } from "./queue/command-queue.js";
import { PushService } from "./apns/push-service.js";
import { ApnsClient } from "./apns/client.js";
import { readPushCertificate } from "./apns/topic.js";
import { MAX_BODY, PlistParseError } from "./plist/parse.js";
import pino from "pino";
export async function createServer(c: Config) {
  const [key, cert, ca] = await Promise.all([
    readFile(c.MDM_KEY),
    readFile(c.MDM_CERT),
    readFile(c.MDM_CA),
  ]);
  const loggerOptions = {
    level: c.LOG_LEVEL,
    redact: [
      "req.headers.authorization",
      "req.headers.cookie",
      "req.url",
      "payload.PIN",
      "err.prefixHex",
    ],
  };
  const logger = pino(loggerOptions);
  const app = Fastify({
    https: {
      key,
      cert,
      ca: [ca],
      requestCert: true,
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
      ALPNProtocols: ["http/1.1"],
    },
    logger: loggerOptions,
    bodyLimit: MAX_BODY,
    requestTimeout: 30_000,
  });
  let apns: ApnsClient | undefined;
  if (c.MDM_PUSH_CERT && c.MDM_PUSH_KEY) {
    const [pushCert, pushKey] = await Promise.all([
      readFile(c.MDM_PUSH_CERT),
      readFile(c.MDM_PUSH_KEY),
    ]);
    const info = readPushCertificate(pushCert);
    if (c.MDM_TOPIC !== info.topic)
      throw new Error("MDM_TOPIC differs from the push certificate UID");
    logger.info(
      { topic: info.topic, expiresAt: info.expiresAt },
      "Push certificate loaded",
    );
    if (info.expiresAt.getTime() - Date.now() < 30 * 86_400_000)
      logger.warn({ expiresAt: info.expiresAt }, "Renew push certificate soon");
    apns = new ApnsClient(
      { cert: pushCert, key: pushKey, topic: info.topic },
      logger,
    );
  }
  const db = new Db(c.MDM_DB);
  const queue = new CommandQueue(db);
  const push = new PushService(db, apns, logger);
  try {
    await queue.initialize();
    await push.initialize();
  } catch (e) {
    await db.close();
    throw e;
  }
  app.addHook("onClose", async () => {
    await push.close();
    await db.close();
  });
  app.addHook("onRequest", async (request) => {
    request.log = request.log.child({
      peerCn: getPeerIdentity(request)?.cn ?? null,
    });
  });
  app.addContentTypeParser(
    [
      "application/x-apple-aspen-mdm-checkin",
      "application/x-apple-aspen-mdm",
      "application/xml",
      "text/xml",
      "application/octet-stream",
    ],
    { parseAs: "buffer" },
    (_request, body, done) => done(null, body),
  );
  app.addContentTypeParser("*", { parseAs: "buffer" }, (_request, body, done) =>
    done(null, body),
  );
  if (c.MDM_DEBUG_CAPTURE === "true")
    app.addHook("preHandler", async (request) => {
      if (request.url.startsWith("/mdm/") && Buffer.isBuffer(request.body)) {
        await mkdir("tests/fixtures/captured", {
          recursive: true,
          mode: 0o700,
        });
        await writeFile(
          `tests/fixtures/captured/${Date.now()}-${randomUUID()}.plist`,
          request.body,
          { mode: 0o600 },
        );
      }
    });
  app.setErrorHandler((err, request, reply) => {
    const e = err instanceof Error ? err : new Error(String(err));
    const status =
      e instanceof ProtocolError
        ? e.status
        : e instanceof PlistParseError || e instanceof ZodError
          ? 400
          : "statusCode" in e && typeof e.statusCode === "number"
            ? e.statusCode
            : 500;
    request.log[status >= 500 ? "error" : "warn"](
      { err: e, status },
      "Request failed",
    );
    void reply
      .code(status)
      .send({ error: status >= 500 ? "Internal server error" : e.message });
  });
  app.get("/healthz", async (request) => ({
    ok: true,
    peer: getPeerIdentity(request),
  }));
  app.get(
    "/mdm/_ping",
    { preHandler: requireClientCertificate },
    async (request) => ({ ok: true, peer: getPeerIdentity(request) }),
  );
  await enrollRoutes(app, c);
  await checkinRoutes(app, db, c);
  await connectRoutes(app, queue, push);
  await apiRoutes(app, queue, push, c);
  return app;
}
async function main(): Promise<void> {
  const c = loadConfig();
  const app = await createServer(c);
  let closing = false;
  const shutdown = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    try {
      await app.close();
    } catch (err) {
      app.log.error({ err }, "Shutdown failed");
      process.exitCode = 1;
    }
  };
  process.once("SIGINT", () => {
    void shutdown();
  });
  process.once("SIGTERM", () => {
    void shutdown();
  });
  try {
    await app.listen({ host: "0.0.0.0", port: c.MDM_PORT });
  } catch (e) {
    await app.close();
    throw e;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch((e: unknown) => {
    console.error(e instanceof Error ? e.message : String(e));
    process.exitCode = 1;
  });
