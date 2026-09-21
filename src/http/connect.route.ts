import type { FastifyInstance, FastifyBaseLogger } from "fastify";
import { dict, parsePlist } from "../plist/parse.js";
import { buildPlist } from "../plist/build.js";
import type { Device } from "../db/client.js";
import { CommandQueue, type QueuedCommand } from "../queue/command-queue.js";
import { errorChainSchema, json } from "../protocol.js";
import type { PushService } from "../apns/push-service.js";
import {
  getPeerIdentity,
  requireClientCertificate,
  type PeerIdentity,
} from "./identity.js";
import { ProtocolError } from "./checkin.route.js";
export async function handleConnect(
  queue: CommandQueue,
  push: Pick<PushService, "scheduleRetry">,
  raw: Buffer,
  peer: PeerIdentity,
  log: FastifyBaseLogger,
): Promise<Buffer> {
  const parsed = parsePlist(raw);
  let p = parsed === null ? {} : dict(parsed);
  if (parsed === null) {
    const d = await queue.db.one<Device>(
      "SELECT * FROM devices WHERE cert_fingerprint=?",
      [peer.fingerprint256],
    );
    if (!d) throw new ProtocolError(401, "Unknown device");
    p = { UDID: d.udid, Status: "Idle" };
  }
  if (typeof p.UDID !== "string" || typeof p.Status !== "string")
    throw new ProtocolError(400, "UDID and Status required");
  const udid = p.UDID,
    status = p.Status;
  const d = await queue.db.one<Device>("SELECT * FROM devices WHERE udid=?", [
    udid,
  ]);
  if (!d || d.unenrolled_at || !d.token_updated_at)
    throw new ProtocolError(401, "Device is not enrolled");
  if (d.cert_fingerprint !== peer.fingerprint256)
    throw new ProtocolError(403, "Certificate does not own UDID");
  if (p.UserID !== undefined) return Buffer.alloc(0); // User channel commands are not mixed into the device queue.
  await queue.db.run("UPDATE devices SET last_seen_at=? WHERE udid=?", [
    Date.now(),
    udid,
  ]);
  const uuid = typeof p.CommandUUID === "string" ? p.CommandUUID : null;
  let stop = false;
  if (status !== "Idle") {
    const active = uuid
      ? await queue.db.one<QueuedCommand>(
          "SELECT * FROM commands WHERE uuid=? AND udid=? AND status='sent'",
          [uuid, udid],
        )
      : undefined;
    if (!active) {
      log.warn({ udid, uuid, status }, "Unknown or stale command response");
      stop = true;
    } else {
      switch (status) {
        case "Acknowledged":
          await queue.markAcknowledged(active.uuid, udid, p, raw);
          log.info({ udid, uuid }, "Command acknowledged");
          break;
        case "Error":
          await queue.markError(
            active.uuid,
            udid,
            errorChainSchema.parse(p.ErrorChain),
            raw,
          );
          log.warn(
            { udid, uuid, errorChain: p.ErrorChain },
            "Device command error",
          );
          break;
        case "CommandFormatError":
          await queue.markError(
            active.uuid,
            udid,
            [{ ErrorDomain: "ServerCommandFormat", ErrorCode: 0 }],
            raw,
          );
          log.error(
            { udid, uuid, payload: JSON.parse(active.payload) as unknown },
            "Command format error",
          );
          break;
        case "NotNow":
          await queue.markNotNow(active.uuid, udid, raw);
          push.scheduleRetry(udid, active.attempts + 1);
          stop = true;
          break;
        default:
          log.warn({ udid, status }, "Unknown Connect status");
          stop = true;
      }
    }
  }
  const next = stop ? undefined : await queue.dequeueNext(udid);
  const response = next
    ? Buffer.from(
        buildPlist({
          CommandUUID: next.uuid,
          Command: dict(JSON.parse(next.payload) as unknown),
        }),
      )
    : Buffer.alloc(0);
  if (next)
    log.info(
      { udid, uuid: next.uuid, requestType: next.request_type },
      "Command sent",
    );
  await queue.db.run(
    "INSERT INTO connect_events(udid,status,command_uuid,raw_body,raw_response,received_at) VALUES(?,?,?,?,?,?)",
    [udid, status, uuid, raw, response, Date.now()],
  );
  return response;
}
export async function connectRoutes(
  app: FastifyInstance,
  queue: CommandQueue,
  push: PushService,
): Promise<void> {
  app.route({
    method: ["PUT", "POST"],
    url: "/mdm/connect",
    preHandler: requireClientCertificate,
    handler: async (request, reply) => {
      const peer = getPeerIdentity(request);
      if (!peer || !Buffer.isBuffer(request.body))
        return reply.code(400).send();
      const response = await handleConnect(
        queue,
        push,
        request.body,
        peer,
        request.log,
      );
      return reply
        .code(200)
        .type("application/xml")
        .header("Content-Length", String(response.length))
        .send(response);
    },
  });
}
