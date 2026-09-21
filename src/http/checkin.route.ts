import type { FastifyInstance } from "fastify";
import type { Config } from "../config.js";
import type { Db, Device } from "../db/client.js";
import { dict, parsePlist } from "../plist/parse.js";
import { authenticateSchema, tokenSchema, json } from "../protocol.js";
import {
  getPeerIdentity,
  requireClientCertificate,
  type PeerIdentity,
} from "./identity.js";
import { ALL_ACCESS_RIGHTS } from "../commands/access-rights.js";
export class ProtocolError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function handleCheckin(
  db: Db,
  config: Config,
  raw: Buffer,
  peer: PeerIdentity,
): Promise<number> {
  const p = dict(parsePlist(raw));
  if (
    typeof p.UDID !== "string" ||
    !p.UDID ||
    typeof p.MessageType !== "string"
  )
    throw new ProtocolError(400, "UDID and MessageType required");
  const udid = p.UDID;
  const now = Date.now();
  let status = 200;
  try {
    await db.transaction(async () => {
      const device = await db.one<Device>(
        "SELECT * FROM devices WHERE udid=?",
        [udid],
      );
      if (device && device.cert_fingerprint !== peer.fingerprint256)
        throw new ProtocolError(403, "Certificate does not own UDID");
      if (p.Topic !== undefined && p.Topic !== config.MDM_TOPIC)
        throw new ProtocolError(403, "Topic mismatch");
      if (p.MessageType === "Authenticate") {
        const a = authenticateSchema.parse(p);
        // Never allow a trusted identity already bound to another device to claim a second UDID.
        const other = await db.one<{ udid: string }>(
          "SELECT udid FROM devices WHERE cert_fingerprint=? AND udid<>?",
          [peer.fingerprint256, udid],
        );
        if (other) throw new ProtocolError(403, "Identity already bound");
        const platform = a.ProductName?.startsWith("Mac") ? "macos" : "ios";
        await db.run(
          `INSERT INTO devices (udid,serial_number,device_name,product_name,model,os_version,build_version,topic,enrollment_id,cert_fingerprint,platform,access_rights,authenticated_at,last_seen_at,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(udid) DO UPDATE SET serial_number=excluded.serial_number,device_name=excluded.device_name,product_name=excluded.product_name,model=excluded.model,os_version=excluded.os_version,build_version=excluded.build_version,topic=excluded.topic,enrollment_id=excluded.enrollment_id,platform=excluded.platform,authenticated_at=excluded.authenticated_at,last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at,push_token=NULL,push_token_hex=NULL,push_magic=NULL,unlock_token=NULL,token_updated_at=NULL,unenrolled_at=NULL,push_dead_at=NULL,awaiting_configuration=0`,
          [
            udid,
            a.SerialNumber ?? null,
            a.DeviceName ?? null,
            a.ProductName ?? null,
            a.Model ?? null,
            a.OSVersion ?? null,
            a.BuildVersion ?? null,
            a.Topic,
            a.EnrollmentID ?? null,
            peer.fingerprint256,
            platform,
            ALL_ACCESS_RIGHTS,
            now,
            now,
            now,
            now,
          ],
        );
        await db.run("DELETE FROM user_channels WHERE udid=?", [udid]);
      } else {
        if (!device || device.unenrolled_at)
          throw new ProtocolError(401, "Device is not enrolled");
        if (p.MessageType === "TokenUpdate") {
          const t = tokenSchema.parse(p);
          if (
            !t.Token.length ||
            t.Token.length > 4096 ||
            (t.UnlockToken?.length ?? 0) > 1024 * 1024
          )
            throw new ProtocolError(400, "Token size invalid");
          if (t.UserID) {
            // A user token must never overwrite the device channel token.
            await db.run(
              "INSERT INTO user_channels(id,udid,user_id,push_token,push_magic,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET push_token=excluded.push_token,push_magic=excluded.push_magic,updated_at=excluded.updated_at",
              [
                `${udid}:${t.UserID}`,
                udid,
                t.UserID,
                t.Token,
                t.PushMagic,
                now,
              ],
            );
          } else
            await db.run(
              "UPDATE devices SET push_token=?,push_token_hex=?,push_magic=?,unlock_token=?,awaiting_configuration=?,token_updated_at=?,last_seen_at=?,updated_at=?,push_dead_at=NULL WHERE udid=?",
              [
                t.Token,
                t.Token.toString("hex"),
                t.PushMagic,
                t.UnlockToken ?? null,
                t.AwaitingConfiguration ? 1 : 0,
                now,
                now,
                now,
                udid,
              ],
            );
        } else if (p.MessageType === "CheckOut") {
          await db.run(
            "UPDATE devices SET unenrolled_at=?,updated_at=?,push_token=NULL,push_token_hex=NULL,push_magic=NULL,unlock_token=NULL WHERE udid=?",
            [now, now, udid],
          );
          await db.run("DELETE FROM user_channels WHERE udid=?", [udid]);
          const queue = await db.one<{ name: string }>(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='commands'",
          );
          if (queue)
            await db.run(
              "UPDATE commands SET status='expired',completed_at=? WHERE udid=? AND status IN ('queued','sent','not_now')",
              [now, udid],
            );
        } else if (p.MessageType === "UserAuthenticate") status = 410;
        else if (
          ![
            "GetBootstrapToken",
            "SetBootstrapToken",
            "DeclarativeManagement",
          ].includes(p.MessageType as string)
        )
          throw new ProtocolError(400, "Unknown MessageType");
      }
    });
  } catch (e) {
    status = e instanceof ProtocolError ? e.status : 400;
    throw e;
  } finally {
    await db.run(
      "INSERT INTO checkin_events(udid,message_type,raw_body,parsed,received_at,peer_cert_cn,http_status_returned) VALUES(?,?,?,?,?,?,?)",
      [udid, p.MessageType as string, raw, json(p), now, peer.cn, status],
    );
  }
  return status;
}
export async function checkinRoutes(
  app: FastifyInstance,
  db: Db,
  config: Config,
): Promise<void> {
  app.route({
    method: ["PUT", "POST"],
    url: "/mdm/checkin",
    preHandler: requireClientCertificate,
    handler: async (request, reply) => {
      const peer = getPeerIdentity(request);
      if (!peer || !Buffer.isBuffer(request.body))
        return reply.code(400).send();
      const status = await handleCheckin(db, config, request.body, peer);
      request.log.info({ status }, "Check-in processed");
      return reply.code(status).header("Content-Length", "0").send();
    },
  });
}
