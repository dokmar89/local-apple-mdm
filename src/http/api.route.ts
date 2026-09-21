import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Config } from "../config.js";
import type { CommandQueue, QueuedCommand } from "../queue/command-queue.js";
import type { Device } from "../db/client.js";
import type { PushService } from "../apns/push-service.js";
import { matchesSecret } from "./enroll.route.js";
import { buildCommand } from "../commands/registry.js";
export async function apiRoutes(
  app: FastifyInstance,
  queue: CommandQueue,
  push: PushService,
  c: Config,
): Promise<void> {
  await app.register(
    async (api) => {
      api.addHook("onRequest", async (request, reply) => {
        if (
          !matchesSecret(
            request.headers.authorization,
            c.MDM_API_TOKEN ? `Bearer ${c.MDM_API_TOKEN}` : undefined,
          )
        )
          await reply.code(401).send({ error: "Bearer token required" });
      });
      api.get("/devices", async () =>
        queue.db.all(
          "SELECT udid,device_name,platform,os_version,token_updated_at,unenrolled_at,push_dead_at,last_seen_at FROM devices",
        ),
      );
      api.get<{ Params: { udid: string } }>(
        "/devices/:udid/commands",
        async (request) =>
          queue.db.all(
            "SELECT uuid,udid,request_type,status,attempts,created_at,sent_at,completed_at,result,error_chain FROM commands WHERE udid=? ORDER BY created_at DESC LIMIT 100",
            [request.params.udid],
          ),
      );
      api.get<{ Params: { uuid: string } }>(
        "/commands/:uuid",
        async (request, reply) => {
          const command = await queue.db.one<QueuedCommand>(
            "SELECT uuid,udid,request_type,status,attempts,created_at,sent_at,completed_at,result,error_chain FROM commands WHERE uuid=?",
            [request.params.uuid],
          );
          return command ?? reply.code(404).send({ error: "Unknown command" });
        },
      );
      api.post<{ Params: { udid: string } }>(
        "/devices/:udid/commands",
        async (request, reply) => {
          const input = z
            .object({
              requestType: z.string(),
              params: z.record(z.unknown()).default({}),
            })
            .strict()
            .parse(request.body);
          const d = await queue.db.one<Device>(
            "SELECT * FROM devices WHERE udid=?",
            [request.params.udid],
          );
          if (!d || d.unenrolled_at)
            return reply.code(404).send({ error: "Unknown active device" });
          const payload = buildCommand(input.requestType, input.params, d);
          const uuid = await queue.enqueue(d.udid, payload);
          request.log.info(
            { udid: d.udid, uuid, requestType: input.requestType },
            "Command queued",
          );
          // An APNs failure never rolls back an already durable command.
          try {
            const result = await push.pushDevice(d.udid);
            return reply.code(202).send({ uuid, push: result });
          } catch (err) {
            request.log.error({ err, uuid }, "Command queued but push failed");
            return reply.code(202).send({
              uuid,
              push: {
                action: "fail",
                reason: err instanceof Error ? err.message : String(err),
              },
            });
          }
        },
      );
      api.post<{ Params: { udid: string } }>(
        "/devices/:udid/push",
        async (request) => push.pushDevice(request.params.udid),
      );
    },
    { prefix: "/api" },
  );
}
