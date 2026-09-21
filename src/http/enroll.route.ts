import { readFile } from "node:fs/promises";
import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { Config } from "../config.js";
export function matchesSecret(
  input: string | undefined,
  secret: string | undefined,
): boolean {
  if (!input || !secret) return false;
  const a = Buffer.from(input);
  const b = Buffer.from(secret);
  return a.length === b.length && timingSafeEqual(a, b);
}
export async function enrollRoutes(
  app: FastifyInstance,
  config: Config,
): Promise<void> {
  app.get("/ca", async (_request, reply) =>
    reply
      .type("application/x-x509-ca-cert")
      .send(await readFile(config.MDM_CA)),
  );
  app.get<{ Querystring: { token?: string } }>(
    "/enroll",
    async (request, reply) => {
      // The profile embeds a private key; mTLS is unavailable before enrollment.
      if (!matchesSecret(request.query.token, config.MDM_ENROLL_TOKEN))
        return reply.code(403).send({ error: "Enrollment token required" });
      return reply
        .header("Cache-Control", "no-store")
        .header(
          "Content-Disposition",
          'attachment; filename="enroll.mobileconfig"',
        )
        .type("application/x-apple-aspen-config")
        .send(await readFile(config.MDM_PROFILE));
    },
  );
}
