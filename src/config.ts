import { z } from "zod";
const schema = z.object({
  MDM_HOSTNAME: z
    .string()
    .regex(/^[a-zA-Z0-9.-]+$/)
    .default("localhost"),
  MDM_PORT: z.coerce.number().int().min(1).max(65535).default(8443),
  MDM_LAN_IP: z.string().ip({ version: "v4" }).default("127.0.0.1"),
  MDM_ORG_NAME: z.string().min(1).default("LocalMDM"),
  MDM_TOPIC: z.string().regex(/^com\.apple\.mgmt\.External\.[0-9a-f-]{36}$/i),
  MDM_KEY: z.string().default("ca/server.key"),
  MDM_CERT: z.string().default("ca/server.crt"),
  MDM_CA: z.string().default("ca/root-ca.crt"),
  MDM_PROFILE: z.string().default("ca/enroll.mobileconfig"),
  MDM_DB: z.string().default("data/mdm.sqlite"),
  MDM_API_TOKEN: z.string().min(32),
  MDM_ENROLL_TOKEN: z.string().min(32),
  MDM_PUSH_CERT: z.string().optional(),
  MDM_PUSH_KEY: z.string().optional(),
  MDM_DEBUG_CAPTURE: z.enum(["true", "false"]).default("false"),
  LOG_LEVEL: z
    .enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"])
    .default("info"),
});
export type Config = z.infer<typeof schema>;
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const result = schema.safeParse(env);
  if (!result.success)
    throw new Error(
      "Invalid configuration: " +
        result.error.issues
          .map((i) => `${i.path.join(".")}: ${i.message}`)
          .join("; "),
    );
  if (Boolean(result.data.MDM_PUSH_CERT) !== Boolean(result.data.MDM_PUSH_KEY))
    throw new Error("Set both MDM_PUSH_CERT and MDM_PUSH_KEY");
  return result.data;
}
