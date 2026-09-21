import { readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { loadConfig } from "../src/config.js";
import { makeProfile } from "../src/profile.js";
import { buildPlist } from "../src/plist/build.js";
import { signWithForge, signWithOpenSSL } from "../src/sign-profile.js";
async function main(): Promise<void> {
  const { values: v } = parseArgs({
    options: {
      device: { type: "string" },
      platform: { type: "string" },
      p12: { type: "string" },
      signer: { type: "string", default: "openssl" },
      out: { type: "string" },
    },
  });
  if (
    !v.device ||
    !v.p12 ||
    (v.platform !== "ios" && v.platform !== "macos") ||
    !process.env.P12_PASSWORD
  )
    throw new Error(
      "Usage: P12_PASSWORD=... npm run profile -- --device iphone --platform ios --p12 ca/iphone.p12 [--signer openssl|forge]",
    );
  if (v.signer !== "openssl" && v.signer !== "forge")
    throw new Error("Unknown signer");
  const c = loadConfig();
  const [root, p12, cert, key] = await Promise.all([
    readFile(c.MDM_CA),
    readFile(v.p12),
    readFile(c.MDM_CERT, "utf8"),
    readFile(c.MDM_KEY, "utf8"),
  ]);
  const xml = buildPlist(
    makeProfile(c, v.device, v.platform, root, p12, process.env.P12_PASSWORD),
  );
  const out = v.out ?? c.MDM_PROFILE;
  await writeFile(out + ".plist", xml, { mode: 0o600 });
  const signed =
    v.signer === "forge"
      ? signWithForge(xml, cert, key, root.toString())
      : await signWithOpenSSL(
          xml,
          c.MDM_CERT,
          c.MDM_KEY,
          c.MDM_CA,
          process.env.OPENSSL_BIN,
        );
  await writeFile(out, signed, { mode: 0o600 });
  console.log(`Created ${out}; contains a private identity for ${v.device}.`);
}
main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exitCode = 1;
});
