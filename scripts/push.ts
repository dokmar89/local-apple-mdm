import { api } from "./http-client.js";
async function main(): Promise<void> {
  const udid = process.argv[2];
  if (!udid) throw new Error("Usage: npm run push -- <udid>");
  console.log(
    JSON.stringify(
      await api(`/devices/${encodeURIComponent(udid)}/push`, "POST"),
      null,
      2,
    ),
  );
}
main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exitCode = 1;
});
