import forge from "node-forge";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
const exec = promisify(execFile);
export function signWithForge(
  xml: string,
  cert: string,
  key: string,
  root: string,
): Buffer {
  const m = forge.pkcs7.createSignedData();
  m.content = forge.util.createBuffer(Buffer.from(xml).toString("binary"));
  m.addCertificate(cert);
  m.addCertificate(root);
  m.addSigner({
    key,
    certificate: cert,
    digestAlgorithm: "2.16.840.1.101.3.4.2.1",
    authenticatedAttributes: [
      { type: "1.2.840.113549.1.9.3", value: "1.2.840.113549.1.7.1" },
      { type: "1.2.840.113549.1.9.4" },
    ],
  });
  m.sign({ detached: false });
  return Buffer.from(forge.asn1.toDer(m.toAsn1()).getBytes(), "binary");
}
export async function signWithOpenSSL(
  xml: string,
  cert: string,
  key: string,
  root: string,
  openssl = "openssl",
): Promise<Buffer> {
  const dir = await mkdtemp(join(tmpdir(), "mdm-profile-"));
  try {
    const input = join(dir, "input.plist");
    const output = join(dir, "signed.der");
    await writeFile(input, xml, { mode: 0o600 });
    await exec(openssl, [
      "smime",
      "-sign",
      "-binary",
      "-nodetach",
      "-outform",
      "DER",
      "-md",
      "sha256",
      "-in",
      input,
      "-out",
      output,
      "-signer",
      cert,
      "-inkey",
      key,
      "-certfile",
      root,
    ]);
    return await readFile(output);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
