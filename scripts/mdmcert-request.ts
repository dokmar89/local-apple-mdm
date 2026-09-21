import { createPublicKey, generateKeyPair, randomBytes } from "node:crypto";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";
import forge from "node-forge";
import { z } from "zod";

const generateKeyPairAsync = promisify(generateKeyPair);
const requestEndpoint = "https://mdmcert.download/api/v1/signrequest";

export interface RequestMaterial {
  pushPrivateKey: string;
  pushCsr: string;
  exchangePrivateKey: string;
  exchangeCertificate: string;
}

async function generateRsaIdentity(): Promise<{
  privateKey: string;
  publicKey: forge.pki.rsa.PublicKey;
}> {
  const pair = await generateKeyPairAsync("rsa", { modulusLength: 2048 });
  return {
    privateKey: pair.privateKey
      .export({ format: "pem", type: "pkcs1" })
      .toString(),
    publicKey: forge.pki.publicKeyFromPem(
      pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
    ),
  };
}

export async function createRequestMaterial(
  email: string,
): Promise<RequestMaterial> {
  z.string().email().parse(email);
  const [push, exchange] = await Promise.all([
    generateRsaIdentity(),
    generateRsaIdentity(),
  ]);

  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = push.publicKey;
  csr.setSubject([
    { name: "countryName", value: "CZ" },
    { name: "commonName", value: "mdm-push" },
    { name: "emailAddress", value: email },
  ]);
  csr.sign(
    forge.pki.privateKeyFromPem(push.privateKey),
    forge.md.sha256.create(),
  );
  if (!csr.verify()) throw new Error("Generated push CSR is invalid");

  // This certificate only decrypts the signed CSR returned by the service.
  // It is deliberately separate from the APNs push key.
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = exchange.publicKey;
  certificate.serialNumber = `01${randomBytes(15).toString("hex")}`;
  certificate.validity.notBefore = new Date(Date.now() - 60_000);
  certificate.validity.notAfter = new Date(Date.now() + 365 * 86_400_000);
  certificate.setSubject([
    { name: "commonName", value: "mdmcert.download exchange" },
  ]);
  certificate.setIssuer(certificate.subject.attributes);
  certificate.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "keyUsage",
      keyEncipherment: true,
      digitalSignature: true,
      critical: true,
    },
  ]);
  certificate.sign(
    forge.pki.privateKeyFromPem(exchange.privateKey),
    forge.md.sha256.create(),
  );

  return {
    pushPrivateKey: push.privateKey,
    pushCsr: forge.pki.certificationRequestToPem(csr),
    exchangePrivateKey: exchange.privateKey,
    exchangeCertificate: forge.pki.certificateToPem(certificate),
  };
}

export function buildSignRequest(
  email: string,
  apiKey: string,
  csrPem: string,
  exchangeCertificatePem: string,
): { email: string; key: string; csr: string; encrypt: string } {
  z.string().email().parse(email);
  if (!apiKey.trim()) {
    throw new Error(
      "MDMCERT_API_KEY is required; verified registration email is not an API key",
    );
  }
  if (!forge.pki.certificationRequestFromPem(csrPem).verify()) {
    throw new Error("Push CSR signature is invalid");
  }
  forge.pki.certificateFromPem(exchangeCertificatePem);
  return {
    email,
    key: apiKey,
    csr: Buffer.from(csrPem).toString("base64"),
    encrypt: Buffer.from(exchangeCertificatePem).toString("base64"),
  };
}

function normalizedPublicKey(pem: string): string {
  return pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
}

function csrEmail(csr: {
  subject: {
    attributes: Array<{ name?: string; type?: string; value?: unknown }>;
  };
}): string | undefined {
  const value = csr.subject.attributes.find(
    (attribute) =>
      attribute.name === "emailAddress" ||
      attribute.type === "1.2.840.113549.1.9.1",
  )?.value;
  return typeof value === "string" ? value : undefined;
}

async function prepare(email: string, baseDirectory: string): Promise<void> {
  const directory = join(resolve(baseDirectory), "request");
  await mkdir(resolve(baseDirectory), { recursive: true, mode: 0o700 });
  // Non-recursive creation atomically refuses to replace an existing identity.
  await mkdir(directory, { mode: 0o700 });
  const material = await createRequestMaterial(email);
  const files: Record<string, string> = {
    "push-key.pem": material.pushPrivateKey,
    "push.csr.pem": material.pushCsr,
    "exchange-key.pem": material.exchangePrivateKey,
    "exchange-cert.pem": material.exchangeCertificate,
  };
  for (const [name, contents] of Object.entries(files)) {
    await writeFile(join(directory, name), contents, {
      flag: "wx",
      mode: 0o600,
    });
  }
  await writeFile(
    join(directory, "manifest.json"),
    JSON.stringify(
      {
        email,
        endpoint: requestEndpoint,
        createdAt: new Date().toISOString(),
        status: "prepared",
      },
      null,
      2,
    ),
    { flag: "wx", mode: 0o600 },
  );
  console.log(
    `Prepared ${directory}. Nothing was sent; keep both private keys safe.`,
  );
}

async function submit(baseDirectory: string): Promise<void> {
  const directory = join(resolve(baseDirectory), "request");
  const manifest = z
    .object({ email: z.string().email() })
    .parse(
      JSON.parse(await readFile(join(directory, "manifest.json"), "utf8")),
    );
  const [csrPem, certificatePem, pushKeyPem] = await Promise.all([
    readFile(join(directory, "push.csr.pem"), "utf8"),
    readFile(join(directory, "exchange-cert.pem"), "utf8"),
    readFile(join(directory, "push-key.pem"), "utf8"),
  ]);
  const csr = forge.pki.certificationRequestFromPem(csrPem);
  if (!csr.publicKey) throw new Error("Push CSR has no public key");
  if (csrEmail(csr) !== manifest.email) {
    throw new Error("CSR email differs from the prepared manifest");
  }
  const keyPublicPem = createPublicKey(pushKeyPem)
    .export({ format: "pem", type: "spki" })
    .toString();
  if (
    normalizedPublicKey(keyPublicPem) !==
    normalizedPublicKey(forge.pki.publicKeyToPem(csr.publicKey))
  ) {
    throw new Error("Push CSR does not match push-key.pem");
  }
  const body = buildSignRequest(
    manifest.email,
    process.env.MDMCERT_API_KEY ?? "",
    csrPem,
    certificatePem,
  );

  // Reserve one attempt before network I/O. A timeout is ambiguous and must
  // be checked before a human deliberately removes this marker and retries.
  const attempt = await open(join(directory, "submission.json"), "wx", 0o600);
  try {
    await attempt.writeFile(
      JSON.stringify({
        status: "pending",
        startedAt: new Date().toISOString(),
      }),
    );
    const response = await fetch(requestEndpoint, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
      headers: {
        "content-type": "application/json",
        "user-agent": "local-apple-mdm/1.0",
      },
      body: JSON.stringify(body),
    });
    const result = z
      .object({ result: z.string(), reason: z.string().optional() })
      .parse(await response.json());
    if (!response.ok || result.result !== "success") {
      throw new Error(
        `Signing service rejected request (HTTP ${response.status}): ${result.reason ?? result.result}`,
      );
    }
    await writeFile(
      join(directory, "accepted.json"),
      JSON.stringify({
        status: "accepted",
        acceptedAt: new Date().toISOString(),
      }),
      { flag: "wx", mode: 0o600 },
    );
    console.log(
      `Signing request accepted. Check ${manifest.email} for the encrypted attachment.`,
    );
  } finally {
    await attempt.close();
  }
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      email: { type: "string" },
      dir: { type: "string", default: "ca/mdmcert" },
    },
  });
  if (positionals[0] === "prepare") {
    await prepare(
      z.string().email().parse(values.email),
      values.dir ?? "ca/mdmcert",
    );
  } else if (positionals[0] === "submit") {
    await submit(values.dir ?? "ca/mdmcert");
  } else {
    throw new Error(
      "Usage: npm run mdmcert -- prepare --email name@example.com | submit",
    );
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
