import { createPublicKey } from "node:crypto";
import forge from "node-forge";
import { expect, it } from "vitest";
import {
  buildSignRequest,
  createRequestMaterial,
} from "../scripts/mdmcert-request.js";

function normalizedPublicKey(pem: string): string {
  return pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
}

it("creates separate push and exchange identities without exposing private keys", async () => {
  const email = "test@example.com";
  const material = await createRequestMaterial(email);
  const csr = forge.pki.certificationRequestFromPem(material.pushCsr);
  if (!csr.publicKey) throw new Error("Generated CSR has no public key");
  expect(csr.verify()).toBe(true);
  expect(
    csr.subject.attributes.find(
      (attribute) => attribute.type === "1.2.840.113549.1.9.1",
    )?.value,
  ).toBe(email);
  expect(normalizedPublicKey(forge.pki.publicKeyToPem(csr.publicKey))).toBe(
    normalizedPublicKey(
      createPublicKey(material.pushPrivateKey)
        .export({ type: "spki", format: "pem" })
        .toString(),
    ),
  );
  expect(material.pushPrivateKey).not.toBe(material.exchangePrivateKey);
  const body = buildSignRequest(
    email,
    "test-api-key",
    material.pushCsr,
    material.exchangeCertificate,
  );
  expect(Object.keys(body).sort()).toEqual(["csr", "email", "encrypt", "key"]);
  expect(Buffer.from(body.csr, "base64").toString()).toBe(material.pushCsr);
  expect(JSON.stringify(body)).not.toContain("PRIVATE KEY");
  expect(() =>
    buildSignRequest(email, "", material.pushCsr, material.exchangeCertificate),
  ).toThrow("MDMCERT_API_KEY");
});
