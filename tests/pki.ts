import forge from "node-forge";
import { generateKeyPair } from "node:crypto";
import { promisify } from "node:util";
const generate = promisify(generateKeyPair);
export async function testPki() {
  const makeKey = async () => {
    const keys = await generate("rsa", { modulusLength: 2048 });
    return {
      key: keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      publicKey: forge.pki.publicKeyFromPem(
        keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
      ),
    };
  };
  const rootKeys = await makeKey(),
    leafKeys = await makeKey();
  const root = forge.pki.createCertificate();
  root.publicKey = rootKeys.publicKey;
  root.serialNumber = "01";
  root.validity.notBefore = new Date(Date.now() - 60_000);
  root.validity.notAfter = new Date(Date.now() + 86_400_000);
  root.setSubject([{ name: "commonName", value: "Test Root" }]);
  root.setIssuer(root.subject.attributes);
  root.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
  ]);
  root.sign(
    forge.pki.privateKeyFromPem(rootKeys.key),
    forge.md.sha256.create(),
  );
  const leaf = forge.pki.createCertificate();
  leaf.publicKey = leafKeys.publicKey;
  leaf.serialNumber = "02";
  leaf.validity = root.validity;
  leaf.setSubject([{ name: "commonName", value: "test-device" }]);
  leaf.setIssuer(root.subject.attributes);
  leaf.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
      critical: true,
    },
    { name: "extKeyUsage", serverAuth: true, clientAuth: true },
    {
      name: "subjectAltName",
      altNames: [
        { type: 2, value: "localhost" },
        { type: 7, ip: "127.0.0.1" },
      ],
    },
  ]);
  leaf.sign(
    forge.pki.privateKeyFromPem(rootKeys.key),
    forge.md.sha256.create(),
  );
  return {
    ca: forge.pki.certificateToPem(root),
    cert: forge.pki.certificateToPem(leaf),
    key: leafKeys.key,
  };
}
