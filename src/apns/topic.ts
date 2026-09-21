import forge from "node-forge";
export interface PushCertificateInfo {
  topic: string;
  expiresAt: Date;
  certPem: string;
}
export function readPushCertificate(
  input: Buffer,
  password = "",
): PushCertificateInfo {
  const certificates: forge.pki.Certificate[] = [];
  if (input.toString("ascii", 0, 40).includes("-----BEGIN"))
    certificates.push(forge.pki.certificateFromPem(input.toString()));
  else {
    const p12 = forge.pkcs12.pkcs12FromAsn1(
      forge.asn1.fromDer(input.toString("binary")),
      password,
    );
    for (const content of p12.safeContents)
      for (const bag of content.safeBags)
        if (bag.cert) certificates.push(bag.cert);
  }
  for (const cert of certificates) {
    const attribute = cert.subject.attributes.find(
      (a) => a.type === "0.9.2342.19200300.100.1.1",
    );
    if (
      typeof attribute?.value !== "string" ||
      !/^com\.apple\.mgmt\.External\.[0-9a-f-]{36}$/i.test(attribute.value)
    )
      continue;
    if (
      cert.validity.notAfter.getTime() <= Date.now() ||
      cert.validity.notBefore.getTime() > Date.now()
    )
      throw new Error("Push certificate is outside its validity interval");
    return {
      topic: attribute.value,
      expiresAt: cert.validity.notAfter,
      certPem: forge.pki.certificateToPem(cert),
    };
  }
  throw new Error("No MDM UID found in push certificate");
}
