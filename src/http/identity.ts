import { TLSSocket } from "node:tls";
import type { FastifyReply, FastifyRequest } from "fastify";
export interface PeerIdentity {
  cn: string;
  issuerCn: string;
  serialNumber: string;
  fingerprint256: string;
  validTo: string;
}
export function getPeerIdentity(request: FastifyRequest): PeerIdentity | null {
  const socket = request.raw.socket;
  if (!(socket instanceof TLSSocket)) return null;
  const cert = socket.getPeerCertificate();
  if (!cert || Object.keys(cert).length === 0 || !cert.fingerprint256)
    return null;
  const cn = cert.subject.CN;
  const issuer = cert.issuer.CN;
  return {
    cn: Array.isArray(cn) ? cn.join(",") : (cn ?? ""),
    issuerCn: Array.isArray(issuer) ? issuer.join(",") : (issuer ?? ""),
    serialNumber: cert.serialNumber,
    fingerprint256: cert.fingerprint256,
    validTo: cert.valid_to,
  };
}
export async function requireClientCertificate(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const socket = request.raw.socket;
  if (
    !(socket instanceof TLSSocket) ||
    !socket.authorized ||
    !getPeerIdentity(request)
  ) {
    request.log.warn(
      {
        authorizationError:
          socket instanceof TLSSocket ? socket.authorizationError : "Not TLS",
      },
      "Client certificate rejected",
    );
    await reply
      .code(403)
      .send({ error: "Trusted client certificate required" });
  }
}
