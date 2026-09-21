# Nasazení MDM na malou Linux VM

Tento server musí přijímat TLS přímo v Node procesu, protože ověřuje klientský certifikát zařízení. Před něj proto nedávej Vercel, Cloudflare proxy ani běžný HTTPS load balancer, který TLS ukončí a certifikát zařízení zahodí.

## Doporučený testovací hosting

Oracle Cloud Always Free VM s Ubuntu 24.04, veřejnou IPv4 a otevřenými TCP porty 22, 80 a 443. Alternativou je Google Compute Engine e2-micro, ale veřejná IPv4 je účtovaná zvlášť.

## Co je potřeba před nasazením

1. Veřejná VM s trvalým diskem.
2. Stabilní DNS jméno, například `mdm.example.cz`, namířené na veřejnou IP VM. Pro krátký test lze použít dynamické DNS, ale jméno se po registraci zařízení nesmí změnit.
3. Veřejný TLS certifikát pro toto jméno. Certbot uloží `fullchain.pem` jako `ca/server.crt` a `privkey.pem` jako `ca/server.key`.
4. Soukromý device root `ca/root-ca.crt` a odpovídající klíč pro vytvoření enrollment identity.
5. Již získané APNs soubory `ca/apns/push-cert.pem` a `ca/apns/push-key.pem`.

## Kontejner

`compose.yaml` předává TLS beze změny přímo aplikaci na portu 8443 v kontejneru a publikuje jej na veřejném portu 443. SQLite je v bind mountu `./data`; server dostane pouze šest potřebných certifikátů/klíčů jako read-only mounty; kořenový privátní klíč ani MDMCert dešifrovací klíč se do kontejneru nepřipojují. Kontejner běží bez root práv, s read-only root filesystemem a bez Linux capabilities.

Po doplnění skutečné domény do `.env`:

```bash
mkdir -p data
sudo chown -R 1000:1000 data
sudo chmod 700 data ca
sudo chmod 600 .env ca/*.key ca/apns/*.pem
docker compose build
docker compose up -d
curl https://mdm.example.cz/healthz
```

Před registrací zařízení je nutné znovu vygenerovat enrollment profil se skutečným `MDM_HOSTNAME`; profil s `localhost` nepoužívej. Změna URL po registraci vyžaduje nový profil a nové zaregistrování zařízení.