# Local Apple MDM

Produkčně strukturovaný výukový Apple MDM server v Node.js 22. Implementuje lokální PKI, podepsaný enrollment profil, check-in, trvalou frontu příkazů, nativní HTTP/2 APNs klient a pět příkazů. Server je určený pro laboratorní síť; před vystavením do internetu doplň rate limiting, rotaci enrollment tokenů, zálohování a správu tajemství.

**Stav:** laboratorní implementace s automatickými testy protokolu, fronty, profilů a skutečného HTTPS/mTLS serveru. Veřejný repozitář obsahuje pouze zdrojový kód a bezpečné příklady; provozní .env, databáze, APNs materiál, certifikáty, privátní klíče a zachycené požadavky jsou vyloučené.

## 1. Instalace a konfigurace

Na macOS nainstaluj Node.js 22 a OpenSSL 3:

```bash
brew install node@22 openssl@3
cd mdm
npm ci
cp .env.example .env
chmod 600 .env
```

V `.env` nastav skutečné LAN jméno/IP, název organizace, dvě náhodná tajemství a `MDM_TOPIC`. Topic není volitelný placeholder: musí být přesná hodnota UID z MDM push certifikátu `com.apple.mgmt.External.<uuid>`.

## 2. PKI a mTLS

```bash
export MDM_HOSTNAME=macbook.local MDM_LAN_IP=192.168.1.50 MDM_ORG_NAME=ExampleOrg
bash scripts/make-ca.sh
export P12_PASSWORD="$(openssl rand -hex 24)"
bash scripts/make-client-cert.sh iphone-lab
```

Skripty preferují `$(brew --prefix openssl@3)/bin/openssl` a odmítnou LibreSSL. Existující klíče nikdy nepřepíší. Root má kritické `basicConstraints CA:TRUE,pathlen:0` a `keyUsage keyCertSign,cRLSign`. `critical` přikazuje klientovi rozšíření pochopit a vynutit; chybějící/nesprávná CA omezení způsobí selhání ověření řetězce v iOS. `pathlen:0` nedovolí podřízenou CA.

Serverový certifikát má DNS i IP v SAN. Moderní Apple TLS validace ověřuje SAN; Common Name není náhradní identita. Bez odpovídajícího SAN skončí TLS před HTTP jako chyba názvu certifikátu. Skript volí 397 dní. Limit 398 dní se vztahuje na TLS certifikáty vydané systémově důvěryhodnými rooty od září 2020, nikoli obecně na soukromý root ručně přidaný uživatelem; kratší leaf je přesto dobrá rotační disciplína.

PKCS#12 export používá legacy 3DES/SHA-1 pouze pro obal identity kvůli kompatibilitě starších Apple parserů. Neoslabuje RSA klíč ani SHA-256 podpis certifikátu, ale ochrana souboru je slabší než moderní AES/PBKDF2. Proto má `.p12`, profil a heslo zůstat tajné a profil smí dostat jen příslušné zařízení.

Server nastavuje `requestCert:true`, ale `rejectUnauthorized:false`: `/enroll` musí obsloužit zařízení, které ještě certifikát nemá. Node přesto řetězec ověří a výsledek uloží do `TLSSocket.authorized` a `authorizationError`; hook ho na `/mdm/*` vynutí. Root v `ca` zároveň určuje ověřovací kotvu a jeho DN se posílá v TLS `CertificateRequest` jako přijatelný issuer. Když identita zařízení nemá odpovídajícího vydavatele, iOS ji nemusí vůbec nabídnout.

Ověření listeneru:

```bash
npm run dev
curl --cacert ca/root-ca.crt https://macbook.local:8443/healthz
curl --cacert ca/root-ca.crt --cert ca/iphone-lab.crt --key ca/iphone-lab.key https://macbook.local:8443/mdm/_ping
openssl s_client -connect macbook.local:8443 -servername macbook.local -CAfile ca/root-ca.crt -cert ca/iphone-lab.crt -key ca/iphone-lab.key -state -showcerts </dev/null
```

Správný výpis obsahuje `Verify return code: 0 (ok)` a v detailu handshaku `Acceptable client certificate CA names` s DN lokálního rootu. Bez klientského certifikátu `/healthz` vrátí 200 a `/mdm/_ping` 403.

## 3. Enrollment profil

```bash
export P12_PASSWORD='stejné-heslo-jako-při-exportu'
npm run profile -- --device iphone-lab --platform ios --p12 ca/iphone-lab.p12 --out ca/iphone.mobileconfig
plutil -lint ca/iphone.mobileconfig.plist
security cms -D -i ca/iphone.mobileconfig > /tmp/decoded-profile.plist
plutil -lint /tmp/decoded-profile.plist
```

Výchozí signer používá OpenSSL CMS SignedData, SHA-256, vložený obsah a DER. Je doporučený, protože macOS/OpenSSL CMS implementace je lépe prověřená než `node-forge`. Alternativa `--signer forge` nepotřebuje externí proces. Podepsaný soubor už není XML: je to binární CMS kontejner, jehož vložený obsah rozbalí `security cms -D`.

XML plist 1.0 používá `string`, `integer`, `real`, `true/false`, ISO-8601 `date`, base64 `data`, `array` a `dict`, s Apple PLIST 1.0 DOCTYPE. Builder zachová `Buffer` jako `<data>` a `Date` jako `<date>`.

Payload `com.apple.security.root` instaluje důvěryhodný DER certifikát, `com.apple.security.pem` nese PEM/DER certifikát bez soukromého klíče a `com.apple.security.pkcs1` nese PKCS#1 certifikát. Identita s privátním klíčem patří do `com.apple.security.pkcs12`. `IdentityCertificateUUID` propojí MDM payload s konkrétní identitou; bez něj zařízení nemůže vybrat certifikát pro mTLS check-in/connect. Stabilní UUIDv5 zajistí, že opakované generování aktualizuje tentýž payload místo vytvoření paralelní instalace.

`SignMessage:false` vypíná CMS podpis HTTP těla v hlavičce `Mdm-Signature`; při přímém mTLS spojení je tělo chráněné TLS. Podpis se hodí, pokud zprávu ověřuje komponenta za TLS terminátorem nebo potřebuje end-to-end původ. Capability `com.apple.mdm.per-user-connections` říká macOS, že server zvládá oddělený device a user channel.

Profil obsahuje privátní klíč, proto `/enroll` vyžaduje jednorázově distribuovaný token v URL:

```text
https://macbook.local:8443/enroll?token=<MDM_ENROLL_TOKEN>
```

Na iPhonu nejprve v Safari otevři `/ca`, nainstaluj stažený profil, potom v Nastavení → Obecné → Informace → Nastavení důvěryhodnosti certifikátů zapni plnou důvěru pro root. Ručně nainstalovaný root není pro TLS automaticky plně důvěryhodný. Pak stáhni enrollment profil, otevři Nastavení → Profil stažen a nainstaluj jej. Na macOS otevři profil v Nastavení → Soukromí a zabezpečení → Profily; ruční MDM vyžaduje schválení uživatelem (UAMDM) a lokální root může být nutné označit jako důvěryhodný i v Klíčence.

## 4. Check-in a databáze

Zařízení posílá Apple MDM HTTP požadavky metodou `PUT`; server přijímá i `POST` pro laboratorní simulátor. Parser přijímá XML i `bplist00`, prázdné tělo, maximálně 4 MiB a 48 úrovní zanoření. XML entity odmítá. V debug režimu uloží raw plisty do `tests/fixtures/captured`; mohou obsahovat UnlockToken, takže adresář nesdílej.

Tok enrollmentu je:

1. `Authenticate` idempotentně vytvoří/obnoví zařízení a sváže UDID s fingerprintem certifikátu. HTTP 401 enrollment odmítne; neprázdná odpověď není součástí tohoto check-inu.
2. `TokenUpdate` uloží binární token, hex cestu pro APNs a PushMagic. Teprve potom je zařízení aktivní. macOS user channel poznáme podle `UserID` a ukládáme odděleně, aby nepřepsal device token. `UnlockToken` umožňuje citlivé passcode/escrow operace a zůstává jen jako chráněný BLOB. `AwaitingConfiguration` při ADE znamená, že Setup Assistant čeká na dokončení konfigurace.
3. `CheckOut` zachová audit, zneplatní push údaje a expiruje čekající příkazy.
4. `UserAuthenticate` vrací 410, což přeskočí Network/Digest user autentizaci. Alternativní `DigestChallenge` vyžaduje ověřovací backend, který tento lokální server nemá.
5. `GetBootstrapToken` žádá escrow token pro bootstrap FileVault/Secure Token, `SetBootstrapToken` jej ukládá a `DeclarativeManagement` obsluhuje DDM synchronizaci. V této verzi jsou bezpečně zalogované jako podporované stuby s prázdnou 200 odpovědí.

Fingerprint vazba brání zařízení A, aby ve vlastním platném mTLS spojení uvedlo UDID zařízení B a přepsalo jeho push token nebo vyzvedlo jeho příkazy. Neshoda vrací 403. SQLite běží v dedikovaném worker threadu, takže synchronní `better-sqlite3` neblokuje síťovou smyčku Node.

Kontrola databáze:

```bash
sqlite3 data/mdm.sqlite 'select udid,device_name,token_updated_at,cert_fingerprint,unenrolled_at from devices;'
sqlite3 data/mdm.sqlite 'select id,udid,message_type,http_status_returned,datetime(received_at/1000,"unixepoch") from checkin_events order by id;'
```

Po instalaci mají logy pořadí `Authenticate`, `TokenUpdate`; oba s HTTP 200 a stejným `peerCn`. `devices.token_updated_at` a `push_token_hex` nesmí být NULL.

## 5. APNs

Z Apple Push Certificates Portal exportuj `.p12` a převeď ho OpenSSL 3:

```bash
openssl pkcs12 -in push.p12 -clcerts -nokeys -out ca/push-cert.pem -legacy
openssl pkcs12 -in push.p12 -nocerts -nodes -out ca/push-key.pem -legacy
chmod 600 ca/push-key.pem ca/push-cert.pem
openssl x509 -in ca/push-cert.pem -noout -subject -dates -fingerprint -sha256
```

Klient čte topic z UID/OID `0.9.2342.19200300.100.1.1` v certifikátu a odmítne nesoulad s konfigurací. Špatný topic typicky vede na APNs 400 `BadTopic` nebo `DeviceTokenNotForTopic`. Push certifikáty bývají platné jeden rok; server loguje expiraci a 30 dní před ní varuje.

MDM push certifikát z produkčního portálu používá `https://api.push.apple.com:443` a profil má `UseDevelopmentAPNS:false`. Sandbox patří vývojovému APNs prostředí a vyžaduje token vydaný pro stejné prostředí. Nativní `http2` vyjedná ALPN `h2`; APNs provider API HTTP/1.1 nepřijímá.

Požadavek obsahuje `apns-topic`, `apns-push-type: mdm`, prioritu 10, krátkou pětiminutovou expiraci a přesně `{"mdm":"<PushMagic>"}`. MDM payload nemá `aps`, alert ani badge, protože jde o tiché probuzení mdmclientu. PushMagic je zařízení vygenerovaný korelační secret; APNs certifikát autentizuje provider a PushMagic pomůže zařízení přijmout správné MDM probuzení. Expirace 0 znamená „nedoručuj později“, nenulový Unix čas umožní krátké uložení při dočasné nedostupnosti; pět minut omezuje zbytečně staré wakeupy.

HTTP 200 znamená přijetí APNs, nikoli doručení zařízení. 410 `Unregistered` označí jen stále stejný token jako mrtvý. 429/500/503 a transportní chyby se opakují s exponenciálním backoffem a jitterem. Klient udržuje jednu HTTP/2 session, respektuje `SETTINGS_MAX_CONCURRENT_STREAMS`, pingá po 60 s, timeoutuje streamy po 15 s a po GOAWAY otevře novou session; nedokončené requesty projdou retry.

Bez push certifikátu lze otestovat enrollment, DB, queue i Connect simulátorem. APNs CLI pak čitelně vrátí `PushNotConfigured`:

```bash
npm run push -- <udid>
npm run simulate -- simulator simulator --enroll
```

Úspěšný push log obsahuje `status:200`, `action:"ok"`, `apnsId`; reakce zařízení vytvoří následný `/mdm/connect` request.

## 6. Fronta, Connect a příkazy

```bash
npm run mdm -- info <udid>
npm run mdm -- info <udid> --queries UDID,DeviceName,OSVersion,BatteryLevel
npm run mdm -- profiles <udid>
npm run mdm -- security <udid>
npm run mdm -- apps <udid>
npm run mdm -- lock <mac-udid> --message "Zařízení je spravováno" --phone "+420..." --pin 123456
```

Fronta používá `BEGIN IMMEDIATE` a částečný unikátní index, takže jedno zařízení nikdy nemá dva příkazy `sent`. Apple MDM nepipelinuje příkazy: zařízení odpovídá na jeden CommandUUID a až odpověď může obsahovat další příkaz. Druhý předčasný příkaz poruší korelaci a může zůstat nevyhodnotitelný. PostgreSQL varianta by vybrala řádek pomocí `SELECT ... FOR UPDATE SKIP LOCKED`, což zamkne jen kandidáta a škáluje mezi instancemi lépe než databázový write lock SQLite.

`Idle` dostane nejstarší příkaz. `Acknowledged`, `Error` a `CommandFormatError` se uloží a stejná session dostane další. `NotNow` vrátí příkaz do fronty, inkrementuje pokus, naplánuje push a ukončí session. NotNow vzniká například při zamčeném zařízení, nedostupném uživatelském kontextu nebo probíhající systémové operaci. Pokračovat dalšími příkazy by obvykle opakovalo stejnou překážku. Konec session je HTTP 200 s nulovým tělem a `Content-Length: 0`; 204 není protokolem definovaná odpověď a chyba vyvolá retry/backoff zařízení. Apple veřejně nestanovuje pevný Connect timeout; server proto drží vlastní hranici 30 s a při ztrátě odpovědi zachová `sent`, protože destruktivní příkaz už mohl proběhnout.

Debug API vyžaduje `Authorization: Bearer <MDM_API_TOKEN>`. Enqueue je trvalý dřív než push; selhání push tedy příkaz neztratí. Auditní sekvence je:

```text
Command queued → APNs push result (status=200, apnsId) → Command sent → Command acknowledged
```

Chybí-li `APNs push result`, selhalo načtení tokenu nebo APNs transport. Chybí-li `Command sent`, zařízení push nevyzvedlo. `Command sent` bez výsledku znamená ztracenou Connect odpověď nebo zamrzlé zařízení. `Device command error` obsahuje ErrorChain; běžné domény jsou `MCMDMErrorDomain`, `MCProfileErrorDomain`, `NSCocoaErrorDomain` a `NSPOSIXErrorDomain`. `Command format error` loguje payload jako chybu serveru.

### Podporované příkazy

| RequestType | Platforma | AccessRights | Poznámka |
| --- | --- | ---: | --- |
| DeviceInformation | iOS 4+, macOS 10.7+ | 16; síťové dotazy navíc 32 | Chybějící QueryResponses jsou normální. BatteryLevel je 0–1 nebo -1; kapacity jsou desetinné GB na iOS/macOS 12+, na macOS 11− historicky GiB. |
| DeviceLock | iOS 4+, macOS 10.7+ | 4 | iOS ignoruje PIN. Server vyžaduje pro macOS šest číslic. Apple dnes používá Find My framework; na Apple silicon před macOS 11.5 může příkaz Mac deaktivovat a reaktivace vyžaduje síť a lokálního Secure Token administrátora. PIN uchovej mimo logy. |
| ProfileList | iOS 4+, macOS 10.7+ | 1 | Vrací nainstalované profily. |
| SecurityInfo | iOS 4+, macOS 10.7+ | 1024 | `PasscodePresent` patří sem, nikoli mezi DeviceInformation Queries. |
| InstalledApplicationList | iOS 5+, macOS 10.7+ | 256 | User Enrollment vždy omezuje výsledek na spravované aplikace. Apple command nemá stránkovací token; lze omezit `Identifiers`, `ManagedAppsOnly` a na novějších iOS `Items`. |

`DeviceID` je podle aktuálního Apple schématu tvOS query, ne iOS/macOS query; je v typovém seznamu kvůli požadavku zadání, ale na iPhonu se neočekává. `IMEI` je od iOS 16 deprecated a v iOS 26 odstraněné. Neznámé/nepovolené informace zařízení vynechá, neposílá `null`.

Historie `device_facts` je append-only a view `current_device_facts` vybírá poslední hodnotu. Historie ukáže změny názvu, OS, baterie nebo kapacity a zachová audit; přepis sloupců v `devices` by předchozí stav ztratil.

## Testy a akceptace

```bash
npm ci
npm run typecheck
npm test
npm run audit -- --omit=dev
```

Testy generují vlastní PKI a ověřují skutečný HTTPS/mTLS server, veřejné a chráněné routy, enrollment, všech pět Connect stavů, cizí fingerprint, checkout, parser limity, UUIDv5, registry, macOS PIN, chybějící QueryResponses, `BatteryLevel === -1` a souběžné dequeue. Fyzické Apple zařízení a skutečný APNs certifikát z Windows CI ověřit nelze.

Akceptační stav fyzického iPhonu:

1. `openssl s_client` ukazuje verify code 0 a přijatelný CA DN.
2. `security cms -D` a `plutil -lint` profil přijmou.
3. Instalace vytvoří 200 `Authenticate`, potom 200 `TokenUpdate`; v DB je token.
4. `npm run mdm -- info <udid>` vypíše CommandUUID, APNs 200 a tabulku například:

```text
CommandUUID: 7ad4...
Push: { status: 200, apnsId: '...', reason: null, action: 'ok' }
┌─────────────────────────┬────────────────────┐
│ DeviceName              │ Test iPhone        │
│ OSVersion               │ 18.x               │
│ BatteryLevel            │ 0.73               │
└─────────────────────────┴────────────────────┘
```

Konkrétní hodnoty závisí na zařízení a OS. Server považuj za funkční, pokud stav příkazu skončí `acknowledged`, `commands.result` obsahuje normalizovaná data a `device_facts` má nové řádky.


## Licence

Zdrojový kód je zveřejněn pod licencí [MIT](LICENSE).
