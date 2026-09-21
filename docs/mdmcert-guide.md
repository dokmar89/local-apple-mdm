# Žádost přes mdmcert.download

Registrace a ověření e-mailu stačí; osobní API klíč se nevydává. Pro odeslání používáme oficiální klient MicroMDM `mdmctl`, který provozovatel služby doporučil.

Žádost pro `dokoupil@skolapopulo.cz` byla odeslána 21. září 2026. Lokální klíče a CSR jsou v `ca/mdmcert/official-request`; celý adresář `ca` je v `.gitignore`.

Po doručení přílohy e-mailem ji ulož beze změny. Rozšifrujeme ji oficiálním klientem a vzniklý soubor `mdmcert.download.push.req` nahrajeme na [Apple Push Certificates Portal](https://identity.apple.com). Stažený APNs certifikát následně spojíme se souborem `mdmcert.download.push.key` a nastavíme v serveru.

Při každoroční obnově je nutné v Apple portálu použít **Renew**, aby zůstal stejný APNs topic a zařízení se nemusela znovu registrovat.

Podklady: [postup služby](https://mdmcert.download/instructions), [oficiální postup MicroMDM](https://github.com/micromdm/micromdm/blob/main/docs/user-guide/quickstart.md).