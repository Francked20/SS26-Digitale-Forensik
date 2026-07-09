#import "../style/style.typ": hinweis

= Netzwerkforensik (Mitglied 1)

== Asservat

#table(
  columns: 2,
  [*Datei*], [silent_quarry.pcap],
  [*Größe*], [~8.82 MB],
  [*Gesamtpakete*], [12.132],
  [*Aufnahmeort*], [VM2 (Server), Interface ens37],
  [*Aufnahmedauer*], [00:05:36],
  [*SHA256*], [`be90bf4ef239aead9675acb509d2262d30b540142db01d9e91e56d1f578871d4`],
)

== Identifiziertes Netzwerkumfeld

#table(
  columns: 4,
  [*IP-Adresse*], [*Rolle*], [*MAC*], [*OS-Indikator*],
  [192.168.50.10], [Angreifer (Kali)], [00:0C:29:41:13:85], [Linux (TTL 64)],
  [192.168.50.20], [Server (Opfer)], [00:0C:29:23:90:01], [Linux (TTL 64), SSH Port 22 offen],
  [192.168.50.30], [Client (Opfer)], [00:0C:29:CF:1A:0D], [Windows (TTL 128), RDP Port 3389 offen, Hostname: DESKTOP-GKDAU52],
)

== Rekonstruierte Angriffs-Timeline

#table(
  columns: 4,
  [*Zeit (UTC)*], [*Zeit (CEST)*], [*Ereignis*], [*Beweis*],
  [00:23:42], [02:23:42], [RDP-Verbindung aufgebaut], [Sessions-Tab, Port 3389],
  [00:23:42], [02:23:42], [Benutzername "vogel" erfasst], [RDP-Cookie (Credentials-Tab)],
  [00:24:35], [02:24:35], [SSH-Verbindung \#1], [Sessions-Tab, Port 22],
  [00:26:47], [02:26:47], [SSH-Verbindung \#2 (Exfiltration)], [Sessions-Tab, Port 22],
)

== Zentrale Befunde

=== Finding 1: RDP als Angriffsvektor

- Der Angreifer (192.168.50.10) verband sich per RDP (Port 3389) mit dem Client.
- Die Verbindung war TLS-1.2-verschlüsselt.
- Es wurden ca. 8 MB Bildschirmdaten vom Client zum Angreifer übertragen.
- Der Benutzername "vogel" wurde im RDP-Cookie im Klartext erfasst und belegt
  den Diebstahl der Zugangsdaten.

=== Finding 2: SSH-Zugangsdatenwiederverwendung

Der Angreifer nutzte die gestohlenen Zugangsdaten (m.vogel) in Desktop von vogel, um sich per SSH
am Server anzumelden. Es wurden zwei SSH-Sitzungen aufgebaut:

+ *Erste Sitzung:* OpenSSH 10.2p1 (Kali) → OpenSSH 9.6p1 (Ubuntu Server),
  2026-07-05 00:24:35 UTC, Dauer 233 Sekunden
+ *Zweite Sitzung:* geringes Datenvolumen, 2026-07-05 00:26:47 UTC,
  Dauer 6 Sekunden

=== Finding 3: Datenexfiltration

Innerhalb der ersten SSH-Sitzung (OpenSSH 10.2p1 → OpenSSH 9.6p1,
2026-07-05 00:24:35 UTC, 233 Sekunden):

- ca. 1 MB wurde vom Server zum Angreifer übertragen
- kontinuierlicher Transfer über ca. 4 Minuten
- der Dateninhalt selbst ist SSH-verschlüsselt, Volumen und Richtung
  belegen jedoch den Diebstahl

=== Finding 4: Extrahiertes TLS-Zertifikat

Aus dem RDP-TLS-Handshake wurde das Zertifikat `DESKTOP-GKDAU52.cer`
extrahiert. Es bestätigt den Windows-Hostnamen des Opfer-Clients.

== Bestätigung der isolierten Umgebung

- Kein DNS-Verkehr beobachtet → bestätigt die Isolation von net-quarry.
- Keine externen IP-Adressen im Mitschnitt → gesamter Verkehr innerhalb von
  192.168.50.0/24.

== Fazit

Die aus `silent_quarry.pcap` gewonnenen Beweise rekonstruieren einen
kompakten, einsitzungsbasierten Angriff auf die Laborumgebung
192.168.50.0/24. Der Angriff beginnt außerhalb der Sichtbarkeit des
Netzwerkverkehrs: Der Opfer-Client, bedient durch den Benutzer "vogel",
führte lokal ein Skript (`main.py`) aus, in das Zugangsdaten eingegeben
wurden. Da dieser Schritt das Hostsystem nie verlässt, erzeugt er keine
Pakete und ist im vorliegenden Mitschnitt nicht sichtbar – er wird hier
aus dem breiteren Fallkontext sowie hostbasierten Beweisen abgeleitet,
nicht aus dem PCAP selbst.

Das erste im Mitschnitt sichtbare Artefakt ist eine RDP-Verbindung vom
Angreifer (192.168.50.10) zum Client (192.168.50.30) um 00:23:42 UTC.
Obwohl die RDP-Sitzung selbst TLS-1.2-verschlüsselt ist, legt die
Verbindungsaushandlung – die vor dem Aufbau der Verschlüsselung
stattfindet – den Benutzernamen "vogel" im Klartext über das
RDP-Cookie-Feld (`mstshash=vogel`) offen. Dies ist der früheste Punkt im
Mitschnitt, an dem die Identität des kompromittierten Kontos für einen
Netzwerkanalysten sichtbar wird, und ermöglichte dem Angreifer, mit
einem bekannten, gültigen Benutzernamen fortzufahren. Das zugehörige
TLS-Zertifikat, das von NetworkMiner zweimal innerhalb derselben Sekunde
extrahiert wurde, bestätigt zusätzlich den Hostnamen des Clients als
`DESKTOP-GKDAU52` und untermauert damit den Endpunkt der RDP-Sitzung
unabhängig von DHCP- oder NetBIOS-Daten.

Innerhalb von etwa einer Minute nach Beginn der RDP-Sitzung, um 00:24:35
UTC, öffnete der Angreifer eine SSH-Verbindung zum Server (192.168.50.20)
unter Verwendung derselben "vogel"-Zugangsdaten, belegt durch
Versionsbanner-Pakete, die einen OpenSSH-10.2p1-Client (Kali) identifizieren,
der sich mit einem OpenSSH-9.6p1-Server verbindet. Anstatt Anmeldung und
Datenübertragung auf getrennte Verbindungen aufzuteilen, scheint diese
einzelne SSH-Sitzung – mit einer Dauer von 233 Sekunden und einem
Datenvolumen von rund einem Megabyte, nahezu gleichmäßig in beide
Richtungen verteilt – den gesamten Workflow nach der Kompromittierung
getragen zu haben: Authentifizierung, Auffinden der Zugangsdatendatei auf
dem Server, deren Abruf und anschließende Löschung. Die nahezu
ausgeglichene Byteverteilung über die Sitzung hinweg ist mit diesem
gemischten Nutzungsmuster konsistent, im Gegensatz zu dem Erscheinungsbild
eines rein einseitigen Massentransfers. Obwohl die SSH-Nutzlast selbst
verschlüsselt bleibt und ihr genauer Inhalt nicht direkt gelesen werden
kann, markiert ein Cluster größerer Pakete, die etwa in der Mitte der
Sitzung vom Server zum Angreifer fließen, allein anhand von Paketgröße
und Richtung den wahrscheinlichen Zeitpunkt des Dateiabrufs. Das
I/O-Diagramm zeigt zwei getrennte Aktivitätsschübe innerhalb von Stream 2
(t≈105–140s und t≈230–310s), getrennt durch eine Ruhephase von ca.
90 Sekunden, was auf mindestens zwei verhaltensmäßig unterschiedliche
Phasen der Sitzung hindeutet – konsistent mit einem Angreifer, der
zunächst die Datei lokalisiert und später zurückkehrt, um sie
abzurufen und zu löschen. Eine zweite, deutlich kürzere SSH-Verbindung
folgte vier Minuten später, um 00:28:26 UTC, mit einer Dauer von nur
sechs Sekunden; ihre Kürze und der ausgeglichene Datenverkehr legen eine
beiläufige Wiederverbindung nahe, nicht einen zweiten gezielten
Exfiltrationskanal.

Insgesamt stützt der Mitschnitt eine klare und in sich konsistente
Erzählung – Offenlegung von Zugangsdaten per RDP, gefolgt von
SSH-basiertem Datendiebstahl – und veranschaulicht zugleich die
inhärenten Grenzen netzwerkbasierter Beweise: Die initiale lokale
Kompromittierung, die genaue Identität der abgerufenen Datei sowie die
konkret ausgeführten Befehle liegen allesamt außerhalb dessen, was ein
reiner Paketmitschnitt belegen kann, und müssten durch Host- oder
Arbeitsspeicherforensik von Client- und Server-Disk-/RAM-Images ergänzt
werden, um das Gesamtbild zu vervollständigen.
