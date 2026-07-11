#import "../style/style.typ": hinweis

= Netzwerkforensik (Mitglied 1)

== Asservat

#table(
  columns: 2,
  [*Datei*], [silent_quarry.pcap],
  [*Größe*], [~8.82 MB],
  [*Tools genutzt*], [Wireshark, NetworkMiner],
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
  [00:24:35], [02:24:35], [SSH-Verbindung \#1(Exfiltration)], [Sessions-Tab, Port 22],
  [00:26:47], [02:26:47], [SSH-Verbindung \#2], [Sessions-Tab, Port 22],
)

== Zentrale Befunde

=== Zusammenfassung der zentralen Befunde

#table(
  columns: (auto, auto, auto, auto),
  inset: 10pt,
  align: (col, row) => (
    if row == 0 { center + horizon }
    else if col < 2 { center + horizon }
    else { left + horizon }
  ),
  stroke: (x, y) => if y == 0 { (bottom: 1.5pt + rgb("#262626")) } else if y == 1 { none } else { (top: 0.5pt + rgb("#e5e5e5")) },
  fill: (col, row) => if row == 0 { rgb("#f4f4f5") } else if calc.even(row) { rgb("#fafafa") } else { none },
  
  // Header
  [*ID*], [*Vektor / Thema*], [*Betroffene Systeme*], [*Kernbefund / Evidenz*],[*Proof von Artefacts*],
  
  // Row 1
  [B001-NETZ-SQ-2026], 
  [RDP-Angriffsvektor], 
  [192.168.50.10 (Angreifer) \ -> 192.168.50.30 (Client)], 
  [TLS-1.2-verschlüsselte RDP-Sitzung. Übertragung von ca. 8 MB Bildschirmdaten. Benutzername "vogel" wurde im RDP-Cookie im Klartext erfasst.], [RDP_Verbindung.pcap],
  
  // Row 2
  [B002-NETZ-SQ-2026], 
  [SSH-Credential-Wiederverwendung], 
  [192.168.50.10 (Angreifer) \ -> 192.168.50.20 (Server)], 
  [Aufbau von zwei SSH-Sitzungen mit den gestohlenen Zugangsdaten von "vogel". Erste Sitzung dauerte 233s, zweite Sitzung war eine kurze Zweitverbindung (6s) ohne Datenextraktion.],[NetworkMiner_Session.txt],
  
  // Row 3
  [B003-NETZ-SQ-2026], 
  [Datenexfiltration], 
  [192.168.50.20 (Server) \ -> 192.168.50.10 (Angreifer)], 
  [Exfiltration von ca. 1 MB verschlüsselten Daten innerhalb der ersten SSH-Sitzung. Kontinuierlicher Transfer über ca. 4 Minuten hinweg.], [SSH_Verbindung1.txt],
  
  // Row 4
  [B004-NETZ-SQ-2026], 
  [TLS-Zertifikat], 
  [192.168.50.30 (Client)], 
  [Extraktion des Zertifikats `DESKTOP-GKDAU52.cer` aus dem RDP-Handshake. Bestätigt unabhängig den Windows-Hostnamen des Opfer-Clients.], [NetworkMiner_Files.txt],
)

=== Finding 1: RDP als Angriffsvektor

#figure(
  image("../res/Images_M1/RDP_Wireshark.png", width: 90%),
  caption: [Ausgabe von `RDP in Wireshark durch Port 3389`],
) <fig-file>

- Der Angreifer (192.168.50.10) verband sich per RDP (Port 3389) mit dem Client.
- Die Verbindung war TLS-1.2-verschlüsselt.
- Es wurden ca. 8 MB Bildschirmdaten vom Client zum Angreifer übertragen.
#figure(
  image("../res/Images_M1/RDP_IO_Graph.png", width: 90%),
  caption: [Ausgabe von `Graph zeigt 8MB transferiert werden als RDP`],
) <fig-file>

- Der Benutzername "vogel" wurde im RDP-Cookie im Klartext erfasst und belegt
  den Diebstahl der Zugangsdaten.

=== Finding 2: SSH-Zugangsdatenwiederverwendung

Der Angreifer nutzte die gestohlenen Zugangsdaten (m.vogel) in Desktop von vogel, um sich per SSH
am Server anzumelden. Es wurden zwei SSH-Sitzungen aufgebaut:

  #figure(
  image("../res/Images_M1/SSH_Connection_Proof_NetworkMiner.png", width: 90%),
  caption: [Ausgabe von `Proof fur 2 SSH Verbindungen`],
) <fig-file>

+ *Erste Sitzung:* OpenSSH 10.2p1 (Kali) → OpenSSH 9.6p1 (Ubuntu Server),
  2026-07-05 00:24:35 UTC, Dauer 233 Sekunden
  #figure(
  image("../res/Images_M1/TCP_Stream_SSH1.png", width: 90%),
  caption: [Ausgabe von `Erste SSH Verbindung`],
) <fig-file>
  #figure(
  image("../res/Images_M1/Exchange_Data_Graph_SSH1.png", width: 90%),
  caption: [Ausgabe von `Erste SSH Verbindung Graph`],
) <fig-file>
+ *Zweite Sitzung:* geringes Datenvolumen, 2026-07-05 00:26:47 UTC,
  Dauer 6 Sekunden (Einschätzung: Hier liegt keine Extraktion vor, sondern lediglich eine kurze Zweitverbindung.)
    #figure(
  image("../res/Images_M1/NO_Exfiltration_Proof.png", width: 90%),
  caption: [Ausgabe von `Zweite SSH Verbindung`],
) <fig-file>
   #figure(
  image("../res/Images_M1/Exchange_Data_Graph_SSH2.png", width: 90%),
  caption: [Ausgabe von `Zweite SSH Graph`],
) <fig-file>

=== Finding 3: Datenexfiltration

Innerhalb der ersten SSH-Sitzung (OpenSSH 10.2p1 → OpenSSH 9.6p1,
2026-07-05 00:24:35 UTC, 233 Sekunden):

- ca. 1 MB wurde vom Server zum Angreifer übertragen
#figure(
  image("../res/Images_M1/1MB_Exfiltration_Proof.png", width: 90%),
  caption: [Ausgabe von `Wireshark uber 1MB Daten transferiert werden`],
) <fig-file>
- kontinuierlicher Transfer über ca. 4 Minuten
- der Dateninhalt selbst ist SSH-verschlüsselt, Volumen und Richtung
  belegen jedoch den Diebstahl

=== Finding 4: Extrahiertes TLS-Zertifikat

Aus dem RDP-TLS-Handshake wurde das Zertifikat `DESKTOP-GKDAU52.cer`
extrahiert. 
#figure(
  image("../res/Images_M1/Cert_RDP_TLS_Handshake.png", width: 90%),
  caption: [Ausgabe von `Zertifikat von Opfer`],
) <fig-file>
Es bestätigt den Windows-Hostnamen des Opfer-Clients.

== Bestätigung der isolierten Umgebung

- Kein DNS-Verkehr beobachtet → bestätigt die Isolation von net-quarry.
- Keine externen IP-Adressen im Mitschnitt → gesamter Verkehr innerhalb von
  192.168.50.0/24.

== Fazit

Die Analyse von `silent_quarry.pcap` rekonstruiert einen gezielten, kompakten Angriff auf die Laborumgebung (192.168.50.0/24):

1. *Initialer Zugriff & RDP-Sitzung (00:23:42 UTC):* Der Angreifer (192.168.50.10) baute eine RDP-Verbindung zum Client (192.168.50.30) auf. Obwohl die Sitzung TLS-verschlüsselt war, legte die unverschlüsselte Verbindungsaushandlung den Benutzernamen "vogel" im Klartext-Cookie (`mstshash=vogel`) offen. Das extrahierte TLS-Zertifikat bestätigte zudem den Hostnamen `DESKTOP-GKDAU52`.
2. *SSH-Kompromittierung & Exfiltration (00:24:35 UTC):* Unter Verwendung der kompromittierten "vogel"-Zugangsdaten meldete sich der Angreifer per SSH am Server (192.168.50.20) an. Diese erste, 233 Sekunden lange Sitzung trug den gesamten bösartigen Workflow (Authentifizierung, Lokalisierung, Abruf und anschließende Löschung der Zieldatei). Anhand von Paketgrößen, der Flussrichtung und zwei Aktivitätsschüben im I/O-Diagramm lässt sich eine Datenexfiltration von ca. 1 MB vom Server zum Angreifer belegen. 
3. *Zweitverbindung (00:28:26 UTC):* Eine spätere, nur 6-sekündige SSH-Verbindung diente vermutlich lediglich einer kurzen Wiederverbindung und wies keine Anzeichen weiterer Datenextraktion auf.

*Limitation der Netzanalyse:* Während der Paketmitschnitt den Diebstahl der Zugangsdaten und die anschließende Datenexfiltration zweifelsfrei belegt, bleiben die initiale lokale Infektion (Ausführung von `main.py`) sowie die konkret ausgeführten SSH-Befehle im PCAP unsichtbar. Zur lückenlosen Aufklärung sollte diese Netzwerkanalyse durch Host- und Arbeitsspeicherforensik der betroffenen Endpunkte ergänzt werden.