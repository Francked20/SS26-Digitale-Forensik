== 12.1 Netzwerkmitschnitt (tcpdump)

Vor Beginn des Angriffs wurde auf VM2 (Server) ein 
Netzwerkmitschnitt mit tcpdump gestartet. Das Kommando erfasste 
den gesamten Netzwerkverkehr auf dem internen Netzwerksegment 
`net-quarry` (Interface `ens37`) und schrieb ihn in die Datei 
`silent_quarry.pcap`.

*Ausgeführtes Kommando:*

```bash
sudo tcpdump -i ens37 -w /tmp/silent_quarry.pcap
```

Der tcpdump-Prozess lief während des gesamten Angriffsverlaufs 
im Hintergrund und wurde nach Abschluss der Angriffskette mit 
`Ctrl+C` beendet.

*Ergebnis der Erfassung:*

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Attribut*], [*Wert*],
  [Dateiname], [`silent_quarry.pcap`],
  [Interface], [`ens37` (net-quarry)],
  [Erfasste Pakete], [12.132],
  [Dropped Pakete], [0],
  [Dateigröße], [~8.82 MB],
  [Erfassungsdauer], [ca. 5 Minuten],
  [SHA256-Hash], [`be90bf4ef239aead9675acb509d2262d30b540142db01d9e91e56d1f578871d4`],
)

Die PCAP-Datei stellt das primäre Asservat für die Netzwerk-
forensische Analyse (M1) dar und enthält alle relevanten 
Angriffsartefakte, einschließlich RDP-Sitzungen, SSH-Verbindungen 
sowie den exfiltrierten Datenverkehr.

== 12.2 Arbeitsspeicher-Sicherung (RAM Acquisition)

Die Arbeitsspeicher-Sicherung erfolgte gemäß Order of Volatility 
unmittelbar nach Abschluss des Angriffs, während beide Zielsysteme 
(Server und Client) noch aktiv liefen. Dies stellt sicher, dass 
alle flüchtigen Informationen (laufende Prozesse, offene 
Verbindungen, Speicherinhalte) zum Zeitpunkt der Angriffserkennung 
gesichert werden.

=== 12.2.1 Server (VM2) — LiME

Auf dem Linux-Server wurde das Kernel-Modul LiME (Linux Memory 
Extractor) verwendet, welches bereits während der Setup-Phase 
kompiliert wurde. Das Modul greift auf physikalischen RAM zu und 
schreibt den vollständigen Speicherinhalt in eine Datei.

*Ausgeführte Kommandos:*

```bash
cd ~/LiME/src
sudo insmod lime-$(uname -r).ko "path=/tmp/server_ram.lime format=lime"
ls -la /tmp/server_ram.lime
```

*Ergebnis der Sicherung:*

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Attribut*], [*Wert*],
  [Dateiname], [`server_ram.lime`],
  [Werkzeug], [LiME (Linux Memory Extractor, Kernel-Modul)],
  [Speicherpfad (temporär)], [`/tmp/server_ram.lime`],
  [Format], [LiME format],
  [Dateigröße], [~4 GB],
  [Erfassungszeitpunkt], [05.07.2026, 03:08 UTC+2],
  [SHA256-Hash], ["f0d1a5045e849bafd42545b3083af698b1462b555715b1a92805e9209d565dfd"],
)

=== 12.2.2 Client (VM3) — winpmem

Die ursprünglich geplante RAM-Sicherung mittels *FTK Imager* 
scheiterte beim Aufruf der Funktion "Capture Memory" mit der 
Fehlermeldung *"Could not start driver"*. Trotz administrativer 
Rechte konnte der erforderliche Kernel-Treiber nicht geladen 
werden — vermutlich aufgrund von Windows-Treiber-Signaturprüfung 
in der isolierten VM-Umgebung.

#figure(
  image("../res/LivRes/ftk_break.png", width: 85%),
  caption: [FTK Imager funktioniert nicht],
) <fig-ftk-imager>

Als validiertes Ersatzwerkzeug wurde *winpmem* 
(`winpmem_mini_x64_rc2.exe`) verwendet, welches die 
RAM-Sicherung erfolgreich abschloss. winpmem ist ein etabliertes 
Open-Source-Tool aus dem Rekall-Framework und wird in der 
Vorlesung als gleichwertige Alternative zu FTK Imager genannt.

*Ausgeführtes Kommando:*

```powershell
winpmem_mini_x64_rc2.exe client_ram.mem
dir client_ram.mem
```

*Ergebnis der Sicherung:*

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Attribut*], [*Wert*],
  [Dateiname], [`client_ram.mem`],
  [Verwendetes Werkzeug], [winpmem_mini_x64_rc2.exe],
  [Format], [Raw memory dump],
  [Dateigröße], [~ 2,7 GB (entspricht VM3-RAM)],
  [Erfassungszeitpunkt], [05.07.2026, ca. 08:30 UTC+8],
  [SHA256-Hash], ["b26723fa8dba5f567500eb9cda5c8b048a84a74986bf6978c3c0644688b665d1"],
)

Der dokumentierte Werkzeugwechsel folgt dem forensischen Prinzip 
der methodischen Transparenz: Alle Abweichungen von der 
Standardmethodik werden begründet und nachvollziehbar 
dokumentiert.

== 12.3 Live-Response-Kommandos

Auf VM3 (Windows Client) wurden in einer administrativen 
Eingabeaufforderung Standard-Windows-Kommandos zur Erfassung des 
flüchtigen Systemzustands ausgeführt. Die Ausgaben aller Kommandos 
wurden in einer verketteten Anweisung erfasst und in die Datei 
`live_response.txt` auf dem Desktop umgeleitet.

*Ausgeführtes Kommando:*

```powershell
cd %USERPROFILE%
(date /t & time /t & systeminfo & whoami & query user & tasklist /v & ipconfig /all & arp -a & route print & netstat -ano & schtasks /query /fo LIST & reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run) > Desktop\live_response.txt
```

*Erfasste Informationskategorien:*

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Kommando*], [*Erfasste Information*],
  [`date /t & time /t`], [Zeitstempel der Erfassung],
  [`systeminfo`], [Systemidentifikation, OS-Version, Boot-Zeit],
  [`whoami / query user`], [Aktueller Benutzer, aktive Sessions],
  [`tasklist /v`], [Alle laufenden Prozesse mit Details],
  [`ipconfig /all`], [Vollständige Netzwerkkonfiguration],
  [`arp -a`], [ARP-Cache (MAC-zu-IP-Zuordnungen)],
  [`route print`], [Routing-Tabelle],
  [`netstat -ano`], [Aktive Netzwerkverbindungen mit PID],
  [`schtasks /query /fo LIST`], [Geplante Aufgaben],
  [`reg query HKCU\...\Run`], [Autostart-Einträge in Registry],
)

*Ergebnis der Erfassung:*

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Attribut*], [*Wert*],
  [Dateiname], [`live_response.txt`],
  [Speicherort], [`C:\Users\User\Desktop\live_response.txt`],
  [Dateigröße], [103.098 Bytes (ca. 100 KB)],
  [Erfassungszeitpunkt], [05.07.2026, 08:44 UTC+8],
  [Format], [Plain Text (ASCII)],
  [SHA256-Hash], ["c7869c107f378cd100beab26569f1f75d4ffe2669e5254f115a79c52e1f9791c"],
)

*Netzwerkrelevante Auszüge aus der Live-Response:*

Für die Netzwerkforensik (M1) sind insbesondere folgende Einträge 
aus `live_response.txt` von Bedeutung:

- *ARP-Cache:* enthält die MAC-Adresse des Angreifers 
  (`00-0c-29-41-13-85` = `192.168.50.10`)
- *Ethernet0 (NAT):* Status "Media disconnected" bestätigt die 
  Netzwerkisolation zum Angriffszeitpunkt
- *Ethernet1:* IP `192.168.50.30` bestätigt Zugehörigkeit zum 
  `net-quarry`-Segment
- *netstat:* Port `3389` (RDP) im Status `LISTENING` bestätigt 
  den Angriffsvektor

== 12.4 Velociraptor-Sammlung

Zur automatisierten Erfassung Windows-spezifischer forensischer 
Artefakte wurde Velociraptor (v0.77.1) auf VM3 (Windows Client) 
eingesetzt. Server- und Client-Komponente liefen direkt auf dem 
zu sichernden System (Single-Machine-Deployment).

=== 12.4.1 Einrichtung von Velociraptor

Die Konfiguration wurde interaktiv generiert mit folgenden 
Parametern:

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Parameter*], [*Wert*],
  [Deployment Type], [Self-Signed SSL],
  [Server OS], [Windows],
  [Frontend Hostname], [`localhost`],
  [Frontend Port], [8000],
  [GUI Port], [8889],
  [Datastore], [`C:\Windows\Temp`],
  [PKI Zertifikat-Gültigkeit], [1 Jahr],
)

*Kommandos zur Einrichtung:*

```powershell
velociraptor-v0.77.1-windows-amd64.exe config generate -i
velociraptor-v0.77.1-windows-amd64.exe --config server.config.yaml frontend -v
velociraptor-v0.77.1-windows-amd64.exe --config server.config.yaml config client > client.config.yaml
velociraptor-v0.77.1-windows-amd64.exe --config client.config.yaml client -v
```

#figure(
  image("../res/LivRes/gui_client.png", width: 85%),
  caption: [Velociraptor GUI mit verbundenem Client `DESKTOP-GKDAU52` 
    (grüner Status-Indikator)],
) <fig-velociraptor-connected>

=== 12.4.2 Auswahl der Artefakte

Da `Windows.KapeFiles.Targets` in dieser Velociraptor-Version 
nicht verfügbar war, wurden einzelne, spezifische Artefakte 
manuell ausgewählt. Diese decken zusammen alle in der Vorlesung 
behandelten Windows-Forensik-Bereiche ab:

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Artefakt*], [*Zweck*],
  [`Windows.Attack.Prefetch`], [Programm-Ausführungsspuren],
  [`Windows.Forensics.Amcache`], [Anwendungs-Cache mit Hashes],
  [`Windows.Registry.NTUser`], [Benutzer-Registry-Hive],
  [`Windows.Registry.UserAssist`], [GUI-Programm-Ausführung],
  [`Windows.Forensics.SAM`], [Lokale Benutzerkonten],
  [`Windows.Forensics.Lnk`], [Verknüpfungsdateien],
  [`Windows.Forensics.JumpLists`], [Zuletzt verwendete Dateien],
  [`Windows.NTFS.MFT`], [Dateisystem-Master File Table],
  [`Windows.EventLogs.*`], [Windows Event Logs],
)

#figure(
  image("../res/LivRes/selecting_artifacts.png", width: 85%),
  caption: [Auswahl der forensischen Artefakte in der Velociraptor-Sammlung],
) <fig-velociraptor-artifacts>
#figure(
  image("../res/LivRes/selecting_artifacts2.png", width: 85%),
  caption: [Weiter Auswahl der forensischen Artefakte in der Velociraptor-Sammlung],
) <fig-velociraptor-artifacts>
=== 12.4.3 Ausführung der Sammlung

Die Sammlung wurde als einzelner Collection Flow gestartet und 
lief vollautomatisch. Zwei separate Sammlungen wurden 
durchgeführt, um die ursprünglich fehlende Prefetch-Erfassung zu 
ergänzen.

#figure(
  image("../res/LivRes/velo_successful.png", width: 85%),
  caption: [Erfolgreich abgeschlossene Velociraptor-Sammlung 
    (Flow ID: F.D94RB8REBG, Status ✓)],
) <fig-velociraptor-finished>

=== 12.4.4 Export der Ergebnisse

Die gesammelten Artefakte wurden über die Velociraptor GUI als 
ZIP-Archive exportiert und als Asservate gesichert.

#table(
  columns: 3,
  stroke: 0.5pt,
  [*Dateiname*], [*Größe*], [*Inhalt*], [*SHA256*]
  [`N.F.D94RB8REBGE2E-C.14943fad2f2b3c8b-20260705015252Z.zip`],
  [52.9 KB],
  [Hauptsammlung (Amcache, Registry, LNK, JumpLists, MFT, Event Logs)],
  [c81a9ab81b0523001d4f39e16d8e5b61f48522cd15dd1b9e32192d5c0147e774],
  [`N.F.D94RFIU57M5PG-C.14943fad2f2b3c8b-20260705015307Z.zip`],
  [4.1 KB],
  [Nachträgliche Prefetch-Erfassung],
  [4aff14247bdd902d93eeb15d41fa23708aff2ad6cae50b6def864b3f44bed354],
)

#figure(
  image("../res/LivRes/artifacts_zip.png", width: 85%),
  caption: [Herunterladen der Velociraptor-Asservate als ZIP-Archive],
) <fig-velociraptor-downloads>

