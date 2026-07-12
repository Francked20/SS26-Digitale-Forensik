#import "../style/style.typ": thead, hinweis

= Beweissicherung (Secure-Phase) <kap-beweissicherung>

Dieses Kapitel dokumentiert die *Secure*-Phase des S-A-P-Modells: die
Identifizierung und forensisch sichere Erfassung aller Asservate, die Wahrung
der Integrität durch Hashwerte sowie die lückenlose Chain of Custody. Die
Reihenfolge der Sicherung folgt der *Order of Volatility*:
zuerst die flüchtigen Daten (Netzwerkmitschnitt, Arbeitsspeicher,
Live-Response), zuletzt die beständigen Datenträgerabbilder.

Die Sicherung erfolgt *zweigleisig* und ist für die spätere Einordnung der
Befunde zentral:

- *Live-Triage:* tcpdump, RAM-Abbilder, Live-Response-Kommandos und die
  Velociraptor-Sammlung erfassen den *flüchtigen Zustand des laufenden Systems*
  zum Zeitpunkt der Angriffserkennung.
- *Post-Mortem-Abbild:* Mit `Qemu.img.exe` wurden die Vollabbilder `Client.dd`
  und `Server.dd` als integritätsgesicherte Roh-Images (`.dd`) erstellt. Sie
  sind die *maßgebliche Analysequelle* aller Betriebssystem-, Datenträger- und
  Anwendungsbefunde. Bei Abweichungen gilt stets das Post-Mortem-Abbild als
  autoritative Quelle.


== Übersicht der Asservate

Alle im Verfahren gesicherten Beweismittel sind nachfolgend mit ihrem
kryptografischen Integritätshash aufgeführt. Die Hashes wurden bei der Sicherung
gebildet und vor jeder Analyse erneut verifiziert.

// Helfer: langer Hashwert, der bei Bedarf umbricht (Zeichenweise Sollbruchstellen)
#let hashval(h) = text(font: ("New Computer Modern Mono", "DejaVu Sans Mono"), size: 7.5pt)[
  #h.clusters().join(sym.zws)
]

#table(
  columns: (auto, auto, auto, auto),
  align: (left, left, left, left),
  thead[Asservat][Datei][Verfahren][Hashwert],
  [A01], [`Server.dd` — Abbild Ubuntu-Server], [SHA-256],
        [#hashval("4960728cc6b74f7d687266cabbc5ea8d649990f54f2a2480a53418d117282b50")],
  [A02], [`Client.dd` — Abbild Windows-Client], [SHA-256],
        [#hashval("f0d7ba17e5ec5939af0decbe4ad182252fad464515f7a42dd86f61ef91bdf41a")],
  [A03], [`server_ram.lime` — RAM Server (LiME)], [SHA-256],
        [#hashval("f0d1a5045e849bafd42545b3083af698b1462b555715b1a92805e9209d565dfd")],
  [A04], [`client_ram.mem` — RAM Client (WinPmem)], [SHA-256],
        [#hashval("b26723fa8dba5f567500eb9cda5c8b048a84a74986bf6978c3c0644688b665d1")],
  [A05], [`silent_quarry.pcap` — Netzwerkmitschnitt], [SHA-256],
        [#hashval("be90bf4ef239aead9675acb509d2262d30b540142db01d9e91e56d1f578871d4")],
  [A06], [`live_response.txt` — Live-Response], [SHA-256],
        [#hashval("c7869c107f378cd100beab26569f1f75d4ffe2669e5254f115a79c52e1f9791c")],
  [A07], [Velociraptor-Sammlung (Hauptarchiv)], [SHA-256],
        [#hashval("c81a9ab81b0523001d4f39e16d8e5b61f48522cd15dd1b9e32192d5c0147e774")],
  [A08], [Velociraptor-Sammlung (Prefetch)], [SHA-256],
        [#hashval("4aff14247bdd902d93eeb15d41fa23708aff2ad6cae50b6def864b3f44bed354")],
)



== Chain of Custody

Die Sicherung erfolgte am 05.07.2026 durch das Ermittlungsteam. Jedes Asservat
wurde unmittelbar nach der Erfassung gehasht, in das schreibgeschützte
Artefaktverzeichnis überführt und ausschließlich als Arbeitskopie analysiert.

#table(
  columns: (auto, auto, 1fr, auto),
  thead[Zeitpunkt][Asservat][Handlung][Verantwortlich],
  [05.07.2026], [A05 `.pcap`], [Netzwerkmitschnitt beendet, gehasht, gesichert], [Team],
  [05.07.2026], [A03/A04 RAM], [RAM-Sicherung Server (LiME) & Client (WinPmem)], [Team],
  [05.07.2026], [A06/A07/A08], [Live-Response & Velociraptor-Sammlung Client], [Team],
  [05.07.2026], [A01/A02 `.dd`], [Post-Mortem-Datenträgerabbilder], [Team],
  [05.–11.07.], [alle], [Read-only-Analyse auf der SIFT Workstation], [Team],
)

== Durchführung der Sicherung

Die folgenden Abschnitte belegen nachvollziehbar, *wie* jedes Asservat erzeugt wurde. 

#hinweis[
  Zeitzonen-Hinweis für die Timeline: Server-Zeitstempel sind in UTC+2
  angegeben (LiME: 03:08 UTC+2 = 01:08 UTC), Client-Zeitstempel in UTC+8
  (winpmem: 08:30 UTC+8 = 00:30 UTC; Live-Response: 08:44 UTC+8 = 00:44 UTC;
  Velociraptor: 01:52 UTC laut ZIP-Zeitstempel). Für die korrelierte
  Timeline sind alle Werte auf UTC normiert.
]

=== Netzwerkmitschnitt (tcpdump)

Vor Beginn des Angriffs wurde auf VM2 (Server) ein Netzwerkmitschnitt mit
tcpdump gestartet. Das Kommando erfasste den gesamten Netzwerkverkehr auf dem
internen Netzwerksegment `net-quarry` (Interface `ens37`) und schrieb ihn in
die Datei `silent_quarry.pcap`.

*Ausgeführtes Kommando:*

```bash
sudo tcpdump -i ens37 -w /tmp/silent_quarry.pcap
```

Der tcpdump-Prozess lief während des gesamten Angriffsverlaufs im Hintergrund
und wurde nach Abschluss der Angriffskette mit `Ctrl+C` beendet.

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

Die PCAP-Datei stellt das primäre Asservat für die netzwerkforensische
Analyse (M1) dar und enthält alle relevanten Angriffsartefakte,
einschließlich RDP-Sitzungen, SSH-Verbindungen sowie den exfiltrierten
Datenverkehr.

=== Arbeitsspeicher-Sicherung (RAM Acquisition)

Die Arbeitsspeicher-Sicherung erfolgte unmittelbar nach Abschluss des Angriffs,
während beide Zielsysteme noch aktiv liefen. Beide RAM-Abbilder wurden *vor*
der Installation weiterer Sicherungswerkzeuge (insbesondere Velociraptor)
erstellt, damit deren Speicherfußabdruck das Abbild nicht verfälscht. Die
nachfolgenden Tabellen dokumentieren je Abbild das Werkzeug, den
Erfassungszeitpunkt und den Integritätshash.

==== Server (VM2) — LiME

Auf dem Linux-Server wurde das Kernel-Modul LiME (Linux Memory Extractor)
verwendet, welches bereits während der Setup-Phase kompiliert wurde. Das Modul
greift auf physikalischen RAM zu und schreibt den vollständigen Speicherinhalt
in eine Datei.

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
  [Erfassungszeitpunkt], [05.07.2026, 03:08 UTC+2 (= 01:08 UTC)],
  [SHA256-Hash], [`f0d1a5045e849bafd42545b3083af698b1462b555715b1a92805e9209d565dfd`],
)

==== Client (VM3) — winpmem

Die ursprünglich geplante RAM-Sicherung mittels *FTK Imager* scheiterte beim
Aufruf der Funktion „Capture Memory" mit der Fehlermeldung *„Could not start
driver"*. Trotz administrativer Rechte konnte der erforderliche Kernel-Treiber
nicht geladen werden — vermutlich aufgrund von Windows-Treiber-
Signaturprüfung in der isolierten VM-Umgebung.

#figure(
  image("../res/LivRes/ftk_break.png", width: 85%),
  caption: [FTK Imager: Fehlermeldung „Could not start driver" bei der
    RAM-Sicherung des Clients],
) <fig-ftk-imager>

Als validiertes Ersatzwerkzeug wurde *winpmem* (`winpmem_mini_x64_rc2.exe`)
verwendet, welches die RAM-Sicherung erfolgreich abschloss. winpmem ist ein
etabliertes Open-Source-Tool aus dem Rekall-Framework und wird als gleichwertige Alternative zu FTK Imager verwendet.

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
  [Verwendetes Werkzeug], [`winpmem_mini_x64_rc2.exe`],
  [Format], [Raw memory dump],
  [Dateigröße], [~2,7 GB (entspricht VM3-RAM)],
  [Erfassungszeitpunkt], [05.07.2026, ca. 08:30 UTC+8 (= 00:30 UTC)],
  [SHA256-Hash], [`b26723fa8dba5f567500eb9cda5c8b048a84a74986bf6978c3c0644688b665d1`],
)

Der dokumentierte Werkzeugwechsel folgt dem forensischen Prinzip der
methodischen Transparenz: Alle Abweichungen von der Standardmethodik werden
begründet und nachvollziehbar dokumentiert.

=== Live-Response-Kommandos

Auf VM3 (Windows Client) wurden in einer administrativen Eingabeaufforderung
Standard-Windows-Kommandos zur Erfassung des flüchtigen Systemzustands
ausgeführt. Die Ausgaben aller Kommandos wurden in einer verketteten Anweisung
erfasst und in die Datei `live_response.txt` umgeleitet.

#hinweis[
  Methodische Abweichung offenlegen: Die Umleitung erfolgte auf den Desktop
  des zu untersuchenden Systems (`C:\Users\User\Desktop\`). Es wurde keine Informationen auf dem zu untersuchenden System gespeichert.
  Da das System unmittelbar danach vollständig als `Client.dd` abgebildet
  wurde, ist dieser Schreibvorgang im Post-Mortem-Abbild vollständig
  konserviert und als Ermittlerartefakt dokumentiert (F-WIN-12). 
]

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
  [Erfassungszeitpunkt], [05.07.2026, 08:44 UTC+8 (= 00:44 UTC)],
  [Format], [Plain Text (ASCII)],
  [SHA256-Hash], [`c7869c107f378cd100beab26569f1f75d4ffe2669e5254f115a79c52e1f9791c`],
)

*Netzwerkrelevante Auszüge aus der Live-Response:*

Für die Netzwerkforensik (M1) sind insbesondere folgende Einträge aus
`live_response.txt` von Bedeutung:

- *ARP-Cache:* enthält die MAC-Adresse des Angreifers
  (`00-0c-29-41-13-85` = `192.168.50.10`)
- *Ethernet0 (NAT):* Status „Media disconnected" bestätigt die
  Netzwerkisolation zum Angriffszeitpunkt
- *Ethernet1:* IP `192.168.50.30` bestätigt Zugehörigkeit zum
  `net-quarry`-Segment
- *netstat:* Port `3389` (RDP) im Status `LISTENING` bestätigt den
  Angriffsvektor

Die inhaltliche Auswertung dieser Live-Response-Ausgaben erfolgt in der
Analyse-Phase (Findings F-LR-01 bis F-LR-03, Kapitel Live-Response-Analyse).

=== Velociraptor-Sammlung

Zur automatisierten Erfassung Windows-spezifischer forensischer Artefakte
wurde Velociraptor (v0.77.1) auf VM3 (Windows Client) eingesetzt. Server- und
Client-Komponente liefen direkt auf dem zu sichernden System
(Single-Machine-Deployment). Velociraptor ist eine
Open-Source-IR-Plattform zur schnellen Artefakt-Sammlung; die
Sammlung dient hier der *Live-Triage* (siehe Einordnung am Kapitelende).

==== Einrichtung von Velociraptor

Die Konfiguration wurde interaktiv generiert mit folgenden Parametern:

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

==== Auswahl der Artefakte

Da `Windows.KapeFiles.Targets` in dieser Velociraptor-Version nicht verfügbar
war, wurden einzelne, spezifische Artefakte manuell ausgewählt. Diese Auswahl
entspricht der „KapeFiles Basic
Collection" und deckt alle behandelten Windows-Forensik-Bereiche ab:

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
  [`Windows.Forensics.FilenameSearch`], [Gezielte Dateisuche im Dateisystem],
  [`Windows.Forensics.RecycleBin`], [Papierkorb-Inhalte (gelöschte Dateien)],
  [`Windows.NTFS.MFT`], [Dateisystem-Master File Table],
  [`Windows.EventLogs.*`], [Windows Event Logs],
)

#figure(
  image("../res/LivRes/selecting_artifacts.png", width: 85%),
  caption: [Auswahl der forensischen Artefakte in der Velociraptor-Sammlung (1/2)],
) <fig-velociraptor-artifacts-1>
#figure(
  image("../res/LivRes/selecting_artifacts2.png", width: 85%),
  caption: [Auswahl der forensischen Artefakte in der Velociraptor-Sammlung (2/2)],
) <fig-velociraptor-artifacts-2>

==== Ausführung der Sammlung

Die Sammlung wurde als einzelner Collection Flow gestartet und lief
vollautomatisch. Zwei separate Sammlungen wurden durchgeführt, um die
ursprünglich fehlende Prefetch-Erfassung zu ergänzen.

#figure(
  image("../res/LivRes/velo_successful.png", width: 85%),
  caption: [Erfolgreich abgeschlossene Velociraptor-Sammlung
    (Flow ID: F.D94RB8REBG, Status ✓)],
) <fig-velociraptor-finished>

==== Export der Ergebnisse

Die gesammelten Artefakte wurden über die Velociraptor GUI als ZIP-Archive
exportiert und als Asservate gesichert.

#table(
  columns: (2fr, 0.8fr, 2.2fr, 3fr),
  inset: 8pt,
  align: (col, row) => (
    if row == 0 { center + horizon }
    else if col == 1 { center + horizon }
    else { left + horizon }
  ),
  stroke: (x, y) => if y == 0 { (bottom: 1.5pt + rgb("#262626")) } else if y == 1 { none } else { (top: 0.5pt + rgb("#e5e5e5")) },
  fill: (col, row) => if row == 0 { rgb("#f4f4f5") } else if calc.even(row) { rgb("#fafafa") } else { none },

  [*Dateiname*], [*Größe*], [*Inhalt*], [*SHA256*],

  // Row 1
  [
    #set text(size: 8pt)
    `N.F.D94RB8REBGE2E-` \
    `C.14943fad2f2b3c8b-` \
    `20260705015252Z.zip`
  ],
  [52.9 KB],
  [Hauptsammlung (Amcache, Registry, LNK, JumpLists, MFT, Event Logs)],
  [
    #set text(size: 7pt)
    #block(width: 100%)[c81a9ab81b0523001d4f39e16d8e5b61f48522cd15dd1b9e32192d5c0147e774]
  ],

  // Row 2
  [
    #set text(size: 8pt)
    `N.F.D94RFIU57M5PG-` \
    `C.14943fad2f2b3c8b-` \
    `20260705015307Z.zip`
  ],
  [4.1 KB],
  [Nachträgliche Prefetch-Erfassung],
  [
    #set text(size: 7pt)
    #block(width: 100%)[4aff14247bdd902d93eeb15d41fa23708aff2ad6cae50b6def864b3f44bed354]
  ],
)

#figure(
  image("../res/LivRes/artifacts_zip.png", width: 85%),
  caption: [Herunterladen der Velociraptor-Asservate als ZIP-Archive],
) <fig-velociraptor-downloads>

=== Sicherung der beständigen Daten (Datenträgerabbilder)

Die Post-Mortem-Abbilder beider Zielsysteme wurden mit *Qemu.img.exe* als
Roh-Images (`.dd`) erzeugt und dabei unmittelbar gehasht (A01 `Server.dd`,
A02 `Client.dd`). Die Struktur der Abbilder (Partitionen, Dateisysteme) ist in
den jeweiligen Analysekapiteln dokumentiert; die Einbindung erfolgte
ausschließlich schreibgeschützt (read-only).

=== Einordnung: Live-Triage vs. autoritative Post-Mortem-Quelle

Die Velociraptor-Sammlung und die Live-Response-Kommandos sind der
*Sicherungsphase* zuzuordnen, nicht der Analyse. Sie erfassen den Zustand des
*laufenden* Systems und dienen zwei Zwecken: der schnellen Ersttriage sowie
der *Zweitquellen-Bestätigung* der später aus dem Vollabbild gewonnenen
Befunde.

Die *maßgebliche* Auswertung sämtlicher Windows-Artefaktklassen (Registry,
Prefetch, Event Logs, LNK/JumpLists, MFT, Papierkorb u. a.) erfolgt
*post-mortem* auf dem integritätsgesicherten Abbild `Client.dd` (Kapitel
Windows-Betriebssystem- und Anwendungsforensik). Grund: Das Vollabbild
repräsentiert einen eingefrorenen, per Hashwert verifizierbaren Zustand,
während live gesammelte Artefakte am fortlaufend veränderten System entnommen
werden. Bei Abweichungen gilt daher stets das Post-Mortem-Abbild als
autoritative Quelle.

Die Velociraptor-ZIP-Archive werden folglich als *korroborierende Asservate*
archiviert; eine parallele Zweitanalyse derselben Artefakte unterbleibt
bewusst, um widersprüchliche Zeitstempel zu vermeiden. Wo eine
Doppelquellen-Bestätigung den Beweiswert erhöht, wird sie punktuell
ausgewiesen (z. B. Prefetch der Schadcode-Ausführung `PYTHON.EXE`, siehe
Live-Response-Analyse).

Der durch die Vor-Ort-Installation entstandene Werkzeug-Fußabdruck
(Velociraptor-Dienst, Datastore unter `C:\Windows\Temp`, Prefetch-/UserAssist-/
BAM-Einträge) ist ein bewusst in Kauf genommener Kompromiss der isolierten
Laborumgebung. Er ist vollständig offengelegt und in F-WIN-12 als
Ermittlerartefakt von den Täterspuren abgegrenzt. In einem realen Einsatz auf
einem beschlagnahmten System wäre der *Velociraptor Offline Collector* mit
Ausgabe auf externem Datenträger vorzuziehen gewesen.

== Abgrenzung der Ermittlerartefakte

Die in dieser Phase eingesetzten Werkzeuge (tcpdump, LiME, WinPmem,
Live-Response-Kommandos, Velociraptor, Qemu.img.exe, Npcap) hinterlassen eigene
Spuren auf den Zielsystemen. Diese *Ermittlerartefakte* sind vom Tatgeschehen zu
trennen und werden in den Analysekapiteln explizit als solche gekennzeichnet
(insbesondere F-WIN-12 „Zuordnung der Ermittlerartefakte" und F-RAM-05
„Nachweis des Sicherungswerkzeugs WinPmem").


