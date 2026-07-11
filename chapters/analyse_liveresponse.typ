// ============================================================
//  analyse_liveresponse.typ — Analyse-Phase (Mitglied 3)
//  Live-Response-Analyse des Windows-Clients (live_response.txt)
//  (ehem. live_res.typ)
// ============================================================
//  Bildablage:   ../res/lr/<Dateiname>.png
//  Quelldatei:   Artefaktverzeichnis (Nextcloud, Anhang),
//                cases/silent_quarry/live_response.txt
//  Sicherung:    siehe Kapitel „Sicherung der Beweismittel — Durchführung"
// ============================================================

#import "../style/style.typ": finding, hinweis, thead, accent

#let befehl(cmd) = block(
  width: 100%, inset: 7pt, radius: 3pt, above: 0.6em, below: 0.4em,
  fill: luma(244), stroke: (left: 2pt + accent),
)[
  #text(size: 8pt, fill: gray.darken(30%), weight: "bold")[AUSGEFÜHRTER BEFEHL] #linebreak()
  #raw(cmd, block: true, lang: "bash")
]

#let beweis(datei, caption, aktiv: false) = [
  #figure(
    if aktiv {
      image("../res/lr/" + datei, width: 92%)
    } else {
      rect(width: 92%, height: 2.4cm, fill: luma(248), stroke: (paint: gray, dash: "dashed"))[
        #align(center + horizon)[#text(fill: gray, size: 9pt, style: "italic")[Screenshot einfügen: #datei]]
      ]
    },
    caption: caption,
  )
]

#let quelle(pfad) = text(size: 9pt, fill: gray.darken(15%))[
  #text(weight: "bold")[Quelldatei:] #raw(pfad) #text(style: "italic")[(siehe Artefaktverzeichnis, Anhang)]
]

= Live-Response-Analyse des Windows-Clients <kap-liveresponse>

Neben der Post-Mortem-Auswertung (Kapitel Windows-Forensik) und der
Speicheranalyse (Kapitel Speicherforensik) wurde am laufenden System eine
*Live-Response* durchgeführt und mittels *Velociraptor* bzw. verketteter
Windows-Kommandos gesichert (siehe Kapitel „Sicherung der Beweismittel —
Durchführung"). Die Vorlesung ordnet die Live-Response der *Order of
Volatility* zu: Sie erfasst flüchtige Zustandsdaten (laufende Prozesse,
Netzwerkverbindungen, ARP-Cache, angemeldete Benutzer), die nach einem
Neustart unwiederbringlich verloren gehen. Die Ergebnisse liegen in
`live_response.txt` vor und umfassen `systeminfo`, `tasklist /v`,
`ipconfig /all`, `netstat`, `route`, `arp -a` sowie `schtasks`.

Methodische Einordnung: Die Live-Response ist eine *Triage-Momentaufnahme* des
laufenden Systems. Ihre Befunde *bestätigen* die maßgeblichen Post-Mortem- und
Speicherbefunde über unabhängige Zweit- und Drittquellen; sie ersetzen die
Auswertung am integritätsgesicherten Abbild `Client.dd` nicht. Ein Befund —
der dynamische ARP-Eintrag (F-LR-02) — ist darüber hinaus *eigenständig* und
nur live erfassbar.

Da die Live-Response am 05.07.2026 im Rahmen der Akquise durch das
Ermittlungsteam erstellt wurde, bildet sie den Systemzustand während der
Sicherung ab. Einige Einträge (u. a. der eigene `tasklist`-Aufruf) sind
entsprechend als Ermittlerartefakte zu werten.

#quelle("live_response.txt")

== Systeminformationen (systeminfo)

#finding("F-LR-01", "Systemzustand und Bestätigung der Systemparameter")[
  

  #beweis("sysinfo.png", [`systeminfo`: Host DESKTOP-GKDAU52, Windows 10 Education, Zeitzone UTC+08:00, Boot Time 05.07. 08:19:36.], aktiv: true)

  *Was.* Der `systeminfo`-Auszug bestätigt unabhängig zentrale Systemparameter: Host
  *DESKTOP-GKDAU52*, *Windows 10 Education*, Original-Installationsdatum 30.06.2026
  19:51:46 (Ortszeit), *Time Zone (UTC+08:00) Kuala Lumpur, Singapore*, *System Boot Time
  05.07.2026 08:19:36* (Ortszeit), Hersteller *VMware, Inc.* (Modell VMware20,1), 2 NICs,
  Auslagerungsdatei `C:\pagefile.sys`, 2.703 MB physischer Speicher.

  *Wo.* Artefakt `live_response.txt` (Abschnitt `systeminfo`).

  *Bedeutung.* Die Live-Response bestätigt die aus der Registry ermittelten Parameter
  (F-WIN-00) über eine zweite, unabhängige Quelle — insbesondere die *Zeitzone UTC+8*,
  die für die gesamte zeitliche Einordnung maßgeblich ist. Die Boot Time (05.07. 08:19
  Ortszeit = 00:19 UTC) deckt sich mit dem SystemTime des RAM-Abbilds (F-RAM-01).

  *Korrelation.* Stützt F-WIN-00 (Systemidentifikation) und die Zeitzonen-Konvention des
  gesamten Gutachtens. Die VMware-Umgebung bestätigt die Infrastruktur.

  #quelle("live_response.txt")
]

== Netzwerkzustand (ipconfig, netstat, arp)

#finding("F-LR-02", "ARP-Cache: Nachweis der Netzwerkkommunikation mit dem Angreifer-Host")[
  #befehl("ipconfig /all
netstat -ano
arp -a")

  #beweis("arp.png", [ARP-Cache des Clients: Eintrag `192.168.50.10  00-0c-29-41-13-85  dynamic` (Angreifer-Host).], aktiv: true)

  *Was.* Die Netzwerkkonfiguration weist den Client als *192.168.50.30* aus (Adapter
  Ethernet1, MAC `00-0C-29-CF-1A-03`, Herstellerpräfix `00-0C-29` = VMware). Der
  *ARP-Cache* enthält einen dynamischen Eintrag für den Angreifer-Host:
  *`192.168.50.10 → 00-0c-29-41-13-85 (dynamic)`*. `netstat` zeigt zum Erfassungszeitpunkt
  nur Loopback-Verbindungen (Firefox PID 2560, Thunderbird PID 1724) und lokale Listener
  (135, 445, 3389, 139) — keine aktive Verbindung zu 192.168.50.10 oder 192.168.50.20.

  *Wo.* Artefakt `live_response.txt` (Abschnitte `ipconfig /all`, `netstat`, `arp -a`).

  *Bedeutung.* Ein *dynamischer* ARP-Eintrag entsteht ausschließlich, wenn zuvor eine
  Kommunikation auf Layer 2 zwischen den Hosts stattgefunden hat. Der Eintrag belegt
  somit, dass der Client *tatsächlich Netzwerkkontakt mit dem Angreifer-Host
  192.168.50.10 (Kali)* hatte — eine unabhängige Bestätigung der Angreifer-Präsenz im
  Segment. Dass zum Erfassungszeitpunkt keine aktive Verbindung mehr bestand, ist
  konsistent mit dem beendeten Angriff (der ARP-Cache hält den Eintrag jedoch temporär
  vor).

  *Korrelation.* Die Interpretation des Angreifer-Datenverkehrs erfolgt in der
  Netzwerkforensik; der ARP-Eintrag ist der clientseitige
  Beleg des Kontakts. Ergänzt F-RAM-02 (keine aktive Exfiltrationsverbindung zum
  Sicherungszeitpunkt).

  #quelle("live_response.txt")
]

== Prozesse und geplante Aufgaben (tasklist, schtasks)

#finding("F-LR-03", "Laufende Prozesse und geplante Aufgaben (Bestätigung: keine Persistenz)")[
  #befehl("tasklist /v
schtasks /query /fo LIST /v")

  #beweis("task.png", [`tasklist /v` und `schtasks`: legitime Prozesse/Aufgaben, `npcapwatchdog` als Ermittlerartefakt, kein `SecurityUpdater`.], aktiv: true)

  *Was.* `tasklist /v` zeigt u. a. `cmd.exe` (PID 3952, Fenstertitel „Administrator:
  Command Prompt - tasklist /v") und `tasklist.exe` (PID 7144) unter dem Konto
  `DESKTOP-GKDAU52\vogel` — der Erfassungsvorgang selbst. Ein `python.exe`-Prozess ist
  nicht vorhanden. `schtasks` listet ausschließlich legitime Aufgaben (MicrosoftEdgeUpdate,
  OneDrive, Mozilla Firefox) sowie *`\npcapwatchdog`* auf. Ein Eintrag `SecurityUpdater`
  oder ein Bezug zu `python`/`main.py` existiert nicht.

  *Wo.* Artefakt `live_response.txt` (Abschnitte `tasklist /v`, `schtasks`).

  *Bedeutung.* Die Live-Response bestätigt die Post-Mortem-Befunde am laufenden System:
  kein laufender Schadprozess (konsistent mit F-RAM-01) und *kein Persistenzmechanismus*
  (konsistent mit F-WIN-08). Die Aufgabe `npcapwatchdog` gehört zu Npcap/Wireshark und ist
  ein Ermittlerartefakt (Installation am 03.07., siehe F-WIN-12).

  *Korrelation.* Bestätigt F-WIN-08 (keine Persistenz) und F-RAM-01 (kein python-Prozess)
  über eine dritte, unabhängige Quelle. `npcapwatchdog` → Ermittlerabgrenzung (F-WIN-12).

  #quelle("live_response.txt")
]

== Velociraptor Live Response Analyse

Im Rahmen der Windows-Forensik wurden die mittels Velociraptor gesammelten Artefakte des kompromittierten Clients (`DESKTOP-GKDAU52`, `192.168.50.30`) ausgewertet. Ziel der Analyse war die Rekonstruktion der Angriffskette anhand der auf dem Windows-System hinterlassenen Spuren.

Die Auswertung erfolgte mit dem Werkzeug *Timeline Explorer* (Eric Zimmerman Tools) sowie durch manuelle Sichtung der exportierten CSV-Artefakte. Methodisch handelt es sich um eine *Artefakt-Korrelation* und *Timeline-Analyse*, bei der verschiedene Windows-Artefakte in chronologische Beziehung gesetzt werden, um den Tatablauf nachzuvollziehen.

== Übersicht der ausgewerteten Artefakte

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Artefakt*], [*Forensischer Zweck*],
  [Event Logs (EVTX)], [Nachweis des RDP-Zugriffs und der Privilegien],
  [Prefetch], [Nachweis der Programmausführung (Schadsoftware)],
  [UserAssist], [Chronologie der GUI-Programmausführungen],
  [Amcache], [Datei-Identifikation und Hashes],
)

== Rekonstruktion der Angriffskette (UserAssist)

Die UserAssist-Analyse liefert den forensisch wertvollsten Befund dieser Untersuchung: die chronologische Abfolge der GUI-Programmausführungen durch den Benutzer. Diese Sequenz bildet das Rückgrat der Timeline-Rekonstruktion und ordnet die einzelnen Angriffsschritte zeitlich ein.

#table(
  columns: 3,
  stroke: 0.5pt,
  [*Reihenfolge*], [*Programm*], [*Forensische Bedeutung*],
  [1], [Thunderbird], [Öffnen der Phishing-E-Mail durch das Opfer],
  [2], [python.exe], [Ausführung der Schadsoftware (main.py)],
  [3], [Notepad], [Angreifer öffnet `credentials.txt` über RDP],
)

*Interpretation der Sequenz:*

Die chronologische Abfolge der UserAssist-Einträge belegt die einzelnen Phasen des Angriffs:

+ *Thunderbird:* Das Opfer (Vogel) öffnete die präparierte Phishing-E-Mail mit dem Betreff "Wichtiges Update für Ihre Konstruktionssoftware".
+ *python.exe:* Kurz darauf wurde durch das Ausführen des Anhangs die Schadsoftware `main.py` gestartet, welche ein gefälschtes Anmeldefenster anzeigte und die Windows-Anmeldedaten des Opfers erfasste.
+ *Notepad:* Nicht lange nach der Schadsoftware-Ausführung wurde Notepad geöffnet. Dieser Schritt fällt bereits in die Phase des Angreifer-Zugriffs: Über die RDP-Sitzung öffnete der Angreifer die auf dem Desktop abgelegte Datei `credentials.txt`, um die dort im Klartext hinterlegten Server-Zugangsdaten (`m.vogel:Werkzeug\#2026`) auszulesen.

#figure(
  image("../res/LivRes/userassist_sequence.png", width: 90%),
  caption: [UserAssist: Chronologische Abfolge der Programmausführungen 
    (Thunderbird $arrow$ python.exe $arrow$ Notepad)],
) <fig-userassist-sequence>

== Nachweis der Schadsoftware-Ausführung (Prefetch)

Die Prefetch-Analyse bestätigt unabhängig von UserAssist die Ausführung von `PYTHON.EXE`, welches die Python-basierte Schadsoftware (`main.py`) interpretierte. Der Zeitstempel deckt sich mit dem UserAssist-Eintrag und liegt unmittelbar vor dem SSH-Angriff.

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Attribut*], [*Wert*],
  [Prefetch-Datei], [`PYTHON.EXE-[hash].pf`],
  [Zeitstempel (Mod Time)], [00:22:43Z],
  [Bedeutung], [Ausführung der Python-Schadsoftware main.py],
)

#figure(
  image("../res/LivRes/prefetch_python.png", width: 85%),
  caption: [Prefetch-Eintrag für PYTHON.EXE mit Ausführungszeitstempel],
) <fig-prefetch-python>

== Nachweis des RDP-Zugriffs (Event Log Analyse)

Während UserAssist und Prefetch die clientseitigen Aktivitäten belegen, dokumentieren die Windows Event Logs den eigentlichen Fernzugriff des Angreifers über das Remote Desktop Protocol (RDP). Der Terminal Services Manager protokollierte die eingehende Verbindung direkt vom Angreifer-Host.

*Gefundenes Schlüssel-Event:*

#quote(block: true)[
  "Remote Desktop Services accepted a connection from IP address 192.168.50.10."
]

Dieser Eintrag beweist, dass die Verbindung vom Kali-Angreifer (`192.168.50.10`) ausging und vom Zielsystem akzeptiert wurde. Der Befund korreliert direkt mit der Netzwerkanalyse (M1), in der die RDP-Sitzung von `192.168.50.10` im PCAP über Port 3389 nachgewiesen wurde.

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Attribut*], [*Wert*],
  [Ereignistyp], [RDP-Verbindung akzeptiert],
  [Quell-IP], [192.168.50.10 (Kali-Angreifer)],
  [Dienst], [Remote Desktop Services],
  [Zielsystem], [DESKTOP-GKDAU52],
)

#figure(
  image("../res/LivRes/eventlog_rdp_connection.png", width: 90%),
  caption: [Event Log: Annahme der RDP-Verbindung von 192.168.50.10],
) <fig-rdp-connection>

=== Zugewiesene Sonderprivilegien und Enumeration

Nach der erfolgreichen Anmeldung dokumentieren die Event Logs die Zuweisung weitreichender administrativer Privilegien an das kompromittierte Konto `vogel` sowie Anzeichen von Konto-Enumeration.

*Zugewiesene Privilegien (Event: Special privileges assigned to new logon):*

#table(
  columns: 2,
  stroke: 0.5pt,
  [*Privileg*], [*Bedeutung*],
  [`SeDebugPrivilege`], [Zugriff auf fremde Prozesse],
  [`SeTakeOwnershipPrivilege`], [Übernahme von Datei-Eigentümerschaft],
  [`SeLoadDriverPrivilege`], [Laden von Kernel-Treibern],
  [`SeBackupPrivilege`], [Umgehung von Dateiberechtigungen],
  [`SeRestorePrivilege`], [Wiederherstellungsrechte],
  [`SeImpersonatePrivilege`], [Identitätsübernahme],
)

Zusätzlich wurde ein Event registriert, das die Abfrage nach leeren Passwörtern dokumentiert (Ziel: `WDAGUtilityAccount`) — ein typisches Merkmal von Reconnaissance-Aktivitäten des Angreifers.

#figure(
  image("../res/LivRes/eventlog_privileges.png", width: 90%),
  caption: [Event Log: Zuweisung administrativer Sonderprivilegien an das Konto vogel],
) <fig-privileges>

== Zeitliche Gesamtkorrelation

Die Zusammenführung aller Windows-Artefakte mit der Netzwerkanalyse (M1) ergibt eine lückenlose, chronologische Rekonstruktion der Angriffskette:

#table(
  columns: 3,
  stroke: 0.5pt,
  [*Zeit (UTC)*], [*Ereignis*], [*Quelle*],
  [00:22:10Z], [Thunderbird geöffnet (Phishing-E-Mail)], [UserAssist],
  [00:22:43Z], [Ausführung PYTHON.EXE (Schadsoftware)], [Prefetch / UserAssist],
  [00:23:42Z], [RDP-Verbindung von 192.168.50.10 akzeptiert], [Event Log/ PCAP (M1)],
  [00:23:51Z], [Notepad geöffnet (credentials.txt)], [UserAssist],
  [00:24:35Z], [Erste SSH-Verbindung zum Server], [PCAP (M1)],
)

Die enge zeitliche Abfolge — insbesondere das Öffnen von Notepad unmittelbar vor der SSH-Verbindung — belegt die kausale Kette: Der Angreifer las die Server-Zugangsdaten aus `credentials.txt` aus und nutzte diese wenige Sekunden später für den SSH-Zugriff auf den Projektserver.

== Zusammenfassung der Windows-forensischen Befunde

Die Windows-Artefakt-Analyse (M3) rekonstruiert die clientseitige Angriffskette lückenlos und bestätigt die Befunde der Netzwerkforensik (M1):

#table(
  columns: 3,
  stroke: 0.5pt,
  [*Angriffsphase*], [*Windows-Artefakt*], [*Nachweis*],
  [Phishing geöffnet], [UserAssist], [Thunderbird-Ausführung],
  [Schadsoftware ausgeführt], [Prefetch, UserAssist], [python.exe-Ausführung],
  [RDP-Zugriff], [Event Log], [Verbindung von 192.168.50.10],
  [Privilegien-Erhöhung], [Event Log], [SeDebugPrivilege u.a.],
  [Credential-Diebstahl], [UserAssist], [Notepad öffnet credentials.txt],
)

Die konsistente Korrelation zwischen den Windows-Artefakten (M3) und der Netzwerkanalyse (M1) untermauert die Beweiskette: Der Angriff begann mit einer Phishing-E-Mail, führte über die Ausführung der Schadsoftware und den RDP-Zugriff zum Diebstahl der Server-Zugangsdaten und mündete schließlich in der SSH-basierten Kompromittierung des Projektservers.


== Zusammenfassung der Live-Response

Die Live-Response bestätigt die Post-Mortem- und Speicherbefunde am laufenden System
und liefert einen eigenständigen, wichtigen Beweis: den *dynamischen ARP-Eintrag für
den Angreifer-Host 192.168.50.10* (F-LR-02), der einen tatsächlichen Netzwerkkontakt
zwischen Client und Kali-System belegt. Ergänzend bestätigt sie die Systemparameter
und die Zeitzone UTC+8 (F-LR-01) sowie das Fehlen eines laufenden Schadprozesses und
eines Persistenzmechanismus (F-LR-03). Der eigene Erfassungsvorgang (`tasklist` unter
`vogel`, `npcapwatchdog`) ist als Ermittlerartefakt gekennzeichnet.

Über die reine Live-Response hinaus wurden dieselben Windows-Artefaktklassen im Rahmen
der Sicherung auch per *Velociraptor* erfasst (siehe Sicherungskapitel). Diese Sammlung
diente der Triage und als korroborierende Zweitquelle; die maßgebliche Auswertung
erfolgte post-mortem am Abbild `Client.dd`. So ist etwa die Ausführung des Schadcodes
`PYTHON.EXE` sowohl in den live erfassten als auch in den aus dem Abbild extrahierten
Prefetch-Daten inhaltlich deckungsgleich belegt — eine Doppelquellen-Bestätigung des
zentralen Befunds. Die Interpretation des zugrunde liegenden Netzwerkverkehrs erfolgt
in der Netzwerkforensik.
