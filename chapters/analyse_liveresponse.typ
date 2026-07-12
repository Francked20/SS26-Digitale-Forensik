// ============================================================
//  analyse_liveresponse.typ — Analyse-Phase (Mitglied 3)
//  Live-Response- und Velociraptor-Analyse des Windows-Clients
// ============================================================
//  Bildablage:   ../res/lr/<Datei>.png  bzw. ../res/LivRes/<Datei>.png
//  Quelldateien: Artefaktverzeichnis (Nextcloud, Anhang),
//                cases/silent_quarry/live_response.txt
//                sowie Velociraptor-Sammlung (A07/A08)
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

= Live-Response- und Velociraptor-Analyse des Windows Clients 
#text(style: "italic", fill: gray.darken(20%))[Bearbeiter: Mitglied 3 und 1]

Neben der Post-Mortem-Auswertung (Kapitel Windows-Forensik) und der
Speicheranalyse (Kapitel Speicherforensik) wurde der Systemzustand am
*laufenden* Client zusätzlich über zwei live erfasste Quellen ausgewertet:
die verketteten Windows-Kommandos in `live_response.txt` sowie die
strukturierte *Velociraptor*-Artefaktsammlung (A07/A08). Beide wurden am
05.07.2026 im Rahmen der Akquise durch das Ermittlungsteam erstellt (siehe
Kapitel „Sicherung der Beweismittel — Durchführung").

Dieses Kapitel gliedert sich entsprechend in zwei Analyseteile:

- *Teil A — Live-Response (`live_response.txt`):* Auswertung des flüchtigen
  Systemzustands (Systemparameter, Netzwerkzustand, laufende Prozesse) durch
  *Order of Volatility* (F-LR-01 bis F-LR-03).
- *Teil B — Velociraptor-Sammlung:* Auswertung der automatisiert erfassten
  Windows-Artefakte (UserAssist, Prefetch, Event Logs) zur Rekonstruktion der
  clientseitigen Ereignisabfolge (F-LR-04 bis F-LR-06).

*Methodische Einordnung.* Beide Quellen sind der *Triage* zuzuordnen. Ihre
Befunde bestätigen die maßgeblichen Post-Mortem- und Speicherbefunde über
unabhängige Zweit- und Drittquellen; sie ersetzen die Auswertung am
integritätsgesicherten Abbild `Client.dd` nicht. Bei Abweichungen gilt stets
das Post-Mortem-Abbild als autoritative Quelle. Ein Befund — der dynamische
ARP-Eintrag (F-LR-02) — ist darüber hinaus *eigenständig* und nur live
erfassbar. Einige Einträge (u. a. der eigene `tasklist`-Aufruf, `npcapwatchdog`)
sind als Ermittlerartefakte zu werten und entsprechend gekennzeichnet.

#quelle("live_response.txt")

== Teil A — Analyse der Live-Response (live_response.txt)

=== Systeminformationen (systeminfo)

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

=== Netzwerkzustand (ipconfig, netstat, arp)

#finding("F-LR-02", "ARP-Cache: Nachweis der Netzwerkkommunikation mit dem Angreifer-Host")[
  #befehl("ipconfig /all
netstat -ano
arp -a")

  #beweis("arp.png", [ARP-Cache des Clients: Eintrag `192.168.50.10  00-0c-29-41-13-85  dynamic` (Angreifer-Host).], aktiv: true)

  *Was.* Die Netzwerkkonfiguration weist den Client als *192.168.50.30* aus (Adapter
  Ethernet1, Herstellerpräfix `00-0C-29` = VMware). Der *ARP-Cache* enthält einen
  dynamischen Eintrag für den Angreifer-Host:
  *`192.168.50.10 → 00-0c-29-41-13-85 (dynamic)`*. `netstat` zeigt zum Erfassungszeitpunkt
  nur Loopback-Verbindungen (Firefox PID 2560, Thunderbird PID 1724) und lokale Listener
  (135, 445, 3389, 139) — keine aktive Verbindung zu 192.168.50.10 oder 192.168.50.20.

  *Wo.* Artefakt `live_response.txt` (Abschnitte `ipconfig /all`, `netstat`, `arp -a`).

  *Bedeutung.* Ein *dynamischer* ARP-Eintrag entsteht ausschließlich, wenn zuvor eine
  Kommunikation auf Layer 2 zwischen den Hosts stattgefunden hat. Der Eintrag belegt
  somit, dass der Client *tatsächlich Netzwerkkontakt mit dem Angreifer-Host
  192.168.50.10 (Kali)* hatte eine unabhängige, clientseitige Bestätigung der
  Angreifer-Präsenz im Segment. Dass zum Erfassungszeitpunkt keine aktive Verbindung
  mehr bestand, ist konsistent mit dem beendeten Angriff (der ARP-Cache hält den Eintrag
  jedoch temporär vor).

  *Korrelation.* Die Interpretation des Angreifer-Datenverkehrs erfolgt in der
  Netzwerkforensik (M1); der ARP-Eintrag ist der clientseitige Beleg des Kontakts.
  Ergänzt F-RAM-02 (keine aktive Exfiltrationsverbindung zum Sicherungszeitpunkt).

  #quelle("live_response.txt")
]

=== Prozesse und geplante Aufgaben (tasklist, schtasks)

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

== Teil B — Analyse der Velociraptor-Sammlung

Die per Velociraptor (A07/A08) automatisiert gesammelten Windows-Artefakte
wurden mit dem *Timeline Explorer* (Eric Zimmerman Tools) sowie durch manuelle
Sichtung der exportierten CSV-Dateien ausgewertet. Methodisch handelt es sich
um eine *Artefakt-Korrelation*: Verschiedene Artefaktklassen werden in
chronologische Beziehung gesetzt, um die *Reihenfolge* der clientseitigen
Ereignisse zu belegen.

#hinweis[
  Abgrenzung zur Post-Mortem-Auswertung: UserAssist, Prefetch und Event Logs
  werden maßgeblich am Abbild `Client.dd` ausgewertet (F-WIN-04/05). Die
  Velociraptor-Sammlung dient hier als *korroborierende Zweitquelle*; sie
  belegt dieselben Artefakte unabhängig aus der Live-Erfassung. Wo die
  live erfassten Werte den Post-Mortem-Befunden entsprechen, erhöht dies den
  Beweiswert (Doppelquellen-Bestätigung).
]

=== Übersicht der ausgewerteten Artefakte

#table(
  columns: 2,
  stroke: 0.5pt,
  thead[Artefakt][Forensischer Zweck],
  [Event Logs (EVTX)], [Nachweis des RDP-Zugriffs und der zugewiesenen Privilegien],
  [Prefetch], [Nachweis der Programmausführung (Schadsoftware)],
  [UserAssist], [Reihenfolge der GUI-Programmausführungen],
  [Amcache], [Datei-Identifikation und Hashes],
)

=== Rekonstruktion der Ereignisabfolge (UserAssist)

#finding("F-LR-04", "Reihenfolge der GUI-Programmausführungen (UserAssist)")[
  #figure(
    image("../res/LivRes/userassist_sequence.png", width: 90%),
    caption: [UserAssist: Abfolge der Programmausführungen
      (Thunderbird $arrow$ python.exe $arrow$ Notepad)],
  ) <fig-userassist-sequence>

  *Was.* Die UserAssist-Einträge belegen die *Reihenfolge* der GUI-gestützten
  Programmausführungen auf dem Client:

  #table(
    columns: 3,
    stroke: 0.5pt,
    thead[Reihenfolge][Programm][Forensische Bedeutung],
    [1], [Thunderbird], [Öffnen der Phishing-E-Mail],
    [2], [python.exe], [Ausführung des Schadcodes (`main.py`)],
    [3], [Notepad], [Öffnen von `credentials.txt`],
  )

  *Wo.* Velociraptor-Artefakt `Windows.Registry.UserAssist` (A07), ausgewertet im
  Timeline Explorer.

  *Bedeutung.* Die Sequenz Thunderbird → python.exe → Notepad bildet die
  clientseitige Ereignisabfolge ab: Öffnen der Phishing-Mail, Ausführung des
  Schadcodes (der ein gefälschtes Anmeldefenster darstellte, vgl. F-WIN-03), und
  das anschließende Öffnen der Klartext-Datei `credentials.txt` in Notepad.
  UserAssist belegt die *Reihenfolge*, nicht die Urheberschaft einzelner Schritte;
  die Zuordnung des Notepad-Zugriffs zur Angreifer-RDP-Sitzung ergibt sich erst in
  Zusammenschau mit F-LR-06 und der Netzwerkforensik (M1).

  *Korrelation.* Korroboriert F-WIN-05 (Ausführung `python.exe`) und F-WIN-06
  (`credentials.txt` als exponierte Serverzugangsdaten) aus der Live-Erfassung.

  #quelle("Velociraptor A07 — Windows.Registry.UserAssist")
]

=== Nachweis der Schadcode-Ausführung (Prefetch)

#finding("F-LR-05", "Ausführung PYTHON.EXE (Prefetch, Zweitquelle)")[
  #figure(
    image("../res/LivRes/prefetch_python.png", width: 85%),
    caption: [Prefetch-Eintrag für PYTHON.EXE mit Ausführungszeitstempel],
  ) <fig-prefetch-python>

  *Was.* Die Prefetch-Analyse bestätigt unabhängig von UserAssist die Ausführung
  von `PYTHON.EXE`, welches den Python-Schadcode (`main.py`) interpretierte.

  #table(
    columns: 2,
    stroke: 0.5pt,
    thead[Attribut][Wert],
    [Prefetch-Datei], [`PYTHON.EXE-[hash].pf`],
    [Ausführungszeit], [05.07.2026 00:22Z (lokal 08:22 UTC+8)],
    [Bedeutung], [Ausführung des Python-Schadcodes `main.py`],
  )

  *Wo.* Velociraptor-Artefakt `Windows.Attack.Prefetch` (A08).

  *Bedeutung.* Der live erfasste Prefetch-Befund ist mit dem Post-Mortem-Prefetch
  aus `Client.dd` (F-WIN-05) inhaltlich deckungsgleich — eine
  Doppelquellen-Bestätigung der Schadcode-Ausführung. Die Ausführungszeit fällt in
  das Zeitfenster 04.–05.07.2026, das mit der Vorbereitungs- und Akquisephase des
  Teams überlappt (vgl. F-WIN-05, F-WIN-12); UserAssist und Prefetch belegen die
  *Ausführung und ihre Einordnung in die Abfolge*, nicht eine „natürliche"
  Ausführung durch die simulierte Zielperson.

  *Korrelation.* Deckungsgleich mit F-WIN-05 (Post-Mortem-Prefetch). Bestätigt die
  Wirksamkeit des Schadcodes (F-WIN-03).

  #quelle("Velociraptor A08 — Windows.Attack.Prefetch")
]

=== Nachweis des RDP-Zugriffs und der Privilegien (Event Logs)

#finding("F-LR-06", "RDP-Zugriff und zugewiesene Sonderprivilegien (Event Logs)")[
  #figure(
    image("../res/LivRes/eventlog_rdp_connection.png", width: 90%),
    caption: [Event Log: Annahme der RDP-Verbindung von 192.168.50.10],
  ) <fig-rdp-connection>

  *Was.* Die Windows Event Logs dokumentieren den Fernzugriff über das Remote
  Desktop Protocol. Protokolliert ist die Annahme einer eingehenden RDP-Verbindung
  vom Angreifer-Host *192.168.50.10* (Dienst „Remote Desktop Services",
  Zielsystem `DESKTOP-GKDAU52`). Ergänzend ist die Zuweisung administrativer
  Sonderprivilegien an das kompromittierte Konto `vogel` verzeichnet:

  #table(
    columns: 2,
    stroke: 0.5pt,
    thead[Privileg][Bedeutung],
    [`SeDebugPrivilege`], [Zugriff auf fremde Prozesse],
    [`SeTakeOwnershipPrivilege`], [Übernahme von Datei-Eigentümerschaft],
    [`SeLoadDriverPrivilege`], [Laden von Kernel-Treibern],
    [`SeBackupPrivilege`], [Umgehung von Dateiberechtigungen],
    [`SeRestorePrivilege`], [Wiederherstellungsrechte],
    [`SeImpersonatePrivilege`], [Identitätsübernahme],
  )

  Zusätzlich ist ein Ereignis mit Bezug auf leere Passwörter registriert (Ziel:
  `WDAGUtilityAccount`) — vereinbar mit Reconnaissance-Aktivität.

  *Wo.* Velociraptor-Artefakt `Windows.EventLogs.*` (A07); zugehörige EVTX-Kanäle
  (u. a. `TerminalServices-RemoteConnectionManager`, `Security`).

  *Bedeutung.* Der Event-Log-Befund bestätigt clientseitig den RDP-Zugriff von
  192.168.50.10, den die Netzwerkforensik (M1) unabhängig im PCAP nachgewiesen hat
  (RDP-Sitzung 00:23:42 UTC, Benutzername `vogel` im Klartext-Cookie
  `mstshash=vogel`). Die zugewiesenen Privilegien entsprechen den in F-WIN-00
  festgestellten Administratorrechten des Kontos `vogel`.

  *Korrelation.* Korroboriert das Netzwerk-Finding zum RDP-Vektor (M1) sowie
  F-WIN-00 (Kontorechte). Die vollständige, mitgliederübergreifende Zeitleiste
  wird in der Present-Phase zusammengeführt.

  #quelle("Velociraptor A07 — Windows.EventLogs.*")
]

== Zusammenfassung

Die beiden live erfassten Quellen bestätigen die Post-Mortem- und Speicherbefunde
am laufenden System und liefern in einem Punkt einen eigenständigen Beweis.

*Teil A (Live-Response).* Der wichtigste eigenständige Befund ist der
*dynamische ARP-Eintrag für den Angreifer-Host 192.168.50.10* (F-LR-02), der
einen tatsächlichen Netzwerkkontakt zwischen Client und Kali-System belegt und
nur live erfassbar ist. Ergänzend bestätigt die Live-Response die Systemparameter
und die Zeitzone UTC+8 (F-LR-01) sowie das Fehlen eines laufenden Schadprozesses
und eines Persistenzmechanismus (F-LR-03).

*Teil B (Velociraptor).* Die Artefakt-Sammlung korroboriert die
Post-Mortem-Befunde aus `Client.dd` über eine unabhängige Live-Erfassung: die
Reihenfolge der Programmausführungen (F-LR-04), die Schadcode-Ausführung
`PYTHON.EXE` deckungsgleich zum Post-Mortem-Prefetch (F-LR-05) sowie der
RDP-Zugriff von 192.168.50.10 und die Kontoprivilegien (F-LR-06). Damit liegt
für die zentralen clientseitigen Befunde eine Doppelquellen-Bestätigung vor.

Die maßgebliche Auswertung erfolgt in allen Fällen post-mortem am
integritätsgesicherten Abbild `Client.dd`; die live erfassten Quellen dienen der
Triage und der Korroboration. Die Interpretation des zugrunde liegenden
Netzwerkverkehrs sowie die mitgliederübergreifende Gesamttimeline erfolgen in
der Netzwerkforensik (M1) bzw. in der Present-Phase.
