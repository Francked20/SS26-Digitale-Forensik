// ============================================================
//  live_response.typ — Kapitel 5.x
//  Live-Response-Analyse des Windows-Clients (live_response.txt)
// ============================================================
//  Bildablage:   ../res/lr/<Dateiname>.png
//  Quelldatei:   Artefaktverzeichnis (Nextcloud, Anhang),
//                cases/silent_quarry/live_response.txt
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

#let quelle(pfad) = text(size: 9pt, fill: gray.darken(15%))[
  #text(weight: "bold")[Quelldatei:] #raw(pfad) #text(style: "italic")[(siehe Artefaktverzeichnis, Anhang)]
]

= Live-Response-Analyse des Windows-Clients

Neben der Post-Mortem-Auswertung (Kap. 5.3) und der Speicheranalyse (Kap. 5.4) wurde
am laufenden System eine *Live-Response* durchgeführt und mittels Velociraptor
gesichert. Die Vorlesung ordnet die Live-Response der „Order of Volatility“ zu: sie
erfasst flüchtige Zustandsdaten (laufende Prozesse, Netzwerkverbindungen,
ARP-Cache, angemeldete Benutzer), die nach einem Neustart verloren gehen. Die
Ergebnisse liegen in `live_response.txt` vor und umfassen `systeminfo`, `tasklist /v`,
`ipconfig /all`, `netstat`, `route`, `arp -a` sowie `schtasks`.

Da die Live-Response am 05.07.2026 im Rahmen der Akquise durch das Ermittlungsteam
erstellt wurde, bildet sie den Systemzustand während der Sicherung ab. Einige Einträge
(u. a. der eigene `tasklist`-Aufruf) sind entsprechend als Ermittlerartefakte zu werten.

#quelle("live_response.txt")

== Systeminformationen (systeminfo)

#finding("F-LR-01", "Systemzustand und Bestätigung der Systemparameter")[
  #befehl("# via Velociraptor Live-Response gesammelt:
systeminfo")

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
  gesamten Gutachtens. Die VMware-Umgebung bestätigt die Infrastruktur (Kap. 3).

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
  Netzwerkforensik (Kap. 5.1, Mitglied 1); der ARP-Eintrag ist der clientseitige
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
  Command Prompt - tasklist /v“) und `tasklist.exe` (PID 7144) unter dem Konto
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

== Zusammenfassung der Live-Response

Die Live-Response bestätigt die Post-Mortem- und Speicherbefunde am laufenden System
und liefert einen eigenständigen, wichtigen Beweis: den *dynamischen ARP-Eintrag für
den Angreifer-Host 192.168.50.10* (F-LR-02), der einen tatsächlichen Netzwerkkontakt
zwischen Client und Kali-System belegt. Ergänzend bestätigt sie die Systemparameter
und die Zeitzone UTC+8 (F-LR-01) sowie das Fehlen eines laufenden Schadprozesses und
eines Persistenzmechanismus (F-LR-03). Der eigene Erfassungsvorgang (`tasklist` unter
`vogel`, `npcapwatchdog`) ist als Ermittlerartefakt gekennzeichnet. Die Interpretation
des zugrunde liegenden Netzwerkverkehrs erfolgt in der Netzwerkforensik (Kap. 5.1).
