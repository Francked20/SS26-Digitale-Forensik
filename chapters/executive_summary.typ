= Executive Summary

#text(style: "italic", fill: gray.darken(20%))[
  Technische Kurzzusammenfassung der zentralen Findings über alle vier
  Forensikbereiche hinweg.
]

Die forensische Untersuchung belegt einen *mehrstufigen, gezielten Angriff*
gegen die Bayern Präzision GmbH. Die Beweisführung stützt sich auf sechs
unabhängige, sich gegenseitig bestätigende Datenquellen: Netzwerkmitschnitt
(M1), Linux-Server- und Server-RAM (M2), Windows-Client-Post-Mortem,
Client-RAM und Live-Response (M3) sowie Datenträger-/Dateiforensik beider
Abbilder (M4). Die Korrelation der Einzelbefunde ergibt folgende Angriffskette:

*1. Initialer Zugriff — Spear-Phishing (Client).*
Am 02.07.2026 ging über Thunderbird eine gefälschte, scheinbar interne
E-Mail mit dem Anhang `App.zip` ein (F-WIN-01). Das Archiv enthielt den
Python-Schadcode `main.py`/`login_check.py`, der ein gefälschtes
„Windows Sicherheit"-Fenster erzeugte (F-WIN-02, F-WIN-03).

*2. Ausführung & Credential Harvesting (Client).*
Die Ausführung des Schadcodes ist über Prefetch, UserAssist, BAM und die
Windows-Timeline nachgewiesen (F-WIN-05). Der Stealer schrieb die
abgegriffenen Windows-Anmeldedaten (`vogel/admin`) im Append-Modus zweifach
in `pwlog.txt` (F-WIN-06). Speicherresident waren die zugehörigen
Datei- und Prozessartefakte im Client-RAM noch nachweisbar (F-RAM-03).

*3. Lateral Movement — RDP zum Client.*
Mit den erbeuteten Windows-Anmeldedaten (`vogel/admin`, F-WIN-06) baute der
Angreifer (192.168.50.10) eine RDP-Sitzung zum Client (192.168.50.30) auf;
der Benutzername `vogel` wurde im RDP-Cookie (`mstshash=vogel`) im Klartext
übertragen (Netzwerk-Finding 1). Auf dem Desktop lagen zusätzlich die davon
verschiedenen *Serverzugangsdaten* `m.vogel:Werkzeug#2026` doppelt offen —
als `credentials.txt` und in `logins.json` von Firefox (F-WIN-06).

*4. Server-Kompromittierung & Exfiltration (Server).*
Mit den erbeuteten Serverzugangsdaten meldete sich der Angreifer per SSH am
Projektserver (192.168.50.20) an — zwei Logins am 05.07.2026 ab 00:24:35 UTC
(Netzwerk-Findings 2/3; `auth.log`, B003-SERVER-SQ-2026). Innerhalb der
ersten Sitzung (233 s, bis ~00:28:28) wurden ca. 1 MB Daten zum Angreifer
exfiltriert; die zweite, nur 6 s kurze Sitzung (Login 00:26:53) läuft
*parallel* zur noch offenen ersten und zeigt keine Exfiltration. Datenrichtung
und Volumen belegen den Diebstahl trotz SSH-Verschlüsselung.

*5. Sabotage & Anti-Forensik (Server).*
Der Angreifer löschte die Projektdaten (`rm -rf`, B004-SERVER-SQ-2026) und
manipulierte anschließend Zeitstempel per `touch -t 202401010000`
(Timestomping, B005-SERVER-SQ-2026). Die Datenträgerforensik bestätigt leere
Projektverzeichnisse und widersprüchliche Zeitstempel via `istat`/`mactime`;
die Inhalte der gelöschten STEP-Dateien konnten als Datenreste im
Unallocated Space (`blkls`/`strings`) rekonstruiert, aber nicht vollständig
wiederhergestellt werden.

*Abgegrenzte Ermittlerartefakte.* Die während der Sicherung eingesetzten
Werkzeuge (Qemu.img.exe, WinPmem, Velociraptor, Wireshark/Npcap) erzeugen eigene
Spuren, die konsequent von den Täterspuren getrennt dokumentiert sind
(F-WIN-12, F-RAM-05).

*Abgedeckte Bereiche:* Netzwerk-, Linux-OS-, Windows-OS-, Anwendungs-,
Datenträger-/Datei- und Speicherforensik. Alle Zeitstempel in diesem Gutachten
sind in UTC angegeben; für die Ortszeit des Clients ist +8 h (Singapore
Standard Time, UTC+8) zu addieren.

#pagebreak(weak: true)
