// ============================================================
//  analyse_ram.typ — Kapitel 5.x
//  Speicherforensik des Windows-Clients (client_ram.mem)
// ============================================================
//  Bildablage:   ../res/ram/<Dateiname>.png
//  Quelldateien: Artefaktverzeichnis (Nextcloud, Anhang),
//                Schema cases/silent_quarry/ram/<Datei>
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
      image("../res/ram/" + datei, width: 92%)
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

= Speicherforensik (RAM) des Windows-Clients
#text(style: "italic", fill: gray.darken(20%))[Bearbeiter: Mitglied 3]

Gegenstand dieses Abschnitts ist die Analyse des Arbeitsspeicherabbilds des
Windows-Clients (`client_ram.mem`). Die Auswertung folgt der Analyse mit Volatility (Prozesse, Dienste, Netzwerk,
weitere Module, Malware-Analyse). Ziel war die Korrelation mit den auf dem
Datenträger festgestellten Befunden sowie die Prüfung auf laufende
Schadprozesse, verdächtige Netzwerkverbindungen und Code-Injektion zum Zeitpunkt der
Sicherung.

== Werkzeug, Image-Identifikation und Reproduzierbarkeit

Hier wurde *Volatility 3 (Framework 2.28.0)* eingesetzt, da es sich beim Client um *Windows 10 (Build 19041/19045)* handelt

Der erste und wichtigste Schritt ist die Identifikation des Abbilds:

#befehl("vol -f client_ram.mem windows.info")

#beweis("info.png", [`windows.info`: Windows 10, x64, Major/Minor 15.19041, SystemTime 2026-07-05 00:37:28 UTC.], aktiv: true)

*Ergebnis*: Windows 10 x64, `Major/Minor 15.19041`, 2 Prozessoren (`KeNumberProcessors 2`),
`SystemTime 2026-07-05 00:37:28 UTC` (lokal 08:37 UTC+8). Die Symboltabelle
(`ntkrnlmp.pdb`) wurde von Volatility 3 automatisch geladen. Der Sicherungszeitpunkt
(05.07.2026) liegt in der Akquisephase des Ermittlungsteams.



== Prozessanalyse

#finding("F-RAM-01", "Prozessliste und Prozessbaum (pslist, pstree, psscan)")[
  #befehl("vol -f client_ram.mem windows.pslist > ram/R1_pslist.txt
vol -f client_ram.mem windows.pstree > ram/R2_pstree.txt
vol -f client_ram.mem windows.psscan > ram/R3_psscan.txt")

  #beweis("pslist.png", [Prozessliste (Auszug): `winpmem_mini_x`, `thunderbird.exe`, `firefox.exe`; kein `python.exe`.], aktiv: true)

  *Was.* Die Prozessliste umfasst 115 Prozesse. Ein Prozess `python.exe` ist *nicht*
  vorhanden — weder in `pslist` (aktive Prozesse) noch in `pstree` oder `psscan`
  (beendete/verborgene Prozesse). Vorhanden und relevant sind: `thunderbird.exe`
  (PID 1724), `firefox.exe` (PID 2560) sowie der Acquisitionsprozess
  `winpmem_mini_x64_rc2.exe` (PID 3152), gestartet von `cmd.exe` (PID 3952) um
  *00:37:28 UTC* — exakt dem SystemTime des Abbilds.

  *Wo.* Asservat `client_ram.mem`; Plugins `windows.pslist`, `windows.pstree`,
  `windows.psscan`.

  *Bedeutung.* Das Fehlen von `python.exe` ist mit dem Angriffsablauf konsistent: der
  Credential-Stealer (`login_check.py`) beendet sich nach der Eingabe selbst
  (`root.destroy()`), sodass zum Sicherungszeitpunkt (05.07., nach der eigentlichen
  Ausführung) kein python-Prozess mehr lief. Der Arbeitsspeicher belegt somit keine
  laufende Schadaktivität, sondern den Systemzustand während der forensischen Sicherung.

  *Korrelation.* Ergänzt F-WIN-05 (disk-seitiger Ausführungsnachweis über UserAssist/BAM):
  die RAM bestätigt, dass der Stealer zum Sicherungszeitpunkt bereits terminiert war.
  `winpmem` ist als Ermittlerartefakt zu werten (siehe F-WIN-12 / F-RAM-05).

  #quelle("ram/R1_pslist.txt, ram/R2_pstree.txt, ram/R3_psscan.txt")
]

== Netzwerkanalyse

#finding("F-RAM-02", "Netzwerkverbindungen (netscan)")[
  #befehl("vol -f client_ram.mem windows.netscan > ram/R4_netscan.txt")

  #beweis("netscan.png", [`netscan`: nur Loopback-Verbindungen (Firefox/Thunderbird) und lokale Listener; keine Verbindung zu 192.168.50.10/.20.], aktiv: true)

  *Was.* `netscan` weist ausschließlich Loopback-Verbindungen (127.0.0.1, u. a.
  `firefox.exe` PID 2560 und `thunderbird.exe` PID 1724) sowie lokale Listener aus
  (u. a. SMB 445, RPC 135, RDP 3389, NetBIOS 137–139 auf 192.168.50.30). Es besteht
  *keine* aktive oder hergestellte Verbindung zum Angreifer-Host 192.168.50.10 oder zum
  Projektserver 192.168.50.20.

  *Wo.* Asservat `client_ram.mem`; Plugin `windows.netscan`.

  *Bedeutung.* Zum Sicherungszeitpunkt bestand keine clientseitige Exfiltrationsverbindung.
  Dies ist konsistent mit dem Gesamtbild: die Exfiltration der CAD-Daten erfolgte
  serverseitig, nicht über den Client. Die lokalen Listener sind
  Standarddienste von Windows 10.

  *Korrelation.* Stützt F-WIN-11 (kein python-Netzwerkverkehr im SRUM) und die
  Domänenabgrenzung: der Client war Einfallstor, nicht Exfiltrationsknoten.

  #quelle("ram/R4_netscan.txt")
]

== Kommandozeilen und Dateiobjekte

#finding("F-RAM-03", "Kommandozeilen und speicherresidente Dateiobjekte (cmdline, filescan)")[
  #befehl("vol -f client_ram.mem windows.cmdline > ram/R5_cmdline.txt
vol -f client_ram.mem windows.filescan > ram/R6_filescan.txt
grep -iE \"App|pwlog|Thunderbird|logins.json\" ram/R6_filescan.txt")

  #beweis("filescan.png", [`filescan`: speicherresidente Referenzen auf `Desktop\\App`, `Downloads\\App\\App` und das Thunderbird-Profil.], aktiv: true)

  *Was.* `cmdline` bestätigt den Acquisitionsvorgang: PID 3152
  `winpmem_mini_x64_rc2.exe client_ram.mem`, gestartet aus `cmd.exe` (PID 3952). Ein
  Aufruf von `python`/`main.py` ist in den Kommandozeilen *nicht* enthalten (konsistent
  mit dem beendeten Prozess, F-RAM-01). `filescan` findet hingegen speicherresidente
  Dateiobjekte des Angriffs: `\Users\User\Desktop\App`, `\Users\User\Downloads\App\App`
  sowie das vollständige Thunderbird-Profil `6p73ordg.default-release` (u. a.
  `Mail\Local Folders\Inbox.msf`, `key4.db`) und das Firefox-Profil.

  *Wo.* Asservat `client_ram.mem`; Plugins `windows.cmdline`, `windows.filescan`.

  *Bedeutung.* Obwohl der Schadprozess beendet war, waren die Datei-Referenzen des
  Angriffs (Ordner `App` auf Desktop und in Downloads) noch im Arbeitsspeicher
  vorhanden. Dies korroboriert die disk-seitigen Befunde (F-WIN-02, F-WIN-03) auf einer
  zweiten, unabhängigen Ebene.

  *Korrelation.* Bestätigt die Existenz des Angriffsordners `App` (F-WIN-02) und des
  Thunderbird-Profils mit der Phishing-Mail (F-WIN-01) speicherseitig.

  #quelle("ram/R5_cmdline.txt, ram/R6_filescan.txt")
]

== Malware-Analyse

#finding("F-RAM-04", "Code-Injektion (malfind)")[
  #befehl("vol -f client_ram.mem windows.malfind > ram/R8_malfind.txt")

  #beweis("malfind.png", [`malfind`: ausschließlich RWX-Regionen von `MsMpEng.exe` (Windows Defender) — bekannter Fehlalarm.], aktiv: true)

  *Was.* `malfind` meldet ausschließlich Speicherregionen des Prozesses `MsMpEng.exe`
  (PID 2332, Windows Defender) mit dem Schutz `PAGE_EXECUTE_READWRITE` und dem Hinweis
  „Function prologue“. Es wurden *keine* Injektionen in Anwendungs- oder Systemprozesse
  festgestellt.

  *Wo.* Asservat `client_ram.mem`; Plugin `windows.malfind`.

  *Bedeutung.* Die RWX-Regionen von `MsMpEng.exe` (Windows Defender) sind ein bekannter,
  legitimer Fehlalarm — die Antimalware-Engine nutzt planmäßig ausführbaren
  Schreibspeicher. Es liegt *keine* Code-Injektion vor. Dies ist mit der Art des
  Schadcodes konsistent: `main.py`/`login_check.py` sind interpretierte Python-Skripte
  ohne Prozessinjektion.

  *Korrelation.* Bestätigt F-WIN-03 (der Schadcode ist ein Skript-basierter
  Credential-Stealer, kein injizierender Loader).

  #quelle("ram/R8_malfind.txt")
]

== Abgrenzung: Ermittlerartefakte im Arbeitsspeicher

#finding("F-RAM-05", "Nachweis des Sicherungswerkzeugs (WinPmem)")[
  #befehl("grep -i winpmem ram/R1_pslist.txt ram/R5_cmdline.txt")

  #beweis("image.png", [Prozess `winpmem_mini_x64_rc2.exe` (PID 3152), gestartet aus `cmd.exe`, 00:37:28 UTC.], aktiv: true)

  *Was.* Der Arbeitsspeicher enthält den Acquisitionsprozess selbst:
  `winpmem_mini_x64_rc2.exe client_ram.mem` (PID 3152, PPID 3952/`cmd.exe`),
  Erstellungszeit 05.07.2026 00:37:28 UTC — identisch mit dem SystemTime des Abbilds.

  *Wo.* Asservat `client_ram.mem`; `windows.pslist`, `windows.cmdline`.

  *Bedeutung.* Der Dump wurde mit *WinPmem* durch das Ermittlungsteam erstellt; das
  Werkzeug bildet sich erwartungsgemäß selbst im Abbild ab.

  *Korrelation.* Ergänzt die Abgrenzung der Ermittlertätigkeit (F-WIN-12). Der
  Sicherungszeitpunkt 00:37:28 UTC bildet den oberen Rand des Untersuchungszeitfensters.

  #quelle("ram/R1_pslist.txt, ram/R5_cmdline.txt")
]

== Grenzen der Speicheranalyse (nicht erfolgreiche Auswertungen)

Im Sinne einer vollständigen und ehrlichen Dokumentation werden auch die
Auswertungen aufgeführt, die aufgrund technischer Einschränkungen kein Ergebnis
lieferten. Diese Einschränkungen sind für Windows 10 (Speicherkomprimierung seit Windows 10).

#finding("F-RAM-06", "Nicht erfolgreiche Module (svcscan, hashdump)")[
  #befehl("vol -f client_ram.mem windows.svcscan   # Swap error
vol -f client_ram.mem windows.hashdump  # Swap error")

  #beweis("svcscan.png", [Swap-Fehler bei `svcscan`/`hashdump`: „No suitable swap file having been provided".], aktiv: true)

  *Was.* Die Module `windows.svcscan` (Dienste) und `windows.hashdump` (Passwort-Hashes)
  lieferten kein verwertbares Ergebnis. `svcscan` brach mit „Swap error … No suitable
  swap file having been provided“ ab; `hashdump` konnte nicht abgeschlossen werden.

  *Wo.* Asservat `client_ram.mem`; Plugins `windows.svcscan`, `windows.hashdump`.

  *Bedeutung.* Seit Windows 10 wird der Arbeitsspeicher komprimiert (Xpress-Algorithmus,
  „Compression Store“); ausgelagerte Seiten liegen im `pagefile.sys`. Ohne Einbindung
  der Auslagerungsdatei können bestimmte Module (Dienste, SAM-Hashes) nicht vollständig
  rekonstruiert werden. Eine
  Wiederholung mit `--single-swap-locations pagefile.sys` ist möglich; die Passwort-Hashes
  sind jedoch bereits disk-seitig verfügbar (SAM-Hive, extrahierbar mit `samdump2`), und
  die Klartext-Zugangsdaten sind über `pwlog.txt`/`credentials.txt` (F-WIN-06) belegt.

  *Korrelation.* Kein Informationsverlust für die Beweisführung: die Zugangsdaten sind
  über F-WIN-06 vollständig belegt; die Dienste-Persistenz wurde disk-seitig geprüft
  (F-WIN-08, kein Persistenzmechanismus).

  #quelle("ram/R7_svcscan.txt (leer), ram/R9_hashdump.txt (leer)")
]

== Zusammenfassung des Speicherbefunds

Die Speicheranalyse bestätigt und ergänzt die disk-seitigen Befunde, liefert jedoch
keinen eigenständigen Nachweis einer laufenden Schadaktivität — was mit dem
Angriffsablauf konsistent ist. Zum Sicherungszeitpunkt (05.07.2026 00:37:28 UTC) war
der python-basierte Credential-Stealer bereits beendet (F-RAM-01); es bestanden keine
Exfiltrationsverbindungen (F-RAM-02) und keine Code-Injektionen (F-RAM-04). Die
Datei-Referenzen des Angriffsordners `App` sowie das Thunderbird-Profil waren jedoch
noch speicherresident (F-RAM-03) und korroborieren die Befunde F-WIN-01/02/03 auf einer
zweiten Ebene. Der Arbeitsspeicher dokumentiert darüber hinaus die forensische
Sicherung selbst (WinPmem, F-RAM-05). Zwei Module (svcscan, hashdump) waren aufgrund
der Windows-10-Speicherkomprimierung nicht auswertbar (F-RAM-06); dies führt zu keinem
Informationsverlust für die Beweisführung.
