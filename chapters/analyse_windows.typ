// ============================================================
//  analyse_windows.typ — Kapitel 5.3
//  Windows-Betriebssystem- und Anwendungsforensik (Mitglied 3)
// ============================================================
//  Bildablage:   ../res/win/<Dateiname>.png
//  Quelldateien: Artefaktverzeichnis (Nextcloud, Anhang),
//                Schema cases/silent_quarry/<Ordner>/<Datei>
// ============================================================

#import "../style/style.typ": finding, hinweis, thead, accent

// --- Helfer: ausgeführter Befehl (monospace, dezenter Kasten) ---
#let befehl(cmd) = block(
  width: 100%, inset: 7pt, radius: 3pt, above: 0.6em, below: 0.4em,
  fill: luma(244), stroke: (left: 2pt + accent),
)[
  #text(size: 8pt, fill: gray.darken(30%), weight: "bold")[AUSGEFÜHRTER BEFEHL] #linebreak()
  #raw(cmd, block: true, lang: "bash")
]

// --- Helfer: Beweis-Screenshot (Platzhalter) ---
// Helper: image si fournie, sinon placeholder
#let beweis(datei, caption, aktiv: false) = [
  #figure(
    if aktiv {
      image("../res/win/" + datei, width: 92%)
    } else {
      rect(width: 92%, height: 2.4cm, fill: luma(248), stroke: (paint: gray, dash: "dashed"))[
        #align(center + horizon)[#text(fill: gray, size: 9pt, style: "italic")[Screenshot einfügen: #datei]]
      ]
    },
    caption: caption,
  )
]

// --- Helfer: Fundort der Quelldatei ---
#let quelle(pfad) = text(size: 9pt, fill: gray.darken(15%))[
  #text(weight: "bold")[Quelldatei:] #raw(pfad) #text(style: "italic")[(siehe Artefaktverzeichnis, Anhang)]
]

= Windows-Betriebssystem- und Anwendungsforensik <kap-windows>
#text(style: "italic", fill: gray.darken(20%))[Bearbeiter: Mitglied 3]

Gegenstand dieses Abschnitts ist die post-mortem-Auswertung des Datenträgerabbilds
des Windows-Clients (Asservat `Client.dd`). Untersucht wurden sämtliche in der
Vorlesung behandelten Windows-Artefaktklassen (Registry, Prefetch, Event Logs,
Scheduled Tasks, Jump Lists/LNK, Papierkorb, Windows Timeline, SRUM, Thumbnails,
Notifications, Volume Shadow Copies) sowie die anwendungsbezogenen Artefakte
(Thunderbird, Firefox, Schadcode, Dokumentmetadaten). Ziel war der Nachweis des
initialen Zugangsvektors, der Ausführung des Schadcodes, der Erbeutung der
Zugangsdaten sowie die Prüfung etwaiger Persistenz- und Anti-Forensik-Maßnahmen.

Jedes Finding ist so aufgebaut, dass es *reproduzierbar* ist: Es nennt den exakten
ausgeführten Befehl, den zugehörigen Beweis-Screenshot sowie die Fundstelle der
Quelldatei im Artefaktverzeichnis. Damit ist für jeden Befund nachvollziehbar, *was*
getan wurde, *wie* es getan wurde und *womit* das Ergebnis belegt ist.


== Reproduzierbarkeit, Integrität und Werkzeuge

Die gesamte Auswertung ist mit den nachstehenden Angaben reproduzierbar. Das
Datenträgerabbild wurde ausschließlich schreibgeschützt eingebunden; die Integrität
wurde vor der Analyse durch Hashwertbildung gesichert.

*Integritätshashes der zentralen Asservate:*
#table(
  columns: (auto, auto, 1fr),
  thead[Asservat][Verfahren][Hashwert],
  [`Client.dd`], [SHA-1], [`3b1af5ea0983b1f6c8c751c9b38a7eec5e77a554`],
  [`App.zip`], [SHA-256], [`b898051b65c2362c8a95649e22fd00e7ce9aaca76b48aeb2645e06661ff78ccd`],
  [`credentials.txt`], [SHA-256], [`09846850a7809eed4293ecd3ce6f43e7a2966efd94f4c941622032c366fb26d9`],
)



*Partitionierung und schreibgeschützte Einbindung.* Die Struktur des Abbilds wurde
mit `mmls` ermittelt (GPT/EFI, Windows-Partition „Basic data partition“, Start-Sektor
673792). Die Einbindung erfolgte read-only mit Anzeige der Systemdateien und
NTFS-ADS-Unterstützung:

#befehl("mmls Client.dd")
#befehl("sudo mount -o ro,loop,offset=$((673792*512)),show_sysfiles,streams_interface=windows Client.dd /mnt/client")

#beweis("mmls.png", [Partitionierung mit mmls], aktiv: true)

*Extraktion der Registry-Hives.* Die Hives wurden aus der eingebundenen Partition in
das Arbeitsverzeichnis `hives/` kopiert:

#befehl("cp /mnt/client/Windows/System32/config/{SYSTEM,SOFTWARE,SAM,SECURITY} hives/
cp /mnt/client/Users/User/NTUSER.DAT hives/
cp /mnt/client/Users/User/AppData/Local/Microsoft/Windows/UsrClass.dat hives/
cp /mnt/client/Windows/AppCompat/Programs/Amcache.hve hives/")

*Eingesetzte Werkzeuge (Versionen).*
#table(
  columns: (auto, auto, auto),
  thead[Werkzeug][Version][Zweck],
  [RegRipper], [#hinweis[Rip v.3.0]], [Registry-Auswertung],
  [EvtxeCmd], [#hinweis[1.5.2.0]], [Event-Log-Aufbereitung],
  [esedbexport (libesedb)], [20240420], [SRUM-Extraktion],
  [vshadowinfo (libvshadow)], [20240504], [Volume Shadow Copies],
  [ExifTool], [#hinweis[`13.53`]], [Dokumentmetadaten],
  [The Sleuth Kit (mmls)], [#hinweis[`4.11.1`]], [Partitionsanalyse],
)


=== Zeitzone und Zeitstempel-Konvention

Die Systemzeitzone wurde aus der Registry ermittelt:

#befehl("rip.pl -r hives/SYSTEM -p timezone > out/B2_timezone.txt")

Ergebnis: *Singapore Standard Time*, Bias `-480` Minuten, also *UTC+8*. Die von den
Werkzeugen ausgegebenen Zeitstempel liegen in *UTC* („Z“) vor; für die lokale
Systemzeit sind acht Stunden zu addieren. Sämtliche Zeitangaben in diesem Kapitel sind,
sofern nicht anders gekennzeichnet, in UTC. Die Umrechnung in Ortszeit erfolgt in der
korrelierten Zeitleiste.

#beweis("timezone.png", [RegRipper-Plugin `timezone`: Singapore Standard Time, Bias -480 (UTC+8).], aktiv: true)

#quelle("out/B2_timezone.txt")

=== Abgrenzung von Ermittler- und Täterartefakten

Ein zentraler Befund ist, dass sich auf dem System zwei klar trennbare
Aktivitätsphasen abbilden:

#table(
  columns: (auto, 1fr),
  thead[Phase][Zeitraum (UTC) und Charakter],
  [Angriff (simuliert)], [30.06.–02.07.2026 — Ablage/Entpacken von `App.zip`, Zugang der Phishing-Mail, Navigation im Angriffsordner],
  [Ausführung des Schadcodes], [04.–05.07.2026 — Ausführung von `python.exe` (siehe F-WIN-05)],
  [Forensische Akquise (Ermittler)], [05.07.2026 — FTK Imager, Wireshark/Npcap, Velociraptor, WinPmem],
)

Zahlreiche Artefakte enthalten Einträge vom 05.07.2026, die eindeutig der Tätigkeit
des Ermittlungsteams zuzuordnen sind. Diese werden konsequent als Ermittlerartefakte
gekennzeichnet und nicht als Angriffsspuren gewertet (siehe F-WIN-12).

== Systemidentifikation und Benutzerkonten

#finding("F-WIN-00", "Systemidentifikation und Benutzerkonten")[
  #befehl("rip.pl -r hives/SAM -p samparse > out/D1_samparse.txt
rip.pl -r hives/SOFTWARE -p winver > out/C2_winver.txt
rip.pl -r hives/SYSTEM -p compname > out/B1_compname.txt
rip.pl -r hives/SOFTWARE -p profilelist > out/C5_profilelist.txt")

  #beweis("samparse.png", [SAM-Auswertung: Konto `vogel` (RID 1000), Administrator, Login-Zähler 26.], aktiv: true)

  *Was.* Der Client trägt den Hostnamen *DESKTOP-GKDAU52* und läuft unter *Windows 10
  Education, Build 19045* (UBR 6456), installiert am 30.06.2026 11:51:46Z. Das SAM-Hive
  weist als reguläres Benutzerkonto *`vogel`* (RID 1000, Vollname „Markus Vogel“) aus.
  Das Konto ist Mitglied der Gruppe *Administratoren*, mit dem Flag „Password not
  required“ versehen, Login-Zähler 26, letzte Anmeldung 05.07.2026 01:22:43Z. Das
  Profilverzeichnis lautet abweichend `C:\Users\User`. Die übrigen Konten sind
  deaktiviert und wurden nie angemeldet.

  *Wo.* Asservat `Client.dd`, Hives `SYSTEM`, `SOFTWARE`, `SAM` — RegRipper.

  *Bedeutung.* Die Diskrepanz zwischen Kontoname (`vogel`) und Profilpfad
  (`C:\Users\User`) erklärt das parallele Auftreten der Timeline-Profile `L.User` und
  `L.vogel`. Administratorrechte und fehlende Passwortpflicht begünstigten den
  Angriffsverlauf.

  *Korrelation.* Der Hostname `DESKTOP-GKDAU52` deckt sich mit dem Client 192.168.50.30.

  #quelle("out/D1_samparse.txt, out/C2_winver.txt, out/B1_compname.txt, out/C5_profilelist.txt")
]

== Initialer Angriffsvektor: Phishing-Mail

#finding("F-WIN-01", "Phishing-Mail als initialer Zugangsvektor (Thunderbird)")[
  #befehl("cp \"/mnt/client/Users/User/AppData/Roaming/Thunderbird/Profiles/6p73ordg.default-release/Mail/Local Folders/Inbox\" thunderbird/Inbox
cat thunderbird/Inbox")

  #beweis("mail_header.png", [Header und Text der Phishing-Mail: gefälschter Absender, Betreff, Handlungsanweisung, Anhang `App.zip`.], aktiv: true)

  *Was.* Im Thunderbird-Profil `6p73ordg.default-release` wurde unter
  `Mail\Local Folders\Inbox` eine E-Mail vom *02.07.2026* mit dem Betreff „Wichtiges
  Update — Ihre Konstruktionssoftware“ festgestellt. Absender ist die gefälschte interne
  Adresse `it-support@bayern-praezision.de` (Signatur „Thomas Krämer, IT-Sicherheit &
  Systemadministration“), Empfänger `m.vogel@bayern-praezision.de`. Der Text fordert
  unter dem Vorwand eines dringenden Sicherheitsupdates dazu auf, den Anhang `App.zip`
  auf dem Desktop zu speichern, zu entpacken, `main.py` per Doppelklick auszuführen und
  die Windows-Zugangsdaten „zur Neuregistrierung des Profils“ einzugeben. Der Anhang ist
  als `application/x-zip-compressed` base64-kodiert eingebettet.

  *Wo.* Asservat `Client.dd`, MBOX-Datei `thunderbird/Inbox` (4894 Bytes).

  *Bedeutung.* Belegbarer initialer Zugangsvektor. Kombiniert Autoritätsvortäuschung,
  Dringlichkeit und präzise Handlungsanweisung — klassisches Social-Engineering-Muster.
  Der Anhang lieferte den Schadcode frei Haus; ein Browser-Download war nicht nötig.

  *Korrelation.* Erklärt die Abwesenheit eines Downloads im Firefox-Verlauf (F-WIN-08).
  Der Header `Fcc: imap://m.vogel...@192.168.50.30/Sent` bestätigt die Client-IP. Deckt
  sich wörtlich mit `README.md` (F-WIN-02).

  #quelle("thunderbird/Inbox")
]

== Schadpaket und Benutzerinteraktion

#finding("F-WIN-02", "Schadpaket App.zip: Herkunft und Handhabung")[
  #befehl("sha256sum thunderbird/App.zip
unzip -l thunderbird/App.zip
rip.pl -r hives/NTUSER.DAT -p comdlg32 > out/A4_comdlg32.txt
rip.pl -r hives/UsrClass.dat -p shellbags > out/E1_shellbags.txt")

  #beweis("shellbags.png", [Shellbags: Anlegen und Navigation der Ordner `App` und `App\\Test` mit Zeitstempeln.], aktiv: true)

  *Was.* Der Anhang `App.zip` (SHA-256 `b898051b...78ccd`) enthält vier Elemente:
  `App/README.md`, `App/main.py`, `App/Test/login_check.py` sowie leere Verzeichnisse
  (interne Zeitstempel 30.06.2026 15:02–15:04Z). `README.md` wiederholt persönlich
  adressiert („Hallo Markus“) die Handlungsanweisung. Die Registry belegt die
  Handhabung: `ComDlg32\OpenSavePidlMRU\zip` führt `App.zip` auf, `LastVisitedPidlMRU`
  verknüpft den Speichervorgang mit `thunderbird.exe`. Die Shellbags dokumentieren
  `Downloads\App.zip` (30.06. 15:09:38Z), `Downloads\App` (15:52:52Z) und
  `Downloads\App\App\Test` (Zugriff 02.07. 19:37:38Z).

  *Wo.* Asservat `Client.dd`: `thunderbird/App/`; Hive `NTUSER.DAT` (comdlg32),
  `UsrClass.dat` (shellbags).

  *Bedeutung.* ComDlg32 (Speichern aus Thunderbird) und Shellbags (Entpacken,
  Navigation bis `Test`) beweisen die aktive Benutzerinteraktion mit dem Schadpaket.

  *Korrelation.* Fortsetzung von F-WIN-01. Die Navigation in `App\Test` führt zu
  `login_check.py` (F-WIN-03).

  #quelle("thunderbird/App.zip, out/A4_comdlg32.txt, out/E1_shellbags.txt")
]

// zusätzlicher Beweis README optional:
#beweis("readme.png", [`README.md`: persönlich adressierte Handlungsanweisung an „Markus".], aktiv: true)

== Analyse des Schadcodes

#finding("F-WIN-03", "Credential-Stealer: gefälschtes Windows-Anmeldefenster")[
  #befehl("cat thunderbird/App/main.py
cat thunderbird/App/Test/login_check.py")

  #beweis("main.png", [`main.py`: Starter mit Kommentar „Gefälschtes Login-Fenster starten" und `keylogger_path`.], aktiv: true)
  #beweis("login.png", [`login_check.py`: tkinter-Fenster „Windows Sicherheit", Schreibvorgang in `pwlog.txt`.], aktiv: true)

  *Was.* Der Schadcode besteht aus zwei Python-Dateien. `main.py` ermittelt den
  Unterordner `Test` und startet über `subprocess.Popen(['python', keylogger_path])` die
  Datei `login_check.py`. Kommentar („\# Gefälschtes Login-Fenster starten“) und
  Variablenname `keylogger_path` dokumentieren die Absicht. `login_check.py` erzeugt per
  `tkinter` ein Fenster „Windows Sicherheit“, das per `-topmost` im Vordergrund gehalten
  wird und eine System-Dialogbox imitiert. Es fragt „Benutzername“ und „Windows-Passwort“
  (maskiert per `show='*'`) ab und schreibt die Eingaben in `on_submit()` im
  Anhänge-Modus („a“) nach `~\Desktop\App\pwlog.txt`. Keine Validierung.

  *Wo.* Asservat `Client.dd`: `thunderbird/App/main.py`, `thunderbird/App/Test/login_check.py`.

  *Bedeutung.* Eindeutiger Credential-Stealer: täuscht eine Windows-Sicherheitsabfrage
  vor und speichert Zugangsdaten im Klartext. Der hartkodierte Pfad
  `~\Desktop\App\pwlog.txt` verknüpft den Code direkt mit dem Beweisartefakt (F-WIN-06).

  *Korrelation.* Ausgabepfad = Fundort von `pwlog.txt` (F-WIN-06). Der Start über
  `subprocess.Popen` erklärt die zwei `PYTHON.EXE`-Prefetch-Dateien (F-WIN-05).

  #quelle("thunderbird/App/main.py, thunderbird/App/Test/login_check.py")
]

== Nachweis der Ausführung

#finding("F-WIN-04", "Zugriff auf die Schaddateien (RecentDocs, LNK, Jump Lists)")[
  #befehl("rip.pl -r hives/NTUSER.DAT -p recentdocs > out/A3_recentdocs.txt
LECmd.exe -d lnk --csv out --csvf lnk.csv
JLECmd.exe -d jumplists --csv out --csvf jumplists.csv")

  #beweis("recentdocs.png", [RecentDocs: geöffnete Schaddateien (zB .py, .zip, .txt)], aktiv: true)

  *Was.* RecentDocs listet sämtliche Angriffsdateien als zuletzt geöffnet: `App.zip`,
  `main.py`, `login_check.py`, `README.md`, `pwlog.txt`, `credentials.txt`. Die
  dateitypbezogenen Unterschlüssel (`.py`, `.md`, `.zip`, LastWrite 05.07. 00:22:42Z)
  bestätigen dies. Ergänzend belegen die LNK-Dateien (`main.lnk`, `login_check.lnk`,
  `README.md.lnk`, `App.lnk`, `pwlog.lnk`, `credentials.lnk`) und die Jump Lists das
  Öffnen dieser Dateien.

  *Wo.* Asservat `Client.dd`, Hive `NTUSER.DAT`; LNK unter `lnk/`, Jump Lists unter
  `jumplists/`.

  *Bedeutung.* RecentDocs, LNK und Jump Lists belegen unabhängig, dass der Benutzer die
  Schaddateien öffnete. LNK-Dateien bleiben auch nach Löschung des Ziels erhalten.

  *Korrelation.* Ergänzt die Shellbags (F-WIN-02) um die Ebene der geöffneten Dateien.
  `pwlog.txt`/`credentials.txt` → F-WIN-06.

  #quelle("out/A3_recentdocs.txt, out/lnk.csv, out/jumplists_AutomaticDestinations.csv")
]

#finding("F-WIN-05", "Ausführung des Python-Schadcodes (UserAssist, BAM, Timeline, Prefetch)")[
  #befehl("rip.pl -r hives/NTUSER.DAT -p userassist > out/A1_userassist.txt
rip.pl -r hives/SYSTEM -p bam > out/B5_bam.txt
sqlite3 timeline/ActitiesCache_vogel.db \"SELECT datetime(LastModifiedTime,'unixepoch'), AppId FROM Activity ORDER BY LastModifiedTime DESC;\"
ls prefetch/PYTHON.EXE-*.pf")

  #beweis("bam.png", [BAM: Ausführung von `python.exe` (pythoncore-3.14) unter der SID von vogel, 05.07. 00:22:55Z], aktiv: true)

  *Was.* Die Ausführung von `python.exe` ist mehrfach unabhängig belegt, mit steigender
  Beweiskraft. *UserAssist* (ROT13-kodiert, leicht manipulierbar) führt
  `C:\Users\User\AppData\Local\Python\pythoncore-3.14-64\python.exe` auf. Das *BAM*
  (systemseitig, höhere Beweiskraft) verzeichnet denselben Pfad unter der SID von vogel
  mit Zeitstempel *05.07.2026 00:22:55Z* (lokal 08:22 UTC+8). Die *Windows Timeline*
  (Profil L.vogel) dokumentiert `python.exe` am 04.07. 23:51–23:52Z und 05.07.
  00:22Z. Zwei Prefetch-Dateien (`PYTHON.EXE-1E65C076.pf`, `PYTHON.EXE-F2A4EC14.pf`)
  bestätigen zwei Ausführungskontexte.

  *Wo.* Asservat `Client.dd`: Hive `NTUSER.DAT` (userassist), `SYSTEM` (bam),
  `timeline/act_cache_vogel.txt`, `prefetch/PYTHON.EXE-*.pf`.

  *Bedeutung.* Die zwei Prefetch-Kontexte sind mit F-WIN-03 konsistent: `main.py` startet
  per `subprocess.Popen` einen zweiten python-Prozess für `login_check.py`. Die Ausführung
  fällt in das Zeitfenster 04.–05.07.2026, das mit der Vorbereitungs-/Akquisephase des
  Teams überlappt; eine frühere „natürliche“ Ausführung durch die simulierte Zielperson
  ist artefaktseitig nicht belegt und wird nicht behauptet.

  *Korrelation.* Bestätigt die Wirksamkeit des Schadcodes (F-WIN-03) und führt zum
  Ergebnis in `pwlog.txt` (F-WIN-06).

  #quelle("out/A1_userassist.txt, out/B5_bam.txt, timeline/act_cache_vogel.txt, prefetch/PYTHON.EXE-1E65C076.pf, prefetch/PYTHON.EXE-F2A4EC14.pf")
]

#hinweis[Methodische Anmerkung: PECmd verweigert unter Linux die Prefetch-Dekompression („Non-Windows platforms not supported"). Da die Ausführung dreifach (UserAssist, BAM, Timeline) belegt ist, wurde auf eine Windows-VM verzichtet.]

== Erbeutete und exponierte Zugangsdaten

#finding("F-WIN-06", "Erbeutete und exponierte Zugangsdaten (pwlog.txt, credentials.txt, Firefox)")[
  #befehl("cat /mnt/client/Users/User/Desktop/App/pwlog.txt
cat /mnt/client/Users/User/Desktop/credentials.txt
sha256sum /mnt/client/Users/User/Desktop/credentials.txt
python3 firefox_decrypt.py firefox/   # bzw. Auswertung von logins.json")

  #beweis("pwlog.png", [`pwlog.txt`: zweifach erfasste Windows-Anmeldedaten (vogel/admin)], aktiv: true)
  #beweis("credentials.png", [`credentials.txt`: im Klartext exponierte Serverzugangsdaten für 192.168.50.20.], aktiv: true)

  *Was.* Drei Zugangsdaten-Artefakte. *(1)* Die vom Schadcode erzeugte Datei
  `~\Desktop\App\pwlog.txt` enthält zweifach `Benutzername: vogel / Passwort: admin` —
  konsistent mit dem Anhänge-Modus („a“) aus F-WIN-03 (zwei Eingabevorgänge). *(2)* Die
  vom Benutzer angelegte Datei `credentials.txt` (Desktop, SHA-256 `09846850...b26d9`)
  enthält im Klartext `m.vogel:Werkzeug\#2026 through 192.168.50.20`. *(3)* Das
  Firefox-Profil enthält in `logins.json` einen gespeicherten Datensatz für
  `ssh://192.168.50.20` (`encryptedUsername`/`encryptedPassword` gefüllt, `timesUsed:1`).

  *Wo.* Asservat `Client.dd`: `Desktop\App\pwlog.txt`, `Desktop\credentials.txt`,
  `firefox/logins.json` + `firefox/key4.db`.

  *Bedeutung.* Zwei verschiedene Datensätze: erbeutete *Windows-Anmeldedaten*
  (vogel/admin) und *Serverzugangsdaten* für 192.168.50.20 (m.vogel/Werkzeug\#2026). Die
  Serverzugangsdaten lagen doppelt fahrlässig offen — als Klartextdatei und im Browser.
  Dies erklärt den Serverzugriff und begründet zentrale Empfehlungen.

  *Korrelation.* Fundort `pwlog.txt` = hartkodierter Pfad aus F-WIN-03. Die
  Serverzugangsdaten sind Grundlage des SSH-Zugriffs.

  #quelle("Desktop\\App\\pwlog.txt, Desktop\\credentials.txt, firefox/logins.json, firefox/key4.db")
]

== Sensible Konstruktionsunterlagen und Dokumentmetadaten

#finding("F-WIN-07", "Sensible Projektdaten und Metadaten (ExifTool)")[
  #befehl("exiftool project/Projekte/cad_notes.docx.odt
exiftool project/Projekte/Stueckliste.ods
exiftool -r project/Projekte/ > out/exif_projekte.txt")

  #beweis("exif.png", [ExifTool-Metadaten eines Projektdokuments: Generator, Zeitstempel, Bearbeitungszyklen], aktiv: true)

  *Was.* Unter `...\Documents\Projekte` liegen vier Arbeitsdokumente, die den
  vertraulichen Arbeitskontext belegen: `cad_notes.docx.odt`, `new_notes.odt`,
  `Besprechungsnotizen.odt`, `Stueckliste.ods` (Stückliste). Interne Konstruktions- und
  Projektunterlagen der Bayern Präzision GmbH. Alle mit `Generator`
  `LibreOffice/26.2.4.2 Windows_X86_64`, identische Projekt-ID. Auffällig: Divergenz
  zwischen internen Dokument-Zeitstempeln (UTC) und NTFS-Zeitstempeln; bei
  `cad_notes.docx.odt` liegt die interne „Creation-date“ (03.07. 03:47) nach der
  NTFS-Änderungszeit (02.07. 19:47).

  *Wo.* Asservat `Client.dd`: `...\Documents\Projekte\*`, extrahiert nach
  `project/Projekte/`.

  *Bedeutung.* Die Dokumente belegen die Art der sensiblen Daten (CAD/Konstruktion,
  Stücklisten) und damit den Gegenstand des Angriffsinteresses. Die Zeitstempel-Divergenz
  erklärt sich durch die Zeitzone UTC+8 (interne Metadaten in UTC, NTFS lokal); ohne
  deren Berücksichtigung entstünde der falsche Eindruck einer Manipulation. Ein
  clientseitiges Timestomping ist nicht belegt.

  *Korrelation.* Exfiltration/Löschung der Konstruktionsdaten erfolgte serverseitig. Die clientseitigen Dokumente belegen Wert und Sensibilität der
  Zielobjekte.

  #quelle("project/Projekte/cad_notes.docx.odt, project/Projekte/Stueckliste.ods, project/Projekte/Besprechungsnotizen.odt, project/Projekte/new_notes.odt")
]

== Prüfung auf Persistenz (Befund durch Abwesenheit)

#finding("F-WIN-08", "Kein Persistenzmechanismus vorhanden")[
  #befehl("rip.pl -r hives/NTUSER.DAT -p run > out/F-WIN-01_run_hkcu.txt
rip.pl -r hives/SOFTWARE -p run > out/F-WIN-01_run_hklm.txt
grep -rilE \"python|main.py|App|SecurityUpdater\" /mnt/client/Windows/System32/Tasks/")

  #beweis("runkeys.png", [Run-Keys HKCU/HKLM: ausschließlich legitime Einträge, kein `SecurityUpdater`], aktiv: true)

  *Was.* Geprüft wurde ein Neustart-übergreifender Persistenzmechanismus. Die *Run-Keys*
  enthalten nur legitime Einträge: HKCU — OneDrive, Mozilla-Firefox; HKLM —
  SecurityHealth, VMware User Process. Ein Eintrag `SecurityUpdater` ist *nicht*
  vorhanden; `RunOnce`/`RunServices`/StartupApproved sind leer bzw. nicht vorhanden. Die
  *Scheduled Tasks* enthalten nur legitime Aufgaben (MicrosoftEdgeUpdate, OneDrive,
  npcapwatchdog); die `grep`-Suche nach `python`/`main.py`/`App`/`SecurityUpdater` im
  XML-Inhalt blieb ergebnislos.

  *Wo.* Asservat `Client.dd`: Hives `NTUSER.DAT`/`SOFTWARE` (run),
  `C:\Windows\System32\Tasks\*`.

  *Bedeutung.* Der vermutete Persistenzeintrag `SecurityUpdater` existiert nicht. Der
  Credential-Stealer besaß keinen Autostart-Mechanismus; die Ausführung erfolgte durch
  manuellen Doppelklick auf `main.py`. Für das Angriffsziel war Persistenz nicht
  erforderlich. Der Befund ist ein Ergebnis der Untersuchung, kein Fehlen von Spuren.

  *Korrelation.* Konsistent mit dem Schadcode (F-WIN-03, kein Autostart) und der
  einmaligen Interaktion (F-WIN-02/F-WIN-04).

  #quelle("out/F-WIN-01_run_hkcu.txt, out/F-WIN-01_run_hklm.txt, tasks/")
]

== Weitere geprüfte Artefaktklassen (Vollständigkeitsnachweis)

Zur vollständigen Abdeckung des Windows-Artefaktkatalogs wurden folgende Klassen
zusätzlich geprüft. Auch negative Befunde werden dokumentiert.

#finding("F-WIN-09", "Datenträger-, USB- und Netzwerkartefakte")[
  #befehl("rip.pl -r hives/SYSTEM -p usbstor > out/B3_usbstor.txt
rip.pl -r hives/SYSTEM -p mountdev > out/B4_mounteddevices.txt
rip.pl -r hives/SOFTWARE -p networklist > out/C3_networklist.txt")

  #beweis("network.png", [`NetworkList`: kabelgebundenes Profil „Network“ (localdomain), kein WLAN, kein VPN], aktiv: true)

  *Was.* `USBStor` ist *nicht vorhanden* (`ControlSet001\Enum\USBStor not found`); kein
  USB-Massenspeicher angeschlossen. `MountedDevices` weist neben C: nur ein
  VMware-SATA-CD-Laufwerk (D:) und ein Floppy-Gerät (A:) aus. Der Pfad „Forensik-USB“ ist
  laut Shellbags ein *VMware Shared Folder* (`vmware-host\Shared Folders\Forensik-USB`).
  Die `NetworkList` zeigt ein kabelgebundenes Profil „Network“ (localdomain).

  *Wo.* Asservat `Client.dd`: Hive `SYSTEM` (usbstor, mountdev), `SOFTWARE` (networklist).

  *Bedeutung.* Der Datenabfluss erfolgte nicht über einen USB-Datenträger am Client. Der
  „Forensik-USB“ ist ein Werkzeug des Ermittlungsteams (Ermittlerartefakt).

  *Korrelation.* Exfiltration (SSH/scp) serverseitig. Ergänzt F-WIN-12.

  #quelle("out/B3_usbstor.txt, out/B4_mounteddevices.txt, out/C3_networklist.txt, out/E1_shellbags.txt")
]

#finding("F-WIN-10", "Papierkorb und Volume Shadow Copies")[
  #befehl("ls -la \"/mnt/client/\\$Recycle.Bin/\"S-1-5-21-*-1000/
vshadowinfo -o $((673792*512)) Client.dd")

  #beweis("vss.png", [`vshadowinfo`: „No Volume Shadow Snapshots found"; Papierkorb ohne \$I/\$R-Dateien], aktiv: true)

  *Was.* Der Papierkorb des Benutzers (SID …-1000) enthielt nur `desktop.ini`, keine
  gelöschten Benutzerdateien (`$I`/`$R`). `vshadowinfo` (libvshadow) ergab „No Volume
  Shadow Snapshots found“ — keine Schattenkopien vorhanden.

  *Wo.* Asservat `Client.dd`: `$Recycle.Bin\S-1-5-21-...-1000`, `vshadowinfo`.

  *Bedeutung.* Clientseitig wurden keine Dateien über den Papierkorb gelöscht; die
  Löschung der CAD-Daten erfolgte serverseitig. Mangels Schattenkopien keine
  clientseitige Rekonstruktion früherer Versionen möglich.

  *Korrelation.* Löschung/Wiederherstellung der CAD-Daten.
]

#finding("F-WIN-11", "Event Logs, SRUM, Notifications, Thumbnails")[
  #befehl("EvtxeCmd.exe -d evtx --csv out --csvf events.csv
esedbexport -t srum/srum srum.export/../SRUDB.dat
sqlite3 notifications/wpndatabase.db \"SELECT ArrivalTime, Payload FROM Notification;\"")


  *Was.* *Event Logs* (`winevt\Logs`) mit EvtxeCmd zu `events.csv` aufbereitet. Eine
  Prozess-Auditierung (Event-ID 4688) war nicht aktiviert (Standardkonfiguration Windows
  10); ein Log-Clearing (Event-ID 1102) wurde nicht festgestellt. *SRUM* (`SRUDB.dat`)
  mit esedbexport extrahiert; die Netzwerknutzungstabelle enthielt keinen `python`-Eintrag,
  die SRU-Logs datieren auf den 05.07. (Ermittleraktivität). *Notifications*
  (`wpndatabase.db`) enthielten eine Thunderbird-Benachrichtigung mit Bezug auf den
  Mailserver 192.168.50.30. *Thumbnails* (`thumbcache_*.db`) vorhanden; tiefergehende
  Auswertung unter Linux nicht möglich, unterblieb.

  *Wo.* Asservat `Client.dd`: `out/events.csv`, `srum/srum.export/`,
  `notifications/wpndatabase.db`.

  *Bedeutung.* Fehlende 4688-Auditierung ist kein Verschleierungsindiz (Ausführung über
  F-WIN-05 belegt). Ausbleiben von 1102 zeigt: keine Sicherheits-Logs gelöscht. Fehlende
  python-Netzwerknutzung im SRUM ist konsistent — der Stealer speicherte lokal, die
  Exfiltration erfolgte serverseitig.

  *Korrelation.* Die Thunderbird-Notification (192.168.50.30) stützt F-WIN-01.

  #quelle("out/events.csv, srum/srum.export/, notifications/wpndatabase.db")
]

== Abgrenzung der Ermittlertätigkeit

#finding("F-WIN-12", "Zuordnung der Ermittlerartefakte (05.07.2026)")[
  #befehl("rip.pl -r hives/SOFTWARE -p uninstall > out/C4_uninstall.txt
ls prefetch/ | grep -iE \"FTK|WIRESHARK|VELOCIRAPTOR|WINPMEM|NPCAP\"")


  *Was.* Zahlreiche Artefakte dokumentieren die forensische Akquise und sind vom Angriff
  zu trennen. UserAssist/BAM führen `FTK Imager.exe`, `Wireshark-4.6.6-x64.exe`,
  `npcap-1.88.exe`, `NPFInstall.exe`, `WinPmem` (03.–05.07.). Die Prefetch-Sammlung
  enthält entsprechend `FTK IMAGER.EXE-*.pf`, `WIRESHARK-4.6.6-X64.EXE-*.pf`,
  `VELOCIRAPTOR-V0.77.1-WINDOWS-*.pf`, `WINPMEM_MINI_X64_RC2.EXE-*.pf`. Timeline (L.vogel)
  und RecentDocs enthalten `live_response.txt` und die Velociraptor-Exportarchive; der
  Firefox-Verlauf verzeichnet am 03.07. „FTK imager download“ und am 05.07. Zugriffe auf
  `localhost:8889`.

  *Wo.* Asservat `Client.dd`: NTUSER, SYSTEM, SOFTWARE, Firefox `places.sqlite`,
  `prefetch/`, `timeline/`.

  *Bedeutung.* Die konsequente Trennung ist Voraussetzung für die Nachvollziehbarkeit der
  Kausalität. Ohne sie bestünde die Gefahr, Ermittlerhandlungen als Angriffsaktivität zu
  werten.

  *Korrelation.* Betrifft die zeitliche Einordnung aller Findings mit Zeitstempeln vom
  04.–05.07.2026 (insb. F-WIN-05).

  #quelle("out/A1_userassist.txt, out/B5_bam.txt, out/C4_uninstall.txt, firefox/places.sqlite, prefetch/")
]

== Zusammenfassung des Windows-Befunds

Die Auswertung belegt clientseitig eine geschlossene Angriffskette: Eine Phishing-Mail
(F-WIN-01) lieferte das Schadpaket `App.zip` (F-WIN-02), dessen Code ein gefälschtes
Windows-Anmeldefenster darstellt und Zugangsdaten in `pwlog.txt` schreibt (F-WIN-03).
Zugriff und Ausführung sind über RecentDocs, LNK, Shellbags, UserAssist, BAM und die
Windows Timeline mehrfach belegt (F-WIN-04, F-WIN-05). Erbeutet wurden die
Windows-Anmeldedaten (vogel/admin); die Serverzugangsdaten (m.vogel/Werkzeug\#2026 für
192.168.50.20) lagen zusätzlich als Klartextdatei und im Browser offen (F-WIN-06). Die
sensiblen Konstruktionsunterlagen (F-WIN-07) belegen den Wert der Zielobjekte. Ein
Persistenzmechanismus wurde nicht etabliert (F-WIN-08); clientseitige Anti-Forensik
(Log-Clearing, Timestomping, Papierkorb-Löschung) wurde nicht festgestellt (F-WIN-07,
F-WIN-10, F-WIN-11). Die Ermittlerartefakte wurden konsequent abgegrenzt (F-WIN-12).
Sämtliche Zeitangaben sind unter Berücksichtigung der Systemzeitzone UTC+8 zu
interpretieren.

Die weitere Verwendung der erbeuteten Serverzugangsdaten (SSH-Zugriff, Exfiltration und
Löschung der CAD-Daten) ist Gegenstand der Netzwerk-, Linux- und Datenträgerforensik.
