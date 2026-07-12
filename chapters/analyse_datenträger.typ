#import "../style/style.typ": hinweis, thead,
= Datenträger-/Dateiforensik (Mitglied 4)

== Asservate
#table(
  columns: 4,
  [*Asservat*], [*Datei*], [*Beschreibung*], [*SHA-256*],
  [01], [`Server.dd`], [Datenträgerabbild des Ubuntu-Projektservers], [`4960728cc6b74f7d687266cabbc5ea8d649990f54f2a2480a53418d117282b50`],
)

== Identifizierte Dateisysteme
#table(
  columns: 4,
  [*Image*], [*Offset*], [*Dateisystem / Struktur*], [*Bedeutung*],
  [`Server.dd`], [`4096`], [ext4], [`/boot`-Partition],
  [`Server.dd`], [`3721216`], [ext4 über LVM], [relevantes Server-Dateisystem],
)

== Zentrale Befunde
#table(
  columns: 4,
  [*Finding*], [*Artefakt*], [*Tool*], [*Bewertung*],
  [Projektverzeichnis gefunden], [`/srv/projekte`], [`fls`], [Kunden, Projekte und Verwaltung vorhanden],
  [Kundendatei extrahiert], [`kunden_2026.csv`], [`icat`], [Datei regulär vorhanden und lesbar],
  [Gelöschte STEP-Inhalte], [`cnc_steuerung_v2.step`,  `antriebsachse.step`], [  `  blkls`, `strings`], [Inhalte als Datenreste im unallocated space gefunden],
  [Timestomping], [`Verwaltung`, `kunden_2026.csv`], [`istat`, `mactime`], [auffällige Zeitstempel],
)

=== Finding 1: Projektverzeichnis auf Server.dd
Mit `fls` wurde das Verzeichnis `/srv/projekte` auf dem Server-Dateisystem identifiziert. Darin befanden sich die Unterverzeichnisse `Kunden`, `Projekte` und `Verwaltung`.

#figure(
  image("../res/Images_M4/srv_projekte.jpg", width: 90%),
  caption: [`fls`-Ausgabe zur Verzeichnisstruktur unter `/srv/projekte`.]
)

Die weitere Untersuchung zeigte, dass das Verzeichnis `Kunden` weiterhin die Datei `kunden_2026.csv` enthielt. Die Verzeichnisse `Projekte` und `Verwaltung` waren dagegen leer.

#figure(
  image("../res/Images_M4/kunden_folder.png", width: 90%),
  caption: [`fls`-Ausgabe zum Verzeichnis `Kunden` mit der Datei `kunden_2026.csv`.]
)

#figure(
  image("../res/Images_M4/projekte_folder.png", width: 90%),
  caption: [`fls`-Ausgabe zum Verzeichnis `Projekte`. Es wurden keine regulären Einträge ausgegeben.]
)

#figure(
  image("../res/Images_M4/verwaltung_folder.png", width: 90%),
  caption: [`fls -d`-Prüfung im Verzeichnis `Verwaltung`. Es wurden keine gelöschten Einträge ausgegeben.]
)

Dieser Befund ist forensisch relevant, da die leeren Projektverzeichnisse mit dem Szenario einer gezielten Löschung von Projektdaten übereinstimmen. Für sich allein beweist dieser Befund noch nicht den Täter, korreliert jedoch mit den Server-Artefakten wie Bash-History, auth.log und den gefundenen Datenresten im unallocated space.

=== Finding 2: Gelöschte STEP-Artefakte
Unter Projektverzeichnis Kunden wurde eine Datei `kunden_2026.csv` gefunden. Die Inode-Nummer `263241` wurde mit `fls` identifiziert und anschließend mit `icat` zur Extraktion der Datei verwendet.

Verwendeter Befehl:
`icat -o 3721216 Server.dd 263241 > kunden_2026.csv`

#figure(
  image("../res/Images_M4/kunden_2026_csv.jpg", width: 90%),
  caption: [Extraktion und Prüfung der Datei `kunden_2026.csv` mit `icat`, `file` und `cat`.]
)

Der Inhalt der extrahierten Datei lautete `Kundenliste 2026`.

Die erwarteten STEP-Artefakte `cnc_steuerung_v2.step` und `antriebsachse.step` waren nicht mehr als reguläre Dateien im Dateisystem sichtbar. Eine Prüfung mit `fls -d` zeigte keine gelöschten Inodes für diese Dateien. Dadurch war eine direkte Wiederherstellung mit `icat` nicht möglich.

Da die Inhalte der Dateien sehr klein waren und jeweils nur aus einer kurzen Textzeile bestanden, wurde zusätzlich der unallocated space mit `blkls` und `strings` durchsucht. Dabei wurden die Zeichenketten `CNC-Steuerung v2 - VERTRAULICH` und `Antriebsachse Spezifikationen` gefunden.

#figure(
  image("../res/Images_M4/cnc_deleted.jpg", width: 90%),
  caption: [Nachweis der Zeichenkette `CNC-Steuerung v2 - VERTRAULICH` im unallocated space.]
)

#figure(
  image("../res/Images_M4/antrieb_deleted.jpg", width: 90%),
  caption: [Nachweis der Zeichenkette `Antriebsachse Spezifikationen` im unallocated space.]
)

Damit konnten die Inhalte der gelöschten Projektartefakte zumindest als Datenreste rekonstruiert werden. Eine vollständige Wiederherstellung inklusive ursprünglicher Metadaten war jedoch nicht möglich, da keine gelöschten Inodes sichtbar waren.

Als weiterer Wiederherstellungsversuch wurde File Carving mit `foremost` durchgeführt.

Verwendeter Befehl:

`foremost -t all -i Server.dd -o output`

`foremost` extrahierte mehrere Dateien aus dem Abbild. Die Ergebnisse wurden anschließend mit `file` und Keyword-Suchen überprüft. Es konnte jedoch keine eindeutig projektbezogene Datei vollständig rekonstruiert werden.

#figure(
  image("../res/Images_M4/foremost_audit.png", width: 90%),
  caption: [`foremost`-Audit der File-Carving-Ergebnisse auf `Server.dd`.]
)

Die fehlende vollständige Rekonstruktion ist plausibel, da die betroffenen STEP-Artefakte nur kurze textbasierte Inhalte enthielten und keine verwertbare Dateisignatur für File Carving aufwiesen.

=== Finding 3: Zeitstempelmanipulation
Um Zeitstempelmanipulation zu prüfen, wurden die Metadaten relevanter Dateien und Verzeichnisse mit `istat` untersucht. Besonders relevant waren die Datei `kunden_2026.csv` und das Verzeichnis `Verwaltung`.

#figure(
  image("../res/Images_M4/kunden_istat.png", width: 90%),
  caption: [Metadaten der Datei `kunden_2026.csv` mit `istat`.]
)

#figure(
  image("../res/Images_M4/verwaltung_istat.png", width: 90%),
  caption: [Metadaten des Verzeichnisses `Verwaltung` mit `istat`.]
)

#figure(
  image("../res/Images_M4/projekte_istat.png", width: 90%),
  caption: [Metadaten des Verzeichnisses `Projekte` mit `istat`.]
)

Bei `kunden_2026.csv` war auffällig, dass der Accessed- und File-Modified-Zeitstempel auf `2024-01-01 00:00:00 UTC` gesetzt waren, während die Datei laut File-Created-Zeitstempel erst am `2026-07-04` erstellt wurde. Zusätzlich wurde der Inode am `2026-07-05` verändert. Diese Kombination ist zeitlich widersprüchlich und spricht für eine nachträgliche Manipulation der Zeitstempel.

Auch beim Verzeichnis `Verwaltung` war ein auffälliger File-Modified-Zeitstempel auf `2024-01-01 00:00:00 UTC` sichtbar, obwohl das Verzeichnis laut File-Created-Zeitstempel am `2026-06-30` erstellt wurde und der Inode am `2026-07-04` verändert wurde. Auch dieser Befund spricht für Timestomping als Anti-Forensik-Maßnahme.

== Beitrag zur Angriffstimeline
#table(
  columns: 3,
  [*Zeitpunkt (UTC)*], [*Ereignis*], [*Quelle*],

  [`2024-01-01 00:00:00`], [Manipulierter Accessed-/Modified-Zeitstempel von `kunden_2026.csv`], [`istat`, `mactime`],
  [`2024-01-01 00:00:00`], [Manipulierter Modified-Zeitstempel von `/srv/projekte/Verwaltung`], [`istat`, `mactime`],
  [`2026-07-04 21:08:31`], [Metadatenänderungen an `/srv/projekte`, `Kunden` und `Verwaltung`], [`istat`, `mactime`],
  [`2026-07-05 00:27:45`], [Metadaten-/Modified-Änderung am Verzeichnis `/srv/projekte/Projekte`], [`istat`, `mactime`],
  [`2026-07-05 00:28:13`], [Metadatenänderung an `/srv/projekte/Kunden/kunden_2026.csv`], [`istat`, `mactime`],
)

#figure(
  image("../res/Images_M4/server_timeline.png", width: 90%),
  caption: [`mactime`-Timeline zu `/srv/projekte`.]
)

Die Einträge vom `2024-01-01` stellen keine tatsächlichen Ereigniszeitpunkte des Angriffs dar, sondern manipulierte Zeitstempelwerte. Die späteren Inode-Modified-Zeitpunkte im Jahr 2026 zeigen, dass die Metadaten nachträglich verändert wurden.

== Fazit
Zusammenfassend zeigte die Datenträger- und Dateiforensik, dass auf `Server.dd` das Verzeichnis `/srv/projekte` vorhanden war. Das Unterverzeichnis `Kunden` enthielt weiterhin die Datei `kunden_2026.csv`, während `Projekte` und `Verwaltung` leer waren. Die Datei `kunden_2026.csv` konnte mit `icat` vollständig extrahiert werden.

Die erwarteten STEP-Artefakte `cnc_steuerung_v2.step` und `antriebsachse.step` waren nicht mehr als reguläre Dateien sichtbar und konnten nicht über `icat` wiederhergestellt werden, da keine gelöschten Inodes vorhanden waren. Über `blkls` und `strings` konnten jedoch die Inhalte `CNC-Steuerung v2 - VERTRAULICH` und `Antriebsachse Spezifikationen` im unallocated space nachgewiesen werden. Damit sind Datenreste gelöschter Projektdaten auf dem Server belegt.

Zusätzlich zeigten `istat` und `mactime` auffällige Zeitstempel, insbesondere beim Verzeichnis `Verwaltung` und bei `kunden_2026.csv`. Die Kombination aus alten Modified-Zeitstempeln und späteren Created- bzw. Inode-Modified-Zeitpunkten unterstützt die Annahme von Zeitstempelmanipulation als Anti-Forensik-Maßnahme.

Der Schwerpunkt der Datenträger- und Dateiforensik lag damit auf `Server.dd`. Die zentralen Hinweise auf Löschung und Verschleierung befinden sich im Server-Dateisystem und korrelieren mit den Linux-OS- sowie Netzwerkbefunden der anderen Teilbereiche.