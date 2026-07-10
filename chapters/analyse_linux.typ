#import "../style/style.typ": hinweis, thead,
= Server und RAM Analyse (Mitglied 2)
== Linux Server (Ubuntu) - Linux OS & RAM Analyse
=== Übersicht der untersuchten Asservate

*Systeminformationen*:

Nach der Erstellung eines forensischen Images des kompromittierten Servers mit Ubuntu 24.04 LTS (Noble Numbat) wurden die folgenden Asservate mittels `Live-Response-Analyse` für die Analyse bereitgestellt. Ziel war dabei, die auf dem Server gespeicherten Projektdaten zu sichern und die Aktivitäten des Angreifers zu rekonstruieren. Die Analyse erfolgte sowohl auf dem Datenträgerabbild (Server.dd) als auch auf dem RAM-Dump (server_ram.lime).
#table(
  columns: (auto, auto),
  thead[Asservat][Beschreibung],
  [01], [Server Disk Image (Server.dd)],
  [03], [RAM Dump (server_ram.lime)],
)
#hinweis[Übersicht der untersuchten Asservate. Die Nummerierung entspricht der Gliederung.]

== Befundkatalog (Beweis-IDs)

Zur eindeutigen Referenzierung zwischen den Analyseteilen des Projekts wird jedem zentralen Befund eine Beweis-ID nach dem Schema `B{Nummer}-{Asservat}-SQ-{Jahr}` zugewiesen. Die Nummerierung beginnt pro Asservat bei 001. Die Beweis-IDs werden im nachfolgenden Fließtext an den jeweils relevanten Stellen ergänzend zu den Abbildungsverweisen aufgeführt.

=== Asservat 01 – Server.dd

#table(
  columns: (auto, auto, auto),
  thead[Beweis-ID][Kurzbezeichnung][Quelle/Nachweis],
  [B003-SERVER-SQ-2026], [Zwei erfolgreiche SSH-Logins m.vogel von 192.168.50.10], [`auth.log`],
  [B004-SERVER-SQ-2026], [Löschbefehle (`rm -rf`) auf Projekte und Kunden], [`~/.bash_history`],
  [B005-SERVER-SQ-2026], [Timestomping-Befehle (`touch -t 202401010000`)], [`~/.bash_history`],
  [B006-SERVER-SQ-2026], [Inkonsistente Verzeichniszeitstempel nach dem Mounten], [`ls -lah`],
  [B007-SERVER-SQ-2026], [Anomale Dateigröße kunden_2026.csv (17 Bytes)], [`ls -lahR`],
  [B008-SERVER-SQ-2026], [ctime widerlegt gefälschte Access-/Modify-Zeit], [`stat`],
)
#hinweis[Befundkatalog Asservat 01 (Server.dd). Die Kennungen B001-SERVER-SQ-2026 und B002-SERVER-SQ-2026 wurden nicht vergeben, da die zugrunde liegenden Schritte (Partitionserkennung, Auflösung des LVM-Namenskonflikts) methodische Vorbereitungshandlungen der Untersuchung darstellen und keine Beweismittel im eigentlichen Sinne sind. Sie sind in Abschnitt „Analyse des Datenträgerabbildes" als Methodik dokumentiert.]

=== Asservat 03 – server_ram.lime

#table(
  columns: (auto, auto, auto),
  thead[Beweis-ID][Kurzbezeichnung][Quelle/Nachweis],
  [B001-RAM-SQ-2026], [Kernel-Identifikation (Linux 6.8.0-31-generic, Ubuntu 24.04 LTS)], [`banners.Banners`],
  [B002-RAM-SQ-2026], [Eigenständig erzeugte ISF-Symboltabelle verifiziert], [`dwarf2json`, `linux.pslist.PsList`],
  [B003-RAM-SQ-2026], [pslist (231) vs. psscan (505) – kein Hinweis auf Prozessverschleierung], [`linux.pslist`, `linux.psscan`],
  [B004-RAM-SQ-2026], [Zwei unabhängige Sitzungsbäume identifiziert (svc/lokal, m.vogel/SSH)], [psscan-PPID-Analyse],
  [B005-RAM-SQ-2026], [Bash-History Session svc: Testdaten-Vorbereitung + Live-Response-Sicherung], [`linux.bash.Bash` (PID 1461)],
  [B006-RAM-SQ-2026], [Bash-History Session m.vogel: deckungsgleich mit Datenträgerbefund], [`linux.bash.Bash` (PID 1884)],
  [B007-RAM-SQ-2026], [Ursprung/Inhalt von kunden_2026.csv geklärt], [Abgleich mit B007/B008-SERVER-SQ-2026],
  [B008-RAM-SQ-2026], [Aktive TCP-Verbindung 192.168.50.20:22 <-> 192.168.50.10:47922], [`linux.sockstat.Sockstat`],
  [B009-RAM-SQ-2026], [malfind-Treffer PID 852 als bekannter False Positive eingeordnet], [`linux.malfind.Malfind`],
  [B010-RAM-SQ-2026], [Erzeugung eines Netzwerkmitschnitts (/tmp/silent_quarry.pcap) durch Session svc nachgewiesen], [`linux.bash.Bash`, `auth.log`],
)
#hinweis[Befundkatalog Asservat 03 (server_ram.lime).]

== Verwendete Werkzeuge
=== Datenträger- und RAM-Analyse
#table(
  columns: (auto, auto),
  thead[Datenträgeranalyse][RAM-Analyse],
  [SIFT Workstation als allgemeine Analyseumgebung für beide Analysen], [Volatility3],
  [The Sleuth Kit (TSK) zum Teil (mmls, fsstat)], [dwarf2json],
  [Linux Standard-Tools (Grep, Find, ...)], [Ubuntu-ddebs-Repository(Kernel-Debug-Symbole)],
  [LVM-Tools (losetup, vgimportclone, vgchange)], [Kernel Symboltabellen im ISF-Format (Linux 6.8.0-31-generic)],
  [SHA256-Hashing], [],
)
#hinweis[Für die RAM-Analyse musste zusätzlich zu Volatility3 eine kernelspezifische ISF-Symboltabelle selbst erzeugt werden (siehe Abschnitt „Vorbereitung: Erstellung der Symboltabelle" weiter unten), da für den vorgefundenen Kernel keine vorgefertigte Tabelle verfügbar war.]

 == Hashwerte der Asservate

 Vor Beginn der eigentlichen Analyse wurde die Integrität beider Asservate mittels SHA256-Prüfsummenbildung auf der SIFT Workstation verifiziert:

#table(
  columns: (auto, auto, auto),
  thead[Asservat][Datei][SHA256-Hashwert],
  [01], [Server.dd], [4960728cc6b74f7d687266cabbc5ea8d649990f54f2a2480a53418d117282b50],
  [03], [server_ram.lime], [f0d1a5045e849bafd42545b3083af698b1462b555715b1a92805e9209d565dfd],
)
#hinweis[SHA256-Hashwerte der untersuchten Asservate (Befehl: `sha256sum Server.dd server_ram.lime`).]

== Analyse des Datenträgerabbildes (Server.dd)
=== Mounten des Datenträgerabbildes

Bevor das Datenträgerabbild eingebunden werden konnte, musste zunächst die Partitionsstruktur identifiziert werden, da eine einfache Einbindung mittels `mount -o loop` aufgrund der zugrunde liegenden GPT- und LVM-Struktur nicht möglich war. Die tatsächlich durchgeführten Schritte werden in den folgenden Unterabschnitten im Detail dokumentiert.

=== Identifikation der Partitionsstruktur

Ein erster Blick mit dem Befehl `file` auf das Abbild lieferte eine irreführende Aussage:

#figure(
  image("../res/Images_M2/file_server_dd.png", width: 90%),
  caption: [Ausgabe von `file Server.dd`],
) <fig-file-server>

Wie in @fig-file-server ersichtlich, erkennt das Tool lediglich den sogenannten Protective MBR, der bei GPT-partitionierten Datenträgern aus Kompatibilitätsgründen im ersten Sektor abgelegt wird, und interpretiert diesen fälschlicherweise als klassischen MBR-Bootsektor ("DOS/MBR boot sector, extended partition table (last)").

Die tatsächliche Partitionsstruktur wurde daraufhin mit `fdisk -l` und `mmls` verifiziert:

#figure(
  image("../res/Images_M2/fdisk_server_dd.png", width: 90%),
  caption: [Ausgabe von `fdisk -l Server.dd`],
) <fig-fdisk>

#figure(
  image("../res/Images_M2/mmls_server_dd.png", width: 90%),
  caption: [Ausgabe von `mmls Server.dd`],
) <fig-mmls>

Beide Werkzeuge bestätigten ein GPT-Disklabel (Disk-ID 94C7ED46-875A-4F68-8558-9B0230AC8BE8) mit drei Partitionen auf einer 20-GiB-Platte:

#table(
  columns: (auto, auto, auto, auto),
  thead[Partition][Größe][Typ][Vermutete Funktion],
  [Server.dd1], [1 MiB], [BIOS boot], [GPT-Bootloader-Partition],
  [Server.dd2], [1.8 GiB], [Linux filesystem], [/boot],
  [Server.dd3], [18.2 GiB], [Linux filesystem (LVM PV)], [Root-Dateisystem via LVM],
)
#hinweis[Partitionsübersicht laut @fig-fdisk und @fig-mmls.]

Ein Versuch, das Dateisystem der dritten Partition direkt mit `fsstat -o 3719168 Server.dd` auszulesen, schlug fehl, da es sich hierbei nicht um ein klassisches Dateisystem, sondern um ein LVM Physical Volume (PV) handelt, das TSK ohne vorherige LVM-Aktivierung nicht interpretieren kann:

#figure(
  image("../res/Images_M2/fsstat_not.png", width: 90%),
  caption: [Fehlgeschlagener Versuch, das Dateisystem der LVM-Partition direkt mit `fsstat` auszulesen ("Cannot determine file system type")],
) <fig-fsstat>

=== Einbinden des Abbildes über Loop-Device und LVM

Um dennoch auf die Partitionen zugreifen zu können, wurde das Abbild mit `losetup` als Loop-Device eingebunden. Die Option `-P` sorgt dafür, dass für jede erkannte Partition ein eigenes Device (z. B. `/dev/loop10p1`) angelegt wird:

#figure(
  image("../res/Images_M2/losetup_Server_dd.png", width: 90%),
  caption: [Einbinden des Abbildes als Loop-Device mittels `losetup -Pf --show Server.dd`],
) <fig-losetup>

Mit `lsblk` und `blkid` wurden anschließend die einzelnen Partitionen sowie deren Dateisystemtypen bestätigt:

#figure(
  image("../res/Images_M2/lsblk_blkid_Server_dd.png", width: 90%),
  caption: [Partitionsübersicht und Dateisystemtypen mittels `lsblk /dev/loop10` und `blkid /dev/loop10*`],
) <fig-lsblk>

#table(
  columns: (auto, auto, auto),
  thead[Device][Größe][Typ],
  [loop10p1], [1M], [(keine FS-Kennung, BIOS boot)],
  [loop10p2], [1.8G], [ext4],
  [loop10p3], [18.2G], [LVM2_member],
)
#hinweis[Zusammenfassung von @fig-lsblk.]

Da `loop10p3` als LVM2-Mitglied identifiziert wurde, war ein direktes Mounten nicht möglich. Ein einfacher `vgscan`/`vgchange` hätte zudem zu einem Namenskonflikt geführt, da sowohl die SIFT Workstation selbst als auch das untersuchte Serverabbild eine Volume Group mit dem Ubuntu-Standardnamen `ubuntu-vg` verwenden. Um diesen Konflikt zu vermeiden, wurde die Volume Group des Abbildes mit `vgimportclone` importiert. Dieses Tool vergibt neue UUIDs und benennt die importierte Volume Group automatisch um (hier zu `ubuntu-vg1`), sodass keine Kollision mit der produktiven Volume Group der SIFT Workstation entsteht:

#figure(
  image("../res/Images_M2/Namenskonflikt_gelöst.png", width: 90%),
  caption: [Import der Volume Group des Serverabbildes via `vgimportclone`, um den Namenskonflikt mit der Volume Group der SIFT Workstation zu vermeiden],
) <fig-vgimport>

Da das logische Volume `ubuntu-vg1/ubuntu-lv` nach dem Import zunächst inaktiv war (siehe @fig-vgimport), musste es noch manuell aktiviert werden:

#figure(
  image("../res/Images_M2/Aktivierung_Asservat.png", width: 90%),
  caption: [Aktivierung der importierten Volume Group mittels `vgchange -ay ubuntu-vg1`],
) <fig-vgchange>

Erst danach konnte das logische Volume schreibgeschützt eingebunden werden:

#figure(
  image("../res/Images_M2/mount_asservat.png", width: 90%),
  caption: [Erfolgreiches read-only-Mounten des Root-Dateisystems unter `/mnt/serverimage` mittels `mount -o ro /dev/ubuntu-vg1/ubuntu-lv /mnt/serverimage`],
) <fig-mount>

Die tatsächliche Vorgehensweise zum Einbinden des Abbildes weicht damit von einem einfachen `mount -o loop,ro` ab, da die GPT-Partitionierung sowie die LVM-Struktur des Servers eine mehrstufige Vorbereitung (Loop-Device, LVM-Import, Volume-Aktivierung) erforderten.

= Findings

== Auswertung von Logdateien und Bash-History (`Server.dd`)

Nach dem erfolgreichen Mounten des Abbildes (@fig-mount) wurden zunächst die Authentifizierungsprotokolle des Systems ausgewertet, um Hinweise auf einen initialen oder wiederholten Zugriff auf das System zu finden.

=== Auswertung von auth.log

Die Filterung des Logs nach erfolgreichen Anmeldungen ergab zwei Treffer für denselben Benutzer auf dem Host `projektserver`:

#figure(
  image("../res/Images_M2/Beweis1_server_dd.png", width: 90%),
  caption: [Erfolgreiche SSH-Anmeldungen des Benutzers m.vogel, ausgelesen aus `/var/log/auth.log` (Befehl: `grep "Accepted" auth.log`)],
) <fig-auth>

#table(
  columns: (auto, auto, auto, auto),
  thead[Zeitstempel (UTC)][Benutzer][Quell-IP][Port],
  [2026-07-05T00:24:41], [m.vogel], [192.168.50.10], [47922],
  [2026-07-05T00:26:53], [m.vogel], [192.168.50.10], [52306],
)
#hinweis[Zusammenfassung von @fig-auth (B003-SERVER-SQ-2026).]

Beide Anmeldungen erfolgten per Passwort-Authentifizierung innerhalb eines Zeitfensters von rund zwei Minuten und stammen von derselben Quell-IP-Adresse. Dies deutet auf zwei aufeinanderfolgende interaktive SSH-Sitzungen desselben Akteurs hin. Die IP-Adresse 192.168.50.10 sollte als zentraler IOC in die teamübergreifende Korrelation einfließen.

=== Auswertung der Bash-History

Die vollständige Bash-History des Benutzers m.vogel wurde zunächst im Ganzen gesichtet:

#figure(
  image("../res/Images_M2/Beweis2_bash_history_server_dd.png", width: 90%),
  caption: [Vollständige Bash-History des Benutzers m.vogel (`cat ~/.bash_history`)],
) <fig-history-full>

Auffällig sind darin insbesondere zwei Befehlsgruppen, die gezielt gefiltert wurden. Zunächst die Löschbefehle:

#figure(
  image("../res/Images_M2/Beweis4_Löschbefehle_server_dd.png", width: 90%),
  caption: [Gefilterte Löschbefehle aus der Bash-History (`cat ~/.bash_history | grep rm`)],
) <fig-rm>

sowie die anschließenden Befehle zur Manipulation der Zeitstempel:

#figure(
  image("../res/Images_M2/Beweis3_Projektdaten_server_dd.png", width: 90%),
  caption: [Gefilterte `touch`-Befehle auf die Projektdaten (`cat ~/.bash_history | grep touch`)],
) <fig-touch>

#table(
  columns: (auto, auto),
  thead[Befehl][Interpretation],
  [`rm -rf /srv/projekte/Projekte/*`], [Vollständige Löschung des Inhalts von Projekte],
  [`rm -rf /srv/projekte/Kunden/*`], [Vollständige Löschung des Inhalts von Kunden],
  [`touch -t 202401010000 /srv/projekte/Verwaltung/`], [Zurücksetzen der Zeitstempel des Verzeichnisses Verwaltung auf den 01.01.2024],
  [`touch -t 202401010000 /srv/projekte/Kunden/kunden_2026.csv`], [Zurücksetzen der Zeitstempel der Datei kunden_2026.csv auf den 01.01.2024],
)
#hinweis[Zusammenfassung der Befehle aus @fig-rm (B004-SERVER-SQ-2026) und @fig-touch (B005-SERVER-SQ-2026).]

Die gefilterten Ausgaben zeigen, dass diese Befehle mehrfach vorkommen (siehe @fig-rm), was auf zwei separate Sitzungen schließen lässt – passend zu den beiden in @fig-auth dokumentierten SSH-Logins.

== Nachweis von Timestomping im Projektverzeichnis

Die Live-Sichtung von `/srv/projekte` zeigte auf den ersten Blick unauffällige, aber inkonsistente Zeitstempel:

#figure(
  image("../res/Images_M2/Beweis5_Zustand_Projektverzeichnis_server_dd.png", width: 70%),
  caption: [Zustand des Projektverzeichnisses nach dem Mounten (`ls -lah /mnt/serverimage/srv/projekte`)],
) <fig-state>

Während Kunden und Projekte plausible, aktuelle Änderungsdaten im Juli 2026 aufweisen, erscheint Verwaltung auf den ersten Blick unauffällig alt (Januar 2024) – genau das Ergebnis, das der zuvor gefundene Befehl `touch -t 202401010000` (@fig-touch) bewirken sollte. (B006-SERVER-SQ-2026)

Eine rekursive Auflistung offenbarte zusätzlich die manipulierte Datei innerhalb von Kunden:

#figure(
  image("../res/Images_M2/Beweis7_manipulierte_daten_server_dd.png", width: 90%),
  caption: [Rekursive Verzeichnisauflistung mit sichtbarer Platzhalterdatei kunden_2026.csv (`ls -lahR /mnt/serverimage/srv/projekte`)],
) <fig-recursive>

Die Datei `kunden_2026.csv` fiel durch ihre geringe Größe von lediglich 17 Bytes auf (@fig-recursive) – für eine Kundendatenbank ein deutlich zu geringer Wert. (B007-SERVER-SQ-2026)

Um die durch `touch` gesetzten Zeitstempel zu verifizieren, wurde die Datei mit `stat` im Detail untersucht:

#figure(
  image("../res/Images_M2/Beweis6_Timestomping_kundencsv_server_dd.png", width: 90%),
  caption: [Detaillierte Zeitstempel der Datei kunden_2026.csv (`stat kunden_2026.csv`) – Access- und Modify-Zeit wurden manipuliert, Change- und Birth-Zeit belegen die tatsächliche Aktivität],
) <fig-stat>

Dieser Befund (@fig-stat) ist forensisch von zentraler Bedeutung: `touch -t` kann Access- (atime) und Modify-Zeitstempel (mtime) frei setzen, hat jedoch keinen Einfluss auf die Change-Zeit (ctime), da diese vom Dateisystem automatisch bei jeder Metadatenänderung aktualisiert wird – auch durch `touch` selbst. Die ctime von kunden_2026.csv (05.07.2026, 00:28:13 UTC) liegt exakt im Zeitfenster kurz nach der zweiten in @fig-auth dokumentierten SSH-Sitzung (00:26:53 UTC). Die Birth-Zeit (crtime, 04.07.2026, 21:08:04 UTC) entspricht zudem exakt dem in @fig-state angezeigten Änderungsdatum des Kunden-Verzeichnisses. (B008-SERVER-SQ-2026)

*Diese Birth-Zeit korreliert, wie die nachfolgende RAM-Analyse zeigt (siehe Abschnitt „Rekonstruktion der Bash-History aus dem Speicher" im RAM-Kapitel weiter unten), mit der Anlage der Datei durch das Systemkonto svc im Rahmen der Testdatenvorbereitung (B007-RAM-SQ-2026).*

Die Analyse belegt damit einen Versuch der Anti-Forensik (Timestomping): Es wurde gezielt versucht, die Spuren des Zugriffs durch Zurücksetzen von Zeitstempeln zu verschleiern – die vom Dateisystem unabhängig geführte ctime entlarvt diesen Versuch jedoch eindeutig.

== Schlussfolgerung Datenträgeranalyse

Die Analyse des Linux-Servers liefert klare Hinweise auf einen gezielten Zugriff mit anschließender Löschung und Verschleierung von Projektdaten:

+ *Zugriff per SSH*: Am 05.07.2026 erfolgten innerhalb von rund zwei Minuten zwei erfolgreiche SSH-Anmeldungen des Benutzers m.vogel von der IP-Adresse 192.168.50.10 auf dem Host projektserver (@fig-auth, B003-SERVER-SQ-2026).

+ *Löschung sensibler Verzeichnisse*: Die Bash-History belegt die Ausführung von `rm -rf` auf die Verzeichnisse Projekte und Kunden (@fig-rm, B004-SERVER-SQ-2026).

+ *Anti-forensische Zeitstempel-Manipulation*: Sowohl das Verzeichnis Verwaltung als auch die Datei kunden_2026.csv wurden mittels `touch -t 202401010000` (@fig-touch, B005-SERVER-SQ-2026) auf ein Datum vor dem eigentlichen Vorfall zurückdatiert.

+ *Aufdeckung des Timestomping durch die ctime*: Die `stat`-Analyse (@fig-stat, B008-SERVER-SQ-2026) zeigt, dass die Change-Zeit von kunden_2026.csv exakt in das Zeitfenster der zweiten SSH-Sitzung fällt und die Manipulation damit zweifelsfrei nachweist.

== RAM-Analyse (server_ram.lime) <sec-ram>

Ergänzend zur Post-Mortem-Analyse des Datenträgerabbildes wurde der gesicherte Arbeitsspeicher-Dump (server_ram.lime, Asservat 03) mit Volatility3 untersucht.

=== Vorbereitung: Erstellung der Symboltabelle <sec-symtab>

Da Volatility3 für Linux-Systeme keine generischen Profile verwendet, sondern eine exakt zum untersuchten Kernel passende ISF-Symboltabelle benötigt, wurde zunächst der Kernel-Banner aus dem Speicherabbild extrahiert:

`python3 vol.py -f server_ram.lime banners.Banners`

#figure(
  image("../res/Images_M2/banner_server_ram.png", width: 90%),
  caption: [Extraktion des Kernel-Banners aus dem Speicherabbild mittels `banners.Banners`],
) <fig-banner>

Die Auswertung (@fig-banner) ergab den Kernel *Linux 6.8.0-31-generic*, den initialen Release-Kernel von Ubuntu 24.04 LTS ("Noble Numbat"). (B001-RAM-SQ-2026) Da für diesen Build keine vorgefertigte Symboltabelle vorlag, wurde sie eigenständig erzeugt:

+ Einbindung des Ubuntu-ddebs-Repositories (`ddebs.ubuntu.com`, Suite `noble`) sowie Installation von `ubuntu-dbgsym-keyring`.
+ Installation des zugehörigen Debug-Symbol-Pakets `linux-image-6.8.0-31-generic-dbgsym`, welches die vollständige Debug-Version des Kernels (`vmlinux`) unter `/usr/lib/debug/boot/` bereitstellt.
+ Konvertierung der DWARF-Debug-Informationen in das von Volatility3 benötigte ISF-Format mittels `dwarf2json`:

`./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-6.8.0-31-generic > 6.8.0-31-generic.json`

+ Ablage der erzeugten Symboltabelle im Symbols-Verzeichnis von Volatility3.

#figure(
  image("../res/Images_M2/pslist_server_ram.png", width: 90%),
  caption: [Erfolgreicher Testlauf von `linux.pslist.PsList` nach Einbindung der selbst erstellten Symboltabelle],
) <fig-pslist-ram>

Wie in @fig-pslist-ram ersichtlich, konnte nach Einbindung der Symboltabelle eine vollständige, korrekt aufgelöste Prozessliste (PID, PPID, UID/GID, Erstellzeitpunkt) erzeugt werden. (B002-RAM-SQ-2026)

=== Live-Prozessanalyse: Abgleich von pslist und psscan

Um auszuschließen, dass Prozesse gezielt aus der vom Kernel geführten Prozessliste entfernt wurden (*Unlinking*, eine gängige Rootkit-Technik), wurden die Ergebnisse von `linux.pslist.PsList` und `linux.psscan.PsScan` verglichen. Während `pslist` die verkettete Task-Liste des Kernels abläuft, durchsucht `psscan` den physischen Speicher unabhängig davon nach gültigen `task_struct`-Signaturen.

#table(
  columns: (auto, auto),
  thead[Plugin][Anzahl Einträge],
  [`linux.pslist.PsList`], [231],
  [`linux.psscan.PsScan`], [505],
)
#hinweis[Vergleich der Ergebnisanzahl beider Plugins (B003-RAM-SQ-2026).]

Ein Abgleich der PIDs ergab 15 Einträge, die ausschließlich in `psscan` auftauchten (Status `EXIT_DEAD`). Die Detailanalyse zeigte, dass es sich fast ausschließlich um die für Ubuntu typische Prozesskette zur Erzeugung der "Message of the Day" handelt (`run-parts`, `landscape-sysinfo`, `update-motd-fsck` sowie zugehörige `cat`-/`grep`-/`find`-Hilfsprozesse), die bei jedem interaktiven Login automatisch ausgelöst wird – kein Hinweis auf Prozessverschleierung, sondern auf Slab-Speicher-Wiederverwendung.

Zwei Einträge waren jedoch für die Sitzungszuordnung direkt relevant:

#table(
  columns: (auto, auto, auto, auto),
  thead[PID][Prozess][PPID][Status],
  [1758], [sudo], [1461], [EXIT_DEAD],
  [1904], [sshd], [1343], [EXIT_DEAD],
)
#hinweis[Forensisch relevante Einträge aus dem `psscan`-Ergebnis.]

Die Analyse der vollständigen Prozessliste ergab zwei voneinander unabhängige Prozessbäume:

#table(
  columns: (auto, auto, auto, auto, auto),
  thead[Wurzel-Prozess][PID-Kette][Benutzer][Kanal][Rolle],
  [`login`], [1267 → 1461 (bash)], [svc (UID 1000)], [tty1, lokal], [Beweissicherung],
  [`sshd`], [1343 → 1770/1883 → 1884 (bash)], [m.vogel (UID 1001)], [pts, SSH], [Untersuchter Vorfall],
)
#hinweis[Zuordnung der beiden im RAM identifizierten, unabhängigen Sitzungen (B004-RAM-SQ-2026).]

=== Rekonstruktion der Bash-History aus dem Speicher <sec-bash-ram>

Mittels `linux.bash.Bash` wurde der im Speicher der Shell-Prozesse vorgehaltene History-Puffer rekonstruiert:

`python3 vol.py -f server_ram.lime linux.bash.Bash`

Zu beachten ist eine Einschränkung des Plugins: Der ausgegebene `CommandTime`-Wert bezieht sich auf den Zeitpunkt der zuletzt referenzierten History-Struktur, nicht auf den individuellen Ausführungszeitpunkt jedes einzelnen Befehls. Für die zeitliche Einordnung bleibt daher das `auth.log` maßgeblich; die rekonstruierte History dient primär dem Nachweis, *dass* bestimmte Befehle ausgeführt wurden.

*Session svc (PID 1461, lokale Konsole):*
Die History zeigt die Vorbereitung der Testumgebung sowie die anschließende Live-Response-Sicherung (Auszug, gekürzt):

`sudo mkdir -p /srv/projekte/{Kunden,Projekte,Verwaltung}`

`sudo chown -R m.vogel:m.vogel /srv/projekte`

`echo 'Kundenliste 2026' | sudo tee /srv/projekte/Kunden/kunden_2026.csv`

`echo 'CNC-Steurung v2 - VERTRAULICH' | sudo tee /srv/projekte/Projekte/cnc_steurung_v2.step`

`echo 'Antriebsachse Spezifikationen' | sudo tee /srv/projekte/Projekte/antriebsachse.step`

 `[...]`

`sudo tcpdump -i ens37 -w /tmp/silent_quarry.pcap`

`sudo insmod lime-$(uname -r).ko "path=/tmp/server_ram.lime format=lime"`

#hinweis[Auszug aus der rekonstruierten Bash-History der Session svc (`linux.bash.Bash`, PID 1461) (B005-RAM-SQ-2026).]

Der Inhalt der angelegten Datei kunden_2026.csv ("Kundenliste 2026", 17 Bytes inkl. Zeilenumbruch) deckt sich exakt mit der bei der Post-Mortem-Analyse ermittelten Dateigröße (@fig-stat) und belegt damit, dass diese Datei nicht inhaltlich manipuliert, sondern ausschließlich in ihren Zeitstempeln gefälscht wurde (B007-RAM-SQ-2026, Abgleich mit B007-SERVER-SQ-2026/B008-SERVER-SQ-2026). Die beiden weiteren angelegten Testdateien (`cnc_steurung_v2.step`, `antriebsachse.step`) konnten im Datenträgerabbild nicht mehr aufgefunden werden, was ihre vollständige Löschung durch den nachfolgend beschriebenen `rm -rf`-Befehl bestätigt.

*Session m.vogel (PID 1884, SSH):* Die rekonstruierte History bestätigt unabhängig von der bereits auf Datenträgerebene gesicherten `~/.bash_history` (@fig-history-full) dieselben Befehle:

`rm -rf /srv/projekte/Projekte/*`

`rm -rf /srv/projekte/Kunden/*`

`touch -t 202401010000 /srv/projekte/Verwaltung/`

`rm -rf /srv/projekte/Projekte/*`

`touch -t 202401010000 /srv/projekte/Kunden/kunden_2026.csv`

`stat /srv/projekte/Kunden/kunden_2026.csv`

#hinweis[Auszug aus der rekonstruierten Bash-History der Session m.vogel (`linux.bash.Bash`, PID 1884), inhaltlich deckungsgleich mit der Datenträgeranalyse (B006-RAM-SQ-2026).]

Die übereinstimmende Rekonstruktion derselben Befehle aus zwei unabhängigen Quellen – Datenträgerabbild und flüchtigem Speicher – bestätigt die Integrität und Zuverlässigkeit dieses Beweismittels.

=== Offene Netzwerkverbindungen (sockstat)

Die Auswertung mittels `linux.sockstat.Sockstat` bestätigte zum Sicherungszeitpunkt eine bestehende TCP-Verbindung auf Port 22:

sshd 1770  AF_INET6 TCP  192.168.50.20:22  <->  192.168.50.10:47922  ESTABLISHED

sshd 1883  AF_INET6 TCP  192.168.50.20:22  <->  192.168.50.10:47922  ESTABLISHED

#hinweis[Ausschnitt aus dem `sockstat`-Ergebnis; beide sshd-Prozesse referenzieren denselben Socket-Deskriptor (B008-RAM-SQ-2026).]

Sichtbar ist ausschließlich die erste der beiden dokumentierten SSH-Sitzungen (Quellport 47922); die zweite Sitzung (Port 52306) war zum Sicherungszeitpunkt bereits beendet, was sich mit dem zuvor unter `psscan` festgestellten `EXIT_DEAD`-Status des zugehörigen Prozesses (PID 1904) deckt. Die lokale Adresse 192.168.50.20 entspricht der statischen Konfiguration des Interfaces `ens37`, auf dem parallel der Netzwerkmitschnitt `silent_quarry.pcap` durch die Session svc erstellt wurde. (B010-RAM-SQ-2026)

=== Suche nach Code-Injektion (malfind)

Mittels `linux.malfind.Malfind` wurde der Speicher nach anonymen Speicherbereichen mit gleichzeitigen Schreib- und Ausführungsrechten durchsucht. Es ergab sich ein einzelner Treffer:

PID 852, unattended-upgr, Anonymous Mapping, Schutz: rwx

#hinweis[Einziger Treffer von `linux.malfind.Malfind` (B009-RAM-SQ-2026).]

Der Prozess `unattended-upgrades` ist ein regulärer Ubuntu-Systemdienst zur automatischen Installation von Sicherheitsupdates. Da dieser in Python implementiert ist und für die APT-Anbindung intern auf `ctypes`/`libffi` zurückgreift, erzeugt er zur Laufzeit kleine ausführbare Trampolin-Stubs in anonymen RWX-Speicherseiten – ein bekannter, gutartiger False-Positive von `malfind` bei Python-basierten Linux-Prozessen. Der zugehörige Hexdump zeigt keinerlei Anzeichen für Shellcode, sondern einen regulären Funktionsprolog. Es ergaben sich somit keine Hinweise auf Code-Injektion oder Malware-Persistenz im Arbeitsspeicher.

== Schlussfolgerung RAM-Analyse

+ *Bestätigung der Datenträgerbefunde*: Die aus dem Arbeitsspeicher rekonstruierte Bash-History der Session m.vogel deckt sich inhaltlich vollständig mit der auf dem Datenträger gesicherten `~/.bash_history` – eine unabhängige zweite Beweisquelle für dieselben Befehle (B006-RAM-SQ-2026).

+ *Zwei unabhängige Sitzungen identifiziert*: Neben der SSH-Sitzung des Benutzers m.vogel wurde eine zweite, unabhängige lokale Sitzung des Systemkontos svc identifiziert, die nachweislich der Vorbereitung der Testumgebung sowie der Live-Response-Beweissicherung diente und in keinem inhaltlichen Zusammenhang mit dem Vorfall steht (B004-RAM-SQ-2026, B005-RAM-SQ-2026).

+ *Herkunft der Kundendatei geklärt*: Der Testinhalt der Datei kunden_2026.csv ("Kundenliste 2026", 17 Bytes) deckt sich exakt mit der Post-Mortem-Dateigröße und belegt, dass ausschließlich die Zeitstempel, nicht der Inhalt, durch den Angreifer manipuliert wurden (B007-RAM-SQ-2026).

+ *Keine Hinweise auf Prozessverschleierung oder Code-Injektion*: Der Abgleich von `pslist`/`psscan` sowie `malfind` ergaben keine Hinweise auf Rootkit-Techniken oder injizierten Schadcode (B003-RAM-SQ-2026, B009-RAM-SQ-2026).

+ *Netzwerkmitschnitt bestätigt und zeitlich korreliert*: Die in der Bash-History dokumentierte Erzeugung des Netzwerkmitschnitts `/tmp/silent_quarry.pcap` (Interface ens37) durch die Session svc wurde durch die eigenständige Analyse der Netzwerkforensik (Mitglied 1) bestätigt. Die dort rekonstruierten SSH-Verbindungszeitpunkte liegen jeweils rund sechs Sekunden vor den in `auth.log` protokollierten Anmeldungen – konsistent mit dem TCP-Verbindungsaufbau, der der Authentifizierung vorausgeht (B010-RAM-SQ-2026, siehe Gesamtfazit).

== Gesamtfazit (M2 – Server und RAM)

Die kombinierte Analyse von Datenträger- und Arbeitsspeicherabbild des Linux-Servers zeichnet ein konsistentes, durch zwei unabhängige Quellen bestätigtes Bild: Der Benutzer *m.vogel* griff am *05.07.2026* zweimal per *SSH* von *192.168.50.10* auf das System zu *(B003-SERVER-SQ-2026)* und löschte anschließend gezielt die Verzeichnisse *Projekte* und *Kunden* *(B004-SERVER-SQ-2026, B006-RAM-SQ-2026)*, wobei die Zeitstempel manipuliert wurden, um die Aktivität zu verschleiern *(B005-SERVER-SQ-2026, B008-SERVER-SQ-2026)*. Die davon unabhängige, zeitlich überlappende Konsolensitzung des Systemkontos *svc (B004-RAM-SQ-2026, B005-RAM-SQ-2026)* steht im Zusammenhang mit der Vorbereitung des Testszenarios sowie der ordnungsgemäßen forensischen Sicherung *(Netzwerkmitschnitt, RAM-Dump)* und ist klar vom eigentlichen Vorfall abzugrenzen.

Der in der Bash-History der Session svc dokumentierte Netzwerkmitschnitt *`silent_quarry.pcap` (B010-RAM-SQ-2026)* konnte durch die Netzwerkforensik (Mitglied 1) bestätigt und ausgewertet werden. Deren Analyse ordnet dem SSH-Zugriff auf den Server eine vorgelagerte RDP-Sitzung auf dem Client zu *(192.168.50.10 → 192.168.50.30, 00:23:42 UTC)*, in deren Rahmen die Zugangsdaten des Benutzers "vogel" im Klartext über das RDP-Cookie-Feld erfasst wurden.

Dies erklärt, wie der Angreifer überhaupt in den Besitz der für den anschließenden SSH-Zugriff verwendeten Zugangsdaten gelangte, und schließt die auf Asservat 01/03 beschränkte Beweiskette lückenlos an die vorgelagerte Angriffsphase auf dem Client an.

Die im Netzwerkmitschnitt rekonstruierten SSH-Verbindungszeitpunkte *(00:24:35 UTC und 00:26:47 UTC)* liegen jeweils rund sechs Sekunden vor den in `auth.log` protokollierten Anmeldezeitpunkten *(00:24:41 UTC und 00:26:53 UTC, B003-SERVER-SQ-2026)* – erwartungsgemäß, da der TCP-Verbindungsaufbau der Authentifizierung vorausgeht. 

Die Netzwerkforensik ordnet der ersten, *233 Sekunden* dauernden Sitzung anhand des Datenvolumens (*~1 MB*, mit einem erkennbaren Übertragungsschub in der Sitzungsmitte) die eigentliche Dateizugriffs- und Exfiltrationsaktivität zu, während die zweite, nur sechs Sekunden dauernde Sitzung als kurze Wiederverbindung mit geringem Datenvolumen eingeordnet wird. Dies deckt sich mit den serverseitigen Befunden: 

Die erste Sitzung umfasst gemäß *Bash-History* die Löschung von *Projekte* und *Kunden* sowie die Zeitstempel-Manipulation von *Verwaltung*, während die zweite Sitzung im Wesentlichen die erneute Löschung von *Projekte* sowie die Verifikation der Timestomping-Manipulation an *kunden_2026.csv* mittels `touch`/`stat` umfasst *(B004-RAM-SQ-2026, B006-RAM-SQ-2026)*
– die zweite Sitzung stellt somit überwiegend Aufräum- und Verschleierungsaktivität dar, keinen eigenständigen zweiten Exfiltrationskanal.

Die Netzwerkforensik bestätigt zudem die Isolation der Laborumgebung für den auf Interface `ens37` erfassten Verkehr (kein DNS-Verkehr, keine externen IP-Adressen). Das servereigene, mit dem Internet verbundene zweite Interface (`ens33`, vgl. Netplan-Konfiguration) betrifft ausschließlich die Vorbereitungs- und Sicherungsaktivität der Session svc und liegt außerhalb des von Mitglied 1 erfassten Zeitfensters.