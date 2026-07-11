#import "../style/style.typ": thead, hinweis

= Grundlagen und Rahmen

Dieses Kapitel legt die methodische und technische Grundlage der Untersuchung
offen. Es beschreibt das zugrunde gelegte Vorgehensmodell (S-A-P), die
forensischen Grundsätze, die eingesetzten Werkzeuge und die Infrastruktur des
Laborfalls. Damit ist für Dritte nachvollziehbar, *nach welchen Regeln* und *mit
welchen Mitteln* die nachfolgenden Befunde erhoben wurden.

== Motivation

Digitale Forensik gewinnt mit der zunehmenden Digitalisierung von
Geschäftsprozessen stetig an Bedeutung. Ein erheblicher Teil aller
sicherheitsrelevanten Vorfälle in Unternehmen beginnt mit menschlichem Faktor —
insbesondere mit Phishing als initialem Zugriffsvektor — und mündet in
Datenabfluss durch kompromittierte Zugangsdaten. Der hier untersuchte Fall
„Operation Silent Quarry" bildet genau dieses Muster ab: Social Engineering,
Diebstahl von Zugangsdaten, Lateral Movement und Exfiltration mit anschließender
Spurenverwischung. Ziel der digitalen Forensik ist es, einen solchen Vorfall
*gerichtsverwertbar*, *nachvollziehbar* und *reproduzierbar* aufzuklären: Es soll
belegt werden, *was* geschah, *wann*, *von wo aus*, *durch welche Handlungen* und
mit welchem Schaden — ohne die Beweismittel dabei zu verändern.

== Methodik

=== Das S-A-P-Modell

Die Untersuchung folgt durchgängig dem in der Vorlesung vermittelten
*S-A-P-Modell* mit drei Phasen:

#table(
  columns: (auto, 1fr),
  thead[Phase][Inhalt],
  [*Secure*],
  [Identifizierung der Beweismittel, Erfassung, forensisch sichere
   Datensicherung (Imaging), lückenlose Protokollierung und Wahrung der
   Chain of Custody.],
  [*Analyse*],
  [Systematische Untersuchung der gesicherten Daten, objektive Bewertung der
   Befunde, Korrelation der Artefakte über mehrere Quellen hinweg.],
  [*Present*],
  [Zielgruppenorientierte Aufbereitung der Ergebnisse: technische
   Beweisführung für Fachpublikum, verständliche Zusammenfassung für die
   Geschäftsführung. Das vorliegende Gutachten ist das Produkt dieser Phase.],
)

Die Phasen sind nicht streng linear: *Rücksprünge* sind zulässig und häufig nötig
(etwa wenn ein Analysebefund eine erneute gezielte Sicherung erfordert). Das
Gutachten selbst liegt vollständig in der Present-Phase, referenziert aber
transparent die Ergebnisse der beiden vorgelagerten Phasen.

=== Live-Response vs. Post-Mortem

Bei der Sicherung wird zwischen zwei Ansätzen unterschieden:

- *Live-Response* erfasst den Zustand eines *laufenden* Systems. Sie ist
  notwendig für *flüchtige* Daten (Arbeitsspeicher, laufende Prozesse, offene
  Netzwerkverbindungen, ARP-Cache, angemeldete Benutzer), die bei einem Neustart
  unwiederbringlich verloren gehen. Nachteil: Jede Aktion verändert das System
  minimal und ist selbst ein Ermittlerartefakt.
- *Post-Mortem* untersucht ein *ausgeschaltetes* System anhand eines
  forensischen Datenträgerabbilds. Sie ist reproduzierbar und
  veränderungsfrei, erfasst aber keine flüchtigen Zustandsdaten.

Die Reihenfolge der Sicherung richtet sich nach der *Order of Volatility*: Es
wird von den flüchtigsten zu den beständigsten Daten hin gesichert, damit keine
volatilen Spuren durch die Sicherung beständigerer Quellen verloren gehen.

#table(
  columns: (auto, 1fr, auto),
  thead[Rang][Datenkategorie (flüchtig → beständig)][Sicherung im Fall],
  [1], [CPU-Register, Cache], [nicht separat gesichert],
  [2], [Arbeitsspeicher (RAM), laufende Prozesse, Verbindungen],
       [WinPmem (Client), LiME (Server)],
  [3], [Netzwerkzustand (ARP, Routing, offene Ports)],
       [Live-Response, tcpdump],
  [4], [Laufende Prozesse / temporäre Dateien], [Velociraptor],
  [5], [Datenträger (Dateisystem, gelöschte Daten)], [Qemu.img.exe → `.dd`],
  [6], [Archiv-/Backup-Medien], [nicht relevant],
)

Im vorliegenden Fall wurde diese Reihenfolge eingehalten: Zuerst der laufende
Netzwerkmitschnitt und die RAM-Sicherung, danach die Live-Response, zuletzt die
Post-Mortem-Datenträgerabbilder.

=== Verwendete Werkzeuge

Alle eingesetzten Werkzeuge entstammen dem in der Vorlesung behandelten Kanon.
Sie sind nachfolgend nach Forensikbereich und S-A-P-Phase gegliedert.

#table(
  columns: (auto, 1fr, auto),
  thead[Werkzeug][Zweck][Phase],

  table.cell(colspan: 3, fill: luma(238))[*Sicherung (Secure)*],
  [Qemu.img.exe], [Forensisch sichere Datenträgerabbilder (`.dd`) inkl. Hashwertbildung], [Secure],
  [WinPmem], [RAM-Sicherung des Windows-Clients], [Secure],
  [LiME], [RAM-Sicherung des Linux-Servers (Kernel-Modul)], [Secure],
  [tcpdump], [Netzwerkmitschnitt auf dem Serversegment (`silent_quarry.pcap`)], [Secure],
  [Velociraptor], [Strukturierte Live-Response-Sammlung (Endpoint-Artefakte)], [Secure],

  table.cell(colspan: 3, fill: luma(238))[*Netzwerkforensik*],
  [Wireshark], [Protokoll- und Stream-Analyse des PCAP (RDP, SSH, TLS)], [Analyse],
  [NetworkMiner], [Session-/Credential-Extraktion, Zertifikat- und Datei-Carving aus PCAP], [Analyse],

  table.cell(colspan: 3, fill: luma(238))[*Datenträger- und Dateiforensik*],
  [The Sleuth Kit (`mmls`, `fls`, `icat`, `istat`, `blkls`, `mactime`)],
    [Partitions-, Datei- und Metadatenanalyse, Extraktion, Timelining], [Analyse],
  [Autopsy], [Grafisches Frontend für TSK, Dateisystem-Browsing], [Analyse],
  [foremost / scalpel], [File Carving aus dem Unallocated Space], [Analyse],
  [Rifiuti2], [Analyse des Windows-Papierkorbs (`$I`/`$R`)], [Analyse],

  table.cell(colspan: 3, fill: luma(238))[*Betriebssystem- und Anwendungsforensik (Windows)*],
  [RegRipper (`rip.pl`)], [Auswertung der Registry-Hives (Plugins)], [Analyse],
  [EvtxECmd], [Aufbereitung der Windows Event Logs (`.evtx` → CSV)], [Analyse],
  [libesedb (`esedbexport`)], [Extraktion der SRUM-Datenbank], [Analyse],
  [libvshadow (`vshadowinfo`)], [Prüfung der Volume Shadow Copies], [Analyse],
  [ExifTool], [Metadaten von Dokumenten und Dateien], [Analyse],
  [SQLite Browser], [Auswertung von Browser-/App-Datenbanken (places, wpndatabase)], [Analyse],

  table.cell(colspan: 3, fill: luma(238))[*Speicherforensik (RAM)*],
  [Volatility], [Analyse der RAM-Abbilder (pslist, pstree, netscan, cmdline, filescan, malfind)], [Analyse],

  table.cell(colspan: 3, fill: luma(238))[*Timeline / Korrelation*],
  [plaso / log2timeline], [Erzeugung einer Super-Timeline aus mehreren Quellen], [Analyse],
)

=== Forensische Grundsätze

Der Untersuchung liegen die folgenden, in der Vorlesung vermittelten Grundsätze
zugrunde. Ihre Einhaltung ist Voraussetzung für die Verwertbarkeit der Befunde.

- *Keine Veränderung am Original.* Originaldatenträger werden ausschließlich
  schreibgeschützt behandelt (Write-Blocker bzw. read-only-Mount). Sämtliche
  Analysen erfolgen auf Arbeitskopien.
- *Integritätssicherung durch Hashwerte.* Für jedes Asservat wird bei der
  Sicherung ein kryptografischer Hash (SHA-256, ergänzend SHA-1) gebildet und vor
  jeder Analyse erneut verifiziert. Eine Abweichung würde eine Manipulation
  anzeigen.
- *Chain of Custody.* Jeder Besitz- und Bearbeitungsübergang eines Asservats wird
  lückenlos protokolliert (wer, wann, was, womit).
- *Nachvollziehbarkeit und Reproduzierbarkeit (E3).* Jeder Befund nennt den exakt
  ausgeführten Befehl, den zugehörigen Beweis, dessen Interpretation und die
  Quelldatei. Ein Dritter muss den Befund mit denselben Mitteln unabhängig
  reproduzieren können.
- *Vier-Augen-Prinzip / Objektivität.* Befunde werden wertneutral erhoben; auch
  ergebnislose oder entlastende Prüfungen werden dokumentiert.
- *Abgrenzung der Ermittlerartefakte.* Spuren, die erst durch die Sicherung
  selbst entstehen (Qemu.img.exe, WinPmem, Velociraptor, Npcap), werden klar von den
  Täterspuren getrennt ausgewiesen.
- *Locard'sches Prinzip.* Jede Interaktion hinterlässt Spuren — Grundlage dafür,
  dass die Täterhandlungen über mehrere unabhängige Artefaktquellen belegbar sind.

== Infrastruktur

=== Netzwerkübersicht

Der Fall wurde in einer isolierten VMware-Laborumgebung mit vier virtuellen
Maschinen nachgestellt. Alle Systeme befinden sich im internen, vom Internet
getrennten Netzsegment `net-quarry` (192.168.50.0/24). Die Isolation wurde
netzwerkforensisch bestätigt (kein DNS-Verkehr, keine externen IP-Adressen im
Mitschnitt, siehe Kap. Netzwerkforensik).

#hinweis[Netzwerkdiagramm einfügen (`res/netzwerk.png`): vier VMs im Segment
`net-quarry` (192.168.50.0/24), Angreifer → Client (RDP) und Angreifer →
Server (SSH).]

=== Systemübersicht

#table(
  columns: (auto, auto, 1fr, auto),
  thead[Hostname][IP][Betriebssystem][Rolle],
  [kali], [192.168.50.10], [Kali Linux], [Angreifer],
  [projektserver], [192.168.50.20], [Ubuntu 24.04 LTS (Server)], [Projektserver (Ziel)],
  [DESKTOP-GKDAU52], [192.168.50.30], [Windows 10 Education, Build 19045], [Mitarbeiter-Client (Opfer)],
  [siftworkstation], [192.168.50.40], [Ubuntu / SIFT Workstation], [Forensik-Workstation],
)

Der Client `DESKTOP-GKDAU52` ist auf die Zeitzone *Singapore Standard Time
(UTC+8)* eingestellt. Sämtliche werkzeuggenerierten Zeitstempel liegen in UTC
(„Z") vor; für die lokale Systemzeit des Clients sind +8 Stunden zu addieren.
Diese Konvention gilt einheitlich für das gesamte Gutachten und ist in der
korrelierten Gesamttimeline (Kap. Present) berücksichtigt.

#pagebreak(weak: true)
