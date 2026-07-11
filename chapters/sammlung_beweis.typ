#import "../style/style.typ": thead, hinweis

= Beweissicherung (Secure-Phase)

Dieses Kapitel dokumentiert die *Secure*-Phase des S-A-P-Modells: die
Identifizierung und forensisch sichere Erfassung aller Asservate, die Wahrung
der Integrität durch Hashwerte sowie die lückenlose Chain of Custody. Die
Reihenfolge der Sicherung folgt der *Order of Volatility*:
zuerst die flüchtigen Daten (Netzwerkmitschnitt, Arbeitsspeicher,
Live-Response), zuletzt die beständigen Datenträgerabbilder.

== Übersicht der Asservate

Alle im Verfahren gesicherten Beweismittel sind nachfolgend mit ihrem
kryptografischen Integritätshash aufgeführt. Die Hashes wurden bei der Sicherung
gebildet und vor jeder Analyse erneut verifiziert.

// Helfer: langer Hashwert, der bei Bedarf umbricht (Zeichenweise Sollbruchstellen)
#let hashval(h) = text(font: ("New Computer Modern Mono", "DejaVu Sans Mono"), size: 7.5pt)[
  #h.clusters().join(sym.zws)
]

#table(
  columns: (auto, 1.5fr, auto, 1.6fr),
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
  [05.–11.07.], [alle], [Read-only-Analyse auf der SIFT Workstation], [M1–M4],
)

== Sicherung der flüchtigen Daten

=== Netzwerkmitschnitt (tcpdump)

Bereits vor Angriffsbeginn wurde auf dem Server (VM2, Interface `ens37`) ein
vollständiger Mitschnitt des Segments `net-quarry` gestartet und nach Abschluss
der Angriffskette beendet.

```bash
sudo tcpdump -i ens37 -w /tmp/silent_quarry.pcap
```

Ergebnis: `silent_quarry.pcap`, 12.132 Pakete (0 verworfen), ~8,82 MB,
Erfassungsdauer ca. 5 Minuten. Das PCAP ist das primäre Asservat der
Netzwerkforensik und enthält RDP-, SSH- und
Exfiltrationsverkehr.

=== Arbeitsspeicher-Sicherung (Server — LiME)

Auf dem Linux-Server wurde der physische Arbeitsspeicher mit dem Kernel-Modul
*LiME* (Linux Memory Extractor) gesichert:

```bash
cd ~/LiME/src
sudo insmod lime-$(uname -r).ko "path=/tmp/server_ram.lime format=lime"
```

Ergebnis: `server_ram.lime` (~4 GB, LiME-Format). Das Abbild ist Grundlage der
Server-RAM-Analyse (Mitglied 2).

=== Arbeitsspeicher-Sicherung (Client — WinPmem)

Die zunächst geplante RAM-Sicherung mit *FTK Imager* („Capture Memory")
scheiterte mit der Meldung „Could not start driver" — der Kernel-Treiber ließ
sich trotz Administratorrechten wegen der Windows-Treibersignaturprüfung in der
isolierten VM nicht laden. Als gleichwertige
Alternative wurde daraufhin *WinPmem* eingesetzt:

```powershell
winpmem_mini_x64_rc2.exe client_ram.mem
```

Ergebnis: `client_ram.mem` (~2,7 GB, Raw-Format), Erfassung 05.07.2026 ca.
08:30 UTC+8. Der dokumentierte Werkzeugwechsel folgt dem Prinzip der
methodischen Transparenz: Jede Abweichung von der Standardmethodik wird begründet
und nachvollziehbar festgehalten. Das Abbild ist Grundlage der Client-RAM-Analyse
(Mitglied 3).

=== Live-Response-Kommandos (Client)

Zur Erfassung des flüchtigen Systemzustands wurden auf dem Client in einer
administrativen Eingabeaufforderung Standard-Windows-Kommandos in einer
verketteten Anweisung ausgeführt und nach `live_response.txt` umgeleitet:

```powershell
(date /t & time /t & systeminfo & whoami & query user & tasklist /v & ipconfig /all & arp -a & route print & netstat -ano & schtasks /query /fo LIST & reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run) > Desktop\live_response.txt
```

Erfasst wurden u. a. Systeminformationen, aktive Sessions, laufende Prozesse,
Netzwerkkonfiguration, ARP-Cache, Routing, offene Verbindungen und
Autostart-Einträge. Die netzwerkrelevanten Auszüge (ARP-Eintrag der
Angreifer-MAC `00-0c-29-41-13-85` = 192.168.50.10; Port 3389 im Status
`LISTENING`) sind bei der Live Response und Netzwerkforensik ausgewertet.

=== Velociraptor-Sammlung (Client)

Zur automatisierten Erfassung Windows-spezifischer Artefakte wurde
*Velociraptor* (v0.77.1) im Single-Machine-Deployment auf dem Client eingesetzt
(GUI-Port 8889, Self-Signed SSL). Da `Windows.KapeFiles.Targets` in dieser
Version nicht verfügbar war, wurden die relevanten Artefakte einzeln ausgewählt
(u. a. `Windows.Attack.Prefetch`, `Windows.Forensics.Amcache`,
`Windows.Registry.NTUser`, `Windows.Registry.UserAssist`,
`Windows.Forensics.SAM`, `Windows.Forensics.Lnk`,
`Windows.Forensics.JumpLists`, `Windows.NTFS.MFT`, `Windows.EventLogs.*`). Die
Sammlung wurde in zwei Flows durchgeführt (Nachtrag der Prefetch-Erfassung) und
als ZIP-Archive (A07, A08) exportiert.

== Sicherung der beständigen Daten (Datenträgerabbilder)

Die Post-Mortem-Abbilder beider Zielsysteme wurden mit *FTK Imager* als
Roh-Images (`.dd`) erzeugt und dabei unmittelbar gehasht (A01 `Server.dd`,
A02 `Client.dd`). Die Struktur der Abbilder (Partitionen, Dateisysteme) ist in
den jeweiligen Analysekapiteln dokumentiert; die Einbindung erfolgte
ausschließlich schreibgeschützt (read-only).

== Abgrenzung der Ermittlerartefakte

Die in dieser Phase eingesetzten Werkzeuge (tcpdump, LiME, WinPmem,
Live-Response-Kommandos, Velociraptor, FTK Imager, Npcap) hinterlassen eigene
Spuren auf den Zielsystemen. Diese *Ermittlerartefakte* sind vom Tatgeschehen zu
trennen und werden in den Analysekapiteln explizit als solche gekennzeichnet
(insbesondere F-WIN-12 „Zuordnung der Ermittlerartefakte" und F-RAM-05
„Nachweis des Sicherungswerkzeugs WinPmem"). Der Sicherungszeitpunkt
(05.07.2026) grenzt sie zeitlich eindeutig vom Angriff (02.–05.07.2026 durch den
Täter) ab.

#pagebreak(weak: true)
