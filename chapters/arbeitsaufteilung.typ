#import "../style/style.typ": thead, hinweis

#heading("Arbeitsaufteilung", outlined: false, numbering: none)

Die Bearbeitung von „Operation Silent Quarry" erfolgte arbeitsteilig durch ein
vierköpfiges Team. Die Aufteilung orientiert sich an den forensischen Domänen
(Netzwerk, Server/Linux, Client/Windows, Datenträger) und den zugehörigen
Asservaten. Jedes Teammitglied verantwortet die vollständige S-A-P-Bearbeitung
seines Bereichs (Sicherung, Analyse, Dokumentation) einschließlich der
reproduzierbaren Befunddokumentation. Übergreifende Aufgaben (Szenario,
Beweissicherung, Zusammenführung, Präsentation) wurden gemeinsam bearbeitet.

#heading(level: 2, "Zuständigkeiten im Überblick", outlined: false, numbering: none)

#table(
  columns: (auto, 1.2fr, auto, 1.6fr),
  align: (center, left, left, left),
  thead[Rolle][Name][MatNr.][Verantwortungsbereich],
  [Mitglied 1], [Bin Mohd Farid Muhammad], [12306215], [Netzwerkforensik (PCAP), Infrastrukturaufbau, Laborvorbereitung, Live response,],
  [Mitglied 2], [Kouami Jérôme Houngbo], [00801723], [Linux-/Server-OS- und Server-RAM-Forensik],
  [Mitglied 3], [Franck Emmanuel Da Si], [22209183], [Windows-OS-, Anwendungs-, Client-RAM- und Live-Response-Forensik],
  [Mitglied 4], [Syaura Binti Yusaini], [12306221], [Datenträger-/Dateiforensik (Server.dd)],
)

#heading(level: 2, "Gemeinsam bearbeitete Aufgaben", outlined: false, numbering: none)

Folgende Aufgaben wurden vom gesamten Team gemeinsam verantwortet:

- *Szenario und Laboraufbau:* Entwurf des Falls, Einrichtung der VMware-Umgebung
  `net-quarry` und Erzeugung der Artefakte (Kap. Environment Setup).
- *Beweissicherung (Secure-Phase):* Sicherung aller Asservate nach der Order of
  Volatility, Hashwertbildung und Chain of Custody.
- *Zusammenführung und Korrelation:* Abgleich der Befunde über alle Domänen,
  Erstellung der korrelierten Gesamttimeline und der Schlussfolgerung.
- *Gutachten und Präsentation:* Redaktion des Gesamtdokuments, einheitliche
  Terminologie und Vorbereitung der Abschlusspräsentation.

#pagebreak(weak: true)
