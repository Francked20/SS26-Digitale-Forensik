#import "../style/style.typ": thead, hinweis

= Grundlagen und Rahmen

== Motivation
#hinweis[Warum digitale Forensik? Ca. 1 Seite, Verweis auf aktuelle Statistiken (z. B. Verizon DBIR).]

== Methodik

=== Das S-A-P-Modell
Secure (Identifizierung, Erfassung, Datensicherung, Protokollierung),
Analyse (Untersuchung, objektive Bewertung), Present (zielgruppenorientierte
Aufbereitung). Rücksprünge sind möglich; das Gutachten liegt in der Present-Phase.

=== Live-Response vs. Post-Mortem
#hinweis[Unterschied erklären; Order of Volatility benennen und begründen.]

=== Verwendete Werkzeuge
#table(
  columns: (auto, 1fr, auto),
  thead[Werkzeug][Zweck][Phase],
  [WinPMem], [RAM-Sicherung Client], [Secure],
  [tcpdump], [Netzwerkmitschnitt], [Secure],
  [Volatility], [RAM-Analyse], [Analyse],
  [Autopsy / TSK], [Datenträgeranalyse], [Analyse],
  [Wireshark / NetworkMiner], [PCAP-Analyse], [Analyse],
)
#hinweis[Vollständige Tool-Tabelle aus der Gliederung übernehmen.]

=== Forensische Grundsätze
#hinweis[Keine Veränderung am Original, Integrität (SHA-256 + GPG), Chain of Custody, Nachvollziehbarkeit.]

== Infrastruktur

=== Netzwerkübersicht
#hinweis[Netzwerkdiagramm einfügen (res/netzwerk.png): 4 VMs im Netz net-quarry.]

=== Systemübersicht
#table(
  columns: (auto, auto, 1fr, auto),
  thead[Hostname][IP][Betriebssystem][Rolle],
  [kali], [192.168.50.10], [Kali Linux], [Angreifer],
  [projektserver], [192.168.50.20], [Ubuntu 22.04 LTS], [Projektserver (Ziel)],
  [DESKTOP-VOGEL], [192.168.50.30], [Windows 10 Pro], [Mitarbeiter-Client],
  [siftworkstation], [192.168.50.40], [Ubuntu / SIFT], [Forensik-Workstation],
)

#pagebreak(weak: true)