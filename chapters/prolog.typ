#import "../style/style.typ": thead

= Verwaltungsinformationen und Prolog

Dieses Kapitel dokumentiert den formalen Rahmen der Untersuchung: den erteilten
Auftrag, die daraus abgeleiteten Untersuchungsfragen, die organisatorischen
Rahmenbedingungen sowie den zugrunde liegenden Sachverhalt. Es ordnet die
nachfolgende Beweisführung ein und ist Teil der *Present*-Phase des S-A-P-Modells.

== Rahmendaten der Untersuchung

#table(
  columns: (auto, 1fr),
  thead[Merkmal][Angabe],
  [Aktenzeichen], [SQ-2026-01],
  [Auftraggeber], [Geschäftsführung der Bayern Präzision GmbH (fiktiv)],
  [Gegenstand], [Vermuteter Abfluss vertraulicher Konstruktionsdaten sowie
                  Sabotage (Löschung) auf dem Projektserver],
  [Sachverständige], [Vierköpfiges Forensik-Team (Mitglied 1–4)],
  [Betreuung], [Prof. Dr. Michael Heigl, A. Popp — THD, SoSe 2026],
  [Meldung des Vorfalls], [04.07.2026],
  [Übergabe der Asservate], [05.07.2026],
  [Auswertungszeitraum], [05.07.2026 – 11.07.2026],
)

== Untersuchungsauftrag und Fragestellung

Die Geschäftsführung der Bayern Präzision GmbH beauftragte das Forensik-Team mit
der vollständigen und nachvollziehbaren Aufklärung des Vorfalls. Das Gutachten
beantwortet die folgenden fünf Leitfragen; jede Frage wird am Ende in der
Present Phase beweisgestützt beantwortet.

+ *Datenabfluss.* Wurden vertrauliche Konstruktionsdaten unbefugt entwendet?
  Wenn ja, welche konkret?
+ *Angriffskette.* Auf welchem Weg erlangte der Täter Zugriff auf den
  Projektserver (initialer Vektor, Lateral Movement, Exfiltration)?
+ *Herkunft und Zeitpunkt.* Von welchem System aus und zu welchem Zeitpunkt
  erfolgte der Zugriff?
+ *Manipulation.* Wurden Daten gelöscht oder verändert? Sind sie ganz oder in
  Teilen wiederherstellbar?
+ *Anti-Forensik.* Gibt es Hinweise auf Verschleierungsmaßnahmen des Täters
  (z. B. Zeitstempelmanipulation / Timestomping)?

=== Rahmenbedingungen

Bei dem Vorfall handelt es sich um einen *frei erfundenen, im Labor
nachgestellten Fall*; sämtliche Personen, Firmen, IP-Adressen und Daten sind
fiktiv und dienen ausschließlich der Lehre. Die Asservate wurden dem Team in
aufbereiteter Form (Datenträgerabbilder, RAM-Dumps, Netzwerkmitschnitt,
Live-Response-Ausgaben) übergeben. Die Aufbewahrungsfrist der Asservate ist auf
sechs Monate festgelegt; danach erfolgt die datenschutzkonforme Löschung. Die
Bearbeitung folgt dem Grundsatz der Nichtveränderung der Originaldaten.

=== Untersuchungszeitraum und Arbeitsumgebung

Die Asservate wurden am 05.07.2026 an das Team übergeben und im Zeitraum vom
05.07.2026 bis 11.07.2026 ausgewertet. Als zentrale Analyseplattform diente die
*SIFT Workstation* (Ubuntu-basiert, 192.168.50.40) im isolierten Laborsegment
`net-quarry`. Das Forensik-Toolkit wurde über einen *schreibgeschützten VMware
Shared Folder* bereitgestellt, sodass eine Rückwirkung der Werkzeuge auf die
Asservate ausgeschlossen ist. Alle Abbilder wurden ausschließlich
*read-only* eingebunden.

== Ausgangslage / Sachverhalt

Am 04.07.2026 stellte die Bayern Präzision GmbH fest, dass vertrauliche
Konstruktionsdaten (CAD-/STEP-Dateien sowie Kundenlisten) auf dem zentralen
Projektserver nicht mehr vollständig auffindbar waren. Nahezu zeitgleich meldete
der Konstrukteur *Markus Vogel* eine verdächtige E-Mail, die ihn zur Ausführung
eines Anhangs aufgefordert hatte und deren Anweisung er befolgt hatte. Aus der
Zusammenschau beider Beobachtungen ergab sich der Anfangsverdacht eines gezielten
Angriffs mit anschließendem Datenabfluss und Spurenverwischung. Die
Geschäftsführung leitete daraufhin die forensische Untersuchung ein.

=== Beteiligte Systeme

Die vier am Vorfall beteiligten Systeme (Angreifer-Host, Projektserver,
Mitarbeiter-Client, Forensik-Workstation) sind in der Systemübersicht im Kapitel
„Grundlagen und Rahmen“ (Abschnitt Infrastruktur) zusammengefasst.

=== Meldung des Vorfalls

Die Kombination aus der Feststellung fehlender Projektdaten durch die IT der
Bayern Präzision GmbH und der eigenständigen Meldung der verdächtigen E-Mail
durch Herrn Vogel bildete den Auslöser der Beauftragung. Beide Meldungen gingen
am 04.07.2026 ein; die Sicherung der Systeme erfolgte am 05.07.2026.

#pagebreak(weak: true)
