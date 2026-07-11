= Management Summary

#text(style: "italic", fill: gray.darken(20%))[
  Nicht-technische Zusammenfassung für die Geschäftsführung.
]

*Was ist passiert?* \
Ein Angreifer täuschte den Konstrukteur Markus Vogel mit einer gefälschten,
scheinbar internen E-Mail („dringendes Sicherheitsupdate"). Herr Vogel öffnete
den Anhang; das darin versteckte Programm gaukelte ein echtes
Windows-Anmeldefenster vor und griff so seine Zugangsdaten ab. Über diese und
über weitere, unverschlüsselt auf dem Arbeitsplatz abgelegte Passwörter gelangte
der Täter an den zentralen Projektserver, kopierte vertrauliche
Konstruktions- und Kundendaten und löschte sie anschließend auf dem Server.
Zusätzlich manipulierte er Zeitstempel, um die Tat zu verschleiern.

*Was wurde entwendet?* \
Betroffen sind vertrauliche CAD-Konstruktionsdaten (u. a. „CNC-Steuerung v2"
und „Antriebsachse") sowie eine Kundenliste. Die Daten wurden vom Server
abgezogen und dort gelöscht. Reste der gelöschten Dateien konnten forensisch
nachgewiesen, aber nicht vollständig wiederhergestellt werden.

*Wie schwerwiegend ist der Vorfall?* \
Der Abfluss betrifft geschäftskritisches Know-how. Der Angriff war gezielt und
mehrstufig, blieb aber auf das interne Labornetz begrenzt; ein Abfluss ins
öffentliche Internet wurde im untersuchten Zeitraum nicht beobachtet. Die
Kombination aus Diebstahl und anschließender Löschung bedeutet sowohl einen
Vertraulichkeits- als auch einen Verfügbarkeitsschaden.

*Wie konnte es dazu kommen? — Die wesentlichen Schwachstellen* \
- Ein Mitarbeiter wurde durch eine überzeugende Phishing-E-Mail getäuscht.
- Server-Passwörter lagen im Klartext auf dem Arbeitsplatz (Textdatei und im Browser gespeichert).
- Das genutzte Benutzerkonto besaß weitreichende Administratorrechte ohne Passwortpflicht.

*Unsere Empfehlungen* \
- *Kein Lösegeld* zahlen und den Vorfall dem BSI melden.
- *Regelmäßige Mitarbeiterschulungen* zu Phishing und im Umgang mit E-Mail-Anhängen.
- *Keine Passwörter im Klartext* ablegen; Einsatz eines geprüften Passwort-Managers,
  keine dauerhafte Speicherung sensibler Zugangsdaten im Browser.
- *Rechte einschränken* (keine unnötigen Administratorrechte, Passwortpflicht erzwingen).
- *Protokollierung und Monitoring* zentraler Systeme einführen, um künftige
  Zugriffe früher zu erkennen.

Die technischen Einzelheiten und die vollständige Beweisführung finden sich in
der nachfolgenden Executive Summary sowie in den Analysekapiteln.

#pagebreak(weak: true)
