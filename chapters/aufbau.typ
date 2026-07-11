= Erstellung und Bereitstellung der Artefakte (Environment Setup)

Um das Angriffsszenario für die spätere forensische Analyse vorzubereiten, wurden die bösartigen Artefakte auf der Angreifer-Plattform generiert, die Opfer-Umgebung realistisch eingerichtet und die Zieldaten auf dem Projektserver strukturiert. Dieses Kapitel dokumentiert die einzelnen Setup-Schritte, die eine authentische Angriffskette ermöglichen.

== 1. Vorbereitung der Phishing-Artefakte auf Kali Linux

Auf der Angreifer-Plattform (Kali Linux, `192.168.50.10`) wurde im Verzeichnis `~/phishing` die Schadsoftware vorbereitet und in ein E-Mail-fähiges Format gebracht.

- *Inhalt des App-Ordners:* Der Ordner `App` enthält die bösartige Quelldatei `main.py`, die das gefälschte Windows-Sicherheitsfenster generiert, sowie eine begleitende Anleitung namens `README.md`.
- *Komprimierung:* Der gesamte Ordner wurde als `App.zip` archiviert, um als E-Mail-Anhang versendet werden zu können.
- *Phishing-Text:* In der Datei `prank.txt` wurde der deutsche E-Mail-Text vorformuliert, welcher den Benutzer Markus Vogel unter dem Vorwand eines "wichtigen Systemupdates" zur Ausführung verleitet.

#figure(
  image("../res/Images_Aufbau/new_cdApp.png", width: 75%),
  caption: [Übersicht des Phishing-Arbeitsverzeichnisses auf dem Kali-Host],
) <fig-kali-dir>

#figure(
  image("../res/Images_Aufbau/new_cdApp.png", width: 85%),
  caption: [Inhalt der Datei `prank.txt` mit dem vorbereiteten Phishing-Mailtext],
) <fig-kali-prank>

#figure(
  image("../res/Images_Aufbau/new_cdApp.png", width: 85%),
  caption: [Inhalt der `README.md` innerhalb des präparierten App-Archivs],
) <fig-kali-readme>

== 2. Einrichtung des Windows-Opfer-Clients

Der Windows 10 Client (`192.168.50.30`, Hostname: `DESKTOP-GKDAU52`) wurde als Arbeitsplatzsystem des Mitarbeiters Markus Vogel konfiguriert. Um eine realistische Ausgangslage für den Angriff zu simulieren, wurden mehrere Konfigurationsschritte durchgeführt.

=== 2.1 Aktivierung von Remote Desktop (RDP)

Damit der Angreifer nach dem erfolgreichen Diebstahl der Windows-Zugangsdaten per Remote Desktop auf den Client zugreifen kann, wurde der RDP-Dienst auf dem Windows-Client aktiviert.

Konfigurationspfad: *Einstellungen $arrow$ System $arrow$ Remotedesktop $arrow$ Ein*

Nach der Aktivierung wurde der TCP-Port `3389` (`ms-wbt-server`) auf dem Client für eingehende Verbindungen geöffnet. Diese Einstellung ist entscheidend, da sie den zentralen Angriffsvektor für die Lateral-Movement-Phase darstellt.

#figure(
  image("../res/Images_Aufbau/rdp_on.png", width: 80%),
  caption: [Aktivierung des Remote-Desktop-Dienstes in den Windows-Systemeinstellungen],
) <fig-rdp-enabled>

=== 2.2 Zustellung der Phishing-E-Mail

Das auf Kali erstellte Archiv `App.zip` wurde als Anhang in eine simulierte E-Mail eingebunden und mittels Mozilla Thunderbird in den lokalen Posteingang (`Lokale Ordner`) des Opfers `m.vogel@bayern-praezision.de` zugestellt. Dies simuliert das erfolgreiche Passieren der E-Mail-Filter und stellt sicher, dass die Phishing-Nachricht dem Benutzer in seiner gewohnten Umgebung präsentiert wird.

#figure(
  image("../res/Images_Attack/Email.png", width: 85%),
  caption: [Zugestellte Phishing-E-Mail im lokalen Posteingang von Thunderbird],
) <fig-thunderbird-phishing>

=== 2.3 Ablage der Klartext-Zugangsdaten

Auf dem Desktop des Opfers wurde eine Datei namens `credentials.txt` angelegt. Diese enthält den leichtfertig notierten Klartext-String `m.vogel:Werkzeug#2026` zusammen mit der IP-Adresse des Projektservers (`192.168.50.20`). Diese Datei stellt die Brücke zwischen der Kompromittierung des Windows-Clients und dem lateralen Zugriff auf den Linux-Projektserver dar.

#figure(
  image("../res/Images_Attack/credentials.png", width: 75%),
  caption: [Klartext-Zugangsdaten in der Datei `credentials.txt` auf dem Desktop des Opfers],
) <fig-credentials-desktop>

== 3. Strukturierung und Berechtigung des Projektservers

Auf dem zentralen Projektserver (Ubuntu Server, `192.168.50.20`, angemeldet als `svc@projektserver`) wurden die Zielordner und vertraulichen Dokumente erstellt, die später als Beute des Angriffs exfiltriert werden. Um eine realistische Berechtigungsstruktur zu schaffen, wurden die Besitzrechte explizit auf das Opfer-Konto `m.vogel` übertragen.

=== 3.1 Verzeichnisstruktur anlegen

Die Grundstruktur für die vertraulichen Projektdaten wurde in `/srv/projekte/` mit drei thematischen Unterordnern angelegt:

```bash
sudo mkdir -p /srv/projekte/{Kunden,Projekte,Verwaltung}
```

=== 3.2 Erstellung der Dummy-Inhalte

Mittels `echo` und `sudo tee` wurden die vertraulichen Beispieldateien erzeugt und mit Platzhalter-Inhalten befüllt, die den sensiblen Charakter der Daten symbolisieren:

```bash
echo 'CNC-Steuerung v2 - VERTRAULICH' | sudo tee \
  /srv/projekte/Projekte/cnc_steuerung_v2.step

echo 'Antriebsachse Spezifikation' | sudo tee \
  /srv/projekte/Projekte/antriebsachse.step

echo 'Kundenliste 2026' | sudo tee \
  /srv/projekte/Kunden/kunden_2026.csv
```

=== 3.3 Anpassung der Besitzrechte (chown)

Damit der Benutzer `m.vogel` nach einer SSH-Anmeldung vollen Lese- und Schreibzugriff auf die Projektdaten hat, wurden die Besitzrechte des gesamten Verzeichnisses rekursiv auf ihn übertragen:

```bash
sudo chown -R m.vogel:m.vogel /srv/projekte
```

Diese Rechtezuweisung ist essentiell für den späteren Angriffsablauf: Sobald der Angreifer im Besitz der Zugangsdaten von `m.vogel` ist, kann er die Daten direkt herunterladen und löschen, ohne zusätzliche Rechteausweitung durchführen zu müssen.

#figure(
  image("../res/Images_Aufbau/server_files.png", width: 90%),
  caption: [Befehlsverlauf auf dem Server: Erstellung der Verzeichnisstruktur, Befüllung der Dummy-Dateien und Rechteübergabe per `chown` an `m.vogel`],
) <fig-server-setup>