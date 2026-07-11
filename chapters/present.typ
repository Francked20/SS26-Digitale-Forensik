#import "../style/style.typ": thead, hinweis

= Korrelierte Gesamtbetrachtung und Schlussfolgerung

Dieses Kapitel führt die Einzelbefunde der vier Forensikbereiche zu einer
konsistenten Gesamtdarstellung zusammen (Present-Phase). Es zeigt, wie sich die
Artefakte über Netzwerk, Server, Client, RAM und Datenträger *gegenseitig
bestätigen* (Korroboration), stellt die rekonstruierte Gesamttimeline dar und
beantwortet abschließend die fünf Leitfragen aus dem Prolog.

== Zeitzonen-Konvention

Alle Zeitangaben sind, sofern nicht anders vermerkt, in *UTC*. Der Windows-Client
läuft in *Singapore Standard Time (UTC+8)*; für dessen Ortszeit sind +8 h zu
addieren. Der Netzwerkmitschnitt und der Server operieren in UTC; einzelne
Live-Response-/Setup-Angaben wurden zur Nachvollziehbarkeit in ihrer
Ursprungszone belassen und sind entsprechend gekennzeichnet.

== Korrelierte Angriffstimeline

Die folgende Timeline verbindet die Befunde aller Bereiche. Jede Zeile nennt die
belegende Quelle und — wo vorhanden — die zugehörige Finding- bzw. Beweis-ID.

#table(
  columns: (auto, 1.6fr, 1fr),
  thead[Zeit (UTC)][Ereignis][Quelle / Beleg],
  [02.07.2026], [Eingang der Spear-Phishing-Mail mit Anhang `App.zip`
    (Thunderbird)], [F-WIN-01],
  [02.07.2026], [Entpacken von `App.zip`, Zugriff auf `main.py`/`login_check.py`],
    [F-WIN-02, F-WIN-04],
  [02.07.2026], [Ausführung des Python-Schadcodes; gefälschtes
    „Windows Sicherheit"-Fenster], [F-WIN-03, F-WIN-05],
  [02.07.2026], [Abgriff der Windows-Anmeldedaten `vogel/admin`, zweifach in
    `pwlog.txt`], [F-WIN-06],
  [05.07.2026 00:23:42], [RDP-Verbindung Angreifer → Client; `mstshash=vogel`
    im Klartext], [Netzwerk-Finding 1],
  [05.07.2026 00:23:42], [TLS-Zertifikat `DESKTOP-GKDAU52.cer` aus RDP-Handshake],
    [Netzwerk-Finding 4],
  [05.07.2026 00:24:35], [SSH-Login #1 `m.vogel` von 192.168.50.10 (Dauer 233 s)],
    [Netzwerk-Finding 2, B003-SERVER-SQ-2026],
  [05.07.2026 ~00:24–00:28], [Exfiltration ca. 1 MB Server → Angreifer],
    [Netzwerk-Finding 3],
  [05.07.2026 00:26:47], [SSH-Login #2 (kurz, 6 s; keine Exfiltration)],
    [Netzwerk-Finding 2],
  [05.07.2026 ~00:27–00:28], [Löschung der Projektdaten `rm -rf`],
    [B004-SERVER-SQ-2026, `bash_history`],
  [05.07.2026 ~00:28], [Timestomping `touch -t 202401010000`],
    [B005-SERVER-SQ-2026; istat/mactime (M4)],
  [05.07.2026 00:37:28], [SystemTime des Client-RAM-Abbilds (Akquise)],
    [F-RAM-01],
  [05.07.2026 ~08:30–08:44 (UTC+8)], [Sicherung Client (WinPmem, Live-Response,
    Velociraptor) — Ermittlerartefakte], [F-WIN-12, F-RAM-05],
)

#hinweis[Optional: grafische Timeline als Abbildung ergänzen
(`res/present/timeline.png`), erzeugt z. B. mit plaso/log2timeline über alle
Quellen.]

== Korroboration über die Bereiche

Die Beweiskraft der Untersuchung ergibt sich aus der wechselseitigen Bestätigung
unabhängiger Artefaktquellen:

- *Identität des Clients:* Der Hostname `DESKTOP-GKDAU52` wird dreifach belegt —
  aus dem RDP-TLS-Zertifikat (Netzwerk), aus der Registry (F-WIN-00) und aus dem
  RAM-Abbild (F-RAM-01).
- *Zugangsdatendiebstahl:* Der Klartext-Benutzername `vogel` im RDP-Cookie
  (Netzwerk) korrespondiert mit `pwlog.txt` des Stealers (F-WIN-06) und dem
  Prozessnachweis im RAM (F-RAM-03).
- *Serverzugriff:* Die auf dem Client offen liegenden Serverzugangsdaten
  `m.vogel:Werkzeug#2026` (F-WIN-06) erklären die beiden SSH-Logins im
  `auth.log` (B003) und im PCAP (Netzwerk-Finding 2).
- *Löschung & Anti-Forensik:* Die Löschbefehle und das Timestomping aus der
  `bash_history` (B004/B005) decken sich mit den leeren Projektverzeichnissen und
  den widersprüchlichen Zeitstempeln der Datenträgerforensik (M4).

== Beantwortung der Untersuchungsfragen

*1. Wurden vertrauliche Konstruktionsdaten unbefugt entwendet?* \
Ja. Über die erste SSH-Sitzung wurden ca. 1 MB Daten vom Projektserver zum
Angreifer exfiltriert. Betroffen sind die CAD-/STEP-Dateien `cnc_steuerung_v2.step`
und `antriebsachse.step` sowie die Kundenliste `kunden_2026.csv`. Die Inhalte der
gelöschten STEP-Dateien sind als Datenreste im Unallocated Space belegt.

*2. Auf welchem Weg erlangte der Täter Zugriff?* \
Über eine mehrstufige Kette: Spear-Phishing (E-Mail mit `App.zip`) → Ausführung
des Python-Credential-Stealers → RDP-Zugriff auf den Client → Auslesen der offen
abgelegten Serverzugangsdaten → SSH-Login am Projektserver → Exfiltration per SSH.

*3. Von welchem System aus und zu welchem Zeitpunkt?* \
Vom Angreifer-Host `192.168.50.10` (Kali). Der RDP-Zugriff auf den Client begann
am 05.07.2026 um 00:23:42 UTC, der erste SSH-Login am Server um 00:24:35 UTC. Die
initiale Kompromittierung des Clients (Phishing/Ausführung) erfolgte bereits am
02.07.2026.

*4. Wurden Daten gelöscht oder manipuliert? Sind sie wiederherstellbar?* \
Ja. Der Angreifer löschte die Projektdaten (`rm -rf`). Eine vollständige
Wiederherstellung war nicht möglich (keine gelöschten Inodes; File Carving
erfolglos, da die STEP-Dateien nur kurze Textinhalte hatten). Die Inhalte konnten
jedoch als Datenreste (`blkls`/`strings`) rekonstruiert werden.

*5. Gibt es Hinweise auf Anti-Forensik-Maßnahmen?* \
Ja. Der Täter manipulierte Zeitstempel per `touch -t 202401010000` (Timestomping),
belegt durch die `bash_history` (B005) und durch widersprüchliche
istat-/mactime-Werte (Modified auf 2024-01-01 bei Created/Inode-Änderung 2026).

== Fazit und Empfehlungen

Die Untersuchung weist den Angriff über sechs unabhängige, sich gegenseitig
bestätigende Datenquellen lückenlos nach. Ursächlich waren eine erfolgreiche
Phishing-Täuschung, im Klartext abgelegte Serverzugangsdaten und ein
überprivilegiertes Benutzerkonto. Zur Vermeidung künftiger Vorfälle empfiehlt das
Team: regelmäßige Phishing-Schulungen, konsequente Nutzung eines
Passwort-Managers statt Klartextablage, Einschränkung von Administratorrechten
mit Passwortpflicht, sowie zentrale Protokollierung und Monitoring. Der Vorfall
sollte dem BSI gemeldet werden; auf Lösegeldforderungen ist nicht einzugehen.

*Grenzen der Untersuchung.* Der Server-RAM stand nur eingeschränkt zur Verfügung;
zwei Volatility-Module (svcscan, hashdump) waren wegen der Windows-10-Speicher-
komprimierung nicht auswertbar (F-RAM-06). Der konkrete Dateiinhalt der
SSH-Exfiltration ist verschlüsselt und damit inhaltlich nicht rekonstruierbar —
Volumen und Richtung belegen den Diebstahl jedoch zweifelsfrei. Diese offene
Dokumentation der Grenzen erhöht die methodische Glaubwürdigkeit des Gutachtens.

#pagebreak(weak: true)
