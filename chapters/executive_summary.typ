= Executive Summary

#text(style: "italic")[Technische Kurzzusammenfassung aller Findings (ca. 2/3 Seite).]

Die Untersuchung belegt einen mehrstufigen Angriff: Phishing-Mail mit
Credential-Stealer, Diebstahl der Zugangsdaten, SSH-Login am Server von
192.168.50.10, Exfiltration der CAD-Daten per scp, anschließende Löschung
und Zeitstempelmanipulation. Abgedeckte Bereiche: Netzwerk-, Linux-OS-,
Windows-OS-, Anwendungs-, Datenträger-/Datei- und Speicherforensik.

#pagebreak(weak: true)