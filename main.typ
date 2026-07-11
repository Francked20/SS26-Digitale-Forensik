// ============================================================
//  main.typ — Gesamtdokument "Operation Silent Quarry"
//  Forensisches Gutachten — Bayern Präzision GmbH
// ------------------------------------------------------------
//  Aufbau des Dokuments (folgt dem S-A-P-Modell der Vorlesung):
//    0. Front Matter ....... Titel, Erklärung, Inhaltsverzeichnis
//    1. Prolog ............. Auftrag, Fragestellung, Sachverhalt
//    2. Summaries .......... Management- & Executive Summary
//    3. Grundlagen/Rahmen .. Methodik (S-A-P), Werkzeuge, Infrastruktur
//    4. Szenario ........... Aufbau der Umgebung + Angriffs-Lifecycle
//    5. SECURE ............. Beweissicherung (sammlung_beweis)
//    6. ANALYSE ............ 4 Bereiche + Live-Response
//    7. PRESENT ............ Korrelierte Gesamttimeline & Schluss
//    8. Anhang ............. Artefaktverzeichnis (Nextcloud)
// ============================================================

#import "style/style.typ": gutachten
#import "chapters/titlepage.typ": titlepage
#import "chapters/toc.typ": table-of-contents

// ------------------------------------------------------------
//  0. FRONT MATTER
// ------------------------------------------------------------

// Titelseite (eigene Seitenlogik, vor dem globalen Template)
#titlepage(
  authors: (
    ("Bin Mohd Farid Muhammad", "MatNr. 12306215"),
    ("Franck Emmanuel Da Si",    "MatNr. 22209183"),
    ("Syaura Binti Yusaini",     "MatNr. 12306221"),
    ("Kouami Jérôme Houngbo",    "MatNr. 00801723"),
  ),
)

// Ab hier globales Layout anwenden
#show: gutachten

// Inhaltsverzeichnis
#table-of-contents()

// Eidesstattliche Erklärung
#include "chapters/erklärung.typ"

// ------------------------------------------------------------
//  1. PROLOG — Auftrag & Sachverhalt
// ------------------------------------------------------------
#include "chapters/prolog.typ"

// ------------------------------------------------------------
//  2. ZUSAMMENFASSUNGEN (zuerst nicht-technisch, dann technisch)
// ------------------------------------------------------------
#include "chapters/management_summary.typ"
#include "chapters/executive_summary.typ"

// ------------------------------------------------------------
//  3. GRUNDLAGEN & RAHMEN — Methodik (S-A-P), Werkzeuge, Infrastruktur
// ------------------------------------------------------------
#include "chapters/rahmen.typ"

// ------------------------------------------------------------
//  4. SZENARIO — Aufbau der Laborumgebung & Rekonstruktion des Angriffs
//     (Ground Truth; dient als Referenz fuer die spaetere Beweisfuehrung)
// ------------------------------------------------------------
#include "chapters/aufbau.typ"
#include "chapters/attack.typ"

// ------------------------------------------------------------
//  5. SECURE-PHASE — Beweissicherung & Chain of Custody
// ------------------------------------------------------------
#include "chapters/sammlung_beweis.typ"

// ------------------------------------------------------------
//  6. ANALYSE-PHASE — vier Bereiche + Live-Response (je 1 Mitglied)
//     M1 Netzwerk . M2 Linux/Server+RAM . M3 Windows/RAM/Live . M4 Datentraeger
// ------------------------------------------------------------
#include "chapters/analyse_netzwerk.typ"      // Mitglied 1
#include "chapters/analyse_linux.typ"         // Mitglied 2
#include "chapters/analyse_windows.typ"       // Mitglied 3
#include "chapters/analyse_ram.typ"           // Mitglied 3
#include "chapters/live_res.typ"              // Mitglied 3
#include "chapters/analyse_datenträger.typ"   // Mitglied 4

// ------------------------------------------------------------
//  7. PRESENT-PHASE — Korrelierte Gesamttimeline & Schlussfolgerung
// ------------------------------------------------------------
#include "chapters/present.typ"

// ------------------------------------------------------------
//  8. ANHANG — Artefaktverzeichnis (Nextcloud-Link)
// ------------------------------------------------------------
#include "chapters/anhang.typ"
