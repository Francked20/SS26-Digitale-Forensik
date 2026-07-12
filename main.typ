// ============================================================
//  main.typ — Gesamtdokument Operation Silent Quarry
// ============================================================

#import "style/style.typ": gutachten
#import "chapters/titlepage.typ": titlepage
#import "chapters/toc.typ": table-of-contents

// ---------- Titelseite (vor dem Template, eigene Seitenlogik) ----------
#titlepage(
  authors: (
    ("Bin Mohd Farid Muhammad", "MatNr. 12306215"),
    ("Franck Emmanuel Da Si",    "MatNr. 22209183"),
    ("Syaura Binti Yusaini",     "MatNr. 12306221"),
    ("Kouami Jérôme Houngbo",    "MatNr. 00801723"),
  ),
)

// ---------- Ab hier globales Layout ----------
#show: gutachten
#include "chapters/erklärung.typ"
#include "chapters/arbeitsaufteilung.typ"
// ---------- Inhaltsverzeichnis ----------
#table-of-contents()

// ---------- Teil A: Verwaltung & Prolog ----------


#include "chapters/prolog.typ"

// ---------- Teil B: Zusammenfassungen ----------
#include "chapters/management_summary.typ"
#include "chapters/executive_summary.typ"

// ---------- Teil C: Grundlagen & Rahmen ----------
#include "chapters/rahmen.typ"

// ---------- Teil D: Secure-Phase ----------
// sammlung_beweis: vollständige Beweissicherung — Asservatenverzeichnis,
//                  Chain of Custody, Hashwerttabelle UND Durchführung der
//                  Sicherung (tcpdump, RAM, Live-Response, Velociraptor,
//                  Datenträgerabbilder, Einordnung). Die zuvor getrennte
//                  Datei sicherung_liveresponse.typ wurde hier integriert.
#include "chapters/sammlung_beweis.typ"

// ---------- Teil E: Analyse-Phase (nach Mitgliedern / Bereichen) ----------
#include "chapters/analyse_netzwerk.typ"      // M1 — Netzwerk / PCAP
#include "chapters/analyse_linux.typ"         // M2 — Linux-Server & Server-RAM
#include "chapters/analyse_windows.typ"       // M3 — Windows-OS & Anwendungen
#include "chapters/analyse_ram.typ"           // M3 — Client-RAM / Speicherforensik
#include "chapters/analyse_liveresponse.typ"  // M3 — Live-Response-Korroboration
#include "chapters/analyse_datenträger.typ"   // M4 — Datenträger / Server-Dateiforensik

// ---------- Teil F: Present-Phase ----------
#include "chapters/present.typ"

// ---------- Teil G: Anhang ----------
// attack:  rekonstruierter Attack Lifecycle (narrative Gesamtschau)
// aufbau:  Herstellung der Laborartefakte (Environment Setup) —
//          Lehr-/Reproduktionskontext, kein Beweisführungsschritt

#include "chapters/attack.typ"
#include "chapters/aufbau.typ"
#include "chapters/anhang.typ"
#include "chapters/abbildungsverzeichnis.typ"