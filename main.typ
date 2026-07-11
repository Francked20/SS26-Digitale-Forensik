// ============================================================
//  main.typ — Gesamtdokument Operation Silent Quarry
// ============================================================

#import "style/style.typ": gutachten
#import "chapters/titlepage.typ": titlepage
#import "chapters/toc.typ": table-of-contents

// ---------- Titelseite (vor dem Template, eigene Seitenlogik) ----------
#titlepage(
  authors: (
    ("Vorname Nachname", "MatNr. 000000"),
    ("Vorname Nachname", "MatNr. 000000"),
    ("Vorname Nachname", "MatNr. 000000"),
    ("Vorname Nachname", "MatNr. 000000"),
  ),
)

// ---------- Ab hier globales Layout ----------
#show: gutachten
#include "chapters/arbeitsaufteilung.typ"
// ---------- Inhaltsverzeichnis ----------
#table-of-contents()

// ---------- Teil A: Verwaltung & Prolog ----------

#include "chapters/erklärung.typ"
#include "chapters/prolog.typ"
#include "chapters/attack.typ"
#include "chapters/aufbau.typ"

// ---------- Teil B: Zusammenfassungen ----------
#include "chapters/management_summary.typ"
#include "chapters/executive_summary.typ"

// ---------- Teil C: Grundlagen & Rahmen ----------
#include "chapters/rahmen.typ"

// ---------- Teil D: Secure-Phase ----------
// sammlung_beweis: Chain of Custody, Asservatenverzeichnis,
//                  Single-Evidence-Formulare, Hashwerttabelle
// sicherung_liveresponse: Durchführung der Sicherung
//                  (tcpdump, RAM, Live-Response-Kommandos, Velociraptor)
#include "chapters/sammlung_beweis.typ"
#include "chapters/sicherung_liveresponse.typ"

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
#include "chapters/anhang.typ"
