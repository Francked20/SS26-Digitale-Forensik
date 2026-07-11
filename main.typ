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

// ---------- Inhaltsverzeichnis ----------
#table-of-contents()

// ---------- Teil A: Verwaltung & Prolog ----------
#include "chapters/erklärung.typ"
#include "chapters/prolog.typ"

// ---------- Teil B: Zusammenfassungen ----------
#include "chapters/management_summary.typ"
#include "chapters/executive_summary.typ"

// ---------- Teil C: Grundlagen & Rahmen ----------
#include "chapters/rahmen.typ"

// ---------- Teil D: Secure-Phase ----------
#include "chapters/sammlung_beweis.typ"

// ---------- Teil E: Analyse-Phase (4 Bereiche, je 1 Mitglied) ----------
#include "chapters/analyse_netzwerk.typ"
#include "chapters/analyse_linux.typ"
#include "chapters/analyse_windows.typ"
#include "chapters/analyse_ram.typ"
#include "chapters/analyse_datenträger.typ"
#include "chapters/live_res.typ"

// ---------- Teil F: Present-Phase ----------
#include "chapters/present.typ"

// ---------- Teil G: Anhang ----------
#include "chapters/anhang.typ"