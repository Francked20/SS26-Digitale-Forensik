// ============================================================
//  abbildungsverzeichnis.typ — Abbildungsverzeichnis
// ============================================================
//  Position: Teil G (Verzeichnisse), vor dem Anhang.
//  Sammelt automatisch alle #figure(...)-Elemente des Gesamtdokuments
//  (inkl. der Beweis-Screenshots aus den beweis()-Helfern).
//  Voraussetzung: jede Abbildung besitzt eine caption — im Projekt erfuellt.
// ============================================================

#import "../style/style.typ": accent

#pagebreak(weak: true)

// Unnummerierte Ueberschrift (Verzeichnis, kein Sachkapitel),
// erscheint aber selbst im Inhaltsverzeichnis.
#heading(level: 1, numbering: none, outlined: true)[Abbildungsverzeichnis]

#outline(
  title: none,
  target: figure.where(kind: image),
)

// ------------------------------------------------------------
//  OPTIONAL: Tabellenverzeichnis
// ------------------------------------------------------------
//  Aktuell NICHT aktiviert, weil die Tabellen im Projekt als nacktes
//  #table(...) gesetzt sind. Typst erfasst nur Tabellen, die in ein
//  #figure(...) mit caption gewickelt sind:
//
//      #figure(
//        table( ... ),
//        caption: [Asservate und ihre SHA-256-Hashwerte],
//      ) <tab-asservate>
//
//  Sobald die relevanten Tabellen (Asservatenverzeichnis, Hashwerte,
//  Werkzeugliste, Timeline) so umgestellt sind, diesen Block einkommentieren:
//
// #pagebreak(weak: true)
// #heading(level: 1, numbering: none, outlined: true)[Tabellenverzeichnis]
// #outline(
//   title: none,
//   target: figure.where(kind: table),
// )
// ------------------------------------------------------------
