// ============================================================
//  style/style.typ — Zentrales Layout für das Gutachten
//  Ein einziger Akzent, schlicht & professionell.
// ============================================================

// --- Zentrale Design-Parameter (hier alles anpassen) ---
#let accent   = rgb("#1F3864")   // einziger Akzent (dezentes Dunkelblau)
#let body-font = ("IBM Plex Serif", "Source Serif 4", "Source Serif Pro")
#let mono-font = ("New Computer Modern Mono", "DejaVu Sans Mono")

// --- Haupt-Template: von main.typ per show-rule angewandt ---
#let gutachten(
  title: "Forensisches Gutachten",
  doc,
) = {
  // ---------- Seite ----------
  set page(
    paper: "a4",
    margin: (top: 2.6cm, bottom: 2.6cm, left: 3cm, right: 2.5cm),
    header: context {
      // Kein Header auf den ersten Seiten (Titel/Erklärung)
      if counter(page).get().first() > 2 {
        set text(size: 9pt, fill: gray.darken(20%), font: body-font)
        grid(
          columns: (1fr, auto),
          align: (left, right),
          [Operation Silent Quarry], [Forensisches Gutachten],
        )
        v(-0.4em)
        line(length: 100%, stroke: 0.5pt + gray.lighten(40%))
      }
    },
    footer: context {
      set text(size: 9pt, fill: gray.darken(20%), font: body-font)
      line(length: 100%, stroke: 0.5pt + gray.lighten(40%))
      v(0.2em)
      grid(
        columns: (1fr, auto),
        align: (left, right),
        [Vertraulich], [Seite #counter(page).display() von #context counter(page).final().first()],
      )
    },
  )

  // ---------- Grundtext ----------
  set text(font: body-font, size: 11pt, lang: "de", hyphenate: true)
  set par(justify: true, leading: 0.72em, first-line-indent: 0pt, spacing: 1.0em)

  // ---------- Überschriften: schlicht, nur Akzentfarbe ----------
  set heading(numbering: "1.1")
  show heading: it => {
    set text(fill: accent, font: body-font)
    block(above: 1.3em, below: 0.7em)[#it]
  }
  show heading.where(level: 1): it => {
    set text(size: 17pt, weight: "bold", fill: accent)
    block(above: 1.6em, below: 0.8em)[
      #it
      #v(-0.3em)
      #line(length: 100%, stroke: 1pt + accent)
    ]
  }
  show heading.where(level: 2): set text(size: 13pt, weight: "bold")
  show heading.where(level: 3): set text(size: 11.5pt, weight: "bold")

  // ---------- Links & Code ----------
  show link: set text(fill: accent)
  show raw: set text(font: mono-font, size: 9.5pt)
  show raw.where(block: true): it => block(
    fill: luma(246), inset: 8pt, radius: 3pt, width: 100%,
    stroke: (left: 2pt + accent),
  )[#it]

  // ---------- Tabellen: schlicht, Kopfzeile im Akzent ----------
  set table(
    stroke: (x, y) => (
      top: if y == 0 { 0.8pt + accent } else { 0.4pt + gray.lighten(30%) },
      bottom: 0.4pt + gray.lighten(30%),
    ),
    inset: 6pt,
  )

  doc
}

// --- Kleine Helfer, die die Kapitel benutzen können ---

// Kopfzeile für Tabellen: erste Zeile fett + Akzent-Hintergrund
#let thead(..cells) = table.header(
  ..cells.pos().map(c => table.cell(fill: accent.lighten(82%))[#strong[#c]])
)

// Hinweis-/Platzhalter-Box (grau, kursiv) — was noch auszufüllen ist
#let hinweis(body) = block(
  width: 100%, inset: 8pt, radius: 3pt,
  fill: luma(244), stroke: (left: 2pt + gray),
)[#text(style: "italic", fill: gray.darken(25%), size: 10pt)[➤ #body]]

// Finding-Box mit ID (z.B. F-WIN-01)
#let finding(id, titel, body) = block(
  width: 100%, inset: 9pt, radius: 3pt, above: 0.9em, below: 0.9em,
  stroke: 0.6pt + accent.lighten(40%),
)[
  #text(weight: "bold", fill: accent)[#id — #titel]
  #v(0.3em)
  #body
]