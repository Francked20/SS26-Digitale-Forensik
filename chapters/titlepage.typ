// ============================================================
//  chapters/titlepage.typ — Titelseite (THD-Deckblatt)
// ============================================================

#let titlepage(
  title: "Forensisches Gutachten",
  subtitle: "Operation Silent Quarry",
  description: "Forensische Untersuchung eines Datenabfluss- und Sabotagevorfalls bei der Bayern Präzision GmbH",
  authors: (
    ("Bin Mohd Farid Muhammad", "MatNr. 12306215"),
    ("Franck Emmanuel Da Si", "MatNr. 22209183"),
    ("Syaura Binti Yusaini ", "MatNr. 12306221"),
    ("Kouami Jérôme Houngbo", "MatNr. 00801723"),
  ),
  betreuer: "Prof. Dr. Michael Heigl",
  betreuer2: none,
  aktenzeichen: "SQ-2026-01",
  location: "Deggendorf",
  semester: "SoSe 2026",
  logo: "../res/THD-logo.pdf",
) = {
  page(header: none, footer: none, margin: (top: 3cm, bottom: 3cm, x: 3cm))[
    #set text(font: ("New Computer Modern", "TeX Gyre Termes", "Linux Libertine"))

    // --- Logo ---
    #align(center)[
      #image(logo, width: 62%)
    ]

    #v(1.2cm)

    // --- Studiengang-Bandeau zwischen zwei dicken Linien ---
    #block(width: 100%)[
      #line(length: 100%, stroke: 1.6pt + black)
      #v(0.2em)
      #align(center)[
        #text(size: 20pt, weight: "regular", tracking: 1.5pt)[B#text(size:16pt)[ACHELOR] C#text(size:16pt)[YBER] S#text(size:16pt)[ECURITY]]
      ]
      #v(0.2em)
      #line(length: 100%, stroke: 1.6pt + black)
    ]

    #v(2.4cm)

    // --- Haupttitel ---
    #align(center)[
      #text(size: 30pt, weight: "bold")[#title]

      #v(0.4cm)
      #text(size: 18pt, weight: "bold")[#subtitle]

      #v(0.5cm)
      #block(width: 82%)[
        #text(size: 13pt, weight: "bold")[#description]
      ]
    ]

    #v(1fr)

    // --- Autoren (Name + Matrikelnummer) ---
    #align(center)[
      #text(size: 11pt, style: "italic")[Erstellt von:]
      #v(0.35cm)
      #for a in authors [
        #text(size: 11pt, weight: "medium")[#a.at(0)] #h(0.4em) #text(size: 10pt, fill: gray.darken(20%))[(#a.at(1))]
        #linebreak()
      ]
    ]

    #v(0.8cm)

    // --- Betreuer ---
    #align(center)[
      #text(size: 11pt, style: "italic")[Betreuer:]
      #v(0.25cm)
      #text(size: 11pt)[#betreuer]
      #if betreuer2 != none [ #linebreak() #text(size: 11pt)[#betreuer2] ]
    ]

    #v(1fr)

    // --- Aktenzeichen, Ort & Semester ---
    #align(center)[
      #text(size: 10pt, fill: gray.darken(20%))[Aktenzeichen: #aktenzeichen]
      #v(0.2cm)
      #text(size: 13pt)[#location -- #semester]
    ]
  ]
}