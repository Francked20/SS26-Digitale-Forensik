// ============================================================
//  chapters/toc.typ — Inhaltsverzeichnis
// ============================================================

#import "../style/style.typ": accent

#let table-of-contents() = {
  show outline.entry.where(level: 1): it => {
    set text(weight: "bold", size: 11pt, fill: accent)
    v(0.7em, weak: true)
    it
  }

  outline(
    title: [Inhaltsverzeichnis],
    indent: auto,
    depth: 3,
  )



  pagebreak(weak: true)
}