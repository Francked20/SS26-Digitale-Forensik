# DigFor

This repository contains the `Operation Silent Quarry` report source files, written in a custom `.typ` document format. The project is structured as a single main document with chapter files and a shared style definition.

## Repository structure

- `main.typ` — main document that assembles the report
- `chapters/` — individual chapter files included by `main.typ`
- `style/` — shared styling and layout definitions
- `res/` — supporting resources used by the document
- `.gitignore` — excludes generated `main.typ` output if needed

## How the project is organized

The root `main.typ` file:
- imports the global style template from `style/style.typ`
- includes title page and table of contents
- loads chapter files under `chapters/`
- keeps the overall document structure in one place

Each file in `chapters/` represents a section of the final report.

## Usage

1. Edit the chapter files in `chapters/` or update the layout in `style/style.typ`.
2. Keep `main.typ` as the entry point for building the final document.
3. If a compiler or generator is used for `.typ` files, run it against `main.typ`.

> Note: This README does not assume a specific `.typ` toolchain. If you have one, add the exact build command here.

## Git workflow guide

Use Git to keep the document source versioned and collaborate safely.

### Common workflow

1. Create a branch for your work:
   ```bash
   git checkout -b feature/update-analysis
   ```
2. Make small, incremental changes in chapter files.
3. Stage and commit meaningful changes:
   ```bash
   git add chapters/analyse_linux.typ
   git commit -m "Update Linux analysis section"
   ```
4. Push your branch and open a pull request:
   ```bash
   git push origin feature/update-analysis
   ```

### Commit message guidance

- Use clear, concise messages.
- Mention which chapter or section changed.
- Prefer present-tense verbs, for example: `Add Windows analysis details`.

### Collaboration tips

- Keep each branch focused on a single section or purpose.
- Review chapter changes before merging.
- Avoid committing large generated files unless required by the build process.

## Notes

- The project appears to be a text/source repository, so keep generated artifacts out of version control.
- If you add a build step later, update this README with exact commands and any required tools.
