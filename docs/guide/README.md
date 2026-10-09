# PiLens user guide (LaTeX)

A deliberately skimmable, callout-heavy user guide. British English.

- `pilens-guide.tex` — source
- `fig/` — UI screenshots (captured headless from a running appliance)
- `pilens-guide.pdf` — built, 12 pages A4

Rebuild:

```sh
cd docs/guide && pdflatex pilens-guide.tex && pdflatex pilens-guide.tex
```

Needs a TeX Live with `tcolorbox`, `titlesec`, `enumitem`, `fancyhdr`, `tikz`.
