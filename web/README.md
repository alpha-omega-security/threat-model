# Threat Model website

This directory contains the Jekyll source for the project website.

## Run locally

```bash
cd web
bundle install
bundle exec jekyll serve
```

Open <http://localhost:4000/threat-model/>. GitHub Pages deployment is defined
in `.github/workflows/pages.yml`.

## Add an example model

Add a Markdown file under `_models/` using the front matter in
`_models/zlib.md` as a template. Keep generated artifacts in their canonical
repository location and link to them through the `artifacts` list rather than
copying them into the website.

