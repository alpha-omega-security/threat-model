---
title: Reference
description: Canonical schemas, output specifications, validation gates, glossary, and source repository links.
---

<header class="page-hero">
  <div class="wrap">
    <span class="eyebrow">Reference</span>
    <h1>The operational specification.</h1>
    <p class="lede">The website explains the system; the versioned repository files remain authoritative.</p>
  </div>
</header>

<section class="section">
  <div class="wrap">
    <div class="reference-grid">
      <article class="card">
        <span class="eyebrow">Format</span>
        <h3>Output structure</h3>
        <p>The canonical §1.1–§1.19 prose sections, required tables, provenance tags, and disposition set.</p>
        <a class="card-link" href="{{ site.repository_url }}/blob/main/skills/threat-model/references/output-structure.md">Read specification ↗</a>
      </article>
      <article class="card">
        <span class="eyebrow">Automation</span>
        <h3>YAML sidecar</h3>
        <p>The near-lossless structured model consumed by validation and triage tooling.</p>
        <a class="card-link" href="{{ site.repository_url }}/blob/main/skills/threat-model/references/sidecar-schema.md">Read sidecar schema ↗</a>
      </article>
      <article class="card">
        <span class="eyebrow">Interchange</span>
        <h3>JSON schema</h3>
        <p>The conservative external export, its provenance collapse, and the detail it intentionally omits.</p>
        <a class="card-link" href="{{ site.repository_url }}/blob/main/schema.json">View schema ↗</a>
      </article>
      <article class="card">
        <span class="eyebrow">Method</span>
        <h3>Principles</h3>
        <p>The four-question framework and the boundary between a model, an audit, and build hygiene.</p>
        <a class="card-link" href="{{ site.repository_url }}/blob/main/skills/threat-model/references/principles.md">Read principles ↗</a>
      </article>
      <article class="card">
        <span class="eyebrow">Quality</span>
        <h3>Self-check</h3>
        <p>The publication gates for evidence, coverage, triage readiness, and cross-artifact consistency.</p>
        <a class="card-link" href="{{ site.repository_url }}/blob/main/skills/threat-model/references/self-check.md">Read validation gates ↗</a>
      </article>
      <article class="card">
        <span class="eyebrow">Language</span>
        <h3>Glossary</h3>
        <p>Plain-language definitions for trust boundaries, sinks, provenance, properties, and dispositions.</p>
        <a class="card-link" href="{{ site.repository_url }}/blob/main/skills/threat-model/references/glossary.md">Open glossary ↗</a>
      </article>
    </div>
  </div>
</section>

<section class="section section-dark">
  <div class="wrap">
    <span class="eyebrow">Source of truth</span>
    <h2>Everything is versioned in Git.</h2>
    <p class="lede">Browse the orchestrator, specialist skills, evaluation harness, schemas, and release history in the repository.</p>
    <a class="button button-primary" href="{{ site.repository_url }}">Open the repository</a>
  </div>
</section>

