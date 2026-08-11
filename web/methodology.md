---
title: Methodology
description: The seven-phase evidence, interview, drafting, and backtesting workflow used by the threat-model skill.
---

<header class="page-hero">
  <div class="wrap">
    <span class="eyebrow">Methodology</span>
    <h1>A model built to be challenged.</h1>
    <p class="lede">The workflow starts from source and public commitments, exposes uncertainty, and tests whether the resulting contract can route real findings.</p>
  </div>
</header>

<section class="section">
<div class="wrap content-grid">
<aside class="side-note">
  <strong>Core principle</strong>
  Silence in documentation is not proof that a security property is disclaimed. Uncertainty remains visible until evidence or maintainers resolve it.
</aside>
<div class="prose" markdown="1">

## 3.1 Orient

Identify the project type, supported deployment shape, shipped artifacts, and
existing security policy. Establish the modeled tree and scope before drawing
conclusions from code.

## 3.2 Mine documented intent

Read API documentation, security guidance, release notes, issue history, and
maintainer decisions. These sources reveal the promises and non-goals users
already rely on.

## 3.3 Map the attack surface

Trace public entry points, input operands, output sinks, host side effects,
dependencies, build variants, and component reachability. The result is an
operand-level trust table rather than a vague “inputs are untrusted” statement.

## 3.4 Interview through proposed answers

Turn gaps into small waves of concrete questions. Each question states the
likely answer, its evidence, and exactly which model field changes when a
maintainer responds.

## 3.5 Author the contract

Write the canonical prose with explicit scope, trust boundaries, adversaries,
claimed and disclaimed properties, caller obligations, known misuse, and
conditions that invalidate the model.

## 3.6 Backtest

Route historical vulnerabilities, rejected reports, and representative controls
against the draft. A useful model must distinguish valid findings from
out-of-model reports without closing genuine vulnerabilities.

## 3.7 Iterate and publish

Revise contradictions, promote maintainer-confirmed claims, and either reach an
accepted model or publish an honestly labeled unratified draft. Generate the
YAML sidecar and JSON export only after the prose stabilizes.

<div class="callout callout-warning">
  <strong>Fail safe when authority is weak.</strong>
  An inferred fact may identify the likely disposition, but it cannot silently
  close a report. The route escalates until authoritative evidence exists.
</div>

## Publication gates

The final checks cover provenance, attack-surface coverage, triage usefulness,
cross-artifact consistency, source citations, and the completeness of the
fixed disposition set. The model is a maintained security artifact, not a
one-time generated document.

</div>
</div>
</section>

