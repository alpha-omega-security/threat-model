---
title: Concepts
description: Plain-language explanations of security contracts, provenance, properties, trust boundaries, and dispositions.
---

<header class="page-hero">
  <div class="wrap">
    <span class="eyebrow">Core concepts</span>
    <h1>Threat modeling without the fog.</h1>
    <p class="lede">A small vocabulary for stating what the project owns and what remains the caller’s responsibility.</p>
  </div>
</header>

<section class="section">
<div class="wrap content-grid">
<aside class="side-note">
  <strong>Not an audit</strong>
  A threat model describes the intended contract. An audit looks for places where the implementation violates it.
</aside>
<div class="prose" markdown="1">

## Security contract

A security contract states which parties and data are trusted, what the
software promises under those assumptions, what it does not promise, and what
downstream users must enforce.

<div class="two-up">
  <div class="compact-card">
    <h3>Claimed property</h3>
    <p>A guarantee whose violation is a valid project finding, such as memory safety for attacker-controlled input.</p>
  </div>
  <div class="compact-card">
    <h3>Disclaimed property</h3>
    <p>A guarantee the project explicitly does not provide, such as authenticity from a non-cryptographic checksum.</p>
  </div>
</div>

## Trust boundary

A trust boundary is where data or authority crosses from an adversary-controlled
context into a trusted component. The model records the exact operands that can
cross it and the preconditions required to reach each component.

“The input is untrusted” is rarely precise enough. Compressed bytes may be
attacker-controlled while output buffers, lengths, callbacks, and configuration
remain caller-controlled and trusted.

## Provenance

Every closure-driving claim records why it should be believed.

| Kind | Meaning | May close a report? |
| --- | --- | --- |
| **documented** | Public project documentation or code establishes the claim | Yes |
| **maintainer** | A maintainer explicitly ruled on the claim | Yes |
| **inferred** | The model reasoned to the claim but still asks for confirmation | No; escalate |
| **assumption** | A conservative working assumption under an explicit policy | Limited and policy-dependent |

## Dispositions

A disposition is the single route assigned to a finding after checking the
model in precedence order. The closed set prevents project-specific euphemisms
from silently closing reports.

<div class="three-up">
  <div class="compact-card">
    <h3>VALID</h3>
    <p>The finding violates a property the project claims.</p>
  </div>
  <div class="compact-card">
    <h3>OUT-OF-MODEL</h3>
    <p>The finding requires a component, build, input, dependency violation, or adversary the contract excludes.</p>
  </div>
  <div class="compact-card">
    <h3>MODEL-GAP</h3>
    <p>No existing rule fits. Keep the finding open and revise the model.</p>
  </div>
</div>

## Model status

An **unratified draft** can be useful while still carrying unresolved claims;
its provenance prevents those claims from overreaching. An **accepted** model
has no inferred or assumed closure-driving facts left.

For the full vocabulary, read the
[canonical glossary]({{ site.repository_url }}/blob/main/skills/threat-model/references/glossary.md).

</div>
</div>
</section>

