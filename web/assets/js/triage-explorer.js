(() => {
  const form = document.querySelector("[data-triage-form]");
  if (!form) return;

  const route = form.elements.route;
  const provenance = form.elements.provenance;
  const policy = form.elements.policy;
  const tier = form.elements.tier;
  const tierField = form.querySelector("[data-tier-field]");
  const dispositionNode = document.querySelector("[data-result-disposition]");
  const statusNode = document.querySelector("[data-result-status]");
  const reasonNode = document.querySelector("[data-result-reason]");

  const routes = {
    "known-non-finding": {
      disposition: "KNOWN-NON-FINDING",
      closing: true,
      assumptionCloseable: false,
    },
    "unsupported-component": {
      disposition: "OUT-OF-MODEL: unsupported-component",
      closing: true,
      assumptionCloseable: true,
    },
    "non-default-build": {
      disposition: "OUT-OF-MODEL: non-default-build",
      closing: true,
      assumptionCloseable: true,
    },
    "dependency-contract": {
      disposition: "OUT-OF-MODEL: dependency-contract",
      closing: true,
      assumptionCloseable: false,
    },
    "trusted-input": {
      disposition: "OUT-OF-MODEL: trusted-input",
      closing: true,
      assumptionCloseable: true,
    },
    adversary: {
      disposition: "OUT-OF-MODEL: adversary-not-in-scope",
      closing: true,
      assumptionCloseable: true,
    },
    disclaimed: {
      disposition: "BY-DESIGN: property-disclaimed",
      closing: true,
      assumptionCloseable: true,
    },
    valid: {
      disposition: "VALID",
      closing: false,
      assumptionCloseable: false,
    },
    hardening: {
      disposition: "VALID-HARDENING",
      closing: false,
      assumptionCloseable: false,
    },
    "model-gap": {
      disposition: "MODEL-GAP",
      closing: false,
      assumptionCloseable: false,
    },
  };

  const update = () => {
    const selected = routes[route.value];
    tierField.hidden = route.value !== "disclaimed";
    dispositionNode.textContent = selected.disposition;

    if (route.value === "model-gap") {
      statusNode.textContent = "open";
      reasonNode.textContent =
        "No existing disposition is licensed. Keep the finding open and revise the model.";
      return;
    }

    if (!selected.closing) {
      statusNode.textContent = "open";
      reasonNode.textContent =
        "This disposition stays open by design. Record the model citation and continue the project’s finding process.";
      return;
    }

    if (provenance.value === "inferred") {
      statusNode.textContent = "escalated";
      reasonNode.textContent =
        "The route is plausible, but an inferred fact cannot close a report. Escalate for maintainer confirmation.";
      return;
    }

    if (provenance.value === "assumption") {
      const securityFloor =
        !selected.assumptionCloseable ||
        (route.value === "disclaimed" && tier.value !== "correctness-only");
      if (policy.value !== "relaxed" || securityFloor) {
        statusNode.textContent = "escalated";
        reasonNode.textContent =
          "This assumption lacks authority to close under the selected policy or security-critical floor.";
        return;
      }

      statusNode.textContent = "provisional";
      reasonNode.textContent =
        "A relaxed policy permits this low-blast-radius assumption to close provisionally and reopen on challenge.";
      return;
    }

    statusNode.textContent = "closed";
    reasonNode.textContent =
      "The closing route is licensed by an authoritative model fact. Record the exact citation with the disposition.";
  };

  form.addEventListener("change", update);
  update();
})();

