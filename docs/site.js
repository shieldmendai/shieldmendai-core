const menuButton = document.querySelector(".menu-button");
const siteNav = document.querySelector(".site-nav");

if (menuButton && siteNav) {
  menuButton.addEventListener("click", () => {
    const open = siteNav.classList.toggle("open");
    menuButton.setAttribute("aria-expanded", String(open));
  });

  siteNav.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      siteNav.classList.remove("open");
      menuButton.setAttribute("aria-expanded", "false");
    });
  });
}

const simulatorForm = document.querySelector("#simulator-form");
const simulatorOutput = document.querySelector("#simulator-output");

if (simulatorForm && simulatorOutput) {
  const scenarios = {
    service: {
      target: "api-worker.service",
      observer: "systemd_service",
      finding: "unhealthy",
      category: "service_unavailable",
      proposed: "restart_service",
    },
    api: {
      target: "public-api",
      observer: "http",
      finding: "degraded",
      category: "endpoint_failure",
      proposed: "restart_service",
    },
    file: {
      target: "runtime-config",
      observer: "yaml_file",
      finding: "unhealthy",
      category: "invalid_configuration",
      proposed: "restore_known_good_file",
    },
  };

  simulatorForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(simulatorForm);
    const scenario = scenarios[data.get("scenario")];
    const approval = data.get("approval");
    const verification = data.get("verification");
    const authorized = approval === "approved";
    const verified = verification === "passed";
    const outcome = !authorized
      ? "repair_denied"
      : verified
        ? "simulated_recovery_succeeded"
        : "manual_intervention_required";

    const lines = [
      "[SIMULATION ONLY] No live target, process, network, or provider was contacted.",
      "",
      `01 observe     target=${scenario.target} adapter=${scenario.observer}`,
      `02 classify    status=${scenario.finding} category=${scenario.category}`,
      `03 propose     action=${scenario.proposed} risk=low`,
      `04 authorize   policy=deny_by_default decision=${authorized ? "allow_simulation" : "deny"}`,
    ];

    if (authorized) {
      lines.push(
        `05 act         deterministic_outcome=simulated_success`,
        `06 verify      supplied_result=${verification}`,
        `07 rollback    ${verified ? "not_required" : "simulated_rollback_planned"}`,
      );
    } else {
      lines.push("05 act         skipped_reason=authorization_denied");
    }

    lines.push(
      `08 incident    versioned_record=true integrity_check=true`,
      `09 outcome     ${outcome}`,
      "",
      "Production availability: false",
      "Live repair performed: false",
      "Notification delivered: false",
    );

    simulatorOutput.textContent = lines.join("\n");
    simulatorOutput.focus();
  });
}
