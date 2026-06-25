const menuButton = document.querySelector(".menu-button");
const siteNav = document.querySelector(".site-nav");

if (menuButton && siteNav) {
  const mobileQuery = window.matchMedia("(max-width: 1040px)");
  const focusSelector = 'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])';
  const backdrop = document.createElement("div");
  const closeButton = document.createElement("button");
  let isOpen = false;
  let scrollY = 0;

  if (!siteNav.id) {
    siteNav.id = "site-nav";
  }

  menuButton.setAttribute("aria-controls", siteNav.id);
  backdrop.className = "site-nav-backdrop";
  backdrop.setAttribute("aria-hidden", "true");
  backdrop.hidden = true;
  closeButton.type = "button";
  closeButton.className = "menu-close";
  closeButton.setAttribute("aria-label", "Close navigation");
  closeButton.textContent = "Close";
  siteNav.prepend(closeButton);
  document.body.append(backdrop);

  const focusFirstControl = () => {
    const firstControl = siteNav.querySelector(focusSelector);
    if (firstControl) {
      firstControl.focus({ preventScroll: true });
    }
  };

  const lockBodyScroll = () => {
    scrollY = window.scrollY;
    document.body.style.position = "fixed";
    document.body.style.top = `-${scrollY}px`;
    document.body.style.left = "0";
    document.body.style.right = "0";
    document.body.style.width = "100%";
  };

  const unlockBodyScroll = () => {
    document.body.style.position = "";
    document.body.style.top = "";
    document.body.style.left = "";
    document.body.style.right = "";
    document.body.style.width = "";
    window.scrollTo(0, scrollY);
  };

  const setExpandedState = (open) => {
    menuButton.setAttribute("aria-expanded", String(open));
    siteNav.setAttribute("aria-hidden", String(mobileQuery.matches && !open));
  };

  const closeMenu = ({ restoreFocus = true } = {}) => {
    if (!isOpen) {
      setExpandedState(false);
      return;
    }

    isOpen = false;
    siteNav.classList.remove("open");
    backdrop.classList.remove("open");
    backdrop.hidden = true;
    unlockBodyScroll();
    setExpandedState(false);

    if (restoreFocus) {
      menuButton.focus({ preventScroll: true });
    }
  };

  const openMenu = () => {
    if (isOpen) {
      return;
    }

    isOpen = true;
    siteNav.classList.add("open");
    backdrop.hidden = false;
    backdrop.classList.add("open");
    lockBodyScroll();
    setExpandedState(true);
    window.requestAnimationFrame(focusFirstControl);
  };

  menuButton.addEventListener("click", () => {
    if (isOpen) {
      closeMenu();
    } else {
      openMenu();
    }
  });

  closeButton.addEventListener("click", () => closeMenu());
  backdrop.addEventListener("click", () => closeMenu());

  siteNav.addEventListener("click", (event) => {
    if (event.target.closest("a")) {
      closeMenu();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (isOpen && event.key === "Escape") {
      closeMenu();
    }
  });

  document.addEventListener("pointerdown", (event) => {
    if (!isOpen || !mobileQuery.matches) {
      return;
    }

    const path = typeof event.composedPath === "function" ? event.composedPath() : [];
    if (path.includes(siteNav) || path.includes(menuButton)) {
      return;
    }

    closeMenu();
  });

  const handleViewportChange = () => {
    if (!mobileQuery.matches) {
      closeMenu({ restoreFocus: false });
      siteNav.setAttribute("aria-hidden", "false");
      backdrop.hidden = true;
      backdrop.classList.remove("open");
      return;
    }

    if (!isOpen) {
      siteNav.setAttribute("aria-hidden", "true");
      backdrop.hidden = true;
    }
  };

  if (typeof mobileQuery.addEventListener === "function") {
    mobileQuery.addEventListener("change", handleViewportChange);
  } else {
    mobileQuery.addListener(handleViewportChange);
  }

  handleViewportChange();
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
