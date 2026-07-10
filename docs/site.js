const menuButton = document.querySelector(".menu-button");

const drawerLinks = [
  ["How It Works", "how-it-works.html"],
  ["Pricing", "pricing.html"],
  ["Security", "security.html"],
  ["Tax Pack", "tax-pack.html"],
  ["Archive Mode", "archive-mode.html"],
  ["Community Token", "community-token.html"],
  ["FAQ", "faq.html"],
  ["Beta Access", "beta.html"],
  ["Start Free Scan", "dashboard.html", "drawer-cta"],
];

if (menuButton) {
  const drawer = document.createElement("div");
  drawer.className = "mobile-drawer";
  drawer.hidden = true;
  drawer.innerHTML = `
    <div class="mobile-drawer__backdrop" data-menu-close></div>
    <aside class="mobile-drawer__panel" role="dialog" aria-modal="true" aria-label="Mobile navigation">
      <div class="mobile-drawer__top">
        <a class="brand brand-wordmark" href="index.html">ShieldMendAI</a>
        <button class="mobile-drawer__close" type="button" aria-label="Close navigation">Close</button>
      </div>
      <nav class="mobile-drawer__nav" aria-label="Mobile">
        ${drawerLinks.map(([label, href, className]) => `<a${className ? ` class="${className}"` : ""} href="${href}">${label}</a>`).join("")}
      </nav>
    </aside>
  `;
  document.body.append(drawer);

  const panel = drawer.querySelector(".mobile-drawer__panel");
  const backdrop = drawer.querySelector(".mobile-drawer__backdrop");
  const closeButton = drawer.querySelector(".mobile-drawer__close");
  const links = drawer.querySelectorAll("a");
  let closeTimer;

  menuButton.setAttribute("aria-controls", "mobile-drawer");
  menuButton.setAttribute("aria-expanded", "false");
  drawer.id = "mobile-drawer";

  const openMenu = () => {
    clearTimeout(closeTimer);
    drawer.hidden = false;
    requestAnimationFrame(() => {
      drawer.classList.add("is-open");
      document.body.classList.add("menu-open");
      menuButton.setAttribute("aria-expanded", "true");
      closeButton.focus({ preventScroll: true });
    });
  };

  const closeMenu = ({ restoreFocus = true } = {}) => {
    drawer.classList.remove("is-open");
    document.body.classList.remove("menu-open");
    menuButton.setAttribute("aria-expanded", "false");
    closeTimer = window.setTimeout(() => {
      drawer.hidden = true;
      if (restoreFocus) menuButton.focus({ preventScroll: true });
    }, 230);
  };

  menuButton.addEventListener("click", () => {
    if (drawer.classList.contains("is-open")) closeMenu();
    else openMenu();
  });

  drawer.addEventListener("click", (event) => {
    if (event.target === backdrop) closeMenu();
  });
  panel.addEventListener("click", (event) => event.stopPropagation());
  closeButton.addEventListener("click", () => closeMenu());

  links.forEach((link) => {
    link.addEventListener("click", () => closeMenu({ restoreFocus: false }));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && drawer.classList.contains("is-open")) {
      closeMenu();
    }
  });
}

const revealTargets = document.querySelectorAll(
  ".hero-inner > *, .section, .card, .app-preview, .accordion-item, .notice"
);

revealTargets.forEach((target) => target.classList.add("reveal"));

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

if (reduceMotion.matches || !("IntersectionObserver" in window)) {
  revealTargets.forEach((target) => target.classList.add("is-visible"));
} else {
  const revealObserver = new IntersectionObserver(
    (entries, observer) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    },
    { threshold: 0.14, rootMargin: "0px 0px -40px 0px" }
  );

  revealTargets.forEach((target) => revealObserver.observe(target));
}

document.querySelectorAll(".accordion-trigger").forEach((trigger) => {
  const panel = document.getElementById(trigger.getAttribute("aria-controls"));
  if (!panel) return;

  trigger.addEventListener("click", () => {
    const open = trigger.getAttribute("aria-expanded") === "true";
    trigger.setAttribute("aria-expanded", String(!open));
    panel.classList.toggle("is-open", !open);
    panel.hidden = open;
  });
});

document.querySelectorAll("[data-copy-value]").forEach((button) => {
  const status = button.parentElement ? button.parentElement.querySelector("[data-copy-status]") : null;
  let resetTimer;

  const setStatus = (message) => {
    if (!status) return;
    status.textContent = message;
    clearTimeout(resetTimer);
    resetTimer = window.setTimeout(() => {
      status.textContent = "";
    }, 2200);
  };

  const copyWithFallback = (value) => {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.top = "-999px";
    document.body.append(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    if (!copied) throw new Error("copy failed");
  };

  button.addEventListener("click", async () => {
    const value = button.dataset.copyValue || "";
    if (!value) return;

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        copyWithFallback(value);
      }
      setStatus("Copied");
    } catch {
      setStatus("Copy failed");
    }
  });
});

const pricingModal = document.querySelector("[data-pricing-modal]");

if (pricingModal) {
  const title = pricingModal.querySelector("#pricing-modal-title");
  const closeControls = pricingModal.querySelectorAll("[data-pricing-close]");
  let lastPlanButton = null;

  const openPricingModal = (planName, button) => {
    lastPlanButton = button;
    if (title) title.textContent = `${planName} plan details`;
    pricingModal.hidden = false;
    document.body.classList.add("menu-open");
    const closeButton = pricingModal.querySelector(".pricing-modal__close");
    if (closeButton) closeButton.focus({ preventScroll: true });
  };

  const closePricingModal = () => {
    pricingModal.hidden = true;
    document.body.classList.remove("menu-open");
    if (lastPlanButton) lastPlanButton.focus({ preventScroll: true });
  };

  document.querySelectorAll("[data-plan-info]").forEach((button) => {
    button.addEventListener("click", () => openPricingModal(button.dataset.planInfo || "Selected", button));
  });

  closeControls.forEach((control) => {
    control.addEventListener("click", closePricingModal);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !pricingModal.hidden) closePricingModal();
  });
}

const backendStatusCard = document.querySelector("[data-backend-status]");

if (backendStatusCard) {
  const statusText = backendStatusCard.querySelector("[data-backend-status-text]");
  const backendBadge = backendStatusCard.querySelector("[data-backend-backend]");
  const walletScanBadge = backendStatusCard.querySelector("[data-backend-wallet-scan]");
  const taxEngineBadge = backendStatusCard.querySelector("[data-backend-tax-engine]");

  // GitHub Pages is static. Production should set this from hosting config,
  // not by committing private API keys, RPC URLs, or provider credentials.
  const backendUrl = window.SHIELDMEND_BACKEND_URL;

  if (backendUrl) {
    fetch(`${String(backendUrl).replace(/\/$/, "")}/api/status`, {
      headers: { "Accept": "application/json" },
    })
      .then((response) => {
        if (!response.ok) throw new Error("status request failed");
        return response.json();
      })
      .then((status) => {
        if (statusText) statusText.textContent = "Backend status fetched from the configured read-only API.";
        if (backendBadge) backendBadge.textContent = status.backend || "unknown";
        if (walletScanBadge) walletScanBadge.textContent = status.walletScan || "unknown";
        if (taxEngineBadge) taxEngineBadge.textContent = status.taxEngine || "unknown";
      })
      .catch(() => {
        if (statusText) statusText.textContent = "Backend URL is configured, but the status endpoint is not reachable.";
        if (backendBadge) backendBadge.textContent = "Unavailable";
      });
  }
}

document.querySelectorAll("[data-countdown-target]").forEach((countdown) => {
  const target = new Date(countdown.dataset.countdownTarget);
  const status = countdown.querySelector("[data-countdown-status]");
  const days = countdown.querySelector("[data-countdown-days]");
  const hours = countdown.querySelector("[data-countdown-hours]");
  const minutes = countdown.querySelector("[data-countdown-minutes]");
  const seconds = countdown.querySelector("[data-countdown-seconds]");

  if (Number.isNaN(target.getTime())) return;

  const setText = (element, value) => {
    if (element) element.textContent = String(value).padStart(2, "0");
  };

  const renderCountdown = () => {
    const remaining = target.getTime() - Date.now();

    if (remaining <= 0) {
      if (status) status.textContent = "Launch window is live. Check the official launch link.";
      setText(days, 0);
      setText(hours, 0);
      setText(minutes, 0);
      setText(seconds, 0);
      return;
    }

    const totalSeconds = Math.floor(remaining / 1000);
    const dayValue = Math.floor(totalSeconds / 86400);
    const hourValue = Math.floor((totalSeconds % 86400) / 3600);
    const minuteValue = Math.floor((totalSeconds % 3600) / 60);
    const secondValue = totalSeconds % 60;

    if (status) status.textContent = "Time remaining";
    setText(days, dayValue);
    setText(hours, hourValue);
    setText(minutes, minuteValue);
    setText(seconds, secondValue);
  };

  renderCountdown();
  window.setInterval(renderCountdown, 1000);
});
