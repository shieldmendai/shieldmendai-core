const menuButton = document.querySelector(".menu-button");

const drawerLinks = [
  ["How It Works", "how-it-works.html"],
  ["Pricing", "pricing.html"],
  ["Security", "security.html"],
  ["Tax Pack", "tax-pack.html"],
  ["Archive Mode", "archive-mode.html"],
  ["FAQ", "faq.html"],
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
        <a class="brand" href="index.html"><span class="brand-mark">S</span><span>ShieldMendAI</span></a>
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
