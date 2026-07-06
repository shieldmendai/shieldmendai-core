const menuButton = document.querySelector(".menu-button");
const siteNav = document.querySelector(".site-nav");

if (menuButton && siteNav) {
  const mobileQuery = window.matchMedia("(max-width: 1040px)");
  const overlay = document.createElement("div");
  const closeButton = document.createElement("button");
  let isOpen = false;

  if (!siteNav.id) {
    siteNav.id = "site-nav";
  }

  menuButton.setAttribute("aria-controls", siteNav.id);
  menuButton.setAttribute("aria-expanded", "false");

  overlay.className = "mobile-menu-overlay";
  overlay.hidden = true;
  document.body.append(overlay);
  siteNav.classList.add("mobile-menu-panel");

  closeButton.type = "button";
  closeButton.className = "menu-close";
  closeButton.textContent = "Close";
  closeButton.setAttribute("aria-label", "Close navigation");
  siteNav.prepend(closeButton);

  const setState = (open) => {
    isOpen = open;
    menuButton.setAttribute("aria-expanded", String(open));
    siteNav.classList.toggle("open", open);
    overlay.classList.toggle("is-open", open);
    overlay.hidden = !open;
    document.body.classList.toggle("menu-open", open);
    siteNav.setAttribute("aria-hidden", String(mobileQuery.matches && !open));
  };

  const openMenu = () => {
    if (!mobileQuery.matches || isOpen) return;
    setState(true);
    closeButton.focus({ preventScroll: true });
  };

  const closeMenu = ({ restoreFocus = true } = {}) => {
    if (!isOpen) {
      setState(false);
      return;
    }
    setState(false);
    if (restoreFocus) {
      menuButton.focus({ preventScroll: true });
    }
  };

  menuButton.addEventListener("click", () => {
    if (isOpen) closeMenu();
    else openMenu();
  });

  closeButton.addEventListener("click", () => closeMenu());

  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) closeMenu();
  });

  siteNav.addEventListener("click", (event) => {
    event.stopPropagation();
  });

  siteNav.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => closeMenu({ restoreFocus: false }));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isOpen) {
      closeMenu();
    }
  });

  const handleViewportChange = () => {
    if (mobileQuery.matches) {
      siteNav.setAttribute("aria-hidden", String(!isOpen));
      return;
    }

    setState(false);
    overlay.hidden = true;
    siteNav.setAttribute("aria-hidden", "false");
  };

  if (typeof mobileQuery.addEventListener === "function") {
    mobileQuery.addEventListener("change", handleViewportChange);
  } else {
    mobileQuery.addListener(handleViewportChange);
  }

  handleViewportChange();
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
