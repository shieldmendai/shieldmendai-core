const menuButton = document.querySelector(".menu-button");
const siteNav = document.querySelector(".site-nav");

if (menuButton && siteNav) {
  const mobileQuery = window.matchMedia("(max-width: 1040px)");
  const backdrop = document.createElement("div");
  const closeButton = document.createElement("button");
  let isOpen = false;

  if (!siteNav.id) {
    siteNav.id = "site-nav";
  }

  menuButton.setAttribute("aria-controls", siteNav.id);
  menuButton.setAttribute("aria-expanded", "false");

  backdrop.className = "site-nav-backdrop";
  backdrop.hidden = true;
  document.body.append(backdrop);

  closeButton.type = "button";
  closeButton.className = "menu-close";
  closeButton.textContent = "Close";
  closeButton.setAttribute("aria-label", "Close navigation");
  siteNav.prepend(closeButton);

  const setState = (open) => {
    isOpen = open;
    menuButton.setAttribute("aria-expanded", String(open));
    siteNav.classList.toggle("open", open);
    backdrop.classList.toggle("open", open);
    backdrop.hidden = !open;
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
  backdrop.addEventListener("click", () => closeMenu());

  siteNav.addEventListener("click", (event) => {
    if (event.target.closest("a")) {
      closeMenu({ restoreFocus: false });
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isOpen) {
      closeMenu();
    }
  });

  document.addEventListener("pointerdown", (event) => {
    if (!isOpen) return;
    const path = typeof event.composedPath === "function" ? event.composedPath() : [];
    if (!path.includes(siteNav) && !path.includes(menuButton)) {
      closeMenu();
    }
  });

  const handleViewportChange = () => {
    if (mobileQuery.matches) {
      siteNav.setAttribute("aria-hidden", String(!isOpen));
      return;
    }

    setState(false);
    siteNav.setAttribute("aria-hidden", "false");
  };

  if (typeof mobileQuery.addEventListener === "function") {
    mobileQuery.addEventListener("change", handleViewportChange);
  } else {
    mobileQuery.addListener(handleViewportChange);
  }

  handleViewportChange();
}
