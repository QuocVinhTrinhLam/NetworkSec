(() => {
  const root = document.documentElement;
  const toggle = document.querySelector("[data-sidebar-toggle]");
  const close = document.querySelector("[data-sidebar-close]");
  const sidebar = document.getElementById("primary-sidebar");
  const mobile = window.matchMedia("(max-width: 960px)");
  const focusableSelector = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  const syncSidebar = () => {
    const hidden = mobile.matches && !root.classList.contains("sidebar-open");
    if (sidebar) {
      sidebar.inert = hidden;
      sidebar.setAttribute("aria-hidden", String(hidden));
    }
  };

  const setOpen = (open, restoreFocus = false) => {
    root.classList.toggle("sidebar-open", open);
    document.body.classList.toggle("nav-open", open && mobile.matches);
    toggle?.setAttribute("aria-expanded", String(open));
    syncSidebar();
    if (open) sidebar?.querySelector(".primary-nav a.active")?.focus();
    if (!open && restoreFocus) toggle?.focus();
  };

  toggle?.addEventListener("click", () => {
    setOpen(!root.classList.contains("sidebar-open"));
  });
  close?.addEventListener("click", () => setOpen(false, true));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && root.classList.contains("sidebar-open")) {
      setOpen(false, true);
    }
    if (event.key === "Tab" && root.classList.contains("sidebar-open") && sidebar) {
      const focusable = [...sidebar.querySelectorAll(focusableSelector)];
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });
  mobile.addEventListener("change", () => {
    if (!mobile.matches) {
      setOpen(false);
      return;
    }
    document.body.classList.remove("nav-open");
    syncSidebar();
  });
  syncSidebar();
})();
