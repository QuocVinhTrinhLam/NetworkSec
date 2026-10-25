(() => {
  const root = document.documentElement;
  const toggle = document.querySelector("[data-sidebar-toggle]");
  const close = document.querySelector("[data-sidebar-close]");
  const sidebar = document.getElementById("primary-sidebar");
  const mobile = window.matchMedia("(max-width: 960px)");

  const syncSidebar = () => {
    const hidden = mobile.matches && !root.classList.contains("sidebar-open");
    if (sidebar) {
      sidebar.inert = hidden;
      sidebar.setAttribute("aria-hidden", String(hidden));
    }
  };

  const setOpen = (open, restoreFocus = false) => {
    root.classList.toggle("sidebar-open", open);
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
  });
  mobile.addEventListener("change", () => {
    if (!mobile.matches) root.classList.remove("sidebar-open");
    syncSidebar();
  });
  syncSidebar();
})();
