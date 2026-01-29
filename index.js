(function () {
  "use strict";

  /* ====================================================
   * DATABASE
   * ==================================================== */
  const db = [
    {
      name: "minecraftworlds",
      nav: [
        { name: "Home", hash: "#home", class: "nav-home" },
        { name: "About", hash: "#about", class: "nav-about" },
        { name: "Contact", hash: "#contact", class: "nav-contact" }
      ]
    }
  ];

  /* ====================================================
   * CLASS → ROUTE MAPPING
   * ==================================================== */
  const classRoutes = {
    "nav-home": "#home",
    "nav-about": "#about",
    "nav-contact": "#contact",

    // frei nutzbar überall im HTML
    "go-home": "#home",
    "go-about": "#about",
    "go-contact": "#contact"
  };

  /* ====================================================
   * NAVIGATION RENDER
   * ==================================================== */
  function renderNav(rootId, data) {
    const root = document.getElementById(rootId);
    if (!root) {
      console.error("Root element not found:", rootId);
      return;
    }

    root.textContent = "";

    const header = document.createElement("div");
    header.className = "header";

    const nav = document.createElement("nav");
    nav.className = "main-nav";

    data[0].nav.forEach(item => {
      const a = document.createElement("a");
      a.textContent = item.name;
      a.href = item.hash;
      a.className = item.class;
      nav.appendChild(a);
    });

    header.appendChild(nav);
    root.appendChild(header);
  }

  /* ====================================================
   * CONTENT ROUTES
   * ==================================================== */
  function renderContent() {
    const content = document.getElementById("content");
    if (!content) return;

    const route = window.location.hash || "#home";
    content.textContent = "";

    switch (route) {
      case "#about": {
        const h = document.createElement("h1");
        h.textContent = "About Minecraft Worlds";

        const p = document.createElement("p");
        p.textContent =
          "A community platform for Minecraft worlds, maps and servers.";

        content.append(h, p);
        break;
      }

      case "#contact": {
        const h = document.createElement("h1");
        h.textContent = "Contact";

        const p = document.createElement("p");
        p.textContent = "Get in touch with us.";

        const btn = document.createElement("button");
        btn.textContent = "Back to Home";
        btn.className = "go-home";

        content.append(h, p, btn);
        break;
      }

      case "#home":
      default: {
        const h = document.createElement("h1");
        h.textContent = "Welcome to Minecraft Worlds";

        const p = document.createElement("p");
        p.textContent =
          "Explore maps, servers and community projects.";

        const aboutBtn = document.createElement("button");
        aboutBtn.textContent = "About";
        aboutBtn.className = "go-about";

        const contactBtn = document.createElement("button");
        contactBtn.textContent = "Contact";
        contactBtn.className = "go-contact";

        content.append(h, p, aboutBtn, contactBtn);
        break;
      }
    }

    updateActiveNav(route);
  }

  /* ====================================================
   * ACTIVE NAV STATE
   * ==================================================== */
  function updateActiveNav(route) {
    document.querySelectorAll(".main-nav a").forEach(a => {
      a.classList.toggle(
        "active",
        a.getAttribute("href") === route
      );
    });
  }

  /* ====================================================
   * CLASS CLICK ROUTING (GLOBAL)
   * ==================================================== */
  function handleClassRouting(e) {
    let el = e.target;

    while (el && el !== document.body) {
      for (const cls in classRoutes) {
        if (el.classList.contains(cls)) {
          e.preventDefault();
          window.location.hash = classRoutes[cls];
          return;
        }
      }
      el = el.parentElement;
    }
  }

  /* ====================================================
   * ROUTER
   * ==================================================== */
  function initRouter() {
    window.addEventListener("hashchange", renderContent);
    renderContent();
  }

  /* ====================================================
   * INIT
   * ==================================================== */
  function init() {
    renderNav("root", db);
    initRouter();
    document.addEventListener("click", handleClassRouting);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
