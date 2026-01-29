(function () {
  "use strict";

  /* ----------------------------------------------------
   * DATABASE
   * -------------------------------------------------- */
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

  /* ----------------------------------------------------
   * NAVIGATION
   * -------------------------------------------------- */
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

  /* ----------------------------------------------------
   * CONTENT PAGES
   * -------------------------------------------------- */
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
          "Minecraft Worlds is a community-driven platform for maps, servers and creative content.";

        content.append(h, p);
        break;
      }

      case "#contact": {
        const h = document.createElement("h1");
        h.textContent = "Contact";

        const p = document.createElement("p");
        p.textContent = "Send us your feedback or questions.";

        const form = document.createElement("form");
        form.id = "contactForm";

        const name = document.createElement("input");
        name.placeholder = "Name";
        name.required = true;

        const email = document.createElement("input");
        email.type = "email";
        email.placeholder = "Email";
        email.required = true;

        const msg = document.createElement("textarea");
        msg.placeholder = "Message";
        msg.required = true;

        const btn = document.createElement("button");
        btn.type = "submit";
        btn.textContent = "Send";

        const status = document.createElement("div");
        status.id = "formStatus";

        form.append(name, email, msg, btn);
        content.append(h, p, form, status);

        form.addEventListener("submit", e => {
          e.preventDefault();
          status.textContent = "Message sent successfully.";
          form.reset();
        });

        break;
      }

      case "#home":
      default: {
        const h = document.createElement("h1");
        h.textContent = "Welcome to Minecraft Worlds";

        const p = document.createElement("p");
        p.textContent =
          "Discover worlds, maps and servers created by the community.";

        const ul = document.createElement("ul");
        ["Maps", "Servers", "Community"].forEach(t => {
          const li = document.createElement("li");
          li.textContent = t;
          ul.appendChild(li);
        });

        content.append(h, p, ul);
        break;
      }
    }

    updateActiveNav(route);
  }

  /* ----------------------------------------------------
   * ACTIVE NAV STATE
   * -------------------------------------------------- */
  function updateActiveNav(route) {
    document.querySelectorAll(".main-nav a").forEach(a => {
      a.classList.toggle("active", a.getAttribute("href") === route);
    });
  }

  /* ----------------------------------------------------
   * ROUTER
   * -------------------------------------------------- */
  function initRouter() {
    window.addEventListener("hashchange", renderContent);
    renderContent();
  }

  /* ----------------------------------------------------
   * INIT
   * -------------------------------------------------- */
  function init() {
    renderNav("root", db);
    initRouter();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
