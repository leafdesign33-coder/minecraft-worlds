(function () {
  "use strict";

  /* ====================================================
   * CONFIG / DATABASE
   * ==================================================== */
  const app = {
    name: "minecraftworlds",

    nav: [
      { label: "Home", route: "#home", class: "nav-home" },
      { label: "About", route: "#about", class: "nav-about" },
      { label: "Contact", route: "#contact", class: "nav-contact" }
    ],

    classRoutes: {
      "nav-home": "#home",
      "nav-about": "#about",
      "nav-contact": "#contact",
      "go-home": "#home",
      "go-about": "#about",
      "go-contact": "#contact"
    }
  };

  /* ====================================================
   * PAGE DEFINITIONS
   * ==================================================== */
  const pages = {

    home(container) {
      const h = document.createElement("h1");
      h.textContent = "Welcome to Minecraft Worlds";

      const p = document.createElement("p");
      p.textContent =
        "Explore community-created Minecraft maps, worlds and servers.";

      const about = document.createElement("button");
      about.textContent = "About";
      about.className = "go-about";

      const contact = document.createElement("button");
      contact.textContent = "Contact";
      contact.className = "go-contact";

      container.append(h, p, about, contact);
    },

    about(container) {
      const h = document.createElement("h1");
      h.textContent = "About";

      const p1 = document.createElement("p");
      p1.textContent =
        "Minecraft Worlds is a community-driven platform.";

      const p2 = document.createElement("p");
      p2.textContent =
        "We focus on quality, security and creativity.";

      const back = document.createElement("button");
      back.textContent = "Back to Home";
      back.className = "go-home";

      container.append(h, p1, p2, back);
    },

    contact(container) {
      const h = document.createElement("h1");
      h.textContent = "Contact";

      const p = document.createElement("p");
      p.textContent = "Send us your feedback or ideas.";

      const form = document.createElement("form");

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

      const submit = document.createElement("button");
      submit.type = "submit";
      submit.textContent = "Send";

      const status = document.createElement("div");

      form.append(name, email, msg, submit);
      container.append(h, p, form, status);

      form.addEventListener("submit", e => {
        e.preventDefault();
        status.textContent = "Message sent successfully.";
        form.reset();
      });
    },

    notFound(container) {
      const h = document.createElement("h1");
      h.textContent = "404 – Page not found";

      const back = document.createElement("button");
      back.textContent = "Go Home";
      back.className = "go-home";

      container.append(h, back);
    }
  };

  /* ====================================================
   * NAVIGATION
   * ==================================================== */
  function renderNav() {
    const root = document.getElementById("root");
    if (!root) return;

    root.textContent = "";

    const header = document.createElement("div");
    header.className = "header";

    const nav = document.createElement("nav");
    nav.className = "main-nav";

    app.nav.forEach(item => {
      const a = document.createElement("a");
      a.textContent = item.label;
      a.href = item.route;
      a.className = item.class;
      nav.appendChild(a);
    });

    header.appendChild(nav);
    root.appendChild(header);
  }

  /* ====================================================
   * ROUTER
   * ==================================================== */
  function renderPage() {
    const content = document.getElementById("content");
    if (!content) return;

    content.textContent = "";

    const route = (window.location.hash || "#home").replace("#", "");

    (pages[route] || pages.notFound)(content);

    updateActiveNav("#" + route);
  }

  function updateActiveNav(route) {
    document.querySelectorAll(".main-nav a").forEach(a => {
      a.classList.toggle("active", a.getAttribute("href") === route);
    });
  }

  /* ====================================================
   * CLASS CLICK ROUTING (GLOBAL)
   * ==================================================== */
  function handleClassRouting(e) {
    let el = e.target;

    while (el && el !== document.body) {
      for (const cls in app.classRoutes) {
        if (el.classList.contains(cls)) {
          e.preventDefault();
          window.location.hash = app.classRoutes[cls];
          return;
        }
      }
      el = el.parentElement;
    }
  }

  /* ====================================================
   * INIT
   * ==================================================== */
  function init() {
    renderNav();
    renderPage();

    window.addEventListener("hashchange", renderPage);
    document.addEventListener("click", handleClassRouting);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
