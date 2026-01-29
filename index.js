(function () {
  "use strict";

  const db = [
    {
      name: "minecraftworlds",
      nav: [
        { name: "Home", class: "nav-home" },
        { name: "About", class: "nav-about" },
        { name: "Contact", class: "nav-contact" }
      ]
    }
  ];

  function renderNav(rootId, data) {
    const root = document.getElementById(rootId);
    if (!root) {
      console.error("Root element not found:", rootId);
      return;
    }

    // clear root safely
    root.textContent = "";

    const header = document.createElement("div");
    header.className = "header";

    const nav = document.createElement("nav");
    nav.className = "main-nav";

    data[0].nav.forEach(item => {
      const a = document.createElement("a");
      a.textContent = item.name;
      a.href = "#";
      if (item.class) a.className = item.class;
      nav.appendChild(a);
    });

    header.appendChild(nav);
    root.appendChild(header);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      renderNav("root", db);
    });
  } else {
    renderNav("root", db);
  }

})();
