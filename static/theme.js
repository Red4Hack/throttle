(function () {
  var r = document.documentElement, t = localStorage.getItem("theme");
  if (t) r.dataset.theme = t;
  document.addEventListener("DOMContentLoaded", function () {
    var b = document.getElementById("theme-toggle");
    if (!b) return;
    b.addEventListener("click", function () {
      var dark = (r.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
      r.dataset.theme = dark ? "light" : "dark";
      localStorage.setItem("theme", r.dataset.theme);
    });
  });
})();
