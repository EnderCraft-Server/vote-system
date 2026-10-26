/* 前台交互：排序调整、字数统计、防重复提交、错误聚焦。
   不依赖任何框架；CSP 只允许同源脚本。 */
(function () {
  "use strict";

  /* ---- 排序题 ---- */
  document.querySelectorAll("[data-rank]").forEach(function (list) {
    var items = function () { return Array.prototype.slice.call(list.querySelectorAll(".rank-item")); };

    function refresh() {
      items().forEach(function (item, index) {
        var pos = item.querySelector(".rank-pos");
        if (pos) pos.textContent = String(index + 1);
        var up = item.querySelector('[data-move="-1"]');
        var down = item.querySelector('[data-move="1"]');
        if (up) up.disabled = index === 0;
        if (down) down.disabled = index === items().length - 1;
      });
    }

    list.addEventListener("click", function (event) {
      var btn = event.target.closest("[data-move]");
      if (!btn) return;
      var item = btn.closest(".rank-item");
      if (!item) return;
      var dir = Number(btn.getAttribute("data-move"));
      var all = items();
      var index = all.indexOf(item);
      var target = index + dir;
      if (target < 0 || target >= all.length) return;
      if (dir < 0) {
        list.insertBefore(item, all[target]);
      } else {
        list.insertBefore(all[target], item);
      }
      refresh();
      var live = list.parentElement.querySelector("[data-rank-live]");
      if (live) {
        var pos = item.querySelector(".rank-pos");
        live.textContent = (item.querySelector(".rank-label") || {}).textContent + " → 第 " + pos.textContent + " 位";
      }
      btn.focus();
    });

    refresh();
  });

  /* ---- 简答题字数 ---- */
  document.querySelectorAll("textarea[data-counter]").forEach(function (area) {
    var target = document.getElementById(area.getAttribute("data-counter"));
    if (!target) return;
    var template = target.textContent || "";
    var max = Number(area.getAttribute("maxlength")) || 0;
    function update() {
      var count = Array.from(area.value).length;
      target.textContent = template.replace(/^\d+/, String(count));
      if (max > 0 && count > max * 0.9) {
        target.style.color = "var(--stamp)";
      } else {
        target.style.removeProperty("color");
      }
    }
    area.addEventListener("input", update);
    update();
  });

  /* ---- 防重复提交 ---- */
  document.querySelectorAll("form.vote-form").forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = form.querySelector('button[type="submit"]');
      if (!btn) return;
      if (btn.dataset.busy === "1") return;
      btn.dataset.busy = "1";
      btn.disabled = true;
      window.setTimeout(function () {
        /* 服务端返回错误时页面会重载，这里只是兜底恢复 */
        if (btn.dataset.busy === "1") {
          btn.disabled = false;
          btn.dataset.busy = "0";
        }
      }, 8000);
    });
  });

  /* ---- 提交失败时聚焦错误区 ---- */
  var errorBox = document.getElementById("form-error");
  if (errorBox) {
    errorBox.focus();
  }
})();
