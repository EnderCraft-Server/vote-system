/* 题目编辑器：题目块全部由前端渲染，服务端只提供初始 JSON。
   刻意不用 innerHTML 拼接（用户输入可能含 <>），所有文本走 textContent。 */
(function () {
  "use strict";

  var host = document.getElementById("questions");
  if (!host) return;

  var readonly = host.dataset.readonly === "1";
  var initial = [];
  try {
    initial = JSON.parse(host.dataset.qjson || "[]");
  } catch (e) {
    initial = [];
  }
  var nextIndex = initial.length;

  var TYPES = [
    ["single", "单选"],
    ["multiple", "多选"],
    ["text", "简答"],
    ["rank", "排序"]
  ];

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function labeled(text, control) {
    var wrap = el("label");
    wrap.appendChild(document.createTextNode(text));
    wrap.appendChild(control);
    return wrap;
  }

  function input(name, type, value) {
    var i = document.createElement("input");
    i.type = type;
    i.name = name;
    if (value !== undefined && value !== null) i.value = value;
    if (readonly) i.disabled = true;
    return i;
  }

  function renumber() {
    var sets = host.querySelectorAll("fieldset.q");
    for (var i = 0; i < sets.length; i++) {
      var legend = sets[i].querySelector("legend .q-no");
      if (legend) legend.textContent = "第 " + (i + 1) + " 题";
    }
  }

  function buildLimits(fieldset, idx, q) {
    var old = fieldset.querySelector(".q-limits");
    if (old) old.remove();
    var box = el("div", "q-limits grid-3");
    var required = document.createElement("input");
    required.type = "checkbox";
    required.name = "q" + idx + "_required";
    required.checked = q ? !!q.required : true;
    if (readonly) required.disabled = true;
    var requiredLabel = el("label", "check");
    requiredLabel.appendChild(required);
    requiredLabel.appendChild(document.createTextNode(" 必答"));

    box.appendChild(requiredLabel);
    if (q && (q.type === "multiple")) {
      box.appendChild(labeled("最少选择", input("q" + idx + "_min", "number", q.min_choices || 1)));
      box.appendChild(labeled("最多选择（0 表示不限）", input("q" + idx + "_max", "number", q.max_choices || 0)));
    } else if (q && q.type === "text") {
      box.appendChild(labeled("字数上限", input("q" + idx + "_max_length", "number", q.max_length || 300)));
    } else {
      box.appendChild(el("span"));
      box.appendChild(el("span"));
    }
    fieldset.appendChild(box);
  }

  function buildOptions(fieldset, idx, q) {
    var old = fieldset.querySelector(".opts");
    if (old) old.remove();
    var addBtn = fieldset.querySelector(".q-addopt");
    if (addBtn) addBtn.remove();

    if (q && q.type === "text") return;

    var box = el("div", "opts");
    box.dataset.optHost = "1";
    fieldset.appendChild(box);

    var labels = (q && q.options) ? q.options : ["", ""];
    for (var i = 0; i < labels.length; i++) addOptionRow(box, idx, labels[i]);

    if (!readonly) {
      var btn = el("button", "btn-quiet q-addopt", "＋ 选项");
      btn.type = "button";
      btn.addEventListener("click", function () {
        addOptionRow(box, idx, "");
        syncOptionIndexes(box);
      });
      fieldset.appendChild(btn);
    }
    syncOptionIndexes(box);
  }

  function addOptionRow(box, idx, value) {
    var row = el("div", "opt-row");
    var field = input("q" + idx + "_opt0", "text", value);
    field.placeholder = "选项文字";
    row.appendChild(field);
    if (!readonly) {
      var del = el("button", "btn-quiet", "删除");
      del.type = "button";
      del.addEventListener("click", function () {
        row.remove();
        syncOptionIndexes(box);
      });
      row.appendChild(del);
    }
    box.appendChild(row);
  }

  function syncOptionIndexes(box) {
    var rows = box.querySelectorAll(".opt-row input");
    for (var i = 0; i < rows.length; i++) {
      rows[i].name = rows[i].name.replace(/_opt\d+$/, "_opt" + i);
    }
  }

  function buildQuestion(q) {
    var idx = nextIndex++;
    var fieldset = el("fieldset", "q");
    fieldset.dataset.q = String(idx);

    var legend = el("legend");
    legend.appendChild(el("span", "q-no", "第 " + (host.querySelectorAll("fieldset.q").length + 1) + " 题"));
    if (!readonly) {
      var del = el("button", "btn-quiet q-del", "删除");
      del.type = "button";
      del.addEventListener("click", function () {
        fieldset.remove();
        renumber();
      });
      legend.appendChild(del);
    }
    fieldset.appendChild(legend);

    var top = el("div", "grid-2");
    var select = document.createElement("select");
    select.name = "q" + idx + "_type";
    if (readonly) select.disabled = true;
    for (var t = 0; t < TYPES.length; t++) {
      var opt = document.createElement("option");
      opt.value = TYPES[t][0];
      opt.textContent = TYPES[t][1];
      if (q && q.type === TYPES[t][0]) opt.selected = true;
      select.appendChild(opt);
    }
    top.appendChild(labeled("题型", select));
    var title = input("q" + idx + "_title", "text", q ? q.title : "");
    title.placeholder = "题干";
    top.appendChild(labeled("题干", title));
    fieldset.appendChild(top);

    fieldset.appendChild(labeled("提示（可选）", input("q" + idx + "_hint", "text", q ? q.hint : "")));

    buildLimits(fieldset, idx, q);
    buildOptions(fieldset, idx, q);

    select.addEventListener("change", function () {
      var current = { type: select.value, min_choices: 1, max_choices: 0, max_length: 300, required: true };
      buildLimits(fieldset, idx, current);
      buildOptions(fieldset, idx, current);
    });

    host.appendChild(fieldset);
    return fieldset;
  }

  var addBtn = document.querySelector("[data-add-question]");
  if (addBtn) {
    addBtn.addEventListener("click", function () {
      buildQuestion(null);
      renumber();
    });
  }

  if (initial.length === 0) {
    buildQuestion(null);
  } else {
    for (var i = 0; i < initial.length; i++) buildQuestion(initial[i]);
  }
  renumber();
})();
