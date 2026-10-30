const $ = (id) => document.getElementById(id);

const ACTIONS = {
  blocked: "blockiert",
  forwarded: "weitergeleitet",
  cached: "aus dem Speicher",
  rewritten: "umgeleitet",
  failed: "keine Antwort",
  local: "lokales Netz",
  stale: "alte Antwort",
  limited: "begrenzt",
};

const state = { panel: "overview", data: null };

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (value == null || value === false) continue;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child);
  return node;
}

let holding = false;
document.addEventListener("pointerdown", () => { holding = true; });
document.addEventListener("pointerup", () => { holding = false; });
document.addEventListener("pointercancel", () => { holding = false; });

function typing() {
  const node = document.activeElement;
  return node && ["INPUT", "TEXTAREA", "SELECT"].includes(node.tagName);
}

function selecting() {
  const selection = window.getSelection();
  if (!selection || selection.isCollapsed) return false;
  const node = selection.anchorNode;
  return Boolean(node && $("main")?.contains(node));
}

async function load() {
  const response = await fetch("/api/state");
  state.data = await response.json();
  paintStatus();
  if (!typing() && !holding && !selecting()) render();
}

function paintStatus() {
  const node = $("run-state");
  const data = state.data;
  if (!data) return;
  if (data.running) {
    node.className = "run ok";
    node.textContent = data.config.paused ? "Schutz pausiert" : "Filter läuft";
  } else {
    node.className = "run bad";
    node.textContent = "DNS aus";
  }
}

function render() {
  const main = $("main");
  const data = state.data;
  if (data && state.panel === "overview" && main.dataset.view === "overview" && patchOverview(main, data)) return;
  if (data && state.panel === "log" && main.dataset.view === "log" && patchLog(main, data)) return;
  main.replaceChildren();
  main.dataset.view = state.panel;
  if (!data) {
    main.append(el("p", { class: "note", text: "Lade…" }));
    return;
  }
  if (data.error) main.append(el("p", { class: "banner", text: data.error }));
  if (data.restartRequired) {
    main.append(el("p", { class: "banner", text: "Hostname, Ports oder Zertifikat gelten erst nach einem Neustart." }));
  }
  if (state.panel === "overview") renderOverview(main, data);
  else if (state.panel === "log") renderLog(main, data);
  else if (state.panel === "protect") renderProtect(main, data);
  else if (state.panel === "rewrite") renderRewrite(main, data);
  else renderSettings(main, data);
}

function renderOverview(main, data) {
  const stats = data.stats;
  const total = stats.total || 0;
  const share = total ? Math.round((stats.blocked / total) * 100) : 0;
  main.append(
    el("section", { class: "cards" }, [
      card("Anfragen, 7 Tage", String(total)),
      card("Blockierte Anfragen, 7 Tage", String(stats.blocked || 0)),
      card("Anteil blockiert, 7 Tage", `${share} %`),
      card("Domains in den Sperrlisten", String(data.blockedDomains || 0)),
    ]),
    el("div", { class: "overview-split" }, [
      queryChart(stats.top, stats.blockedTop),
      recentPanel(data.log),
    ]),
    blockedPanel(stats.blockedAll || stats.blockedTop),
  );
  fitOverviewRecent();
}

function patchOverview(main, data) {
  const values = main.querySelectorAll(".cards strong");
  if (values.length !== 4 || !main.querySelector(".query-chart")) return false;
  const stats = data.stats;
  const total = stats.total || 0;
  const share = total ? Math.round((stats.blocked / total) * 100) : 0;
  const next = [String(total), String(stats.blocked || 0), `${share} %`, String(data.blockedDomains || 0)];
  values.forEach((node, index) => { node.textContent = next[index]; });
  const chart = main.querySelector(".query-chart");
  if (chart) chart.replaceWith(queryChart(stats.top, stats.blockedTop));
  fitOverviewRecent();
  const panel = main.querySelector(".blocked-names");
  if (panel) {
    const scroll = panel.querySelector(".blocked-scroll");
    const position = scroll ? scroll.scrollTop : 0;
    const fresh = blockedPanel(stats.blockedAll || stats.blockedTop);
    panel.replaceWith(fresh);
    const next = fresh.querySelector(".blocked-scroll");
    if (next) next.scrollTop = position;
  }
  return true;
}

function card(label, value) {
  return el("article", { class: "card" }, [
    el("span", { text: label }),
    el("strong", { text: value }),
  ]);
}

function queryFilters(onInput, columns) {
  const inputs = {};
  const cells = [["time", "Zeit"], ["client", "Gerät"], ["name", "Name"]].map(([key, label]) => {
    const input = el("input", { placeholder: "suchen", "aria-label": label, "data-filter": key });
    input.addEventListener("input", onInput);
    inputs[key] = input;
    return el("th", {}, [input]);
  });
  const actionIndex = columns === 6 ? 4 : 3;
  for (let index = 3; index < columns; index += 1) {
    if (index !== actionIndex) {
      cells.push(el("th"));
      continue;
    }
    const select = el("select", { "aria-label": "Aktion", "data-filter": "action" });
    select.append(el("option", { value: "", text: "alle" }));
    for (const [value, label] of Object.entries(ACTIONS)) {
      select.append(el("option", { value, text: label }));
    }
    select.addEventListener("change", onInput);
    inputs.action = select;
    cells.push(el("th", {}, [select]));
  }
  return { row: el("tr", { class: "filter-row" }, cells), inputs };
}

function filtersIn(root) {
  if (!root) return null;
  const inputs = {};
  for (const key of ["time", "client", "name", "action"]) {
    inputs[key] = root.querySelector(`[data-filter="${key}"]`);
    if (!inputs[key]) return null;
  }
  return inputs;
}

function filteredRows(rows, inputs, idleLimit) {
  const action = inputs.action ? inputs.action.value : "";
  const query = {
    time: inputs.time.value.trim().toLowerCase(),
    client: inputs.client.value.trim().toLowerCase(),
    name: inputs.name.value.trim().toLowerCase(),
  };
  const matched = [...(rows || [])].reverse().filter((row) => (
    (!query.time || String(row.time || "").toLowerCase().includes(query.time))
    && (!query.client || String(row.client || "").toLowerCase().includes(query.client))
    && (!query.name || String(row.name || "").toLowerCase().includes(query.name))
    && (!action || row.action === action)
  ));
  const narrowed = query.time || query.client || query.name || action;
  return narrowed || !idleLimit ? matched : matched.slice(0, idleLimit);
}

function fillRecent(body, rows, inputs, columns, idleLimit) {
  const shown = filteredRows(rows, inputs, idleLimit);
  body.replaceChildren();
  if (!shown.length) {
    body.append(el("tr", {}, [el("td", {
      colspan: String(columns),
      text: rows && rows.length ? "Kein Treffer." : "Noch keine Anfragen.",
    })]));
    return;
  }
  for (const row of shown) {
    body.append(el("tr", {}, columns === 4 ? [
      el("td", { text: row.time }),
      el("td", { text: row.client }),
      el("td", { text: row.name }),
      el("td", {}, [el("span", { class: `tag ${row.action}`, text: ACTIONS[row.action] || row.action })]),
    ] : [
      el("td", { text: row.time }),
      el("td", { text: row.client }),
      el("td", { text: row.name }),
      el("td", { text: row.type }),
      el("td", {}, [el("span", { class: `tag ${row.action}`, text: ACTIONS[row.action] || row.action })]),
      el("td", { text: String(row.ms) }),
    ]));
  }
}

function fitOverviewRecent() {
  const panel = document.querySelector(".overview-split .recent-queries");
  const scroll = panel?.querySelector(".recent-scroll");
  const body = scroll?.querySelector("tbody");
  const head = scroll?.querySelector("thead");
  const filters = filtersIn(panel);
  if (!scroll || !body || !head || !filters || !state.data) return;
  const log = state.data.log;
  fillRecent(body, log, filters, 4, 0);
  const room = scroll.clientHeight - head.getBoundingClientRect().height;
  if (room <= 0) return;
  const items = [...body.children];
  if (items.length === 1 && items[0].querySelector("td[colspan]")) return;
  let used = 0;
  let count = 0;
  for (const row of items) {
    const height = row.getBoundingClientRect().height;
    if (count && used + height > room + 4) break;
    used += height;
    count += 1;
  }
  if (count && count < items.length) fillRecent(body, log, filters, 4, count);
}

function recentPanel(rows) {
  const body = document.createElement("tbody");
  const table = document.createElement("table");
  table.className = "query-table";
  const filters = queryFilters(() => fitOverviewRecent(), 4);
  table.append(el("colgroup", {}, [
    el("col", { class: "col-time" }),
    el("col", { class: "col-client" }),
    el("col", { class: "col-name" }),
    el("col", { class: "col-result" }),
  ]), el("thead", {}, [
    el("tr", {}, ["Zeit", "Gerät", "Name", "Aktion"].map((text) => el("th", { text }))),
    filters.row,
  ]), body);
  fillRecent(body, rows, filters.inputs, 4, 12);
  return el("section", { class: "panel recent-queries" }, [
    el("h2", { text: "Letzte Anfragen" }),
    el("div", { class: "recent-scroll" }, [table]),
  ]);
}

function blockedPanel(rows) {
  const input = el("input", { placeholder: "Name suchen" });
  const list = el("div", { class: "blocked-scroll" });
  const draw = () => {
    const query = input.value.trim().toLowerCase();
    const shown = (rows || []).filter((row) => !query || row.name.toLowerCase().includes(query));
    list.replaceChildren();
    if (!shown.length) {
      list.append(el("p", { class: "empty", text: rows && rows.length ? "Kein Treffer." : "Noch nichts blockiert." }));
      return;
    }
    for (const row of shown) {
      list.append(el("div", { class: "item" }, [
        el("strong", { text: row.name }),
        el("span", { text: String(row.count) }),
      ]));
    }
  };
  input.addEventListener("input", draw);
  draw();
  return el("section", { class: "panel blocked-names" }, [
    el("h2", { text: "Alle blockierten Namen, 7 Tage" }),
    el("p", { class: "note", text: "Jeder Name, der in den letzten 7 Tagen blockiert wurde, mit der Anzahl der Anfragen." }),
    input,
    list,
  ]);
}

function queryChart(rows, blocked) {
  const items = (rows || []).slice(0, 10);
  const max = items.reduce((peak, row) => Math.max(peak, Number(row.count) || 0), 0);
  const list = el("ol", { class: "bars" });
  if (!items.length) {
    list.append(el("li", {}, [el("p", { class: "empty", text: "Noch nichts." })]));
  }
  for (const row of items) {
    const count = Number(row.count) || 0;
    const width = max ? (count / max) * 100 : 0;
    list.append(el("li", { class: "bar-row" }, [
      el("span", { class: "bar-name", title: row.name, text: row.name }),
      el("span", { class: "bar-count", text: String(count) }),
      el("span", { class: "bar-track" }, [
        el("span", { class: "bar-fill", style: `width:${width}%` }),
      ]),
    ]));
  }
  return el("section", { class: "panel query-chart" }, [
    el("h2", { text: "Die 10 häufigsten Anfragen, 7 Tage" }),
    list,
    el("h2", { class: "blocked-head", text: "Häufig blockiert, 7 Tage" }),
    nameList(blocked),
  ]);
}

function nameList(rows) {
  const list = el("div", { class: "list blocked-compact" });
  if (!rows || !rows.length) list.append(el("p", { class: "empty", text: "Noch nichts." }));
  for (const row of rows || []) {
    list.append(el("div", { class: "item" }, [
      el("strong", { text: row.name }),
      el("span", { text: String(row.count) }),
    ]));
  }
  return list;
}

function germanDate(iso) {
  const [year, month, day] = String(iso).split("-");
  if (!year || !month || !day) return iso;
  return `${day}.${month}.${year}`;
}

function renderLog(main, data) {
  const summary = document.createElement("table");
  summary.append(el("thead", {}, [
    el("tr", {}, ["Tag", "Anfragen", "Blockiert", "Anteil"].map((text) => el("th", { text }))),
  ]));
  const summaryBody = document.createElement("tbody");
  for (const day of data.days || []) {
    const total = day.total || 0;
    const share = total ? Math.round((day.blocked / total) * 100) : 0;
    summaryBody.append(el("tr", {}, [
      el("td", { text: germanDate(day.date) }),
      el("td", { text: String(total) }),
      el("td", { text: String(day.blocked || 0) }),
      el("td", { text: `${share} %` }),
    ]));
  }
  summary.append(summaryBody);
  const body = document.createElement("tbody");
  const table = document.createElement("table");
  table.className = "query-table";
  const filters = queryFilters(() => fillRecent(body, state.data && state.data.log, filters.inputs, 6, 0), 6);
  table.append(el("colgroup", {}, [
    el("col", { class: "col-time" }),
    el("col", { class: "col-client" }),
    el("col", { class: "col-name" }),
    el("col", { class: "col-type" }),
    el("col", { class: "col-result" }),
    el("col", { class: "col-ms" }),
  ]), el("thead", {}, [
    el("tr", {}, ["Zeit", "Gerät", "Name", "Typ", "Aktion", "ms"].map((text) => el("th", { text }))),
    filters.row,
  ]), body);
  fillRecent(body, data.log, filters.inputs, 6, 0);
  main.append(
    el("section", { class: "panel" }, [
      el("h2", { text: "Auswertung, 7 Tage" }),
      el("p", { class: "note", text: "Jeder Tag bleibt gespeichert, auch nach einem Neustart. Ältere Tage fallen weg." }),
      summary,
    ]),
    el("section", { class: "panel log-queries" }, [
      el("h2", { text: "Letzte Anfragen" }),
      el("div", { class: "recent-scroll" }, [table]),
    ]),
  );
}

function patchLog(main, data) {
  const body = main.querySelector(".log-queries tbody");
  const inputs = filtersIn(main.querySelector(".log-queries"));
  if (!body || !inputs) return false;
  fillRecent(body, data.log, inputs, 6, 0);
  const summary = main.querySelector("table tbody");
  if (summary && summary !== body) {
    summary.replaceChildren();
    for (const day of data.days || []) {
      const total = day.total || 0;
      const share = total ? Math.round((day.blocked / total) * 100) : 0;
      summary.append(el("tr", {}, [
        el("td", { text: germanDate(day.date) }),
        el("td", { text: String(total) }),
        el("td", { text: String(day.blocked || 0) }),
        el("td", { text: `${share} %` }),
      ]));
    }
  }
  return true;
}

function renderProtect(main, data) {
  const config = data.config;
  const pause = el("label", { class: "switch" }, [
    el("input", {
      type: "checkbox",
      checked: config.paused ? "checked" : null,
      onchange: (event) => save({ paused: event.target.checked }),
    }),
    document.createTextNode("Schutz pausieren"),
  ]);
  if (!config.paused) pause.querySelector("input").removeAttribute("checked");
  else pause.querySelector("input").checked = true;

  const lists = el("div", { class: "list" });
  for (const item of config.blocklists) {
    const box = el("input", { type: "checkbox", "aria-label": item.name });
    box.checked = !!item.enabled;
    box.addEventListener("change", () => {
      const blocklists = config.blocklists.map((entry) => (
        entry.id === item.id ? { ...entry, enabled: box.checked } : entry
      ));
      save({ blocklists });
    });
    const meta = [
      item.domains ? `${item.domains} Namen` : "noch nicht geladen",
      item.updated ? `Stand ${item.updated}` : "",
      item.error || "",
    ].filter(Boolean).join(" · ");
    lists.append(el("div", { class: "item" }, [
      el("div", {}, [el("strong", { text: item.name }), el("p", { text: meta })]),
      el("div", { class: "row" }, [
        el("label", { class: "switch" }, [box]),
        el("button", {
          class: "danger",
          type: "button",
          text: "Entfernen",
          onclick: () => {
            if (!window.confirm(`${item.name} aus den Sperrlisten nehmen?`)) return;
            save({ blocklists: config.blocklists.filter((entry) => entry.id !== item.id) });
          },
        }),
      ]),
    ]));
  }
  const listName = el("input", { placeholder: "Name" });
  const listUrl = el("input", { placeholder: "https://…" });
  main.append(
    el("section", { class: "panel" }, [
      el("h2", { text: "Sperrlisten" }),
      el("p", { class: "note", text: "Eingeschaltete Listen werden beim Start und danach alle 6 Stunden automatisch neu geladen." }),
      pause,
      lists,
      el("div", { class: "row" }, [listName, listUrl, el("button", {
        class: "primary",
        type: "button",
        text: "Liste dazu",
        onclick: () => addList(listName.value, listUrl.value),
      })]),
      el("div", { class: "actions" }, [
        el("button", { class: "ghost", type: "button", text: "Listen jetzt laden", onclick: () => refreshLists() }),
      ]),
    ]),
    rulePanel("Immer sperren", "deny", config.deny, "z. B. werbung.example", "Gilt für diesen Namen und alles darunter. ads.example sperrt auch a.ads.example, nicht aber example selbst."),
    rulePanel("Immer erlauben", "allow", config.allow, "z. B. meine-seite.example", "Gilt für diesen Namen und alles darunter und hebt die Sperre auf, auch wenn die Domain auf einer Liste oder unter Immer sperren steht."),
  );
}

function rulePanel(title, key, names, placeholder, note) {
  const input = el("input", { placeholder });
  const chips = el("div", { class: "chips" });
  if (!names.length) chips.append(el("p", { class: "empty", text: "Keine Einträge." }));
  for (const name of names) {
    chips.append(el("span", { class: "chip" }, [
      document.createTextNode(name),
      el("button", {
        class: "danger",
        type: "button",
        text: "×",
        onclick: () => save({ [key]: names.filter((item) => item !== name) }),
      }),
    ]));
  }
  return el("section", { class: "panel" }, [
    el("h2", { text: title }),
    el("p", { class: "note", text: note }),
    chips,
    el("div", { class: "row" }, [
      input,
      el("button", {
        class: "primary",
        type: "button",
        text: "Hinzufügen",
        onclick: () => {
          const value = input.value.trim();
          if (!value) return;
          save({ [key]: [...names, value] });
        },
      }),
    ]),
  ]);
}

function renderRewrite(main, data) {
  const rules = data.config.rewrites;
  const name = el("input", { placeholder: "drucker.lan oder *.intern.lan" });
  const address = el("input", { placeholder: "192.168.88.10" });
  const list = el("div", { class: "list" });
  if (!rules.length) list.append(el("p", { class: "empty", text: "Keine Umleitungen." }));
  for (const rule of rules) {
    list.append(el("div", { class: "item" }, [
      el("strong", { text: `${rule.name} → ${rule.address}` }),
      el("button", {
        class: "danger",
        type: "button",
        text: "Entfernen",
        onclick: () => save({ rewrites: rules.filter((item) => item.name !== rule.name) }),
      }),
    ]));
  }
  main.append(el("section", { class: "panel" }, [
    el("h2", { text: "Umleitungen" }),
    el("p", { class: "note", text: "*.name gilt für Namen darunter, nicht für den Namen selbst. Diese Antworten gehen nicht ins Internet." }),
    list,
    el("div", { class: "row" }, [
      name,
      address,
      el("button", {
        class: "primary",
        type: "button",
        text: "Speichern",
        onclick: () => {
          if (!name.value.trim() || !address.value.trim()) return;
          save({ rewrites: [...rules, { name: name.value.trim(), address: address.value.trim() }] });
        },
      }),
    ]),
  ]));
}

function renderSettings(main, data) {
  const config = data.config;
  const hostname = el("input", { value: config.hostname });
  const clients = el("textarea", { text: config.clients.join("\n") });
  const upstreams = el("textarea", { text: config.upstreams.join("\n") });
  const dnsListen = el("input", { value: config.dnsListen });
  const dohListen = el("input", { value: config.dohListen });
  const mode = el("select", {}, [
    el("option", { value: "nxdomain", text: "NXDOMAIN, Name gibt es nicht" }),
    el("option", { value: "zero", text: "0.0.0.0, leere Adresse" }),
  ]);
  mode.value = config.blockMode;
  const signed = el("input", { type: "checkbox" });
  signed.checked = !!config.selfSigned;
  const form = el("section", { class: "panel" }, [
    el("h2", { text: "Einstellungen" }),
    el("label", { text: "Name im Zertifikat und in der DoH-Adresse" }, [hostname]),
    el("label", { text: "Öffentliche IP des RB5009, eine pro Zeile. Nur für unverschlüsseltes DNS. DoH braucht das nicht." }, [clients]),
    el("label", { text: "Weiterleitung, eine Adresse pro Zeile. Ohne Port gilt 53." }, [upstreams]),
    el("label", { text: "DNS-Port. Auf dem Server 0.0.0.0:53. Gilt nach Neustart." }, [dnsListen]),
    el("label", { text: "DoH-Adresse. Gilt nach Neustart." }, [dohListen]),
    el("label", { text: "Antwort für gesperrte Namen" }, [mode]),
    el("label", { class: "switch", text: "" }, [signed, document.createTextNode("Selbst erstelltes Zertifikat bei Namenswechsel neu bauen")]),
    el("div", { class: "actions" }, [el("button", { class: "primary", type: "button", text: "Speichern" })]),
  ]);
  form.querySelector("button").addEventListener("click", () => {
    save({
      hostname: hostname.value.trim(),
      clients: clients.value.split(/\s+/).filter(Boolean),
      upstreams: upstreams.value.split(/\s+/).filter(Boolean),
      dnsListen: dnsListen.value.trim(),
      dohListen: dohListen.value.trim(),
      blockMode: mode.value,
      selfSigned: signed.checked,
    });
  });
  main.append(form, routerPanel(data));
}

function routerPanel(data) {
  return el("section", { class: "panel router-panel" }, [
    el("h2", { text: "RB5009" }),
    el("p", { class: "note", text: "Der Filter läuft auf diesem Linux-Server. Der Router fragt ihn per DNS-over-HTTPS. Die Adresse enthält ein Token, damit der Dienst kein offener Resolver ist." }),
    el("p", { class: "note", text: data.dohUrl }),
    el("pre", { class: "commands", text: data.routeros }),
    el("button", {
      class: "ghost",
      type: "button",
      text: "Befehle kopieren",
      onclick: async (event) => {
        const button = event.currentTarget;
        const text = data.routeros;
        try {
          await navigator.clipboard.writeText(text);
        } catch {
          const area = document.createElement("textarea");
          area.value = text;
          document.body.append(area);
          area.select();
          document.execCommand("copy");
          area.remove();
        }
        button.textContent = "Kopiert";
        window.setTimeout(() => { button.textContent = "Befehle kopieren"; }, 1500);
      },
    }),
    el("p", { class: "note", text: `Statischer Name zeigt auf ${data.serverIp}. Ist das eine private Adresse, im Router die öffentliche Adresse des Servers eintragen. Der DoH-Port muss von außen erreichbar sein. Die Oberfläche bleibt hinter der Anmeldung des Webservers.` }),
    el("p", { class: "note", text: data.config.selfSigned
      ? "Das Zertifikat ist selbst erstellt. Auf dem Router tls.crt importieren und als vertrauenswürdig markieren, sonst lehnt verify-doh-cert die Verbindung ab. Für ein echtes Zertifikat tls.crt und tls.key ersetzen, selbst signiert ausschalten und neu starten."
      : "Zertifikat kommt aus tls.crt und tls.key neben der Konfiguration." }),
    el("div", { class: "actions" }, [
      el("button", {
        class: "ghost",
        type: "button",
        text: "Neues Token",
        onclick: async () => {
          if (!window.confirm("Der Router braucht danach die neue DoH-Adresse.")) return;
          await fetch("/api/token", { method: "POST" });
          $("main").dataset.view = "";
          await load();
        },
      }),
    ]),
  ]);
}

async function save(patch) {
  const response = await fetch("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  const data = await response.json();
  if (!response.ok || data.ok === false) {
    window.alert(data.error || "Speichern fehlgeschlagen");
    return;
  }
  if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
  await load();
}

async function refreshLists() {
  await fetch("/api/refresh", { method: "POST" });
  window.setTimeout(() => load().catch(() => {}), 1500);
}

function addList(name, url) {
  const cleanName = name.trim();
  const cleanUrl = url.trim();
  if (!cleanName || !cleanUrl.startsWith("https://")) return;
  const ident = `custom-${Math.random().toString(16).slice(2, 10)}`;
  const blocklists = [
    ...state.data.config.blocklists.map((item) => ({
      id: item.id,
      name: item.name,
      url: item.url,
      enabled: item.enabled,
    })),
    { id: ident, name: cleanName, url: cleanUrl, enabled: true },
  ];
  save({ blocklists });
}

document.getElementById("nav").addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  state.panel = button.dataset.panel;
  for (const item of document.querySelectorAll("nav button")) {
    item.classList.toggle("active", item === button);
  }
  render();
});

load().catch(() => {
  $("run-state").textContent = "Oberfläche nicht erreichbar";
  $("run-state").className = "run bad";
});
setInterval(() => {
  if (!document.hidden && (state.panel === "overview" || state.panel === "log")) {
    load().catch(() => {});
  }
}, 2000);
window.addEventListener("resize", () => {
  if (state.panel === "overview") fitOverviewRecent();
});
