const state = { selected: null, sending: false, view: "monitor", opcFolder: "Latest", opcRadios: false, remoteCount: 255 };

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&" + "amp;")
    .replace(/</g, "&" + "lt;")
    .replace(/>/g, "&" + "gt;")
    .replace(/"/g, "&" + "quot;")
    .replace(/'/g, "&#" + "39;");
}

function identity(trap) {
  if (trap.version === "v3") return `${trap.user || "—"} · ${trap.securityLevel || "v3"}`;
  return trap.community || "—";
}

function ago(iso) {
  const then = Date.parse(iso);
  if (!then) return "";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${iso.slice(11, 19)} UTC`;
}

let ticking = null;

// One /api/state request at a time. When the gateway is busy a reply can take
// longer than the 1 s interval, and overlapping requests used to pile up.
function tick() {
  if (!ticking) {
    ticking = refreshState().finally(() => {
      ticking = null;
    });
  }
  return ticking;
}

async function refreshState() {
  try {
    const response = await fetch("/api/state");
    if (!response.ok) throw new Error("status");
    render(await response.json());
  } catch (_err) {
    const text = document.getElementById("status-text");
    const dot = document.getElementById("status-dot");
    if (text) text.textContent = "Console lost the gateway";
    if (dot) dot.className = "dot bad";
  }
}

function render(data) {
  window.__trapsnmp = data;
  const snmp = data.snmp || {};
  const opc = data.opcua || {};
  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  if (snmp.listening && opc.ready) {
    dot.className = "dot live";
    text.textContent = `Listening on UDP ${snmp.port}`;
  } else if (snmp.error || opc.error) {
    dot.className = "dot bad";
    text.textContent = snmp.error || opc.error;
  } else if (snmp.listening) {
    dot.className = "dot";
    text.textContent = `UDP ${snmp.port} is up, OPC UA is still opening`;
  } else {
    dot.className = "dot";
    text.textContent = "Opening the trap receiver";
  }
  const note = document.getElementById("snmp-note");
  const base = "The bench sends a real UDP trap into the same receiver agents use.";
  if (note) note.textContent = snmp.note ? `${base} ${snmp.note}` : base;
  const pathSnmp = document.getElementById("path-snmp");
  const pathOpc = document.getElementById("path-opc");
  if (pathSnmp) pathSnmp.textContent = snmp.listening ? `UDP ${snmp.port}` : "Down";
  if (pathOpc) pathOpc.textContent = opc.ready ? "Publishing" : "Starting";
  document.getElementById("count-traps").textContent = data.counts?.traps ?? 0;
  document.getElementById("count-informs").textContent = data.counts?.informs ?? 0;
  document.getElementById("count-events").textContent = data.counts?.events ?? 0;
  document.getElementById("count-forward").textContent = data.upstream?.forwarded ?? 0;

  const chips = document.getElementById("communities");
  const chipSig = (snmp.communities || []).join("|");
  if (chips.dataset.sig !== chipSig) {
    chips.dataset.sig = chipSig;
    chips.innerHTML = (snmp.communities || []).map((name) => `<span class="chip">${esc(name)}</span>`).join("");
  }
  renderUsers(snmp.users || []);

  document.getElementById("opc-endpoint").textContent = opc.ready ? opc.endpoint : (opc.error || "Starting");
  document.getElementById("opc-ns").textContent = opc.namespace || "urn:trapsnmp:snmp";
  document.getElementById("opc-node").textContent = opc.nodes?.trapOid || "—";
  document.getElementById("opc-object").textContent = opc.nodes?.object || "—";
  const cert = opc.certificate || {};
  const subject = document.getElementById("cert-subject");
  const thumb = document.getElementById("cert-thumb");
  const expires = document.getElementById("cert-expires");
  const policies = document.getElementById("cert-policies");
  const rejected = document.getElementById("cert-rejected");
  if (subject) subject.textContent = cert.subject || "—";
  if (thumb) thumb.textContent = cert.thumbprint || "—";
  if (expires) expires.textContent = cert.expires || "—";
  if (policies) {
    const sig = (cert.policies || []).join("|");
    if (policies.dataset.sig !== sig) {
      policies.dataset.sig = sig;
      policies.innerHTML = (cert.policies || []).map((name) => `<span class="chip">${esc(name)}</span>`).join("");
    }
  }
  const opcUsers = document.getElementById("opc-users");
  if (opcUsers) {
    const names = cert.users || [];
    const sig = names.join("|");
    if (opcUsers.dataset.sig !== sig) {
      opcUsers.dataset.sig = sig;
      opcUsers.innerHTML = names.map((name) => `
        <span class="chip">${esc(name)} <button type="button" class="ghost" data-opc-user="${esc(name)}">Remove</button></span>
      `).join("");
    }
  }
  if (rejected) {
    const rows = cert.rejected || [];
    const sig = rows.map((item) => item.name).join("|");
    if (rejected.dataset.sig !== sig) {
      rejected.dataset.sig = sig;
      rejected.innerHTML = rows.length
        ? rows.map((item) => `
            <div class="inline">
              <span class="mono">${esc(item.subject || item.name)}</span>
              <button type="button" class="ghost" data-trust="${esc(item.name)}">Trust</button>
            </div>
          `).join("")
        : `<p class="empty">No rejected certificates.</p>`;
    }
  }
  document.getElementById("up-status").textContent = data.upstream?.enabled
    ? `${data.upstream.status} · ${data.upstream.forwarded} written`
    : (data.upstream?.status || "Not forwarding");
  document.getElementById("up-status").className = data.upstream?.status && /fail|error|Bad/i.test(data.upstream.status)
    ? "note bad"
    : "note";

  const traps = data.traps || [];
  if (state.selected == null && traps[0]) state.selected = traps[0].id;
  if (state.selected != null && !traps.some((trap) => trap.id === state.selected)) {
    state.selected = traps[0] ? traps[0].id : null;
  }
  const feed = document.getElementById("feed");
  const scroll = feed.scrollTop;
  feed.innerHTML = traps.length
    ? traps.map((trap) => `
        <button type="button" class="trap ${esc(trap.severity)} ${trap.id === state.selected ? "selected" : ""}" data-id="${trap.id}">
          <span class="trap-name">${esc(trap.trapName)}</span>
          <span class="sev ${esc(trap.severity)}">${esc(trap.severity)}</span>
          <span class="trap-meta">${esc(trap.source)} · ${esc(identity(trap))} · ${esc(trap.version)} ${esc(trap.kind)} · ${esc(ago(trap.receivedAt))}</span>
          <span class="trap-oid">${esc(trap.trapOid)}</span>
        </button>
      `).join("")
    : '<p class="empty">No traps yet.</p>';
  feed.scrollTop = scroll;
  renderReadback(data.readback);
  renderDetail(traps.find((trap) => trap.id === state.selected));
  renderDiag(data);
  renderAgent(data.agent);
  renderTags(data.tags);
  renderRadios(data.radios);
  if (state.view === "opc") refreshOpc();
  const sine = data.sine || {};
  state.remoteCount = data.radios?.capacity || state.remoteCount;
  const sineToggle = document.getElementById("sine-toggle");
  const sineNote = document.getElementById("sine-note");
  if (sineToggle) sineToggle.textContent = sine.enabled ? "Stop RSSI sine" : "Start RSSI sine";
  if (sineNote) {
    sineNote.textContent = sine.enabled && sine.rssi !== null && sine.rssi !== undefined
      ? `Running every ${sine.every || 10} s. Shared RSSI ${sine.rssi} dBm. Remote1–Remote${state.remoteCount} add a random ±${sine.spread} dBm.`
      : sine.enabled
        ? "Running."
        : "Stopped.";
  }
  const trace = document.getElementById("trace");
  const lines = data.trace || [];
  trace.innerHTML = lines.length
    ? lines.map((line) => `<li>${esc(line)}</li>`).join("")
    : "<li>The path log fills as traps move from SNMP into OPC UA.</li>";
}

function renderDiag(data) {
  const host = document.getElementById("diag-checks");
  const meta = document.getElementById("diag-meta");
  if (!host) return;
  const snmp = data.snmp || {};
  const opc = data.opcua || {};
  const readback = data.readback || {};
  const upstream = data.upstream || {};
  const users = (snmp.users || []).map((user) => `${user.name} ${user.level}`).join(", ");
  const last = (data.traps || [])[0];
  const rows = [
    check(snmp.listening, "SNMP socket", snmp.listening ? `UDP ${snmp.port}` : (snmp.error || "Not listening")),
    check(snmp.port === 162 ? "pass" : "warn", "UDP port", snmp.port === 162 ? "162" : (snmp.note || `Using ${snmp.port || "—"}`)),
    check((snmp.communities || []).length > 0, "Communities", (snmp.communities || []).join(", ") || "None"),
    check((snmp.users || []).length > 0, "SNMPv3", users || "No user"),
    check(opc.ready, "OPC UA server", opc.ready ? `${opc.endpoint} · ${opc.security}` : (opc.error || "Starting")),
    check(data.agent?.listening, "SNMP agent", data.agent?.listening ? `UDP ${data.agent.port} · ${data.agent.objectId}` : (data.agent?.error || "Not listening")),
    check(readback.ok, "Client read", readback.ok ? "Latest read succeeded" : (readback.error || "No read")),
  ];
  if (last && readback.ok) {
    const matched = readback.trapOid === last.trapOid;
    rows.push(check(matched, "Latest node", matched ? last.trapName : `Read ${readback.trapOid || "empty"}`));
  } else {
    rows.push(check("warn", "Latest node", "No trap received yet"));
  }
  if (upstream.enabled) {
    const bad = /fail|error|Bad/i.test(upstream.status || "");
    rows.push(check(!bad, "Forward", upstream.status || "Armed"));
  } else {
    rows.push(check("warn", "Forward", "Not armed"));
  }
  host.innerHTML = `<div class="checks">${rows.map((row) => `
    <div class="check">
      <span class="check-state ${row.kind}">${row.kind === "pass" ? "Pass" : row.kind === "warn" ? "Check" : "Fail"}</span>
      <span class="check-name">${esc(row.name)}</span>
      <span class="check-detail">${esc(row.detail)}</span>
    </div>
  `).join("")}</div>`;
  if (meta) {
    meta.textContent = `trapsnmp ${data.version || ""} · up ${uptime(data.startedAt)}`;
  }
}

function check(kind, name, detail) {
  const label = kind === true || kind === "pass" ? "pass" : kind === "warn" ? "warn" : "fail";
  return { kind: label, name, detail };
}

function uptime(iso) {
  const then = Date.parse(iso);
  if (!then) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function renderReport(report) {
  const host = document.getElementById("diag-report");
  if (!host) return;
  const steps = report.steps || [];
  host.innerHTML = `
    <h3 class="subhead">Last loopback · ${esc(report.ms)} ms</h3>
    <div class="checks">${steps.map((step) => `
      <div class="check">
        <span class="check-state ${step.ok ? "pass" : "fail"}">${step.ok ? "Pass" : "Fail"}</span>
        <span class="check-name">${esc(step.name)}</span>
        <span class="check-detail">${esc(step.detail)}</span>
      </div>
    `).join("")}</div>
  `;
}

function renderReadback(readback) {
  const host = document.getElementById("readback");
  if (!readback || !readback.ok) {
    host.innerHTML = `<p class="empty">${esc(readback?.error || "Waiting for the OPC UA server.")}</p>`;
    return;
  }
  if (!readback.trapOid) {
    host.innerHTML = '<p class="empty">No value published yet. A client Read of Latest would still succeed, with empty strings.</p>';
    return;
  }
  const rows = [
    ["Trap name", readback.trapName],
    ["Trap OID", readback.trapOid],
    ["Source", readback.source],
    ["Security", readback.version === "v3" ? `${readback.user} · ${readback.securityLevel}` : readback.community],
    ["Version", `${readback.version} ${readback.kind}`],
    ["Severity", `${readback.severity} (${readback.severityCode})`],
    ["Message", readback.message],
    ["Received", readback.receivedAt],
    ["Trap count", readback.trapCount],
  ];
  host.innerHTML = `<dl class="kv">${rows.map(([label, value]) => `<dt>${esc(label)}</dt><dd class="mono">${esc(value)}</dd>`).join("")}</dl>`;
}

function renderDetail(trap) {
  const host = document.getElementById("detail");
  if (!trap) {
    host.innerHTML = '<p class="empty">Choose a trap, or send one from the bench.</p>';
    return;
  }
  const binds = (trap.varbinds || []).map((row) => `
    <tr>
      <td>${esc(row.name)}</td>
      <td class="oid">${esc(row.oid)}</td>
      <td>${esc(row.type)}</td>
      <td>${esc(row.display)}</td>
    </tr>
  `).join("");
  const opc = trap.opcua || {};
  const hop = opc.error
    ? `OPC UA error: ${opc.error}`
    : `${opc.written || 0} nodes written${opc.event ? ", event fired" : ""}${opc.upstream === "ok" ? ", forwarded" : ""}`;
  host.innerHTML = `
    <div class="summary-line">
      <h3>${esc(trap.trapName)}</h3>
      <span class="sev ${esc(trap.severity)}">${esc(trap.severity)} ${esc(trap.severityCode)}</span>
    </div>
    <p class="hint">${esc(trap.message)} · ${esc(hop)}</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>OID</th><th>Type</th><th>Value</th></tr></thead>
        <tbody>${binds}</tbody>
      </table>
    </div>
  `;
}

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function setBench(message, bad) {
  for (const id of ["flash", "bench-note"]) {
    const note = document.getElementById(id);
    if (!note) continue;
    note.textContent = message || "";
    note.className = id === "flash"
      ? (bad ? "note flash bad" : "note flash")
      : (bad ? "note bad" : "note");
  }
}

function showView(name) {
  state.view = name;
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.hidden = panel.getAttribute("data-view-panel") !== name;
  });
  document.querySelectorAll(".nav-btn").forEach((button) => {
    const on = button.dataset.view === name;
    button.classList.toggle("active", on);
    button.setAttribute("aria-selected", on ? "true" : "false");
  });
  if (name === "opc") refreshOpc();
}

function renderUsers(users) {
  const chips = document.getElementById("users");
  const hint = document.getElementById("user-hint");
  const select = document.getElementById("v3-user");
  const sig = users.map((user) => [user.name, user.level, user.auth, user.priv].join(":")).join("|");
  if (chips.dataset.sig === sig) return;
  chips.dataset.sig = sig;
  chips.innerHTML = users.map((user) => {
    const suite = user.level === "noAuthNoPriv" ? "noAuth" : `${user.auth}/${user.priv}`;
    return `<span class="chip">${esc(user.name)} · ${esc(user.level)} · ${esc(suite)}</span>`;
  }).join("");
  const current = select.value;
  select.innerHTML = users.map((user) => `<option value="${esc(user.name)}">${esc(user.name)}</option>`).join("");
  if ([...select.options].some((option) => option.value === current)) select.value = current;
  const first = users[0];
  if (!first) {
    hint.textContent = "No SNMPv3 user is configured.";
    return;
  }
  if (first.level === "noAuthNoPriv") {
    hint.textContent = `Agents can send v3 traps as ${first.name} with noAuthNoPriv. Any engine ID is accepted.`;
  } else if (first.level === "authNoPriv") {
    hint.textContent = `Agents can send v3 traps as ${first.name}, ${first.auth} passphrase ${first.authKey}. Any engine ID is accepted.`;
  } else {
    hint.textContent = `Agents can send v3 traps as ${first.name}, ${first.auth} passphrase ${first.authKey}, ${first.priv} passphrase ${first.privKey}. Any engine ID is accepted.`;
  }
}

document.getElementById("presets").addEventListener("click", onPreset);
document.getElementById("ge-presets")?.addEventListener("click", onPreset);
document.getElementById("sine-toggle")?.addEventListener("click", async () => {
  const running = document.getElementById("sine-toggle")?.textContent.startsWith("Stop");
  try {
    await post("/api/sine", { enabled: !running });
    setBench(running ? "RSSI sine stopped." : "RSSI sine started.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

async function onPreset(event) {
  const button = event.target.closest("[data-preset]");
  if (!button || state.sending) return;
  state.sending = true;
  button.disabled = true;
  setBench(`Sending ${button.querySelector(".preset-name")?.textContent || "trap"}…`);
  try {
    const data = await post("/api/inject", { preset: button.dataset.preset });
    state.selected = data.trap?.id ?? state.selected;
    setBench(`${data.trap?.trapName || "Trap"} arrived and was published.`);
    showView("monitor");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  } finally {
    state.sending = false;
    button.disabled = false;
  }
}

document.getElementById("feed").addEventListener("click", (event) => {
  const button = event.target.closest("[data-id]");
  if (!button) return;
  state.selected = Number(button.dataset.id);
  if (window.__trapsnmp) render(window.__trapsnmp);
});

document.getElementById("community-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = event.currentTarget.elements.community;
  try {
    await post("/api/community", { community: input.value });
    input.value = "";
    setBench("Community added.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

function bindRow() {
  const row = document.createElement("div");
  row.className = "bind";
  row.innerHTML = `
    <label class="field"><span>OID</span><input name="oid" spellcheck="false" placeholder="1.3.6.1.2.1.1.5.0" /></label>
    <label class="field"><span>Type</span>
      <select name="type">
        <option value="string">string</option>
        <option value="integer">integer</option>
        <option value="gauge">gauge</option>
        <option value="counter">counter</option>
        <option value="timeticks">timeticks</option>
        <option value="oid">oid</option>
        <option value="ip">ip</option>
      </select>
    </label>
    <label class="field"><span>Value</span><input name="value" placeholder="value" /></label>
    <button type="button" class="ghost remove">Remove</button>
  `;
  row.querySelector(".remove").addEventListener("click", () => row.remove());
  return row;
}

document.getElementById("add-bind").addEventListener("click", () => {
  document.getElementById("binds").appendChild(bindRow());
});

document.getElementById("custom-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.sending) return;
  const form = event.currentTarget;
  const varbinds = [...form.querySelectorAll(".bind")].map((row) => ({
    oid: row.querySelector('[name="oid"]').value.trim(),
    type: row.querySelector('[name="type"]').value,
    value: row.querySelector('[name="value"]').value,
  })).filter((row) => row.oid || row.value);
  state.sending = true;
  setBench("Sending custom trap…");
  try {
    const data = await post("/api/inject", {
      community: form.elements.community.value,
      version: form.elements.version.value,
      trapOid: form.elements.trapOid.value.trim(),
      varbinds,
      user: form.elements.version.value === "3" ? form.elements.user.value : "",
    });
    state.selected = data.trap?.id ?? state.selected;
    setBench(`${data.trap?.trapName || "Trap"} arrived and was published.`);
    showView("monitor");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  } finally {
    state.sending = false;
  }
});

document.getElementById("use-inbox").addEventListener("click", () => {
  const data = window.__trapsnmp;
  if (!data?.opcua) return;
  document.getElementById("up-endpoint").value = data.opcua.endpoint || "";
  document.getElementById("up-node").value = data.opcua.nodes?.inbox || "";
});

document.getElementById("opc-user-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    await post("/api/opc-user", { name: form.elements.name.value, password: form.elements.password });
    form.reset();
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

document.getElementById("opc-users")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-opc-user]");
  if (!button) return;
  try {
    await post("/api/opc-user", { action: "remove", name: button.dataset.opcUser });
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

document.getElementById("cert-rejected")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-trust]");
  if (!button) return;
  button.disabled = true;
  try {
    await post("/api/pki", { action: "trust", name: button.dataset.trust });
    await tick();
  } catch (err) {
    setBench(err.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("forward-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await post("/api/upstream", {
      enabled: true,
      endpoint: document.getElementById("up-endpoint").value.trim(),
      nodeId: document.getElementById("up-node").value.trim(),
    });
    await tick();
  } catch (err) {
    const note = document.getElementById("up-status");
    note.textContent = err.message;
    note.className = "note bad";
  }
});

document.getElementById("stop-forward").addEventListener("click", async () => {
  try {
    await post("/api/upstream", {
      enabled: false,
      endpoint: document.getElementById("up-endpoint").value.trim(),
      nodeId: document.getElementById("up-node").value.trim(),
    });
    await tick();
  } catch (err) {
    const note = document.getElementById("up-status");
    note.textContent = err.message;
    note.className = "note bad";
  }
});

document.getElementById("version").addEventListener("change", (event) => {
  const v3 = event.target.value === "3";
  document.getElementById("community-field").hidden = v3;
  document.getElementById("user-field").hidden = !v3;
});

document.getElementById("user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    await post("/api/user", {
      name: form.elements.name.value,
      level: form.elements.level.value,
      auth: form.elements.auth.value,
      authKey: form.elements.authKey.value,
      priv: form.elements.priv.value,
      privKey: form.elements.privKey.value,
    });
    form.elements.name.value = "";
    form.elements.authKey.value = "";
    form.elements.privKey.value = "";
    setBench("SNMPv3 user added.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

function syncUserFields() {
  const level = document.getElementById("user-level").value;
  document.getElementById("auth-fields").hidden = level === "noAuthNoPriv";
  document.getElementById("priv-fields").hidden = level !== "authPriv";
}

document.getElementById("user-level").addEventListener("change", syncUserFields);

function rssiClass(value) {
  if (value === null || value === undefined || value === "") return "";
  const number = Number(value);
  if (Number.isNaN(number)) return "";
  if (number >= -70) return "good";
  if (number >= -85) return "fair";
  return "poor";
}

const RADIO_COLUMNS = [
  ["oid", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.6"],
  ["remote_mac", "index mIfLnStatusConnRemAddress"],
  ["remote_ip", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.2"],
  ["rssi", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.6 mIfLnStatusConnRemRssi"],
  ["down", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.23 mIfLnStatusConnRemStatsDwnRssi"],
  ["if_index", "ifIndex"],
  ["link", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.4 mIfLnStatusConnRemLinkStatus"],
  ["ttl", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.3"],
  ["nicId", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.5"],
  ["evm", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.7"],
  ["mod", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.8"],
  ["name", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.19"],
  ["temp", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.22"],
  ["alarmed", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.20"],
  ["version", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.21"],
  ["gateway", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.17"],
  ["txPackets", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.9"],
  ["txBytes", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.10"],
  ["rxPackets", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.11"],
  ["rxBytes", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.12"],
  ["txError", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.13"],
  ["rxError", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.14"],
  ["txDrop", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.15"],
  ["rxDrop", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.16"],
  ["downEvm", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.24"],
  ["downMod", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.25"],
  ["allIp", "1.3.6.1.4.1.4130.10.2.5.1.2.2.1.18"],
];

function opcTree() {
  const host = document.getElementById("opc-tree");
  if (!host) return;
  const sig = `${state.opcFolder}|${state.opcRadios}|${state.remoteCount}`;
  if (host.dataset.sig === sig) return;
  host.dataset.sig = sig;
  const current = state.opcFolder;
  const button = (id, label, cls) =>
    `<button type="button" class="${cls}${id === current ? " selected" : ""}" data-opc="${esc(id)}">${esc(label)}</button>`;
  const remotes = state.opcRadios
    ? Array.from({ length: state.remoteCount }, (_, index) => button(`Remote${index + 1}`, `Remote${index + 1}`, "remote")).join("")
    : "";
  host.innerHTML = [
    button("trapsnmp", "trapsnmp", ""),
    button("Latest", "Latest", "child"),
    button("Recent", "Recent", "child"),
    button("Gateway", "Gateway", "child"),
    button("Upstream", "Upstream", "child"),
    button("Radios", "Radios", "child"),
    remotes,
    button("Tags", "Tags", "child"),
  ].join("");
}

async function refreshOpc() {
  opcTree();
  const body = document.getElementById("opc-rows");
  if (!body) return;
  const query = document.getElementById("opc-filter")?.value || "";
  try {
    const response = await fetch(`/api/opc?folder=${encodeURIComponent(state.opcFolder)}&q=${encodeURIComponent(query)}`);
    const data = await response.json();
    if (!data.ok) {
      const html = `<tr><td colspan="4">${esc(data.error || "OPC UA is not ready.")}</td></tr>`;
      if (body.dataset.html !== html) {
        body.dataset.html = html;
        body.innerHTML = html;
      }
      return;
    }
    const rows = data.items || [];
    const html = rows.length
      ? rows.map((item) => `
          <tr>
            <td>${esc(item.name)}</td>
            <td class="oid">${esc(item.value)}</td>
            <td>${esc(item.type)}</td>
            <td class="oid">${esc(item.nodeId)}</td>
          </tr>
        `).join("") + (data.truncated ? `<tr><td colspan="4">Showing the first 300 tags. Use the filter to narrow them.</td></tr>` : "")
      : `<tr><td colspan="4">No tags in ${esc(data.folder)}.</td></tr>`;
    if (body.dataset.html !== html) {
      body.dataset.html = html;
      body.innerHTML = html;
    }
  } catch (_err) {
    const html = `<tr><td colspan="4">Could not read the OPC UA server.</td></tr>`;
    if (body.dataset.html !== html) {
      body.dataset.html = html;
      body.innerHTML = html;
    }
  }
}

document.getElementById("opc-tree")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-opc]");
  if (!button) return;
  const folder = button.dataset.opc;
  if (folder === "Radios") state.opcRadios = !state.opcRadios;
  state.opcFolder = folder;
  refreshOpc();
});

document.getElementById("opc-filter")?.addEventListener("input", () => {
  if (state.view === "opc") refreshOpc();
});

function renderRadios(radios) {
  if (!radios) return;
  const status = document.getElementById("radio-status");
  if (status) {
    const when = radios.updatedAt ? `Last poll ${radios.updatedAt}` : "Not polled yet";
    status.textContent = radios.error
      ? `${radios.error} · ${when}`
      : `${radios.count} remote${radios.count === 1 ? "" : "s"} on ${radios.host} · ${when}`;
  }
  const note = document.getElementById("radio-note");
  if (note) note.textContent = radios.enabled ? `Polling every ${radios.interval}s` : "";
  const head = document.getElementById("radio-head");
  if (head && !head.childElementCount) {
    head.innerHTML = `<th>Tag</th>${RADIO_COLUMNS.map(([label]) => `<th>${esc(label)}</th>`).join("")}`;
  }
  const body = document.getElementById("radio-rows");
  if (body) {
    const slots = radios.slots || [];
    const cell = (value) => (value === null || value === undefined || value === "" ? "—" : esc(String(value)));
    body.innerHTML = slots.length
      ? slots.map((row) => `
          <tr>
            <td class="oid">${esc(row.tag)}</td>
            ${RADIO_COLUMNS.map(([key]) => {
              const colored = key === "rssi" || key === "down" ? `rssi ${rssiClass(row[key])}` : "";
              const mono = key === "oid" || key === "remote_mac" || key === "remote_ip" ? "oid" : "";
              const value = key === "oid" && !row.remote_mac ? null : row[key];
              return `<td class="${colored} ${mono}">${cell(value)}</td>`;
            }).join("")}
          </tr>
        `).join("")
      : `<tr><td colspan="${RADIO_COLUMNS.length + 1}">Tags are not ready yet.</td></tr>`;
  }
  const form = document.getElementById("radio-form");
  if (form && !(document.activeElement && form.contains(document.activeElement))) {
    form.elements.host.value = radios.host || "";
    form.elements.community.value = radios.community || "public";
    form.elements.port.value = radios.port || 161;
    form.elements.interval.value = radios.interval || 15;
    form.elements.enabled.checked = !!radios.enabled;
  }
}

document.getElementById("radio-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const intent = event.submitter?.value || "poll";
  try {
    const response = await fetch("/api/radios", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: intent,
        host: form.elements.host.value,
        community: form.elements.community.value,
        port: Number(form.elements.port.value),
        interval: Number(form.elements.interval.value),
        enabled: form.elements.enabled.checked,
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Radio poll failed");
    setBench(intent === "poll" ? "Polled the LN master." : "Master settings saved.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

function renderTags(tags) {
  if (!tags) return;
  const bits = document.getElementById("trap-bits");
  if (bits) {
    const rows = tags.bits || [];
    bits.innerHTML = rows.length
      ? rows.map((row) => `
          <div class="bit ${row.value ? "on" : ""}">
            <span class="sev ${row.value ? "alarm" : ""}">${row.value ? "True" : "False"}</span>
            <span class="addr">${esc(row.address)}</span>
          </div>
        `).join("")
      : '<p class="empty">No trap tags yet.</p>';
  }
  const count = document.getElementById("events-count");
  if (count) count.textContent = String(tags.count ?? 0);
  const latest = document.getElementById("events-001");
  if (latest) latest.textContent = tags.latest || "—";
  const fields = document.getElementById("events-fields");
  if (fields) {
    const names = ["Time", "Enterprise", "Generic", "Specific", "SysUpTime", "Varbinds", "First OID", "First value"];
    const values = tags.latestFields || [];
    fields.innerHTML = names.map((name, index) => `
      <tr>
        <td>${name}</td>
        <td class="oid">${esc(values[index] || "—")}</td>
      </tr>
    `).join("");
  }
  const form = document.getElementById("tag-filter");
  if (form && !(document.activeElement && form.contains(document.activeElement))) {
    form.elements.community.value = tags.community || "";
    form.elements.deviceIp.value = tags.deviceIp || "";
  }
}

document.getElementById("tag-filter")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const response = await fetch("/api/tags", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        community: form.elements.community.value,
        deviceIp: form.elements.deviceIp.value,
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Could not save the filter");
    setBench("Trap tag filter saved.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

function renderAgent(agent) {
  if (!agent) return;
  const port = document.getElementById("agent-port");
  if (port) port.textContent = agent.listening ? `UDP ${agent.port}` : (agent.error || "Down");
  const oid = document.getElementById("agent-oid");
  if (oid) oid.textContent = agent.objectId || "—";
  const notify = document.getElementById("agent-notify");
  if (notify) notify.textContent = agent.lastNotify || (agent.destinations?.length ? "Waiting for a trap" : "No destinations");
  const note = document.getElementById("agent-note");
  if (note) note.textContent = agent.note || agent.notifyError || "";
  const trapOid = document.getElementById("agent-trap-oid");
  if (trapOid) trapOid.textContent = agent.trapOid || "—";
  const form = document.getElementById("agent-form");
  if (form && !(document.activeElement && form.contains(document.activeElement))) {
    form.elements.description.value = agent.description || "";
    form.elements.contact.value = agent.contact || "";
    form.elements.name.value = agent.name || "";
    form.elements.location.value = agent.location || "";
    form.elements.enabled.checked = !!agent.enabled;
    form.elements.acceptAll.checked = !!agent.acceptAll;
    form.elements.threshold.value = agent.threshold ?? 0;
    const select = form.elements.comparison;
    if (select.options.length !== (agent.comparisons || []).length) {
      select.innerHTML = (agent.comparisons || []).map((item) => `<option value="${esc(item)}">${esc(item)}</option>`).join("");
    }
    if ([...select.options].some((option) => option.value === agent.comparison)) select.value = agent.comparison;
  }
  const system = document.getElementById("agent-system");
  if (system) {
    system.innerHTML = (agent.system || []).map((row) => `
      <tr>
        <td>${esc(row.name)}</td>
        <td>${esc(row.value || "—")}</td>
        <td class="oid">${esc(row.localOid)}</td>
      </tr>
    `).join("");
  }
  const items = document.getElementById("agent-items");
  if (items) {
    items.innerHTML = (agent.items || []).map((row) => `
      <tr>
        <td>${esc(row.name)}</td>
        <td>${esc(row.value || "—")}</td>
        <td class="oid">${esc(row.oid)}</td>
      </tr>
    `).join("");
  }
  const dest = document.getElementById("agent-destinations");
  if (dest) {
    dest.innerHTML = (agent.destinations || []).length
      ? agent.destinations.map((row) => `<span class="chip">${esc(row.address)}:${row.port} · ${esc(row.community)} · V${esc(row.version)}</span>`).join("")
      : '<p class="empty">No trap recipients.</p>';
  }
}

document.getElementById("agent-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const response = await fetch("/api/agent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "settings",
        description: form.elements.description.value,
        contact: form.elements.contact.value,
        name: form.elements.name.value,
        location: form.elements.location.value,
        enabled: form.elements.enabled.checked,
        acceptAll: form.elements.acceptAll.checked,
        comparison: form.elements.comparison.value,
        threshold: form.elements.threshold.value,
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Could not save the agent");
    setBench("Agent saved.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

document.getElementById("dest-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const response = await fetch("/api/agent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "destination",
        address: form.elements.address.value,
        port: form.elements.port.value,
        community: form.elements.community.value,
        version: form.elements.version.value,
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Could not add the recipient");
    form.elements.address.value = "";
    setBench("Trap recipient added.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

document.querySelector(".nav").addEventListener("click", (event) => {
  const button = event.target.closest("[data-view]");
  if (!button) return;
  showView(button.dataset.view);
});

const initial = (location.hash || "").replace("#", "");
if (["monitor", "tags", "send", "access", "agent", "config", "radios", "publish", "diag"].includes(initial)) showView(initial);

document.getElementById("run-diag").addEventListener("click", async () => {
  const button = document.getElementById("run-diag");
  if (state.sending) return;
  state.sending = true;
  button.disabled = true;
  setBench("Running loopback…");
  try {
    const response = await fetch("/api/diag", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const report = await response.json().catch(() => ({}));
    if (!response.ok && !report.steps) {
      throw new Error(report.error || "Loopback failed");
    }
    renderReport(report);
    setBench(report.ok ? "Loopback passed." : "Loopback failed.", !report.ok);
    showView("diag");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  } finally {
    state.sending = false;
    button.disabled = false;
  }
});

tick();
setInterval(tick, 1000);
