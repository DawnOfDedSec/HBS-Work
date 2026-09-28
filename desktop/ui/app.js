// HBS Console desktop shell.
//
// Talks to the Rust side through app commands (`status`, `read_settings`, ...);
// no plugin permissions are needed for these. The dashboard itself is opened in
// its own window and is never modified by this page.
const { invoke } = window.__TAURI__.core;

const el = (id) => document.getElementById(id);
const dot = el("dot");
const statusLabel = el("statusLabel");
const statusDetail = el("statusDetail");
const note = el("note");
const btnOpen = el("btnOpen");
const btnOpenLabel = el("btnOpenLabel");
const autostart = el("autostart");

const setBind = el("setBind");
const setAddress = el("setAddress");
const addressField = el("addressField");
const setPort = el("setPort");
const setTls = el("setTls");
const setCert = el("setCert");
const setKey = el("setKey");
const certField = el("certField");
const keyField = el("keyField");
const settingsForm = el("settingsForm");
const settingsHint = el("settingsHint");
const settingsNote = el("settingsNote");
const settingsSealed = el("settingsSealed");

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

let openedOnce = false;
let busy = false;
let setupNeeded = false;
let settingsBusy = false;

function showNote(message) {
  if (!message) {
    note.hidden = true;
    note.textContent = "";
    return;
  }
  note.hidden = false;
  note.textContent = message;
}

function setBusy(on, label) {
  busy = on;
  btnOpen.disabled = on;
  if (label) btnOpenLabel.textContent = label;
}

function setHint(message, tone) {
  settingsHint.textContent = message;
  if (tone) settingsHint.dataset.tone = tone;
  else delete settingsHint.dataset.tone;
}

async function refresh() {
  try {
    const s = await invoke("status");
    const up = !!s.running;
    setupNeeded = up && !!s.setupRequired;
    dot.dataset.state = setupNeeded ? "setup" : up ? "up" : "down";
    statusLabel.textContent = setupNeeded
      ? "Finish setup"
      : up
        ? "Dashboard running"
        : "Dashboard stopped";
    statusDetail.textContent = `${s.url ?? ""}${s.setupRequired ? " · no administrator yet" : ""}`;
    el("metaRoot").textContent = s.root ? `install ${s.root}` : "";
    el("metaServer").textContent = s.server ? "" : "engine not found — re-run the installer";
    if (up && !openedOnce) {
      openedOnce = true;
      if (setupNeeded) showNote("Create the administrator account to finish setup.");
      setTimeout(() => openConsole(), setupNeeded ? 200 : 700);
    }
    return s;
  } catch (e) {
    dot.dataset.state = "down";
    statusLabel.textContent = "Shell cannot reach the server process";
    statusDetail.textContent = String(e);
    return null;
  }
}

async function openConsole() {
  setBusy(true, "Opening…");
  try {
    await invoke("open_dashboard");
    showNote("");
  } catch (e) {
    showNote(String(e));
  } finally {
    setBusy(false, setupNeeded ? "Finish setup" : "Open console");
  }
}

// --- hosting settings -------------------------------------------------------

function bindModeOf(host) {
  if (LOOPBACK.has(host)) return "local";
  if (host === "0.0.0.0" || host === "::") return "all";
  return "custom";
}

function syncBindFields() {
  const mode = setBind.value;
  addressField.hidden = mode !== "custom";
  const tls = setTls.checked;
  certField.hidden = !tls;
  keyField.hidden = !tls;
}

function populateSettings(payload) {
  const settings = payload?.settings ?? {};
  const mode = bindModeOf(settings.host ?? "127.0.0.1");
  setBind.value = mode;
  setAddress.value = mode === "custom" ? (settings.host ?? "") : "";
  setPort.value = String(settings.port ?? 3000);
  setTls.checked = Boolean(settings.tlsCert);
  setCert.value = settings.tlsCert ?? "";
  setKey.value = settings.tlsKey ?? "";
  syncBindFields();

  const storage = payload?.storage ?? {};
  if (payload?.status === "tampered" || storage.status === "tampered") {
    settingsSealed.textContent =
      "Sealed config failed authentication and is being ignored. The engine is running from the environment.";
  } else {
    const where = storage.path ? `sealed at ${storage.path}` : "no config path resolved";
    const when = settings.updatedAt ? ` · last change ${settings.updatedAt} by ${settings.updatedBy}` : "";
    settingsSealed.textContent = `${where}${when}`;
  }
}

async function loadSettings() {
  try {
    const payload = await invoke("read_settings");
    populateSettings(payload);
  } catch (e) {
    settingsSealed.textContent = `could not read settings: ${String(e)}`;
  }
}

async function saveSettings(event) {
  event.preventDefault();
  if (settingsBusy) return;
  const mode = setBind.value;
  const host = mode === "local" ? "127.0.0.1" : mode === "all" ? "0.0.0.0" : setAddress.value.trim();
  const port = Number(setPort.value);
  const tlsCert = setTls.checked ? setCert.value.trim() : "";
  const tlsKey = setTls.checked ? setKey.value.trim() : "";

  if (!host) {
    setHint("Enter an address to bind.", "error");
    return;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    setHint("Port must be a number between 1 and 65535.", "error");
    return;
  }
  if ((tlsCert && !tlsKey) || (!tlsCert && tlsKey)) {
    setHint("TLS needs both a certificate and a key path.", "error");
    return;
  }

  settingsBusy = true;
  const button = el("btnSaveSettings");
  button.disabled = true;
  setHint("Sealing…");
  try {
    const result = await invoke("save_settings", {
      settings: { host, port, tlsCert: tlsCert || undefined, tlsKey: tlsKey || undefined },
    });
    if (result && result.ok) {
      populateSettings({ settings: result.settings, storage: { path: result.configPath } });
      if (!result.restartRequired) {
        setHint("Saved.", "ok");
      } else if (result.restarting) {
        setHint("Saved. Restarting the engine…", "ok");
      } else {
        setHint("Saved. Restart HBS to apply (tray menu → Restart server).", "ok");
      }
      settingsNote.textContent = "sealed config · restart to apply";
      openedOnce = false;
      await refresh();
      await loadSettings();
    } else {
      setHint((result && result.error) || "Could not save the settings.", "error");
    }
  } catch (e) {
    setHint(String(e), "error");
  } finally {
    settingsBusy = false;
    button.disabled = false;
  }
}

// --- wiring -----------------------------------------------------------------

btnOpen.addEventListener("click", openConsole);
el("btnBrowser").addEventListener("click", async () => {
  try {
    await invoke("open_in_browser");
    showNote("");
  } catch (e) {
    showNote(String(e));
  }
});

el("btnStart").addEventListener("click", async (event) => {
  const tile = event.currentTarget;
  tile.disabled = true;
  try {
    await invoke("start_server");
    showNote("");
    await refresh();
  } catch (e) {
    showNote(String(e));
  } finally {
    tile.disabled = false;
  }
});

el("btnRestart").addEventListener("click", async (event) => {
  const tile = event.currentTarget;
  tile.disabled = true;
  try {
    await invoke("restart_server");
    showNote("");
    openedOnce = false;
    await refresh();
  } catch (e) {
    showNote(String(e));
  } finally {
    tile.disabled = false;
  }
});

el("btnLogs").addEventListener("click", () =>
  invoke("open_path", { kind: "logs" }).catch((e) => showNote(String(e))),
);
el("btnData").addEventListener("click", () =>
  invoke("open_path", { kind: "data" }).catch((e) => showNote(String(e))),
);

el("btnQuit").addEventListener("click", async () => {
  try {
    await invoke("stop_server");
  } catch {
    /* server may be service-owned; quitting the window is enough */
  }
  window.close();
});

setBind.addEventListener("change", syncBindFields);
setTls.addEventListener("change", syncBindFields);
settingsForm.addEventListener("submit", saveSettings);

autostart.addEventListener("change", async () => {
  try {
    const enabled = await invoke("set_autostart", { enabled: autostart.checked });
    autostart.checked = !!enabled;
  } catch (e) {
    showNote(String(e));
    autostart.checked = !autostart.checked;
  }
});

// The tiles advertise keys; make them real, but never steal them from a field.
document.addEventListener("keydown", (event) => {
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const tag = document.activeElement?.tagName;
  if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
  const target = { s: "btnStart", r: "btnRestart", l: "btnLogs", d: "btnData" }[
    event.key.toLowerCase()
  ];
  if (target) {
    event.preventDefault();
    el(target).click();
  }
});

window.addEventListener("hbs-error", (event) =>
  showNote(event.detail ? String(event.detail) : "Unknown error"),
);

(async function init() {
  try {
    const info = await invoke("app_info");
    el("metaVersion").textContent = `v${info.version} · ${info.os}/${info.arch}`;
  } catch {
    /* ignore */
  }
  try {
    const a = await invoke("autostart_state");
    autostart.checked = !!a.enabled;
  } catch {
    /* ignore */
  }
  await Promise.all([refresh(), loadSettings()]);
  setInterval(refresh, 3000);
})();
