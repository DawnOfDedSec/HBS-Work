// HBS Console shell page. Talks to the Rust side through app commands
// (`status`, `start_server`, ...); no plugin permissions are needed for these.
const { invoke } = window.__TAURI__.core;

const el = (id) => document.getElementById(id);
const dot = el("dot");
const statusLabel = el("statusLabel");
const statusDetail = el("statusDetail");
const note = el("note");
const btnOpen = el("btnOpen");
const autostart = el("autostart");

let openedOnce = false;
let busy = false;
let setupNeeded = false;

function showNote(msg) {
  if (!msg) {
    note.hidden = true;
    note.textContent = "";
    return;
  }
  note.hidden = false;
  note.textContent = msg;
}

function setBusy(on, label) {
  busy = on;
  btnOpen.disabled = on;
  if (label) btnOpen.querySelector("span").textContent = label;
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
    statusDetail.textContent = setupNeeded
      ? `no administrator yet · http://127.0.0.1:${s.port}`
      : up
        ? `http://127.0.0.1:${s.port} · embedded window or browser`
        : "start it to open the console";
    el("metaRoot").textContent = s.root ? `install: ${s.root}` : "";
    el("metaBun").textContent = s.server ? "" : "Console engine not found — re-run the installer";
    if (up && !openedOnce) {
      openedOnce = true;
      // On a fresh install the console opens on its setup wizard, so go straight
      // there instead of leaving the user on the shell page.
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
    setBusy(false, setupNeeded ? "Finish setup" : "Open HBS Console");
  }
}

btnOpen.addEventListener("click", openConsole);

el("btnBrowser").addEventListener("click", async () => {
  try {
    await invoke("open_in_browser");
    showNote("");
  } catch (e) {
    showNote(String(e));
  }
});

el("btnStart").addEventListener("click", async (ev) => {
  const tile = ev.currentTarget;
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

el("btnRestart").addEventListener("click", async (ev) => {
  const tile = ev.currentTarget;
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

el("btnLogs").addEventListener("click", () => invoke("open_path", { kind: "logs" }).catch((e) => showNote(String(e))));
el("btnData").addEventListener("click", () => invoke("open_path", { kind: "data" }).catch((e) => showNote(String(e))));

el("btnQuit").addEventListener("click", async () => {
  // Ask the tray to exit: quitting from here keeps the server running.
  try {
    await invoke("stop_server");
  } catch {
    /* server may be service-owned; quitting the window is enough */
  }
  window.close();
});

autostart.addEventListener("change", async () => {
  try {
    const enabled = await invoke("set_autostart", { enabled: autostart.checked });
    autostart.checked = !!enabled;
  } catch (e) {
    showNote(String(e));
    autostart.checked = !autostart.checked;
  }
});

window.addEventListener("hbs-error", (ev) => showNote(ev.detail ? String(ev.detail) : "Unknown error"));

(async function init() {
  try {
    const info = await invoke("app_info");
    el("metaVersion").textContent = `HBS Console ${info.version} · ${info.os}/${info.arch}`;
  } catch {
    /* ignore */
  }
  try {
    const a = await invoke("autostart_state");
    autostart.checked = !!a.enabled;
  } catch {
    /* ignore */
  }
  await refresh();
  setInterval(refresh, 3000);
})();
