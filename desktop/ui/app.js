// HBS Console desktop shell.
//
// Fallback surface only. The Rust side starts (or provisions) the engine and
// opens the dashboard in its own window; this page appears only when that
// fails, so it offers a retry and a few support actions. Lifecycle commands
// (start / stop / restart / update) live in the tray menu and the `hbs` CLI.
const { invoke } = window.__TAURI__.core;

const el = (id) => document.getElementById(id);
const dot = el("dot");
const statusLabel = el("statusLabel");
const statusDetail = el("statusDetail");
const note = el("note");
const btnRetry = el("btnRetry");

let busy = false;
let openedOnce = false;
let setupNeeded = false;

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
  btnRetry.disabled = on;
  btnRetry.textContent = label ?? "Retry";
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
        : s.server
          ? "Dashboard stopped"
          : "Engine not installed";
    statusDetail.textContent = `${s.url ?? ""}${s.setupRequired ? " · no administrator yet" : ""}`;
    el("metaRoot").textContent = s.root ? `install ${s.root}` : "";
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
  try {
    await invoke("open_dashboard");
    showNote("");
  } catch (e) {
    showNote(String(e));
  }
}

// Retry covers both failure modes: no engine yet (fetch it), and engine
// present but stopped (start it). install_engine is a no-op when one exists.
async function retry() {
  if (busy) return;
  setBusy(true, "Starting…");
  try {
    await invoke("install_engine");
    await invoke("start_server");
    showNote("");
    openedOnce = false;
    await refresh();
  } catch (e) {
    showNote(String(e));
    await refresh();
  } finally {
    setBusy(false);
  }
}

btnRetry.addEventListener("click", retry);

el("btnBrowser").addEventListener("click", async () => {
  try {
    await invoke("open_in_browser");
    showNote("");
  } catch (e) {
    showNote(String(e));
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
  await refresh();
  setInterval(refresh, 3000);
})();
