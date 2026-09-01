<script>
  import { onMount } from "svelte";
  import { diffScans } from "./lib/diff.js";
  import {
    filterFindings,
    parseAutoResponderYaml,
    parseHeaderBlock,
    sortFindings,
  } from "./lib/findings.js";

  let view = "scan";
  let target = "http://127.0.0.1:8081";
  let mode = "static";
  let depth = 5;
  let scanning = false;
  let progress = { pages_crawled: 0, current_url: "" };
  let findings = [];
  let selected = null;
  let filterSev = "all";
  let sortKey = "severity";
  let history = [];
  let outputPath = "";
  let error = "";
  let baseId = "";
  let compareId = "";
  let diff = { added: [], resolved: [] };
  let sessions = [];
  let selectedSession = null;
  let proxyOn = false;
  let proxyWs = null;
  let composer = { method: "GET", url: "http://127.0.0.1:8081/", headers: "", body: "" };
  let bpMethod = "GET";
  let bpPattern = ".*";
  let bpStage = "request";
  let paused = [];
  let arYaml =
    "- match:\n    method: GET\n    url_pattern: .*\n  respond:\n    status: 200\n    body: mocked\n";
  let caOpen = false;
  let caAction = "install";

  const sevColor = {
    critical: "var(--sev-critical)",
    high: "var(--sev-high)",
    medium: "var(--sev-medium)",
    low: "var(--sev-low)",
    info: "var(--sev-info)",
  };

  $: visible = sortFindings(filterFindings(findings, { severity: filterSev }), sortKey, "asc");

  function isTauri() {
    return typeof window !== "undefined" && !!(window.__TAURI_INTERNALS__ || window.__TAURI__);
  }

  async function invoke(cmd, args) {
    if (!isTauri()) {
      throw new Error("Tauri shell unavailable — open via `npm run tauri dev`");
    }
    const { invoke: inv } = await import("@tauri-apps/api/core");
    return inv(cmd, args);
  }

  async function startScan() {
    error = "";
    scanning = true;
    progress = { pages_crawled: 0, current_url: target };
    try {
      await invoke("start_scan", { target, mode, depth: Number(depth) });
    } catch (e) {
      error = String(e);
      scanning = false;
    }
  }

  async function stopScan() {
    try {
      await invoke("stop_scan", { scanId: "current" });
    } catch (e) {
      error = String(e);
    }
    scanning = false;
  }

  async function applyDoc(doc, path) {
    findings = doc.findings || [];
    scanning = false;
    outputPath = path || outputPath;
    view = "findings";
    await refreshHistory();
  }

  async function refreshHistory() {
    try {
      history = (await invoke("list_scans")) || [];
      if (!baseId && history[0]) baseId = history[0].id;
      if (!compareId && history[1]) compareId = history[1].id;
    } catch {
      /* preview */
    }
  }

  async function openHistory(h) {
    const doc = await invoke("load_scan", { scanId: h.id });
    findings = doc.findings || [];
    outputPath = h.id;
    view = "findings";
  }

  async function loadFile(ev) {
    const file = ev.target.files[0];
    if (!file) return;
    const doc = JSON.parse(await file.text());
    applyDoc(doc, file.name);
  }

  async function runDiff() {
    try {
      diff = await invoke("diff_scans", { baseId, compareId });
    } catch {
      const a = history.find((h) => h.id === baseId);
      const b = history.find((h) => h.id === compareId);
      const da = a ? await invoke("load_scan", { scanId: a.id }).catch(() => ({ findings: [] })) : { findings: [] };
      const db = b ? await invoke("load_scan", { scanId: b.id }).catch(() => ({ findings: [] })) : { findings: [] };
      diff = diffScans(da, db);
    }
  }

  function sendWs(msg) {
    if (proxyWs && proxyWs.readyState === 1) proxyWs.send(JSON.stringify(msg));
  }

  async function connectProxy() {
    error = "";
    try {
      await invoke("start_proxy");
    } catch (e) {
      error = String(e);
    }
    const ws = new WebSocket("ws://127.0.0.1:8890/control");
    proxyWs = ws;
    ws.onopen = () => {
      proxyOn = true;
      ws.send(JSON.stringify({ type: "subscribe" }));
    };
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "session:complete" && msg.session) {
        sessions = [msg.session, ...sessions];
      }
      if (msg.type === "session:new" && msg.session) {
        sessions = [msg.session, ...sessions.filter((s) => s.id !== msg.session.id)];
      }
      if (msg.type === "breakpoint:hit") {
        paused = [{ session_id: msg.session_id, stage: msg.stage, session: msg.session }, ...paused];
      }
      if (msg.type === "error") error = msg.message;
    };
    ws.onerror = () => {
      error = "Proxy control channel not reachable on :8890";
    };
  }

  function setBreakpoints() {
    sendWs({
      type: "set_breakpoints",
      rules: [{ method: bpMethod, url_pattern: bpPattern, stage: bpStage }],
    });
  }

  function applyAutoResponder() {
    sendWs({ type: "set_autoresponder_rules", rules: parseAutoResponderYaml(arYaml) });
  }

  function composeSend() {
    sendWs({
      type: "compose_request",
      request: {
        method: composer.method,
        url: composer.url,
        headers: parseHeaderBlock(composer.headers),
        body: composer.body,
      },
    });
  }

  async function confirmCa() {
    try {
      if (caAction === "install") await invoke("install_ca", { confirmed: true });
      else await invoke("uninstall_ca", { confirmed: true });
    } catch (e) {
      error = String(e);
    }
    caOpen = false;
  }

  onMount(async () => {
    if (!isTauri()) return;
    const { listen } = await import("@tauri-apps/api/event");
    listen("scan:progress", (ev) => {
      progress = ev.payload;
      scanning = true;
    });
    listen("scan:complete", async (ev) => {
      scanning = false;
      outputPath = ev.payload.output_path;
      try {
        const doc = await invoke("load_scan", { scanId: ev.payload.scan_id });
        findings = doc.findings || [];
        view = "findings";
      } catch {
        /* file may still be flushing */
      }
      refreshHistory();
    });
    listen("scan:error", (ev) => {
      scanning = false;
      error = ev.payload.message;
    });
    refreshHistory();
  });
</script>

<div class="shell">
  <aside>
    <div class="brand">Shroodler</div>
    <nav>
      <button class:active={view === "scan"} on:click={() => (view = "scan")}>Scan</button>
      <button class:active={view === "findings"} on:click={() => (view = "findings")}>Findings</button>
      <button class:active={view === "diff"} on:click={() => (view = "diff")}>Diff</button>
      <button class:active={view === "proxy"} on:click={() => (view = "proxy")}>Proxy</button>
      <button class:active={view === "compose"} on:click={() => (view = "compose")}>Composer</button>
    </nav>
    <div class="hist">
      <h2>History</h2>
      {#each history as h}
        <button class="hist-item" on:click={() => openHistory(h)}
          >{h.target}<span>{h.finding_count}</span></button
        >
      {/each}
    </div>
  </aside>
  <main>
    <header>
      <input bind:value={target} aria-label="Target URL" />
      <select bind:value={mode} aria-label="Mode">
        <option value="static">static</option>
        <option value="headless">headless</option>
      </select>
      <input type="number" bind:value={depth} min="0" aria-label="Depth" />
      {#if scanning}
        <button on:click={stopScan}>Stop</button>
      {:else}
        <button class="primary" on:click={startScan}>Scan</button>
      {/if}
      <label class="file">Load JSON<input type="file" accept="application/json" on:change={loadFile} /></label>
    </header>
    {#if scanning}
      <div class="pulse" role="status">Crawling {progress.pages_crawled} · {progress.current_url || target}</div>
    {/if}
    {#if error}<p class="err">{error}</p>{/if}
    {#if outputPath}<p class="muted">Output: <code>{outputPath}</code></p>{/if}

    {#if view === "scan"}
      <p class="lead">
        Point at a local target. The Go sidecar runs the crawl; this window only renders results.
      </p>
    {:else if view === "findings"}
      <div class="filters">
        {#each ["all", "critical", "high", "medium", "low", "info"] as s}
          <button class:on={filterSev === s} on:click={() => (filterSev = s)}>{s}</button>
        {/each}
        <button on:click={() => (sortKey = "id")}>Sort id</button>
        <button on:click={() => (sortKey = "severity")}>Sort severity</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Sev</th><th>ID</th><th>Category</th><th>URL</th></tr>
          </thead>
          <tbody>
            {#each visible as f}
              <tr on:click={() => (selected = f)} class:sel={selected === f} class="row-in">
                <td style="color:{sevColor[f.severity]}">{f.severity}</td>
                <td><code>{f.id}</code></td>
                <td>{f.category}</td>
                <td><code>{f.url}</code></td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if selected}
          <aside class="drawer">
            <h3>{selected.id}</h3>
            <p>{selected.description}</p>
            {#if selected.evidence}<pre>{selected.evidence}</pre>{/if}
          </aside>
        {/if}
      </div>
    {:else if view === "diff"}
      <div class="row">
        <select bind:value={baseId} aria-label="Baseline">
          {#each history as h}<option value={h.id}>{h.target} {h.id.slice(0, 8)}</option>{/each}
        </select>
        <select bind:value={compareId} aria-label="Compare">
          {#each history as h}<option value={h.id}>{h.target} {h.id.slice(0, 8)}</option>{/each}
        </select>
        <button class="primary" on:click={runDiff}>Compare</button>
      </div>
      <h3>Added</h3>
      {#each diff.added as f}<div class="chip add">{f.id} {f.url}</div>{/each}
      <h3>Resolved</h3>
      {#each diff.resolved as f}<div class="chip res">{f.id} {f.url}</div>{/each}
    {:else if view === "proxy"}
      <div class="row">
        <button class="primary" on:click={connectProxy}>{proxyOn ? "Listening" : "Start proxy"}</button>
        <button
          on:click={() => {
            caAction = "install";
            caOpen = true;
          }}>Install CA…</button
        >
        <button
          on:click={() => {
            caAction = "uninstall";
            caOpen = true;
          }}>Uninstall CA…</button
        >
      </div>
      {#if caOpen}
        <div class="dialog" role="dialog" aria-modal="true">
          <p>
            {caAction === "install"
              ? "This installs a local Shroodler root CA so HTTPS interception works on this machine. Continue?"
              : "This removes the local Shroodler proxy CA files. Continue?"}
          </p>
          <button class="primary" on:click={confirmCa}>Confirm</button>
          <button on:click={() => (caOpen = false)}>Cancel</button>
        </div>
      {/if}
      <ul class="sessions">
        {#each sessions as s}
          <li>
            <button on:click={() => (selectedSession = s)}
              ><code>{s.request?.method} {s.request?.url}</code></button
            >
          </li>
        {/each}
      </ul>
      {#if selectedSession}
        <pre>{JSON.stringify(selectedSession, null, 2)}</pre>
      {/if}
    {:else if view === "compose"}
      <div class="stack">
        <select bind:value={composer.method}><option>GET</option><option>POST</option></select>
        <input bind:value={composer.url} aria-label="Composer URL" />
        <textarea bind:value={composer.headers} placeholder="Header: value"></textarea>
        <textarea bind:value={composer.body} placeholder="Body"></textarea>
        <button class="primary" on:click={composeSend}>Send</button>
        <label>Breakpoint method
          <select bind:value={bpMethod}><option>GET</option><option>POST</option></select>
        </label>
        <label>Breakpoint URL pattern <input bind:value={bpPattern} /></label>
        <label>Stage
          <select bind:value={bpStage}><option>request</option><option>response</option></select>
        </label>
        <button on:click={setBreakpoints}>Set breakpoint</button>
        {#each paused as p}
          <div class="chip">
            paused {p.stage} {p.session_id}
            <button
              on:click={() => {
                sendWs({ type: "resume_breakpoint", session_id: p.session_id, edits: null });
                paused = paused.filter((x) => x !== p);
              }}>Resume</button
            >
            <button
              on:click={() => {
                sendWs({ type: "drop_breakpoint", session_id: p.session_id });
                paused = paused.filter((x) => x !== p);
              }}>Drop</button
            >
          </div>
        {/each}
        <label>AutoResponder YAML<textarea bind:value={arYaml} rows="8"></textarea></label>
        <button on:click={applyAutoResponder}>Apply rules</button>
      </div>
    {/if}
  </main>
</div>

<style>
  .shell {
    display: grid;
    grid-template-columns: 220px minmax(0, 1fr);
    height: 100%;
  }
  aside {
    background: var(--bg-raised);
    border-right: 1px solid var(--border);
    padding: 1rem 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .brand {
    color: var(--accent);
    font-weight: 650;
    letter-spacing: 0.04em;
    font-style: normal;
  }
  nav button,
  .hist-item {
    display: block;
    width: 100%;
    text-align: left;
    background: transparent;
    color: var(--text-muted);
    border: 0;
    border-left: 2px solid transparent;
    padding: 0.4rem 0.6rem;
    cursor: pointer;
  }
  nav button.active,
  nav button:hover,
  .hist-item:hover {
    color: var(--accent);
    border-left-color: var(--accent);
    background: var(--bg-hover);
  }
  main {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  header {
    display: flex;
    gap: 0.5rem;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    background: var(--bg-raised);
    align-items: center;
  }
  header input:not([type="file"]),
  header select,
  button {
    background: var(--bg-base);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.35rem 0.5rem;
  }
  header input:first-of-type {
    flex: 1;
    min-width: 0;
  }
  header input:focus-visible,
  header select:focus-visible,
  .stack input:focus-visible,
  .stack textarea:focus-visible {
    outline: 2px solid var(--accent-rare);
    outline-offset: 1px;
  }
  .primary {
    background: var(--accent);
    color: var(--bg-base);
    border: 0;
    border-radius: 4px;
    padding: 0.4rem 0.8rem;
    font-weight: 600;
    cursor: pointer;
  }
  .primary:disabled {
    opacity: 0.5;
  }
  .file {
    color: var(--secondary);
    font-size: 0.85rem;
  }
  .file input {
    display: none;
  }
  .pulse {
    color: var(--accent);
    padding: 0.5rem 1rem;
    animation: pulse 1.4s ease-in-out infinite;
  }
  @keyframes pulse {
    50% {
      opacity: 0.55;
    }
  }
  .err {
    color: var(--sev-critical);
    padding: 0 1rem;
  }
  .muted {
    color: var(--text-muted);
    padding: 0 1rem;
  }
  code,
  pre {
    font-family: var(--font-mono);
    font-size: 0.85em;
  }
  .filters {
    padding: 0.5rem 1rem;
    display: flex;
    gap: 0.35rem;
    flex-wrap: wrap;
  }
  .filters button {
    background: var(--bg-raised);
    color: var(--text-muted);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.2rem 0.6rem;
    cursor: pointer;
  }
  .filters button.on {
    color: var(--accent);
    border-color: var(--accent-dim);
  }
  .table-wrap {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    flex: 1;
    min-height: 0;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th,
  td {
    border-bottom: 1px solid var(--border);
    padding: 0.4rem 0.6rem;
    text-align: left;
  }
  tr.sel {
    background: var(--bg-hover);
  }
  .row-in {
    animation: fadein 0.22s ease-out;
  }
  @keyframes fadein {
    from {
      opacity: 0;
      transform: translateY(4px);
    }
  }
  .drawer {
    width: min(360px, 90vw);
    background: var(--bg-raised);
    border-left: 1px solid var(--border);
    padding: 1rem;
    animation: slide 0.28s ease-out;
  }
  @keyframes slide {
    from {
      transform: translateX(12px);
      opacity: 0.4;
    }
  }
  .chip {
    margin: 0.3rem 1rem;
    padding: 0.35rem 0.5rem;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 0.85rem;
  }
  .chip.add {
    background: color-mix(in srgb, var(--accent) 18%, var(--bg-raised));
    animation: diffin 0.45s ease-out;
  }
  .chip.res {
    opacity: 0.55;
  }
  @keyframes diffin {
    from {
      background: var(--accent);
    }
  }
  .row,
  .stack {
    display: flex;
    gap: 0.5rem;
    padding: 1rem;
    flex-wrap: wrap;
  }
  .stack {
    flex-direction: column;
  }
  .stack input,
  .stack textarea,
  .stack select {
    background: var(--bg-raised);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.4rem;
  }
  .dialog {
    margin: 1rem;
    padding: 1rem;
    border: 1px solid var(--accent);
    border-radius: 6px;
    background: var(--bg-raised);
  }
  .lead {
    padding: 1.5rem;
    color: var(--text-muted);
    max-width: 40rem;
  }
  .hist h2,
  h3 {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-style: normal;
  }
  @media (prefers-reduced-motion: reduce) {
    .pulse,
    .drawer,
    .row-in,
    .chip.add {
      animation: none;
    }
  }
  @media (max-width: 768px) {
    .shell {
      grid-template-columns: 1fr;
    }
    .table-wrap {
      grid-template-columns: 1fr;
    }
  }
</style>
