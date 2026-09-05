<script>
  import { onMount } from "svelte";
  import Select from "./Select.svelte";
  import Icon from "./Icon.svelte";
  import { diffScans } from "./lib/diff.js";
  import {
    filterFindings,
    parseAutoResponderYaml,
    parseHeaderBlock,
    sortFindings,
  } from "./lib/findings.js";
  import { parseCookieHeader, scanSecrets } from "./lib/secrets.js";
  import {
    cookieHeaderFromSessions,
    copyText,
    filterSessions,
    seedUrlsFromSessions,
    sessionToCurl,
  } from "./lib/sessions.js";
  import { buildSiteMap, flattenTree, pageLabel } from "./lib/sitemap.js";
  import {
    documentToBaseline,
    isSuppressed,
    parseSuppressions,
    suppressionsYaml,
  } from "./lib/baseline.js";
  import { downloadText, renderJunit, renderSarif } from "./lib/export.js";

  let view = "scan";
  let target = "http://127.0.0.1:8081";
  let mode = "static";
  let depth = 5;
  let cookieJar = "";
  let loginRecipe = "";
  let viaProxy = false;
  let useCookies = true;
  let seedFromProxy = true;
  let scanning = false;
  let progress = { pages_crawled: 0, current_url: "" };
  let findings = [];
  let pages = [];
  let scanDoc = { target: "", pages: [], findings: [], crawler: {} };
  let selected = null;
  let selectedNode = null;
  let suppressions = [];
  let showSuppressed = false;
  let filterSev = "all";
  let sortKey = "severity";
  let sortDir = "asc";

  function toggleSort(key) {
    if (sortKey === key) {
      sortDir = sortDir === "asc" ? "desc" : "asc";
    } else {
      sortKey = key;
      sortDir = "asc";
    }
  }
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
  let activeBreakpoint = null;
  let activeAutoResponderRules = null;
  let paused = [];
  let secretHits = [];
  let arYaml =
    "- match:\n    method: GET\n    url_pattern: .*\n  respond:\n    status: 200\n    body: mocked\n";
  let caOpen = false;
  let caAction = "install";
  let caInstalled = false;
  let findingPane = "detail";
  let sessionPane = "headers";
  let composePane = "request";
  let sessMethod = "all";
  let sessStatus = "all";
  let sessUrl = "";
  let curlCopied = false;
  let exportMenuOpen = false;
  let advancedOpen = false;

  function focusOnMount(node) {
    node.focus();
  }

  function activateOnKey(e, fn) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fn();
    }
  }

  function clickOutside(node, callback) {
    const handler = (e) => {
      if (!node.contains(e.target)) callback();
    };
    document.addEventListener("mousedown", handler, true);
    return {
      destroy() {
        document.removeEventListener("mousedown", handler, true);
      },
    };
  }
  let curlCopiedTimer;

  const views = [
    { id: "scan", label: "Scan", icon: "scan" },
    { id: "map", label: "Map", icon: "map" },
    { id: "findings", label: "Findings", icon: "findings" },
    { id: "diff", label: "Diff", icon: "diff" },
    { id: "proxy", label: "Proxy", icon: "proxy" },
    { id: "compose", label: "Composer", icon: "composer" },
  ];
  const modeOpts = [
    { value: "static", label: "static" },
    { value: "headless", label: "headless" },
  ];
  const methodOpts = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => ({
    value: m,
    label: m,
  }));
  const stageOpts = [
    { value: "request", label: "request" },
    { value: "response", label: "response" },
  ];
  const statusFilterOpts = [
    { value: "all", label: "all" },
    { value: "2xx", label: "2xx" },
    { value: "3xx", label: "3xx" },
    { value: "4xx", label: "4xx" },
    { value: "5xx", label: "5xx" },
    { value: "none", label: "none" },
  ];
  const methodFilterBase = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

  $: visible = sortFindings(
    filterFindings(findings, { severity: filterSev }).filter(
      (f) => showSuppressed || !isSuppressed(f, suppressions),
    ),
    sortKey,
    sortDir,
  );
  $: if (selected && !visible.includes(selected)) {
    selected = null;
  }
  $: siteMap = buildSiteMap(pages, findings, sessions);
  $: mapRows = siteMap.flatMap((h) =>
    flattenTree(h.tree).map((n) => ({ ...n, origin: h.origin })),
  );
  $: activeFindings = findings.filter((f) => !isSuppressed(f, suppressions));
  $: cookies = Object.entries(selectedSession?.response?.headers || {})
    .filter(([k]) => k.toLowerCase() === "set-cookie")
    .map(([, v]) => parseCookieHeader(v));
  $: cookieHeader = cookieHeaderFromSessions(sessions, target);
  $: seedUrls = seedUrlsFromSessions(sessions, target);
  $: histOpts = history.map((h) => ({
    value: h.id,
    label: `${h.target} ${h.id.slice(0, 8)}`,
  }));
  $: statusLabel = scanning
    ? `Crawling ${progress.pages_crawled}`
    : proxyOn
      ? "Capturing"
      : "Ready";
  $: visibleSessions = filterSessions(sessions, {
    method: sessMethod,
    status: sessStatus,
    url: sessUrl,
  });
  $: methodFilterOpts = (() => {
    const extra = [];
    const seen = new Set(methodFilterBase);
    for (const s of sessions) {
      const m = String(s.request?.method || "").toUpperCase();
      if (m && !seen.has(m)) {
        seen.add(m);
        extra.push(m);
      }
    }
    extra.sort();
    return [
      { value: "all", label: "all" },
      ...methodFilterBase.concat(extra).map((m) => ({ value: m, label: m })),
    ];
  })();
  $: sessFilterOn = sessMethod !== "all" || sessStatus !== "all" || sessUrl.trim() !== "";

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
      if (viaProxy && !proxyOn) {
        await connectProxy();
      }
      await invoke("start_scan", {
        target,
        mode,
        depth: Number(depth),
        cookieJar: cookieJar || null,
        loginRecipe: loginRecipe || null,
        viaProxy,
        cookie: useCookies ? cookieHeader || null : null,
        seeds: seedFromProxy ? seedUrls : [],
      });
    } catch (e) {
      error = String(e);
      scanning = false;
    }
  }

  async function ingestCaptured() {
    error = "";
    if (!sessions.length) {
      error = "No captured sessions to ingest";
      return;
    }
    try {
      scanning = true;
      await invoke("ingest_sessions", { sessions, target });
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

  function adoptDoc(doc, path) {
    scanDoc = doc || { target: "", pages: [], findings: [], crawler: {} };
    findings = scanDoc.findings || [];
    pages = scanDoc.pages || [];
    if (scanDoc.target) target = scanDoc.target;
    scanning = false;
    outputPath = path || outputPath;
    selected = null;
    selectedNode = null;
  }

  async function applyDoc(doc, path) {
    adoptDoc(doc, path);
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
    adoptDoc(doc, h.id);
    view = "findings";
  }

  async function loadFile(ev) {
    const file = ev.target.files[0];
    if (!file) return;
    const text = await file.text();
    if (file.name.endsWith(".shroodlerignore") || file.name.endsWith(".yaml") || file.name.endsWith(".yml")) {
      suppressions = parseSuppressions(text);
      return;
    }
    const doc = JSON.parse(text);
    if (doc.expected_findings && !doc.findings) {
      error = "Loaded a baseline file — use Diff, or Load JSON a crawl document for Map.";
      return;
    }
    applyDoc(doc, file.name);
  }

  function saveBaseline() {
    const name = scanDoc.target || "local-app";
    const body = documentToBaseline(scanDoc, { name, suppressions });
    downloadText("expected_findings.json", JSON.stringify(body, null, 2) + "\n");
  }

  function exportSarif() {
    downloadText("shroodler.sarif", renderSarif(scanDoc, activeFindings), "application/sarif+json");
  }

  function exportJunit() {
    downloadText("shroodler-junit.xml", renderJunit(scanDoc, activeFindings), "application/xml");
  }

  function saveIgnore() {
    downloadText(".shroodlerignore", suppressionsYaml(suppressions), "text/yaml");
  }

  function suppressSelected() {
    if (!selected) return;
    const path = (() => {
      try {
        return new URL(selected.url).pathname || "/";
      } catch {
        return selected.url || "*";
      }
    })();
    if (suppressions.some((s) => s.id === selected.id && s.url === path)) return;
    suppressions = [
      ...suppressions,
      { id: selected.id, url: path, reason: "accepted in baseline" },
    ];
  }

  function unsuppressSelected() {
    if (!selected) return;
    const path = (() => {
      try {
        return new URL(selected.url).pathname || "/";
      } catch {
        return selected.url || "*";
      }
    })();
    suppressions = suppressions.filter((s) => !(s.id === selected.id && s.url === path));
  }

  function pickNode(row) {
    selectedNode = row;
    if (row.findings?.length) {
      selected = row.findings[0];
    }
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
    const rule = { method: bpMethod, url_pattern: bpPattern, stage: bpStage };
    sendWs({ type: "set_breakpoints", rules: [rule] });
    activeBreakpoint = rule;
  }

  function clearBreakpoints() {
    sendWs({ type: "set_breakpoints", rules: [] });
    activeBreakpoint = null;
  }

  function applyAutoResponder() {
    const rules = parseAutoResponderYaml(arYaml);
    sendWs({ type: "set_autoresponder_rules", rules });
    activeAutoResponderRules = rules.length ? rules : null;
  }

  function clearAutoResponder() {
    sendWs({ type: "set_autoresponder_rules", rules: [] });
    activeAutoResponderRules = null;
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

  async function refreshCaStatus() {
    try {
      const st = await invoke("ca_status");
      caInstalled = !!(st && st.installed);
    } catch {
      caInstalled = false;
    }
  }

  function openCa(action) {
    caAction = action;
    caOpen = true;
  }

  async function confirmCa() {
    try {
      if (caAction === "install") await invoke("install_ca", { confirmed: true });
      else await invoke("uninstall_ca", { confirmed: true });
    } catch (e) {
      error = String(e);
    }
    caOpen = false;
    await refreshCaStatus();
  }

  function hostOf(url) {
    try {
      return new URL(url).host;
    } catch {
      return "";
    }
  }

  function pathOf(url) {
    try {
      const u = new URL(url);
      return u.pathname + u.search;
    } catch {
      return url || "";
    }
  }

  function statusClass(code) {
    if (!code) return "";
    if (code >= 500) return "s5";
    if (code >= 400) return "s4";
    if (code >= 300) return "s3";
    if (code >= 200) return "s2";
    return "";
  }

  function bodyOf(msg) {
    return msg?.body?.content || "";
  }

  function pickFinding(f) {
    selected = f;
    findingPane = "detail";
  }

  function pickSession(s) {
    selectedSession = s;
    secretHits = [];
    sessionPane = "headers";
  }

  function runSecretScan() {
    const body = bodyOf(selectedSession?.response) || bodyOf(selectedSession?.request) || "";
    secretHits = scanSecrets(body);
  }

  async function copySessionCurl() {
    if (!selectedSession) return;
    try {
      await copyText(sessionToCurl(selectedSession));
      curlCopied = true;
      if (curlCopiedTimer) clearTimeout(curlCopiedTimer);
      curlCopiedTimer = setTimeout(() => {
        curlCopied = false;
      }, 1400);
    } catch (e) {
      error = String(e);
    }
  }

  function resumePaused(p) {
    sendWs({ type: "resume_breakpoint", session_id: p.session_id, edits: null });
    paused = paused.filter((x) => x !== p);
  }

  function dropPaused(p) {
    sendWs({ type: "drop_breakpoint", session_id: p.session_id });
    paused = paused.filter((x) => x !== p);
  }

  onMount(async () => {
    if (!isTauri()) return;
    refreshCaStatus();
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
        adoptDoc(doc, ev.payload.scan_id);
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

<div class="shell" class:has-banner={!!error}>
  <div class="titlebar">
    <div class="wordmark"><Icon name="logo" /><span>Shroodler</span></div>
    <div class="title-meta">
      {#if scanning}<span class="live">Crawling</span>{/if}
      {#if proxyOn}<span class="live">Capturing</span>{/if}
      {#if activeBreakpoint}
        <button
          type="button"
          class="ca-chip"
          on:click={() => {
            view = "compose";
            composePane = "breakpoints";
          }}
          title={`Breakpoint active: ${activeBreakpoint.method} ${activeBreakpoint.url_pattern} (${activeBreakpoint.stage})`}
        >
          <Icon name="shield-off" />
          <span>Breakpoint active</span>
        </button>
      {/if}
      {#if activeAutoResponderRules}
        <button
          type="button"
          class="ca-chip"
          on:click={() => {
            view = "compose";
            composePane = "autoresponder";
          }}
          title={`AutoResponder active: ${activeAutoResponderRules.length} rule(s) mocking matching requests`}
        >
          <Icon name="shield-off" />
          <span>AutoResponder active</span>
        </button>
      {/if}
      <button
        type="button"
        class="ca-chip"
        class:on={caInstalled}
        on:click={() => openCa(caInstalled ? "uninstall" : "install")}
        title={caInstalled
          ? "Shroodler root CA is trusted on this machine."
          : "HTTPS interception is unavailable — the Shroodler root CA is not trusted on this machine."}
      >
        <Icon name={caInstalled ? "shield" : "shield-off"} />
        <span>{caInstalled ? "CA trusted" : "CA untrusted"}</span>
      </button>
    </div>
  </div>

  <div class="cmd">
    {#if view === "scan" || view === "findings" || view === "map"}
      <input class="field field-grow" bind:value={target} aria-label="Target URL" />
      <Select class="field-sm" bind:value={mode} ariaLabel="Mode" options={modeOpts} />
      <input class="field field-num" type="number" bind:value={depth} min="0" aria-label="Depth" />
      {#if scanning}
        <button class="btn" on:click={stopScan}><Icon name="stop" />Stop</button>
      {:else}
        <button class="btn btn-primary" on:click={startScan}><Icon name="play" />Scan</button>
      {/if}
      <button class="btn btn-ghost" class:on={viaProxy} on:click={() => (viaProxy = !viaProxy)}><Icon name="plug" />Via proxy</button>
      {#if cookieHeader}
        <button class="btn btn-ghost" class:on={useCookies} on:click={() => (useCookies = !useCookies)}>Cookies</button>
      {/if}
      {#if seedUrls.length}
        <button class="btn btn-ghost" class:on={seedFromProxy} on:click={() => (seedFromProxy = !seedFromProxy)}>Seeds</button>
      {/if}
      <label class="btn file-btn"><Icon name="upload" />Load JSON<input type="file" accept=".json,.yaml,.yml,.shroodlerignore,application/json" on:change={loadFile} /></label>
      {#if view === "map" || view === "findings"}
        <div class="menu-wrap" use:clickOutside={() => (exportMenuOpen = false)}>
          <button
            class="btn"
            disabled={!pages.length && !findings.length}
            title={!pages.length && !findings.length ? "Run a scan or load a crawl document first" : ""}
            on:click={() => (exportMenuOpen = !exportMenuOpen)}
            ><Icon name="download-cloud" />Export<Icon name="chevron" class="caret" /></button
          >
          {#if exportMenuOpen}
            <div class="menu">
              <button
                class="menu-item"
                disabled={!pages.length && !findings.length}
                on:click={() => {
                  saveBaseline();
                  exportMenuOpen = false;
                }}>Baseline JSON</button
              >
              <button
                class="menu-item"
                disabled={!findings.length}
                on:click={() => {
                  exportSarif();
                  exportMenuOpen = false;
                }}>SARIF</button
              >
              <button
                class="menu-item"
                disabled={!findings.length}
                on:click={() => {
                  exportJunit();
                  exportMenuOpen = false;
                }}>JUnit XML</button
              >
            </div>
          {/if}
        </div>
      {/if}
    {:else if view === "diff"}
      <Select
        class="field-grow"
        bind:value={baseId}
        ariaLabel="Baseline"
        placeholder="Baseline"
        disabled={!history.length}
        options={histOpts}
      />
      <span class="subcmd-label">vs</span>
      <Select
        class="field-grow"
        bind:value={compareId}
        ariaLabel="Compare"
        placeholder="Compare"
        disabled={!history.length}
        options={histOpts}
      />
      <button
        class="btn btn-primary"
        on:click={runDiff}
        disabled={!baseId || !compareId}
        title={!baseId || !compareId ? "Pick a baseline and compare scan first" : ""}
        >Compare</button
      >
    {:else if view === "proxy"}
      <button class="btn btn-primary" on:click={connectProxy} disabled={proxyOn}
        ><Icon name="plug" />{proxyOn ? "Listening" : "Start proxy"}</button
      >
      <button class="btn" on:click={ingestCaptured} disabled={!sessions.length}><Icon name="upload" />Ingest findings</button>
      {#if caInstalled}
        <button class="btn" on:click={() => openCa("uninstall")}><Icon name="shield-off" />Uninstall CA</button>
      {:else}
        <button class="btn" on:click={() => openCa("install")}><Icon name="shield" />Install CA</button>
      {/if}
      {#if paused.length}
        <span class="subcmd-label">{paused.length} paused</span>
      {/if}
    {:else if view === "compose"}
      <Select class="field-sm" bind:value={composer.method} ariaLabel="Method" options={methodOpts} />
      <input class="field field-grow" bind:value={composer.url} aria-label="Composer URL" />
      <button class="btn btn-primary" on:click={composeSend}>Send</button>
    {/if}
  </div>

  {#if error}<div class="banner" role="alert">{error}</div>{/if}

  <div class="body">
    <nav class="nav-rail" role="tablist" aria-label="Views">
      {#each views as v}
        <button
          type="button"
          role="tab"
          class:on={view === v.id}
          aria-selected={view === v.id}
          title={v.label}
          aria-label={v.label}
          on:click={() => (view = v.id)}><Icon name={v.icon} /></button
        >
      {/each}
    </nav>
    <aside class="rail">
      <div class="rail-h"><span>Scans</span><span class="count-badge">{history.length}</span></div>
      <div class="rail-list">
        {#each history as h}
          <button class="rail-item" class:on={outputPath === h.id} on:click={() => openHistory(h)}>
            <Icon name="folder" />
            <em title={h.target}>{h.target}</em>
            <span class="count-badge">{h.finding_count}</span>
          </button>
        {:else}
          <div class="hint"><Icon name="folder" />No scans yet</div>
        {/each}
      </div>
    </aside>

    <section class="work">
      {#if view === "scan"}
        <div class="grid-pane">
          <div class="subcmd">
            <button type="button" class="btn-ghost" on:click={() => (advancedOpen = !advancedOpen)}
              ><Icon name="chevron" class={advancedOpen ? "caret" : ""} />Advanced</button
            >
          </div>
          {#if advancedOpen}
            <div class="auth-row">
              <label class="auth-field">
                <span>Cookie jar</span>
                <input
                  class="field"
                  bind:value={cookieJar}
                  placeholder="cookies.json / storageState"
                  aria-label="Cookie jar path"
                />
              </label>
              <label class="auth-field">
                <span>Login recipe</span>
                <input
                  class="field"
                  bind:value={loginRecipe}
                  placeholder="login-recipe.json"
                  aria-label="Login recipe path"
                />
              </label>
            </div>
          {/if}
          <div class="pane-h"><span>Log</span></div>
          {#if scanning}
            <pre class="payload">{`Crawling ${progress.pages_crawled}\n${progress.current_url || target}`}</pre>
          {:else if findings.length}
            <p class="payload">
              {findings.length} findings — <button class="link-btn" on:click={() => (view = "findings")}>open Findings</button>
            </p>
          {:else if outputPath}
            <pre class="payload">{outputPath}</pre>
          {:else}
            <pre class="payload">Set a target in the bar and press Scan. Results open in Findings.</pre>
          {/if}
        </div>
      {:else if view === "map"}
        <div class="split">
          <div class="grid-pane">
            <div class="subcmd">
              <span class="subcmd-label">{pages.length} pages</span>
              <span class="subcmd-label">{activeFindings.length} open findings</span>
              {#if suppressions.length}<span class="subcmd-label">{suppressions.length} suppressed</span>{/if}
              <div class="cmd-gap"></div>
              <button class="btn btn-ghost" on:click={saveIgnore} disabled={!suppressions.length} title={!suppressions.length ? "No suppressions to export yet" : ""}>.shroodlerignore</button>
            </div>
            <div class="scroll">
              <table class="data map-table">
                <thead>
                  <tr>
                    <th class="col-status">St</th>
                    <th>Path</th>
                    <th class="col-num">Forms</th>
                    <th class="col-num">Hits</th>
                  </tr>
                </thead>
                <tbody>
                  {#each mapRows as row}
                    <tr
                      class:sel={selectedNode === row}
                      class:map-host={!row.segment}
                      tabindex="0"
                      role="button"
                      on:click={() => pickNode(row)}
                      on:keydown={(e) => activateOnKey(e, () => pickNode(row))}
                    >
                      <td>{#if row.page?.status_code}<span class="pill {statusClass(row.page.status_code)}">{row.page.status_code}</span>{:else}<span class="mono">{row.segment ? "" : "·"}</span>{/if}</td>
                      <td class="mono clip map-path" style="--depth: {row.depth}" title="{row.origin}{row.path}">
                        {#if !row.segment}<span class="map-origin">{row.origin}</span>{:else}{pageLabel(row)}{/if}
                      </td>
                      <td class="mono">{row.page?.forms?.length || ""}</td>
                      <td>
                        {#if row.findings.length}
                          <span class="map-hits">{row.findings.length}</span>
                        {/if}
                      </td>
                    </tr>
                  {:else}
                    <tr class="empty-row">
                      <td colspan="4"><Icon name="map" />Scan a local app or load crawl JSON. Paths land here as a site map.</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
          <div class="inspect">
            <div class="pane-h"><span>{selectedNode ? selectedNode.path : "Page"}</span></div>
            {#if selectedNode?.page}
              <div class="scroll">
                <table class="kv">
                  <tr><th>Url</th><td>{selectedNode.page.url}</td></tr>
                  <tr><th>Status</th><td>{selectedNode.page.status_code}</td></tr>
                  <tr><th>Params</th><td>{(selectedNode.page.params || []).join(", ") || "—"}</td></tr>
                  <tr><th>JS</th><td>{(selectedNode.page.js_files || []).join(", ") || "—"}</td></tr>
                  {#each selectedNode.page.forms || [] as form}
                    <tr>
                      <th>{form.method} {form.action}</th>
                      <td>{(form.fields || []).map((f) => f.name).join(", ")}</td>
                    </tr>
                  {/each}
                  {#each selectedNode.findings as f}
                    <tr>
                      <th class="sev sev-{f.severity}">{f.id}</th>
                      <td>{f.description}</td>
                    </tr>
                  {/each}
                </table>
              </div>
            {:else}
              <p class="hint"><Icon name="map" />Select a path.</p>
            {/if}
          </div>
        </div>
      {:else if view === "findings"}
        <div class="split">
          <div class="grid-pane">
            <div class="subcmd">
              <span class="subcmd-label"><Icon name="filter" />Severity</span>
              <div class="seg" role="group" aria-label="Severity filter">
                {#each ["all", "critical", "high", "medium", "low", "info"] as s}
                  <button class:on={filterSev === s} on:click={() => (filterSev = s)}>{s}</button>
                {/each}
              </div>
              <div class="cmd-gap"></div>
              <button class="btn btn-ghost" class:on={showSuppressed} on:click={() => (showSuppressed = !showSuppressed)}
                >Suppressed</button
              >
              {#if selected && isSuppressed(selected, suppressions)}
                <button class="btn btn-ghost" on:click={unsuppressSelected}><Icon name="check" />Unsuppress</button>
              {:else}
                <button class="btn btn-ghost" on:click={suppressSelected} disabled={!selected} title={!selected ? "Select a finding first" : ""}>Suppress</button>
              {/if}
              <button class="btn btn-ghost" on:click={saveIgnore} disabled={!suppressions.length} title={!suppressions.length ? "No suppressions to export yet" : ""}>.shroodlerignore</button>
            </div>
            <div class="scroll">
              <table class="data">
                <thead>
                  <tr>
                    <th class="col-sev sortable" class:sorted={sortKey === "severity"} on:click={() => toggleSort("severity")}
                      ><span class="th-label">Sev{#if sortKey === "severity"}<Icon name="sort-asc" class={sortDir === "desc" ? "flip" : ""} />{/if}</span></th
                    >
                    <th class="col-id sortable" class:sorted={sortKey === "id"} on:click={() => toggleSort("id")}
                      ><span class="th-label">Id{#if sortKey === "id"}<Icon name="sort-asc" class={sortDir === "desc" ? "flip" : ""} />{/if}</span></th
                    >
                    <th class="col-cat">Category</th>
                    <th>Url</th>
                  </tr>
                </thead>
                <tbody>
                  {#each visible as f}
                    <tr
                      class:sel={selected === f}
                      class:muted={!!isSuppressed(f, suppressions)}
                      tabindex="0"
                      role="button"
                      on:click={() => pickFinding(f)}
                      on:keydown={(e) => activateOnKey(e, () => pickFinding(f))}
                    >
                      <td><span class="pill sev sev-{f.severity}">{f.severity}</span></td>
                      <td class="mono">{f.id}</td>
                      <td>{f.category}</td>
                      <td class="mono clip" title={f.url}>{f.url}</td>
                    </tr>
                  {:else}
                    <tr class="empty-row"><td colspan="4"><Icon name="findings" />No findings in this filter.</td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
          <div class="inspect">
            <div class="inspect-tabs">
              <button class:on={findingPane === "detail"} on:click={() => (findingPane = "detail")}>Detail</button>
              <button class:on={findingPane === "evidence"} on:click={() => (findingPane = "evidence")}>Evidence</button>
            </div>
            {#if selected}
              {#if findingPane === "detail"}
                <div class="scroll">
                  <table class="kv">
                    <tr><th>Id</th><td>{selected.id}</td></tr>
                    <tr><th>Severity</th><td class="sev sev-{selected.severity}">{selected.severity}</td></tr>
                    <tr><th>Category</th><td>{selected.category}</td></tr>
                    <tr><th>Url</th><td>{selected.url}</td></tr>
                    <tr><th>Description</th><td>{selected.description}</td></tr>
                  </table>
                </div>
              {:else if selected.evidence}
                <pre class="payload">{selected.evidence}</pre>
              {:else}
                <p class="hint"><Icon name="findings" />No evidence.</p>
              {/if}
            {:else}
              <p class="hint"><Icon name="findings" />Select a finding.</p>
            {/if}
          </div>
        </div>
      {:else if view === "diff"}
        <div class="split-cols">
          <div class="pane">
            <div class="pane-h"><span>Added {diff.added.length}</span></div>
            <div class="diff-list">
              {#each diff.added as f}
                <div class="diff-row add"><span>{f.id}</span><span class="clip">{f.url}</span></div>
              {:else}
                <p class="hint"><Icon name="diff" />Nothing added.</p>
              {/each}
            </div>
          </div>
          <div class="pane">
            <div class="pane-h"><span>Resolved {diff.resolved.length}</span></div>
            <div class="diff-list">
              {#each diff.resolved as f}
                <div class="diff-row res"><span>{f.id}</span><span class="clip">{f.url}</span></div>
              {:else}
                <p class="hint"><Icon name="check" />Nothing resolved.</p>
              {/each}
            </div>
          </div>
        </div>
      {:else if view === "proxy"}
        <div class="split">
          <div class="grid-pane">
            <div class="subcmd sess-filters">
              <span class="subcmd-label"
                >{sessFilterOn
                  ? `${visibleSessions.length} / ${sessions.length}`
                  : `${sessions.length} sessions`}</span
              >
              <Select
                class="field-sm"
                bind:value={sessMethod}
                ariaLabel="HTTP method filter"
                options={methodFilterOpts}
              />
              <div class="seg" role="group" aria-label="Status class filter">
                {#each statusFilterOpts as opt}
                  <button
                    type="button"
                    class:on={sessStatus === opt.value}
                    aria-pressed={sessStatus === opt.value}
                    aria-label={opt.value === "none" ? "No response" : opt.label}
                    on:click={() => (sessStatus = opt.value)}>{opt.label}</button
                  >
                {/each}
              </div>
              <span class="search-wrap">
                <Icon name="search" />
                <input
                  class="field field-search"
                  bind:value={sessUrl}
                  aria-label="URL substring filter"
                  placeholder="URL contains"
                />
              </span>
            </div>
            <div class="scroll">
              <table class="data">
                <thead>
                  <tr>
                    <th class="col-num">#</th>
                    <th class="col-method">Method</th>
                    <th class="col-status">Status</th>
                    <th>Host</th>
                    <th>Url</th>
                  </tr>
                </thead>
                <tbody>
                  {#each visibleSessions as s}
                    <tr
                      class:sel={selectedSession === s}
                      tabindex="0"
                      role="button"
                      on:click={() => pickSession(s)}
                      on:keydown={(e) => activateOnKey(e, () => pickSession(s))}
                    >
                      <td class="mono">{sessions.length - sessions.indexOf(s)}</td>
                      <td class="mono">{s.request?.method || ""}</td>
                      <td>{#if s.response?.status_code}<span class="pill {statusClass(s.response.status_code)}">{s.response.status_code}</span>{:else}<span class="mono">—</span>{/if}</td>
                      <td class="mono clip">{hostOf(s.request?.url)}</td>
                      <td class="mono clip" title={s.request?.url}>{pathOf(s.request?.url)}</td>
                    </tr>
                  {:else}
                    <tr class="empty-row"
                      ><td colspan="5"
                        ><Icon name={sessions.length ? "filter" : "proxy"} />{sessions.length
                          ? "No sessions in this filter."
                          : "Start the proxy, then traffic appears here."}</td
                      ></tr
                    >
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
          <div class="inspect">
            <div class="inspect-tabs">
              <button class:on={sessionPane === "headers"} on:click={() => (sessionPane = "headers")}>Headers</button>
              <button class:on={sessionPane === "body"} on:click={() => (sessionPane = "body")}>Body</button>
              <button class:on={sessionPane === "raw"} on:click={() => (sessionPane = "raw")}>Raw</button>
              {#if selectedSession}
                <button class="btn-ghost" on:click={copySessionCurl}
                  >{curlCopied ? "Copied" : "Copy as curl"}</button
                >
                <button class="btn-ghost grow" on:click={runSecretScan}>Scan secrets</button>
              {/if}
            </div>
            {#if selectedSession}
              {#if sessionPane === "raw"}
                <pre class="payload">{JSON.stringify(selectedSession, null, 2)}</pre>
              {:else}
                <div class="split-cols">
                  <div class="pane">
                    <div class="pane-h">
                      <span>Request</span>
                      <div class="pane-h-meta">
                        {#if selectedSession.request?.method}<span class="pill">{selectedSession.request.method}</span>{/if}
                      </div>
                    </div>
                    <div class="scroll">
                      {#if sessionPane === "headers"}
                        <table class="kv">
                          <tr><th>Method</th><td>{selectedSession.request?.method}</td></tr>
                          <tr><th>Url</th><td>{selectedSession.request?.url}</td></tr>
                          {#each Object.entries(selectedSession.request?.headers || {}) as [k, v]}
                            <tr><th>{k}</th><td>{v}</td></tr>
                          {/each}
                        </table>
                      {:else}
                        <pre class="payload">{bodyOf(selectedSession.request) || "—"}</pre>
                      {/if}
                    </div>
                  </div>
                  <div class="pane">
                    <div class="pane-h">
                      <span>Response</span>
                      <div class="pane-h-meta">
                        {#if selectedSession.response?.status_code}
                          <span class="pill {statusClass(selectedSession.response.status_code)}">{selectedSession.response.status_code}</span>
                        {/if}
                        {#if bodyOf(selectedSession.response)}<span class="pill">{bodyOf(selectedSession.response).length} B</span>{/if}
                      </div>
                    </div>
                    <div class="scroll">
                      {#if sessionPane === "headers"}
                        <table class="kv">
                          <tr><th>Status</th><td>{selectedSession.response?.status_code ?? "—"}</td></tr>
                          {#each Object.entries(selectedSession.response?.headers || {}) as [k, v]}
                            <tr><th>{k}</th><td>{v}</td></tr>
                          {/each}
                          {#each cookies as c, i}
                            <tr><th>cookie {i + 1}</th><td>{JSON.stringify(c)}</td></tr>
                          {/each}
                          {#each secretHits as h}
                            <tr><th>{h.id}</th><td>{h.evidence}</td></tr>
                          {/each}
                        </table>
                      {:else}
                        <pre class="payload">{bodyOf(selectedSession.response) || "—"}</pre>
                      {/if}
                    </div>
                  </div>
                </div>
              {/if}
            {:else}
              <p class="hint"><Icon name="proxy" />Select a session.</p>
            {/if}
          </div>
        </div>
      {:else if view === "compose"}
        <div class="split">
          <div class="grid-pane">
            <div class="inspect-tabs">
              <button class:on={composePane === "request"} on:click={() => (composePane = "request")}>Request</button>
              <button class:on={composePane === "breakpoints"} on:click={() => (composePane = "breakpoints")}
                >Breakpoints</button
              >
              <button class:on={composePane === "autoresponder"} on:click={() => (composePane = "autoresponder")}
                >AutoResponder</button
              >
            </div>
            {#if composePane === "request"}
              <div class="compose-split">
                <div class="pane">
                  <div class="pane-h"><span>Headers</span></div>
                  <textarea class="field" bind:value={composer.headers} placeholder="Header: value"></textarea>
                </div>
                <div class="pane">
                  <div class="pane-h"><span>Body</span></div>
                  <textarea class="field" bind:value={composer.body} placeholder="raw body"></textarea>
                </div>
              </div>
            {:else if composePane === "breakpoints"}
              {#if activeBreakpoint}
                <div class="bp-banner">
                  <Icon name="shield-off" />
                  <span>Breakpoint active: {activeBreakpoint.method} {activeBreakpoint.url_pattern} ({activeBreakpoint.stage}) — matching traffic will pause.</span>
                  <button class="btn" on:click={clearBreakpoints}>Clear</button>
                </div>
              {/if}
              <div class="form-grid">
                <label for="bp-method">Method</label>
                <Select
                  id="bp-method"
                  class="field-sm"
                  bind:value={bpMethod}
                  ariaLabel="Breakpoint method"
                  options={methodOpts}
                />
                <label for="bp-pattern">URL pattern</label>
                <input id="bp-pattern" class="field" bind:value={bpPattern} />
                <label for="bp-stage">Stage</label>
                <Select
                  id="bp-stage"
                  class="field-sm"
                  bind:value={bpStage}
                  ariaLabel="Breakpoint stage"
                  options={stageOpts}
                />
                <span></span>
                <button class="btn btn-primary" on:click={setBreakpoints}><Icon name="check" />Set breakpoint</button>
              </div>
              <div class="paused">
                {#each paused as p}
                  <div class="paused-row">
                    <span>{p.stage} {p.session_id}</span>
                    <button class="btn" on:click={() => resumePaused(p)}>Resume</button>
                    <button class="btn" on:click={() => dropPaused(p)}>Drop</button>
                  </div>
                {:else}
                  <p class="hint"><Icon name="check" />No paused sessions.</p>
                {/each}
              </div>
            {:else}
              {#if activeAutoResponderRules}
                <div class="bp-banner">
                  <Icon name="shield-off" />
                  <span>AutoResponder active: {activeAutoResponderRules.length} rule{activeAutoResponderRules.length === 1 ? "" : "s"} mocking matching requests instead of hitting the real server.</span>
                  <button class="btn" on:click={clearAutoResponder}>Clear</button>
                </div>
              {/if}
              <div class="pane-h"><span>AutoResponder rules (YAML)</span></div>
              <textarea class="field ar-editor" bind:value={arYaml}></textarea>
              <div class="subcmd">
                <span class="subcmd-label">Match requests and respond without hitting the real server.</span>
                <div class="cmd-gap"></div>
                <button class="btn btn-primary" on:click={applyAutoResponder}><Icon name="check" />Apply rules</button>
              </div>
            {/if}
          </div>
          <div class="inspect">
            <div class="pane-h"><span>Sessions</span></div>
            <div class="scroll">
              <table class="data">
                <thead>
                  <tr>
                    <th class="col-method">Method</th>
                    <th class="col-status">Status</th>
                    <th>Url</th>
                  </tr>
                </thead>
                <tbody>
                  {#each sessions as s}
                    <tr
                      class:sel={selectedSession === s}
                      tabindex="0"
                      role="button"
                      on:click={() => pickSession(s)}
                      on:keydown={(e) => activateOnKey(e, () => pickSession(s))}
                    >
                      <td class="mono">{s.request?.method || ""}</td>
                      <td>{#if s.response?.status_code}<span class="pill {statusClass(s.response.status_code)}">{s.response.status_code}</span>{:else}<span class="mono">—</span>{/if}</td>
                      <td class="mono clip">{s.request?.url}</td>
                    </tr>
                  {:else}
                    <tr class="empty-row"><td colspan="3"><Icon name="proxy" />Start the proxy, then traffic appears here.</td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      {/if}
    </section>
  </div>

  <footer class="status">
    <strong class:live-dot={scanning || proxyOn}>{statusLabel}</strong>
    <span><Icon name="findings" />{activeFindings.length} findings</span>
    {#if suppressions.length}<span>{suppressions.length} suppressed</span>{/if}
    <span><Icon name="map" />{pages.length} pages</span>
    <span><Icon name="proxy" />{sessions.length} sessions</span>
    {#if cookieHeader}<span>cookies</span>{/if}
    {#if seedUrls.length}<span>{seedUrls.length} seeds</span>{/if}
    {#if paused.length}<span>{paused.length} paused</span>{/if}
    <span class="end">{outputPath || target}</span>
  </footer>
</div>

{#if caOpen}
  <div
    class="modal-back"
    on:click={(e) => {
      if (e.target === e.currentTarget) caOpen = false;
    }}
    on:keydown={(e) => {
      if (e.key === "Escape") caOpen = false;
    }}
  >
    <div class="modal" role="dialog" aria-modal="true">
      <p>
        {caAction === "install"
          ? "This installs a local Shroodler root CA so HTTPS interception works on this machine. Continue?"
          : "This removes the local Shroodler proxy CA files. Continue?"}
      </p>
      <div class="modal-actions">
        <button class="btn" use:focusOnMount on:click={() => (caOpen = false)}>Cancel</button>
        <button class="btn btn-primary" on:click={confirmCa}>Confirm</button>
      </div>
    </div>
  </div>
{/if}
