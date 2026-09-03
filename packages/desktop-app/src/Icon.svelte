<script>
  export let name = "";

  const icons = {
    scan: `<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2.5"/><line x1="12" y1="2" x2="12" y2="5"/>`,
    map: `<circle cx="12" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="19" r="2"/><line x1="12" y1="7" x2="12" y2="12"/><line x1="12" y1="12" x2="6" y2="17"/><line x1="12" y1="12" x2="18" y2="17"/>`,
    findings: `<path d="M12 3 L21 19 H3 Z"/><line x1="12" y1="9" x2="12" y2="13.5"/><circle cx="12" cy="16.2" r="0.6" fill="currentColor" stroke="none"/>`,
    diff: `<line x1="4" y1="8" x2="16" y2="8"/><polyline points="13,5 16,8 13,11"/><line x1="20" y1="16" x2="8" y2="16"/><polyline points="11,13 8,16 11,19"/>`,
    proxy: `<circle cx="5" cy="12" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><line x1="7" y1="12" x2="17" y2="7"/><line x1="7" y1="12" x2="17" y2="17"/>`,
    composer: `<polyline points="6,8 10,12 6,16"/><line x1="13" y1="16" x2="18" y2="16"/>`,
    play: `<polygon points="6,4 20,12 6,20"/>`,
    stop: `<rect x="6" y="6" width="12" height="12" rx="1.5"/>`,
    upload: `<path d="M12 4 V15"/><polyline points="8,8 12,4 16,8"/><path d="M4 15 V18 A2 2 0 0 0 6 20 H18 A2 2 0 0 0 20 18 V15"/>`,
    shield: `<path d="M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z"/><polyline points="9,12 11,14.2 15,9.8"/>`,
    "shield-off": `<path d="M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/>`,
    plug: `<path d="M9 3 V8" /><path d="M15 3 V8" /><path d="M6 8 H18 V12 A6 6 0 0 1 6 12 Z" /><line x1="12" y1="18" x2="12" y2="21" />`,
    "download-cloud": `<path d="M7 16 A4 4 0 0 1 8 8.1 A5 5 0 0 1 18 9 A3.5 3.5 0 0 1 17.5 16" /><polyline points="9,14 12,17 15,14" /><line x1="12" y1="10" x2="12" y2="17" />`,
    folder: `<path d="M4 6 H10 L12 8 H20 V18 A1 1 0 0 1 19 19 H5 A1 1 0 0 1 4 18 Z"/>`,
    search: `<circle cx="11" cy="11" r="6"/><line x1="15.5" y1="15.5" x2="20" y2="20"/>`,
    trash: `<line x1="4" y1="6" x2="20" y2="6"/><path d="M6 6 L7 20 A1.5 1.5 0 0 0 8.5 21.5 H15.5 A1.5 1.5 0 0 0 17 20 L18 6"/><path d="M9.5 6 V4 A1 1 0 0 1 10.5 3 H13.5 A1 1 0 0 1 14.5 4 V6"/>`,
    filter: `<polygon points="3,4 21,4 14,12 14,19 10,21 10,12"/>`,
    check: `<polyline points="4,12 9,17 20,6"/>`,
  };
</script>

<span class="icon" aria-hidden="true">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
    {@html icons[name] || ""}
  </svg>
</span>
