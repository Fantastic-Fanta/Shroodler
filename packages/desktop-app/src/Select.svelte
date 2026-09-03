<script>
  import { onDestroy } from "svelte";

  export let value = "";
  export let options = [];
  export let ariaLabel = undefined;
  export let disabled = false;
  export let placeholder = "Select";
  export let wide = false;
  export let id = undefined;
  let className = "";
  export { className as class };

  let open = false;
  let highlighted = 0;
  let root;
  let triggerEl;
  let listEl;
  const uid = `sel-${Math.random().toString(36).slice(2, 9)}`;

  $: selected = options.find((o) => String(o.value) === String(value));
  $: display = selected ? selected.label : placeholder;

  function optionIndex() {
    const i = options.findIndex((o) => String(o.value) === String(value));
    return i < 0 ? 0 : i;
  }

  function openMenu() {
    if (disabled || !options.length) return;
    open = true;
    highlighted = optionIndex();
    document.addEventListener("pointerdown", onDocDown, true);
    requestAnimationFrame(() => {
      listEl?.focus();
      listEl
        ?.querySelector(`[data-index="${highlighted}"]`)
        ?.scrollIntoView({ block: "nearest" });
    });
  }

  function closeMenu(restoreFocus = true) {
    if (!open) return;
    open = false;
    document.removeEventListener("pointerdown", onDocDown, true);
    if (restoreFocus) triggerEl?.focus();
  }

  function onDocDown(e) {
    if (root && !root.contains(e.target)) closeMenu(false);
  }

  function choose(opt) {
    value = opt.value;
    closeMenu();
  }

  function onTriggerKey(e) {
    if (disabled) return;
    if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
      e.preventDefault();
      openMenu();
    }
  }

  function onListKey(e) {
    if (e.key === "Escape") {
      e.preventDefault();
      closeMenu();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      highlighted = Math.min(options.length - 1, highlighted + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      highlighted = Math.max(0, highlighted - 1);
    } else if (e.key === "Home") {
      e.preventDefault();
      highlighted = 0;
    } else if (e.key === "End") {
      e.preventDefault();
      highlighted = Math.max(0, options.length - 1);
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const opt = options[highlighted];
      if (opt) choose(opt);
    } else if (e.key === "Tab") {
      closeMenu(false);
    }
  }

  onDestroy(() => {
    document.removeEventListener("pointerdown", onDocDown, true);
  });
</script>

<div
  class="select {className}"
  class:wide
  class:is-open={open}
  class:is-disabled={disabled}
  bind:this={root}
>
  <button
    type="button"
    {id}
    class="select-trigger"
    class:is-placeholder={!selected}
    bind:this={triggerEl}
    aria-label={ariaLabel}
    aria-haspopup="listbox"
    aria-expanded={open}
    aria-controls={uid}
    disabled={disabled}
    on:click={() => (open ? closeMenu() : openMenu())}
    on:keydown={onTriggerKey}
  >
    <span class="select-value">{display}</span>
    <svg class="select-chevron" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M4.2 6.2a.75.75 0 0 1 1.06 0L8 8.94l2.74-2.74a.75.75 0 1 1 1.06 1.06l-3.27 3.27a.75.75 0 0 1-1.06 0L4.2 7.26a.75.75 0 0 1 0-1.06z"
        fill="currentColor"
      />
    </svg>
  </button>
  {#if open}
    <ul
      id={uid}
      class="select-menu"
      role="listbox"
      tabindex="-1"
      bind:this={listEl}
      aria-activedescendant="{uid}-opt-{highlighted}"
      on:keydown={onListKey}
    >
      {#each options as opt, i (opt.value)}
        <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-noninteractive-element-interactions -->
        <li
          id="{uid}-opt-{i}"
          class="select-option"
          class:is-active={i === highlighted}
          class:is-selected={String(opt.value) === String(value)}
          role="option"
          data-index={i}
          aria-selected={String(opt.value) === String(value)}
          on:pointerenter={() => (highlighted = i)}
          on:click={() => choose(opt)}
        >
          {opt.label}
        </li>
      {/each}
    </ul>
  {/if}
</div>
