export function toolSearch() {
  return {
    open: false,
    query: "",
    activeIndex: 0,
    tools: [],

    init() {
      const raw = document.getElementById("analisa-tools-index");
      this.tools = raw ? JSON.parse(raw.textContent || "[]") : [];

      window.addEventListener("keydown", (event) => {
        const isShortcut = (event.key === "k" || event.key === "K") && (event.metaKey || event.ctrlKey);
        if (isShortcut) {
          event.preventDefault();
          this.openPalette();
        }
        if (event.key === "Escape" && this.open) {
          this.close();
        }
      });

      window.addEventListener("analisa:open-search", () => this.openPalette());
    },

    openPalette() {
      this.open = true;
      this.query = "";
      this.activeIndex = 0;
      this.$nextTick(() => this.$refs.input && this.$refs.input.focus());
    },

    close() {
      this.open = false;
    },

    get results() {
      const q = this.query.trim().toLowerCase();
      const pool = q
        ? this.tools.filter(
            (tool) =>
              tool.name.toLowerCase().includes(q) ||
              tool.category.toLowerCase().includes(q) ||
              (tool.keywords || "").toLowerCase().includes(q)
          )
        : this.tools;
      return pool.slice(0, 20);
    },

    move(delta) {
      const total = this.results.length;
      if (!total) return;
      this.activeIndex = (this.activeIndex + delta + total) % total;
    },

    goToActive() {
      const item = this.results[this.activeIndex];
      if (item) window.location.href = item.url;
    },
  };
}
