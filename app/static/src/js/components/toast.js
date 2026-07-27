export function toast() {
  return {
    items: [],
    _nextId: 1,

    push(message, variant = "info", ttlMs = 4000) {
      const id = this._nextId++;
      this.items.push({ id, message, variant });
      setTimeout(() => this.dismiss(id), ttlMs);
    },

    dismiss(id) {
      this.items = this.items.filter((item) => item.id !== id);
    },

    init() {
      window.addEventListener("analisa:toast", (event) => {
        const { message, variant, ttlMs } = event.detail || {};
        this.push(message, variant, ttlMs);
      });
    },
  };
}
