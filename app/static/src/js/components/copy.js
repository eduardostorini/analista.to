export function copyButton() {
  return {
    copied: false,

    async copy() {
      const targetSelector = this.$el.dataset.copyTarget;
      const text = targetSelector
        ? document.querySelector(targetSelector)?.innerText ?? ""
        : this.$el.dataset.copyText || "";

      try {
        await navigator.clipboard.writeText(text);
      } catch (err) {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }

      this.copied = true;
      setTimeout(() => {
        this.copied = false;
      }, 1800);
    },
  };
}
