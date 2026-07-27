export function chartTimeline() {
  return {
    points: [],
    hoverIndex: null,

    init() {
      try {
        this.points = JSON.parse(this.$el.dataset.points || "[]");
      } catch (err) {
        this.points = [];
      }
    },

    get maxCount() {
      return Math.max(1, ...this.points.map((p) => p.count));
    },

    xAt(index) {
      const n = this.points.length;
      return n <= 1 ? 0 : (index / (n - 1)) * 100;
    },

    yAt(count) {
      return 100 - (count / this.maxCount) * 100;
    },

    get linePath() {
      return this.points
        .map((p, i) => `${i === 0 ? "M" : "L"}${this.xAt(i).toFixed(2)},${this.yAt(p.count).toFixed(2)}`)
        .join(" ");
    },

    get areaPath() {
      if (!this.points.length) return "";
      const lastX = this.xAt(this.points.length - 1).toFixed(2);
      return `${this.linePath} L${lastX},100 L0,100 Z`;
    },

    onMove(event) {
      if (!this.points.length) return;
      const rect = this.$refs.plot.getBoundingClientRect();
      if (!rect.width) return;
      const fraction = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
      this.hoverIndex = Math.round(fraction * (this.points.length - 1));
    },

    onLeave() {
      this.hoverIndex = null;
    },

    get hovered() {
      return this.hoverIndex === null ? null : this.points[this.hoverIndex];
    },

    get hoverXPercent() {
      return this.hoverIndex === null ? 0 : this.xAt(this.hoverIndex);
    },

    get hoverYPercent() {
      return this.hoverIndex === null || !this.hovered ? 0 : this.yAt(this.hovered.count);
    },

    get tooltipAlign() {
      return this.hoverXPercent > 70 ? "right" : this.hoverXPercent < 30 ? "left" : "center";
    },
  };
}
