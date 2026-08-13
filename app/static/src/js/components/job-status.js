const TERMINAL_STATUSES = new Set(["completed", "failed", "expired", "cancelled"]);
const POLL_INTERVAL_MS = 2000;
const SSE_RECONNECT_DELAY_MS = 1500;
const MAX_SSE_FAILURES_BEFORE_POLL = 2;

const STATUS_LABELS = {
  queued: "Search added to queue",
  validating: "Awaiting validation",
  captcha_check: "Verifying CAPTCHA",
  processing: "Processing",
  querying: "Querying services",
  analyzing: "Analyzing results",
  generating_report: "Generating report",
  generating_page: "Creating public page",
  completed: "Completed",
  failed: "Failed",
  expired: "Expired",
  cancelled: "Cancelled",
};

export function jobStatus() {
  return {
    jobId: null,
    statusUrl: null,
    status: "queued",
    progress: 0,
    message: "",
    errorMessage: "",
    usingPolling: false,
    _eventSource: null,
    _pollTimer: null,
    _sseFailures: 0,
    _redirectTimer: null,

    init() {
      this.jobId = this.$el.dataset.jobId;
      this.statusUrl = this.$el.dataset.statusUrl || `/jobs/${this.jobId}/status`;
      if (!this.jobId) return;
      this.status = this.$el.dataset.initialStatus || "queued";
      this.startStream();
    },

    get label() {
      return STATUS_LABELS[this.status] || this.status;
    },

    get isTerminal() {
      return TERMINAL_STATUSES.has(this.status);
    },

    get isFailure() {
      return this.status === "failed" || this.status === "expired" || this.status === "cancelled";
    },

    startStream() {
      if (typeof window.EventSource === "undefined") {
        this.startPolling();
        return;
      }

      try {
        this._eventSource = new EventSource(this.statusUrl);
      } catch (err) {
        this.startPolling();
        return;
      }

      this._eventSource.addEventListener("job_update", (event) => {
        this._sseFailures = 0;
        this._applyUpdate(JSON.parse(event.data));
      });

      this._eventSource.onerror = () => {
        this._sseFailures += 1;
        if (this.isTerminal) {
          this._closeSource();
          return;
        }
        this._closeSource();
        if (this._sseFailures >= MAX_SSE_FAILURES_BEFORE_POLL) {
          this.startPolling();
        } else {
          setTimeout(() => {
            if (!this.isTerminal) this.startStream();
          }, SSE_RECONNECT_DELAY_MS);
        }
      };
    },

    startPolling() {
      if (this._pollTimer) return;
      this.usingPolling = true;
      const poll = async () => {
        try {
          const response = await fetch(this.statusUrl, {
            headers: { Accept: "application/json" },
          });
          if (response.ok) {
            this._applyUpdate(await response.json());
          }
        } catch (err) {
          /* keeps last known state and retries on next cycle */
        }
        if (!this.isTerminal) {
          this._pollTimer = setTimeout(poll, POLL_INTERVAL_MS);
        }
      };
      poll();
    },

    _applyUpdate(data) {
      this.status = data.status || this.status;
      this.progress = typeof data.progress === "number" ? data.progress : this.progress;
      this.message = data.message || "";
      if (this.isFailure) this.errorMessage = data.message || "The search could not be completed.";
      if (this.isTerminal) {
        this._closeSource();
        if (this._pollTimer) {
          clearTimeout(this._pollTimer);
          this._pollTimer = null;
        }
        this._redirectToResult();
      }
    },

    _redirectToResult() {
      if (this._redirectTimer) return;

      // Do not rely exclusively on an Alpine custom event here. If that event
      // is missed during component initialization, the progress bar reaches
      // 100% but the pending page never transitions to the rendered result.
      this._redirectTimer = setTimeout(() => {
        window.location.reload();
      }, 600);

      this.$dispatch("analisa:job-complete", { jobId: this.jobId, status: this.status });
    },

    _closeSource() {
      if (this._eventSource) {
        this._eventSource.close();
        this._eventSource = null;
      }
    },

    destroy() {
      this._closeSource();
      if (this._pollTimer) clearTimeout(this._pollTimer);
      if (this._redirectTimer) clearTimeout(this._redirectTimer);
    },
  };
}
