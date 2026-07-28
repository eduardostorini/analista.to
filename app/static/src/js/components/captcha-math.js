export function mathCaptcha() {
  return {
    question: "",
    token: "",
    answer: "",
    loading: false,
    error: "",

    init() {
      this.fetchChallenge();
    },

    async fetchChallenge() {
      this.loading = true;
      this.error = "";
      try {
        const response = await fetch("/captcha/math", {
          headers: { Accept: "application/json" },
        });
        if (!response.ok) throw new Error("Failed to generate challenge");
        const data = await response.json();
        this.question = data.question;
        this.token = data.token;
        this.answer = "";
      } catch (err) {
        this.error = "Failed to load the challenge. Please try again.";
      } finally {
        this.loading = false;
      }
    },
  };
}