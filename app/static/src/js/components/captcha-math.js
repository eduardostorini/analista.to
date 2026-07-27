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
        if (!response.ok) throw new Error("Falha ao gerar desafio");
        const data = await response.json();
        this.question = data.question;
        this.token = data.token;
        this.answer = "";
      } catch (err) {
        this.error = "Não foi possível carregar o desafio. Tente novamente.";
      } finally {
        this.loading = false;
      }
    },
  };
}
