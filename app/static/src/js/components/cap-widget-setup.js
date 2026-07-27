// Aponta o WASM do widget Cap (https://trycap.dev) para o próprio serviço
// self-hosted `analisa_cap` em vez do default (cdn.jsdelivr.net) — o
// `analisa_cap` espelha esse binário em /assets quando ENABLE_ASSETS_SERVER
// está ativo. Lido de forma preguiçosa pelo widget só na hora de resolver o
// desafio, então definir isso antes do clique do usuário é suficiente.
export function initCapWidget() {
  const el = document.querySelector("cap-widget[data-cap-api-endpoint]");
  if (!el) return;
  try {
    const origin = new URL(el.dataset.capApiEndpoint).origin;
    window.CAP_CUSTOM_WASM_URL = `${origin}/assets/cap_wasm_bg.wasm`;
  } catch (err) {
    /* endpoint mal configurado — deixa o widget usar o default dele */
  }
}
