# Política de Segurança

## Reportando uma vulnerabilidade

Se você encontrar uma vulnerabilidade de segurança no Analista.to, **não abra
uma issue pública**. Envie um e-mail para **security@analista.to** com:

- Descrição da vulnerabilidade e impacto potencial.
- Passos para reproduzir (PoC, se possível).
- Versão/commit afetado.

Você receberá uma confirmação em até 3 dias úteis. Nos comprometemos a
manter você informado sobre o progresso da correção e a dar crédito (se
desejado) quando o problema for divulgado publicamente, após o patch estar
disponível.

## Controles implementados

### SSRF (`app/security/ssrf.py`)

Toda requisição de rede feita a partir de uma entrada do usuário passa por
`SafeHTTPClient`/`resolve_host_ips`:

- Resolução de DNS e validação de **todos** os IPs retornados contra faixas
  privadas, reservadas, loopback, link-local, multicast e endereços de
  metadata de provedores de nuvem (IPv4 e IPv6).
- Bloqueio de esquemas fora de `http`/`https` e de URLs com credenciais
  embutidas.
- "Pinning" do IP validado na conexão TCP/TLS (Host/SNI corretos mantidos),
  reduzindo a janela de DNS rebinding.
- Redirecionamentos seguidos manualmente, com revalidação completa do IP a
  cada salto — nunca delegado ao cliente HTTP.
- Timeouts, limite de tamanho de resposta, limite de redirecionamentos,
  lista de portas permitidas e User-Agent identificado, todos configuráveis.

### CAPTCHA (`app/security/captcha.py`)

Turnstile, hCaptcha ou desafio matemático (gerado no servidor, token
assinado com validade curta via `itsdangerous`, resposta nunca enviada ao
client, uso único controlado via Redis, limite de tentativas).

### Rate limiting (`app/security/rate_limit.py`)

Janelas fixas em Redis por IP, por IP+ferramenta, por sessão e por entrada
consultada — com limites mais rígidos configurados nas ferramentas de rede
(SSL, headers, redirecionamentos).

### Privacidade de IP (`app/security/hashing.py`)

IP e User-Agent nunca são armazenados em texto puro — apenas um hash
HMAC-SHA256 com salt rotativo. Bloqueio de origens abusivas
(`app/security/blocklist.py`) funciona sobre o hash, sem nunca precisar
reverter para o IP original.

### Cabeçalhos e cookies

CSRF (Flask-WTF) em todos os formulários, Content-Security-Policy,
`X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy`, HSTS em produção, cookies
`HttpOnly`/`SameSite` (e `Secure` fora de debug).

> `script-src` inclui `'unsafe-eval'`, exigido pelo build padrão do
> Alpine.js para avaliar expressões de diretiva. Isso é mitigado por
> `script-src` continuar restrito a `'self'` + domínios de CAPTCHA (sem
> `'unsafe-inline'` nem origens arbitrárias). Migrar para o build
> `@alpinejs/csp` elimina essa necessidade — ver issue de hardening futuro.

### Autenticação administrativa

Um único usuário administrador, senha com hash Argon2
(`scripts/hash_admin_password.py`), sessão via Flask-Login. Suporte a 2FA
(TOTP) está preparado na arquitetura mas não habilitado nesta fase.

## Dependências

Todas as dependências são fixadas por versão exata em `requirements.txt` /
`requirements-dev.txt` / `package.json`. Recomendamos rodar `pip-audit` e
`npm audit` periodicamente e antes de cada release.
