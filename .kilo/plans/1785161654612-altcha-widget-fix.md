# Plano: corrigir widget ALTCHA que não aparece e não envia payload

## Problema confirmado
- `<altcha-widget>` não aparece no DOM.
- Ao submeter o form, o backend recebe `Payload ALTCHA ausente`.

## Causas prováveis (em ordem de likelihood)
1. **Versão do pacote npm errada**: `package.json` está com `"altcha": "2.1.0"`. A docs oficiais pedem `3.x.x` (latest). O `2.1.0` pode ser outro pacote/versão sem o web component.
2. **Assets não rebuildados**: após alterar `main.js` e `package.json`, o `npm run build` não foi executado (ou o Docker não rebuildou a imagem).
3. **Bundling pelo esbuild quebra o widget**: o `altcha` usa Web Workers e `customElements.define` como side-effect. esbuild pode tree-shake o import ou não resolver workers corretamente.
4. **Widget não inicia automaticamente**: o atributo `auto` pode não estar disparando a verificação antes do submit.
5. **CSP bloqueando worker/estilos**: o widget usa Web Worker e estilos embutidos.

## Decisões tomadas

### 1. Corrigir versão do pacote npm
- Alterar `package.json` de `"altcha": "2.1.0"` para `"altcha": "latest"` (ou `"3.x.x"` específico).

### 2. Estratégia de carregamento do widget
**Recomendação**: carregar o widget como script separado no `<head>` do layout base, NÃO via bundler.
- Motivo: evita problemas de esbuild com workers, tree-shaking e side-effects.
- O widget é um Web Component standalone; carregá-lo via `<script type="module" src="/static/dist/altcha.js">` é a abordagem mais robusta.
- Alternativa: manter `import "altcha"` no `main.js` e confiar no bundler. Só use isso se o teste confirmar que funciona.

### 3. Configuração do widget
- Usar `<altcha-widget challenge="/api/altcha-challenge" name="altcha" auto="onsubmit">`.
- `auto="onsubmit"` garante que a verificação inicia quando o usuário submete o form, bloqueando o submit até terminar.
- `name="altcha"` garante que o hidden input tenha o nome correto que o backend espera.

### 4. CSP
- A CSP atual (`worker-src 'self' blob:;`) deve ser suficiente para o widget.
- Se o widget usar `eval` ou `unsafe-eval` internamente, pode ser necessário adicionar `'unsafe-eval'` em `script-src` (já temos).

### 5. Docker rebuild
- Após alterar `package.json`, rebuild da imagem Docker é necessário para instalar a nova versão do `altcha`.

## Passos de implementação

1. **Atualizar `package.json`**
   - Mudar `"altcha": "2.1.0"` para `"altcha": "latest"` (ou fixar em `3.x.x` após verificar qual a latest).

2. **Decidir estratégia de carregamento**
   - Se optar por script separado:
     a. Copiar `node_modules/altcha/dist/altcha.js` (ou `.min.js`) para `app/static/dist/altcha.js` durante o build.
        - Isso pode ser feito no `Dockerfile` ou no `package.json` scripts.
     b. Adicionar `<script type="module" src="{{ url_for('static', filename='dist/altcha.js') }}"></script>` no `<head>` de `app/templates/layout/base.html`.
     c. Remover `import "altcha";` de `main.js`.
   - Se optar por bundler:
     a. Manter `import "altcha";` em `main.js`.
     b. Testar se o widget aparece após rebuild.

3. **Atualizar template do widget**
   - Em `app/templates/tools/_tool_macros.html`, alterar a linha do widget para:
     ```html
     <altcha-widget challenge="/api/altcha-challenge" name="altcha" auto="onsubmit"></altcha-widget>
     ```

4. **Rebuild e teste**
   - Rodar `npm install` (ou `npm ci`).
   - Rodar `npm run build`.
   - Rebuild da imagem Docker: `docker compose build analisa_web`.
   - Subir o compose e testar.

5. **Verificações no browser**
   - Console: sem erros de `customElements.define` ou CSP.
   - Elements: `<altcha-widget>` deve aparecer no DOM.
   - Network: chamada a `/api/altcha-challenge` retornando 200.
   - Após verificação completed, um `<input type="hidden" name="altcha" value="...">` deve aparecer.
   - Submit do form deve incluir o campo `altcha`.

6. **Fallback para HTTP/localhost**
   - O widget exige secure context. `localhost` geralmente é aceito, mas se não for, testar com `https://localhost` ou usar o modo `test` do widget: `<altcha-widget ... test>`. NÃO deixar `test` em produção.

## Arquivos modificados
- `package.json` — versão do `altcha`
- `app/templates/tools/_tool_macros.html` — atributos do widget
- `app/static/src/js/main.js` — remover ou manter import do altcha
- `app/templates/layout/base.html` — adicionar script do widget (se for carregamento separado)
- `Dockerfile` ou `package.json` scripts — copiar widget para static/dist (se for carregamento separado)

## Validação
- [ ] Widget aparece visualmente no formulário
- [ ] `/api/altcha-challenge` retorna JSON com `parameters` e `signature`
- [ ] Após verificação, hidden input `altcha` existe no form
- [ ] Submit do form inclui payload `altcha` e backend aceita (sem erro "Payload ALTCHA ausente")
- [ ] CSP não bloqueia estilos/worker do widget
