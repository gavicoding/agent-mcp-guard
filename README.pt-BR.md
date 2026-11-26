# agent-mcp-guard

**Português** | [English](README.md)

[![CI](https://github.com/gavicoding/agent-mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gavicoding/agent-mcp-guard/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Zero Dependencias](https://img.shields.io/badge/Dependencias-Zero-22c55e)
![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP-Agentic_Top_10-0ea5e9)
![Licenca: MIT](https://img.shields.io/badge/Licenca-MIT-green)

**Auditor de seguranca sem dependencias, protecao SHA-256 contra rug pull e painel web local para instrucoes de agentes de IA e servidores MCP (Model Context Protocol).**

🌐 **[Abrir Scanner Interativo no Navegador (100% local, sem envio de dados)](https://gavicoding.github.io/agent-mcp-guard/)**

![Painel web interativo do agent-mcp-guard](docs/screenshot.png)

## Por que usar

Assistentes de codigo e agentes autonomos (`CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `SKILL.md`, `mcp.json`) rodam com as credenciais do desenvolvedor, chaves SSH e acesso ao terminal. Tres riscos reais costumam passar direto em linters comuns:

1. **Tool Poisoning e Prompt Injection oculto:** instrucoes dentro de tags `<IMPORTANT>`, comentarios HTML invisiveis, caracteres zero-width (`U+E0000..U+E007F`) ou controle bidirecional Trojan Source (`U+202E`).
2. **Rug Pull em servidores MCP:** depois que o time aprova um servidor MCP ou pacote dinamico (`npx -y`, `uvx`, `:latest`), uma atualizacao muda silenciosamente a descricao ou os parametros da tool para exfiltrar arquivos.
3. **Vazamento de segredos e excesso de privilegio:** chaves em texto claro, `autoApprove: ["*"]`, acesso amplo a raiz (`/` ou `~/`), endpoints `http://` sem TLS e URLs remotas sem autenticacao.

O `agent-mcp-guard` audita esses 20 vetores localmente sem instalar pacotes de terceiros, gera um lockfile SHA-256 (`mcp-guard.lock.json`) para travar schemas de tools e exporta relatorios SARIF 2.1.0, HTML e JSON.

## Recursos Principais

- **20 regras praticas (`AMG001` - `AMG020`)** mapeadas ao **OWASP Top 10 for Agentic Applications**, **MITRE ATLAS** e **CWE** ([catalogo completo](docs/rules.pt-BR.md)).
- **Lockfile SHA-256 anti-rug-pull (`lock` / `verify`)**: normalizacao JSON canonica e hash SHA-256 de servidores, argumentos e schemas de tools MCP.
- **Mascaramento automatico de credenciais (`AMG015`)**: exibe apenas um prefixo mascarado (`AKIAIOSF...[REDACTED]`) para nunca vazar segredos nos logs de CI.
- **5 formatos de saida**: Terminal colorido, JSON, **SARIF 2.1.0**, Markdown para PRs e HTML interativo autonomo.
- **Interface web offline**: cole ou carregue seus arquivos direto no navegador e compare hashes SHA-256 via Web Crypto API.

## Como Comecar

```bash
# Testar imediatamente com os cenarios vulneravel e seguro inclusos
PYTHONPATH=src python -m agent_mcp_guard demo --lang pt

# Auditar seu projeto (retorna codigo 1 se houver risco Alto ou Critico)
PYTHONPATH=src python -m agent_mcp_guard scan . --lang pt --fail-on high

# Gerar lockfile SHA-256 apos revisar suas configuracoes MCP
PYTHONPATH=src python -m agent_mcp_guard lock . --lang pt

# Conferir integridade contra rug pull no CI ou pre-commit
PYTHONPATH=src python -m agent_mcp_guard verify . --lockfile mcp-guard.lock.json --lang pt

# Gerar relatorio HTML interativo em portugues
PYTHONPATH=src python -m agent_mcp_guard scan . --format html --output auditoria-mcp.html --lang pt
```

## Uso como GitHub Action

```yaml
name: Auditoria de Agentes IA e MCP
on: [pull_request, push]

permissions:
  contents: read
  security-events: write

jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gavicoding/agent-mcp-guard@v1.0.0
        with:
          path: "."
          lang: "pt"
          fail-on: "high"
          sarif-output: "agent-mcp-guard.sarif"
```

Licenca MIT. Desenvolvido por [Gabriel Souza (@gavicoding)](https://gavicoding.github.io/).
