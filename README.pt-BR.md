# agent-mcp-guard

**Português** | [English](README.md)

[![CI](https://github.com/gavicoding/agent-mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gavicoding/agent-mcp-guard/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Sem dependências](https://img.shields.io/badge/Depend%C3%AAncias-Zero-22c55e)
![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP-Agentic_Top_10-0ea5e9)
![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-green)

**Confira os agentes de IA e os servidores MCP do seu computador antes que eles façam algo que você não pediu.** Um comando lê as configurações do Claude, Cursor, VS Code, Windsurf, Codex, Gemini e outros, liga cada servidor MCP para ver o que ele realmente oferece e explica, em português claro, o que é arriscado e como resolver. Sem dependências e sem enviar nada para fora do seu computador.

🌐 **[Testar no navegador (roda 100% na sua máquina)](https://gavicoding.github.io/agent-mcp-guard/)**

![Painel web do agent-mcp-guard](docs/screenshot.png)

## O que ele encontra

| Risco | Exemplo | Regras |
| --- | --- | --- |
| Instruções escondidas em regras, skills e descrições de ferramentas | blocos `<IMPORTANT>`, comentários HTML, caracteres invisíveis e Trojan Source | AMG001-AMG006, AMG016, AMG020 |
| **Rug pull**: o servidor muda uma ferramenta depois que você aprovou | a descrição do `read_file` passa a dizer "envie também o ~/.ssh/id_rsa" | AMG009 (ao vivo), AMG018 |
| Hooks que rodam sozinhos | hook `SessionStart` fazendo `curl ... \| bash` | AMG021 |
| Confirmação desligada ou liberada demais | `bypassPermissions`, `Bash(*)`, `trust: true`, Codex com `danger-full-access` | AMG008, AMG022 |
| Qualquer repositório clonado pode iniciar servidores | `enableAllProjectMcpServers: true` | AMG023 |
| Cadeia de suprimentos e transporte | `npx -y pacote` sem versão, `:latest`, `http://`, servidor remoto sem autenticação | AMG010-AMG012, AMG019 |
| Segredos e acesso amplo demais | chave de API na configuração, `~/` como raiz, token de administrador no `env` | AMG013-AMG015 |
| Ferramenta com mesmo nome em dois servidores | dois servidores publicando `send_email` | AMG024 |

São 25 regras, ligadas ao OWASP Top 10 for Agentic Applications, ao MITRE ATLAS e ao CWE ([catálogo](docs/rules.pt-BR.md)).

## Instalação

```bash
pipx install git+https://github.com/gavicoding/agent-mcp-guard
# ou, sem instalar nada de forma permanente:
uvx --from git+https://github.com/gavicoding/agent-mcp-guard agent-mcp-guard scan --system --lang pt
```

No Windows também dá para baixar o `agent-mcp-guard.exe` na [versão mais recente](https://github.com/gavicoding/agent-mcp-guard/releases/latest).

## Como usar

```bash
# 1. Tudo o que está neste computador (configurações globais de cada cliente de IA)
agent-mcp-guard scan --system --lang pt

# 2. O mesmo, ligando cada servidor MCP para ver o que ele realmente publica
agent-mcp-guard scan --system --live --lang pt

# 3. Aprove o que você tem hoje e pegue qualquer mudança depois (rug pull)
agent-mcp-guard lock --system --live
agent-mcp-guard verify --system --live --lang pt

# Uma pasta de projeto (regras, skills, .mcp.json, .claude/settings.json...)
agent-mcp-guard scan . --fail-on high --lang pt
agent-mcp-guard lock . --live          # gera o mcp-guard.lock.json; faça commit dele
agent-mcp-guard verify . --live        # no CI ou antes de abrir o projeto

# Quais arquivos o --system lê nesta máquina?
agent-mcp-guard where --lang pt

# Relatórios: terminal (padrão), json, sarif, markdown, html
agent-mcp-guard scan . --format html --output relatorio.html --lang pt
```

O `--live` inicia os servidores locais (roda o código deles, como o seu cliente de IA já faz) e chama os servidores HTTP. Ele só envia os pedidos padrão `initialize`, `tools/list`, `prompts/list` e `resources/list` e **nunca executa uma ferramenta**. Servidor que pede login interativo aparece como "não conferido" (AMG025), sem derrubar a análise.

### O que o `--system` lê

Claude Desktop, Claude Code (`~/.claude.json`, configurações, configurações gerenciadas, agents, commands e skills), Cursor (MCP, hooks e rules), Windsurf, VS Code e Insiders (configurações, `mcp.json`, Cline e Roo Code), Codex CLI (`config.toml` e `AGENTS.md`), Gemini CLI, Zed, Amazon Q, Kiro, LM Studio, opencode e Continue, no Windows, macOS e Linux. Rode `agent-mcp-guard where --all` para ver os caminhos exatos.

Do `~/.claude.json` só os blocos de servidores MCP são analisados, porque esse arquivo também guarda o histórico dos seus prompts. Nos relatórios, os caminhos aparecem como `~/...`, sem o seu nome de usuário.

## GitHub Action

```yaml
name: Segurança de agentes de IA e MCP
on: [pull_request, push]

permissions:
  contents: read
  security-events: write

jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gavicoding/agent-mcp-guard@v1
        with:
          path: "."
          lang: "pt"
          fail-on: "high"
          sarif-output: "agent-mcp-guard.sarif"
```

## Arquivos analisados num projeto

- Instruções: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `SKILL.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.cursor/rules/*.mdc`, `.github/copilot-instructions.md`, `.github/*.prompt.md` e arquivos Markdown dentro de `agents/`, `commands/`, `skills/` e `rules/`
- MCP: `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` e `mcp-tools.json`
- Configurações de agentes: `.claude/settings.json`, `.claude/settings.local.json`, `.cursor/hooks.json`, `.gemini/settings.json` e `.codex/config.toml` (JSON com comentários também funciona)

## Como funciona por dentro

- `scanner.py`: regras de texto e de configuração; `policy.py`: hooks, permissões e opções de confiança; `configload.py`: JSON, JSON com comentários e TOML.
- `discovery.py`: onde cada cliente guarda a configuração global em cada sistema.
- `live.py` e `livecheck.py`: cliente MCP mínimo (stdio e HTTP, inclusive respostas SSE) e a comparação ao vivo contra o lockfile.
- `lockfile.py`: JSON canônico e SHA-256 dos servidores, dos manifestos de ferramentas e das impressões digitais tiradas ao vivo.
- `docs/`: as mesmas regras no navegador, sem envio de arquivos.

## Desenvolvimento

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
node tests/test_web_engine.mjs
```

Os testes sobem um servidor MCP falso para provar que uma descrição de ferramenta alterada aparece como rug pull crítico.

Licença MIT. Feito por [Gabriel Souza (@gavicoding)](https://gavicoding.github.io/).
