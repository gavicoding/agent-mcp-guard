# Catálogo de Regras (AMG001 - AMG025)

| Regra | Gravidade | Categoria | OWASP Agentic / CWE |
|---|---|---|---|
| `AMG001` | Crítico | Caracteres invisíveis / Unicode Tags | ASI01 / CWE-172 |
| `AMG002` | Crítico | Controle bidirecional Trojan Source | ASI01 / CWE-1007 |
| `AMG003` | Alto | Payload Base64 ofuscado | ASI01 / CWE-506 |
| `AMG004` | Crítico | Prompt injection / ocultação ao usuário | ASI01 / CWE-74 |
| `AMG005` | Crítico | Leitura e exfiltração de credenciais | ASI02 / CWE-200 |
| `AMG006` | Alto | Sequestro cruzado entre tools MCP | ASI02 / CWE-94 |
| `AMG007` | Alto | Execução remota direta (`curl\|sh`, `iex`) | ASI05 / CWE-78 |
| `AMG008` | Médio | Liberação total sem aprovação humana | ASI03 / CWE-250 |
| `AMG009` | Crítico | Rug pull MCP (divergência SHA-256) | ASI04 / CWE-494 |
| `AMG010` | Alto | Pacote `npx`, `uvx` ou Docker sem versão fixa | ASI04 / CWE-829 |
| `AMG011` | Alto | Transporte `http://` sem TLS ou bind `0.0.0.0` | ASI07 / CWE-319 |
| `AMG012` | Alto | Servidor MCP HTTPS remoto sem autenticação | ASI03 / CWE-306 |
| `AMG013` | Médio | Escopo de pastas amplo demais | ASI02 / CWE-732 |
| `AMG014` | Médio | Variável de ambiente sensível exposta no MCP | ASI03 / CWE-526 |
| `AMG015` | Crítico | Chave de API, token ou chave privada exposta | ASI03 / CWE-798 |
| `AMG016` | Médio | Descrição longa demais (> 1500 caracteres) | ASI01 / CWE-400 |
| `AMG017` | Médio | Carregamento dinâmico de instruções via URL | ASI04 / CWE-829 |
| `AMG018` | Baixo | Config MCP sem lockfile `mcp-guard.lock.json` | ASI04 / CWE-353 |
| `AMG019` | Alto | Metacaracteres de shell em argumentos MCP | ASI05 / CWE-78 |
| `AMG020` | Médio | Exfiltração via imagem ou link Markdown | ASI02 / CWE-200 |
| `AMG021` | Alto (Crítico quando baixa e executa código) | Hook executa comando arriscado sozinho | ASI05 / CWE-78 |
| `AMG022` | Médio (Alto para shell liberado) | Lista de permissões ampla demais | ASI03 / CWE-250 |
| `AMG023` | Médio | Servidores MCP de projeto liberados automaticamente | ASI04 / CWE-829 |
| `AMG024` | Médio | Mesma ferramenta em dois servidores MCP (`--live`) | ASI02 / CWE-694 |
| `AMG025` | Baixo | Servidor MCP não pôde ser conferido ao vivo (`--live`) | ASI04 / CWE-345 |

A `AMG008` também cobre a confirmação desligada nas configurações: `permissions.defaultMode = bypassPermissions`, `trust: true` no Gemini, `chat.tools.autoApprove` no VS Code e, no Codex, `approval_policy = "never"` junto com `sandbox_mode = "danger-full-access"` (crítico).
Com `--live`, a `AMG009` compara o que cada servidor anuncia agora com as impressões digitais travadas: descrição de ferramenta alterada é crítico; parâmetros alterados ou ferramenta nova são alto.
