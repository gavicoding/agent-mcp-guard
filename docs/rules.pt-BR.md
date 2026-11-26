# Catalogo de Regras (AMG001 - AMG020)

| Regra | Gravidade | Categoria | OWASP Agentic / CWE |
|---|---|---|---|
| `AMG001` | Critico | Caracteres invisiveis / Unicode Tags | ASI01 / CWE-172 |
| `AMG002` | Critico | Controle bidirecional Trojan Source | ASI01 / CWE-1007 |
| `AMG003` | Alto | Payload Base64 ofuscado | ASI01 / CWE-506 |
| `AMG004` | Critico | Prompt injection / ocultacao ao usuario | ASI01 / CWE-74 |
| `AMG005` | Critico | Leitura e exfiltracao de credenciais | ASI02 / CWE-200 |
| `AMG006` | Alto | Sequestro cruzado entre tools MCP | ASI02 / CWE-94 |
| `AMG007` | Alto | Execucao remota direta (`curl\|sh`, `iex`) | ASI05 / CWE-78 |
| `AMG008` | Medio | Liberacao total sem aprovacao humana | ASI03 / CWE-250 |
| `AMG009` | Critico | Rug pull MCP (divergencia SHA-256) | ASI04 / CWE-494 |
| `AMG010` | Alto | Pacote `npx`, `uvx` ou Docker sem versao fixa | ASI04 / CWE-829 |
| `AMG011` | Alto | Transporte `http://` sem TLS ou bind `0.0.0.0` | ASI07 / CWE-319 |
| `AMG012` | Alto | Servidor MCP HTTPS remoto sem autenticacao | ASI03 / CWE-306 |
| `AMG013` | Medio | Escopo de pastas amplo demais | ASI02 / CWE-732 |
| `AMG014` | Medio | Variavel de ambiente sensivel exposta no MCP | ASI03 / CWE-526 |
| `AMG015` | Critico | Chave de API, token ou chave privada exposta | ASI03 / CWE-798 |
| `AMG016` | Medio | Descricao longa demais (> 1500 caracteres) | ASI01 / CWE-400 |
| `AMG017` | Medio | Carregamento dinamico de instrucoes via URL | ASI04 / CWE-829 |
| `AMG018` | Baixo | Config MCP sem lockfile `mcp-guard.lock.json` | ASI04 / CWE-353 |
| `AMG019` | Alto | Metacaracteres de shell em argumentos MCP | ASI05 / CWE-78 |
| `AMG020` | Medio | Exfiltracao via imagem ou link Markdown | ASI02 / CWE-200 |
