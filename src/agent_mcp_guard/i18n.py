"""Native English and Brazilian Portuguese localization strings for agent-mcp-guard."""

from __future__ import annotations

from typing import Any

UI_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "report_title": "agent-mcp-guard Security Audit Report",
        "report_subtitle": "Zero-dependency audit of AI agent instructions, MCP servers, and SHA-256 lockfile integrity",
        "target_label": "Target",
        "files_scanned": "Files Scanned",
        "total_findings": "Findings",
        "risk_score": "Risk Score",
        "lockfile_status": "Lockfile Verification",
        "lockfile_verified": "Verified",
        "lockfile_missing": "Not Provided",
        "clean_status": "Clean: no security issues detected.",
        "severity": "Severity",
        "rule": "Rule",
        "location": "Location",
        "owasp_mapping": "OWASP Agentic / CWE",
        "evidence": "Evidence",
        "remediation": "Remediation",
        "summary_heading": "Severity Breakdown",
        "findings_heading": "Detected Findings",
        "filter_all": "All",
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "lock_written": "SHA-256 lockfile written successfully",
        "lock_ok": "All MCP servers and tool schemas match the SHA-256 lockfile.",
        "lock_drift": "MCP rug-pull or schema drift detected against lockfile.",
        "generated_by": "Generated locally by agent-mcp-guard",
    },
    "pt": {
        "report_title": "Relatório de Auditoria agent-mcp-guard",
        "report_subtitle": "Auditoria local sem dependências de instruções de agentes IA, servidores MCP e integridade SHA-256",
        "target_label": "Alvo",
        "files_scanned": "Arquivos Analisados",
        "total_findings": "Achados",
        "risk_score": "Nível de Risco",
        "lockfile_status": "Verificação de Lockfile",
        "lockfile_verified": "Verificado",
        "lockfile_missing": "Não Informado",
        "clean_status": "Limpo: nenhum problema de segurança encontrado.",
        "severity": "Gravidade",
        "rule": "Regra",
        "location": "Localização",
        "owasp_mapping": "OWASP Agentic / CWE",
        "evidence": "Evidência",
        "remediation": "Como Corrigir",
        "summary_heading": "Distribuição por Gravidade",
        "findings_heading": "Achados Detectados",
        "filter_all": "Todos",
        "critical": "Crítico",
        "high": "Alto",
        "medium": "Médio",
        "low": "Baixo",
        "lock_written": "Lockfile SHA-256 gerado com sucesso",
        "lock_ok": "Todos os servidores MCP e schemas de tools batem com o lockfile SHA-256.",
        "lock_drift": "Alteração silenciosa (rug pull) ou desvio de schema detectado no MCP.",
        "generated_by": "Gerado localmente pelo agent-mcp-guard",
    },
}

RULE_COPY: dict[str, dict[str, dict[str, str]]] = {
    "AMG001": {
        "en": {
            "title": "Hidden zero-width or Unicode Tag characters",
            "description": "Invisible Unicode code points (zero-width spaces, joiners, or Unicode Tags U+E0000..U+E007F) allow attackers to conceal instructions from human reviewers while AI models still parse them.",
            "remediation": "Strip all non-printable control and Unicode Tag characters and inspect the raw hex diff before trusting the file.",
        },
        "pt": {
            "title": "Caracteres invisíveis (zero-width ou Unicode Tags)",
            "description": "Caracteres Unicode ocultos passam despercebidos na revisão humana, mas continuam sendo lidos pelo modelo de IA como parte do prompt ou descrição da tool.",
            "remediation": "Remova todos os caracteres Unicode invisíveis ou de tag e revise o diff em bytes antes de aprovar o arquivo.",
        },
    },
    "AMG002": {
        "en": {
            "title": "Bidirectional text control character (Trojan Source)",
            "description": "Unicode Bidi override or isolate characters can invert the visual reading order of code or agent instructions to hide malicious directives.",
            "remediation": "Remove all Bidi control characters (U+202A..U+202E, U+2066..U+2069) and enforce CI checks against Trojan Source.",
        },
        "pt": {
            "title": "Controle bidirecional oculto (Trojan Source)",
            "description": "Caracteres Bidi do Unicode invertem visualmente a ordem de leitura de regras ou trechos JSON para esconder comandos maliciosos na tela.",
            "remediation": "Exclua todos os caracteres de controle bidirecional e bloqueie esse padrão no CI do repositório.",
        },
    },
    "AMG003": {
        "en": {
            "title": "Obfuscated Base64 or Hex payload in agent context",
            "description": "Long encoded blobs that decode into executable shell verbs, URLs, or override instructions are frequently used to bypass naive keyword filters.",
            "remediation": "Decode and verify the payload manually; never leave opaque Base64/Hex instruction blobs inside prompt rules or tool descriptions.",
        },
        "pt": {
            "title": "Payload ofuscado em Base64 ou Hex nas instruções",
            "description": "Blocos longos codificados que decodificam comandos de shell, URLs ou ordens de sobrescrita costumam burlar revisões manuais.",
            "remediation": "Decodifique e valide o conteúdo; não mantenha blobs ofuscados em regras de agentes ou descrições MCP.",
        },
    },
    "AMG004": {
        "en": {
            "title": "Prompt injection or stealth override directive",
            "description": "Text instructs the agent to ignore prior safety boundaries, conceal actions from the user, or abuse <IMPORTANT> / hidden HTML comment blocks inside context files or MCP schemas.",
            "remediation": "Remove stealth or boundary-override clauses immediately and treat external rules or MCP schemas as untrusted code inputs.",
        },
        "pt": {
            "title": "Diretiva de prompt injection ou ocultação de ações",
            "description": "O texto manda o agente ignorar regras anteriores, agir sem avisar o usuário ou usa blocos <IMPORTANT> / comentários HTML ocultos para sequestrar o comportamento.",
            "remediation": "Remova essas cláusulas imediatamente e trate regras de terceiros e schemas MCP como entrada não confiável.",
        },
    },
    "AMG005": {
        "en": {
            "title": "Sensitive file or credential exfiltration instruction",
            "description": "Combines high-value credential paths (~/.ssh, ~/.aws, .env, id_rsa, kubeconfig) with exfiltration verbs (curl, webhook, send, upload, pass via tool arguments).",
            "remediation": "Remove credential read/exfiltration instructions and isolate agent execution away from developer home secrets.",
        },
        "pt": {
            "title": "Instrução de leitura e exfiltração de credenciais",
            "description": "Combina caminhos críticos (~/.ssh, ~/.aws, .env, id_rsa) com comandos ou verbos para enviar, fazer upload ou passar o conteúdo via tool.",
            "remediation": "Elimine instruções que acessem cofres ou arquivos locais sensíveis e isole o ambiente do agente.",
        },
    },
    "AMG006": {
        "en": {
            "title": "Cross-tool shadowing or hijacking instruction",
            "description": "An MCP tool description attempts to redefine or intercept calls meant for another tool (e.g., altering email recipients, git commits, or shell invocations).",
            "remediation": "Disable the untrusted MCP server, inspect the full tool manifest, and require explicit human confirmation per tool.",
        },
        "pt": {
            "title": "Sequestro cruzado entre tools MCP (tool shadowing)",
            "description": "A descrição de uma tool MCP tenta interferir no uso de outra tool (por exemplo, redirecionando destinatarios, commits ou comandos).",
            "remediation": "Desative o servidor MCP suspeito, audite todo o manifesto de tools e exija aprovação humana.",
        },
    },
    "AMG007": {
        "en": {
            "title": "Remote execution bootstrap or download-and-execute pattern",
            "description": "Piping remote downloads straight into a shell (curl|sh, wget|bash, PowerShell IEX / -enc) enables unverified code execution during agent workflows.",
            "remediation": "Pin signed artifacts with checksum verification instead of piping remote scripts into a shell.",
        },
        "pt": {
            "title": "Execução remota direta (curl|sh, iex, powershell -enc)",
            "description": "Baixar e executar scripts direto na linha de comando abre caminho para execução arbitrária sem verificação de integridade.",
            "remediation": "Substitua por pacotes com versão travada e conferência de hash antes da execução.",
        },
    },
    "AMG008": {
        "en": {
            "title": "Wildcard permission bypass or auto-approve flag",
            "description": "Wildcard approvals (autoApprove: ['*'], alwaysAllow: ['*'], --dangerously-skip-permissions, --yolo) disable human-in-the-loop safety gates.",
            "remediation": "Replace wildcard approvals with an explicit allowlist of read-only tools and require confirmation for state-changing actions.",
        },
        "pt": {
            "title": "Liberação total de permissões sem confirmação humana",
            "description": "Flags como autoApprove ['*'], alwaysAllow ['*'] ou --dangerously-skip-permissions desligam a aprovação humana do agente.",
            "remediation": "Troque o curinga por uma lista enxuta de tools seguras e mantenha confirmação para ações de escrita.",
        },
    },
    "AMG009": {
        "en": {
            "title": "MCP rug pull: schema or server hash mismatch against lockfile",
            "description": "The live MCP server command/URL or tool schema SHA-256 hash differs from mcp-guard.lock.json, indicating silent post-approval tampering or supply-chain drift.",
            "remediation": "Halt execution, inspect the diff between expected and current SHA-256 hashes, and re-lock only after full security review.",
        },
        "pt": {
            "title": "Rug pull no MCP: hash SHA-256 diverge do lockfile",
            "description": "O comando do servidor MCP ou a descrição/schema de uma tool mudou em relação ao mcp-guard.lock.json após a aprovação inicial.",
            "remediation": "Interrompa o uso, revise o diff do schema alterado e gere um novo lockfile apenas após validar a mudança.",
        },
    },
    "AMG010": {
        "en": {
            "title": "Unpinned dynamic MCP runner package or container tag",
            "description": "Running npx -y, uvx, or docker run :latest without an exact immutable version allows upstream package updates to inject malicious code on the next launch.",
            "remediation": "Pin exact versions (package@1.2.3, pkg==1.2.3, or container digest @sha256:...) in MCP server definitions.",
        },
        "pt": {
            "title": "Pacote ou container MCP sem versão fixa (unpinned)",
            "description": "Usar npx -y, uvx ou docker :latest sem versão travada permite que uma atualização externa altere o servidor MCP na próxima execução.",
            "remediation": "Fixe versões exatas (pacote@1.2.3, pacote==1.2.3 ou digest @sha256) na configuração do servidor.",
        },
    },
    "AMG011": {
        "en": {
            "title": "Plaintext remote HTTP transport or 0.0.0.0 bind",
            "description": "Using non-localhost http:// endpoints exposes MCP tokens and tool payloads to interception; binding 0.0.0.0 exposes local MCP servers on the network.",
            "remediation": "Use HTTPS for remote MCP endpoints and bind local servers strictly to 127.0.0.1.",
        },
        "pt": {
            "title": "Transporte HTTP sem criptografia ou bind aberto em 0.0.0.0",
            "description": "Endpoints http:// externos deixam tokens e payloads trafegando em claro; bind em 0.0.0.0 expõe o servidor MCP para a rede local.",
            "remediation": "Exija HTTPS para endpoints remotos e restrinja servidores locais a 127.0.0.1.",
        },
    },
    "AMG012": {
        "en": {
            "title": "Remote HTTPS MCP endpoint without explicit auth configuration",
            "description": "A remote MCP URL is declared without Authorization headers, API token mapping, or OAuth configuration, risking anonymous or misconfigured access.",
            "remediation": "Configure explicit Bearer/OAuth authentication via secret environment variable references (never literal secrets).",
        },
        "pt": {
            "title": "Endpoint MCP remoto sem autenticação configurada",
            "description": "Um servidor MCP remoto em https:// foi declarado sem headers de autenticação (Authorization/X-API-Key) nem configuração OAuth.",
            "remediation": "Defina autenticação explícita via referência a variável de ambiente protegida.",
        },
    },
    "AMG013": {
        "en": {
            "title": "Overly broad filesystem path exposed to MCP server",
            "description": "Granting root paths (/, C:\\), home (~ / $HOME), or parent traversal (..) gives the MCP server access to SSH keys, browser profiles, and OS configs.",
            "remediation": "Scope filesystem MCP roots exclusively to the project working directory or a dedicated sandbox folder.",
        },
        "pt": {
            "title": "Escopo de pastas amplo demais no servidor MCP",
            "description": "Liberar raiz (/, C:\\), pasta do usuário (~ / $HOME) ou traversal (..) expõe chaves SSH, sessões e arquivos fora do projeto.",
            "remediation": "Restrinja os caminhos do servidor MCP apenas ao diretório estrito do projeto.",
        },
    },
    "AMG014": {
        "en": {
            "title": "Sensitive environment variable block passed to MCP server",
            "description": "Broad env blocks or high-privilege variables (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, DATABASE_URL) attached directly inside MCP configs widen blast radius.",
            "remediation": "Inject only minimally scoped runtime variables per server via a secret manager instead of sharing admin tokens.",
        },
        "pt": {
            "title": "Variáveis de ambiente sensíveis expostas na config do MCP",
            "description": "Passar tokens amplos (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, DATABASE_URL) no mcp.json aumenta o impacto em caso de comprometimento.",
            "remediation": "Use credenciais de privilégio mínimo injetadas por cofre seguro em tempo de execução.",
        },
    },
    "AMG015": {
        "en": {
            "title": "Hardcoded API key, token, or private key in agent config",
            "description": "Literal credentials stored in agent rule files or mcp.json get committed to git history and leaked in telemetry or prompt context.",
            "remediation": "Revoke and rotate the credential immediately, then replace it with an environment variable reference such as ${ENV_VAR}.",
        },
        "pt": {
            "title": "Chave de API, token ou chave privada exposta em texto claro",
            "description": "Credenciais gravadas direto em arquivos de regras ou mcp.json acabam vazando no repositório Git e no contexto enviado ao modelo.",
            "remediation": "Revogue e rotacione a credencial imediatamente e substitua por referência a variável de ambiente (${VAR}).",
        },
    },
    "AMG016": {
        "en": {
            "title": "Oversized MCP tool description (> 1500 chars)",
            "description": "Unusually long tool descriptions are commonly used to push hidden prompt-injection instructions below visible UI scroll limits.",
            "remediation": "Keep tool descriptions concise and audit any lengthy documentation before granting tool access.",
        },
        "pt": {
            "title": "Descrição de tool MCP longa demais (> 1500 caracteres)",
            "description": "Descrições gigantes são usadas para esconder instruções maliciosas depois da dobra de rolagem da interface.",
            "remediation": "Mantenha descrições objetivas e revise integralmente qualquer texto extenso antes de aprovar a tool.",
        },
    },
    "AMG017": {
        "en": {
            "title": "Dynamic external instruction loading from remote URL",
            "description": "Instructing the agent to fetch live rules or markdown instructions from remote URLs allows remote attackers to alter agent behavior at any time.",
            "remediation": "Vendor reviewed rule files locally in git rather than pulling unpinned remote instructions dynamically.",
        },
        "pt": {
            "title": "Carregamento dinâmico de instruções via URL externa",
            "description": "Mandar o agente buscar regras em uma URL remota permite que terceiros alterem o comportamento do agente a qualquer momento.",
            "remediation": "Versione as regras localmente no repositório após revisão, sem busca dinâmica em runtime.",
        },
    },
    "AMG018": {
        "en": {
            "title": "MCP configuration present without a SHA-256 lockfile",
            "description": "Without a committed mcp-guard.lock.json baseline, silent post-install modifications to MCP servers or tool schemas go undetected.",
            "remediation": "Run `agent-mcp-guard lock` after reviewing your MCP config and verify with `--lockfile mcp-guard.lock.json` in CI.",
        },
        "pt": {
            "title": "Configuração MCP sem lockfile SHA-256 de integridade",
            "description": "Sem um mcp-guard.lock.json versionado, mudanças silenciosas nos servidores MCP ou schemas de tools passam sem alerta.",
            "remediation": "Execute `agent-mcp-guard lock` após auditar a configuração e valide com `--lockfile` no CI.",
        },
    },
    "AMG019": {
        "en": {
            "title": "Shell metacharacters or command chaining in MCP arguments",
            "description": "Arguments containing ;, &&, ||, pipe operators, backticks, or $() inside MCP launch specs indicate shell-mediated invocation prone to injection.",
            "remediation": "Invoke binary executables directly with discrete argument strings without passing commands through a shell.",
        },
        "pt": {
            "title": "Metacaracteres de shell ou encadeamento em argumentos MCP",
            "description": "Argumentos com ;, &&, ||, pipe, crase ou $() na inicialização do servidor MCP facilitam injeção de comandos.",
            "remediation": "Execute o binário diretamente com argumentos separados, evitando passar comandos por shell intermediário.",
        },
    },
    "AMG020": {
        "en": {
            "title": "Markdown image or hyperlink exfiltration vector",
            "description": "Markdown image tags or URL templates containing query-string placeholders can silently leak conversation state or secrets when rendered by chat UIs.",
            "remediation": "Remove untrusted external markdown image embeds and disable dynamic URL interpolation inside agent instructions.",
        },
        "pt": {
            "title": "Vetor de exfiltração via imagem ou link Markdown",
            "description": "Imagens Markdown com parâmetros de query dinâmicos podem vazar dados da sessão automaticamente quando a interface renderiza a resposta.",
            "remediation": "Remova embeds externos não confiáveis e bloqueie URLs com interpolação de variáveis nas instruções.",
        },
    },
    "AMG021": {
        "en": {
            "title": "Hook runs a risky command automatically",
            "description": "Agent hooks execute shell commands on every session or tool call without asking. A hook that downloads code, decodes payloads, touches credential files or deletes data runs on the machine of everyone who opens the project.",
            "remediation": "Remove the hook or replace it with a reviewed local script that does not reach the network, decode payloads or read secrets. Keep shared settings free of hooks you did not write.",
        },
        "pt": {
            "title": "Hook executa comando arriscado sozinho",
            "description": "Hooks de agentes rodam comandos no terminal a cada sessão ou chamada de ferramenta, sem perguntar. Um hook que baixa código, decodifica conteúdo, mexe em arquivos de credenciais ou apaga dados roda no computador de todo mundo que abrir o projeto.",
            "remediation": "Remova o hook ou troque por um script local revisado, sem acesso à rede, sem decodificar conteúdo e sem ler segredos. Não deixe em configurações compartilhadas hooks que você não escreveu.",
        },
    },
    "AMG022": {
        "en": {
            "title": "Permission allowlist is too broad",
            "description": "Entries such as Bash(*), *, mcp__* or an interpreter wildcard let the agent run anything without confirmation, so a single injected instruction becomes code execution.",
            "remediation": "Allow only the exact commands you need (for example Bash(npm test)) and keep confirmation for everything else.",
        },
        "pt": {
            "title": "Lista de permissões ampla demais",
            "description": "Itens como Bash(*), *, mcp__* ou um interpretador liberado deixam o agente rodar qualquer coisa sem confirmação. Uma única instrução injetada vira execução de código.",
            "remediation": "Libere só os comandos exatos que você usa (por exemplo Bash(npm test)) e mantenha a confirmação para o resto.",
        },
    },
    "AMG023": {
        "en": {
            "title": "Project MCP servers are trusted automatically",
            "description": "With enableAllProjectMcpServers (or MCP autostart) any repository you clone can start its own MCP servers, which run code on your machine with your credentials.",
            "remediation": "Turn the switch off and approve project servers one by one after reading their configuration.",
        },
        "pt": {
            "title": "Servidores MCP de projeto liberados automaticamente",
            "description": "Com enableAllProjectMcpServers (ou o início automático de MCP) qualquer repositório que você clonar pode iniciar servidores MCP próprios, que rodam código no seu computador com as suas credenciais.",
            "remediation": "Desligue a opção e aprove os servidores de cada projeto um por um, depois de ler a configuração.",
        },
    },
    "AMG024": {
        "en": {
            "title": "Two MCP servers expose the same tool name",
            "description": "When servers publish tools with the same name, a malicious server can shadow a trusted one and receive calls (and data) meant for it.",
            "remediation": "Remove the duplicate server or rename the tool, and keep only servers you trust enabled at the same time.",
        },
        "pt": {
            "title": "Dois servidores MCP com ferramenta de mesmo nome",
            "description": "Quando dois servidores publicam ferramentas com o mesmo nome, um servidor malicioso pode se passar pelo confiável e receber as chamadas (e os dados) destinadas a ele.",
            "remediation": "Remova o servidor duplicado ou renomeie a ferramenta, e deixe ligados ao mesmo tempo só servidores em que você confia.",
        },
    },
    "AMG025": {
        "en": {
            "title": "MCP server could not be verified live",
            "description": "The server did not start or did not answer tools/list in time, so its real tool descriptions were not checked or pinned.",
            "remediation": "Check the command, credentials and network, then run again with --live. Servers that need interactive sign-in can be pinned after you sign in.",
        },
        "pt": {
            "title": "Servidor MCP não pôde ser conferido ao vivo",
            "description": "O servidor não iniciou ou não respondeu ao tools/list a tempo, então as descrições reais das ferramentas não foram conferidas nem travadas no lockfile.",
            "remediation": "Confira o comando, as credenciais e a rede e rode de novo com --live. Servidores que pedem login interativo podem ser travados depois que você entrar.",
        },
    },
}


def t_ui(lang: str, key: str) -> str:
    """Lookup localized UI string with English fallback."""
    bucket = UI_STRINGS.get(lang, UI_STRINGS["en"])
    return bucket.get(key, UI_STRINGS["en"].get(key, key))


def t_rule(lang: str, rule_id: str) -> dict[str, str]:
    """Lookup localized rule copy with English fallback."""
    entry = RULE_COPY.get(rule_id, {})
    return entry.get(lang, entry.get("en", {"title": rule_id, "description": "", "remediation": ""}))


def mask_secret_text(text: str) -> str:
    """Redact potential credential substrings while keeping a short identifiable prefix."""
    import re

    patterns = [
        re.compile(r"\b(sk-(?:proj-|ant-)?[A-Za-z0-9_-]{4})[A-Za-z0-9_-]{8,}"),
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}"),
        re.compile(r"\b(AKIA[0-9A-Z]{4})[0-9A-Z]{8,}"),
        re.compile(r"\b(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]{8,}"),
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9]{3})[A-Za-z0-9-]{8,}"),
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9._-]{12,}"),
        re.compile(r"(?i)((?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9_-]{3})[A-Za-z0-9_./+=-]{5,}"),
    ]
    masked = text
    for pat in patterns:
        masked = pat.sub(r"\1...[REDACTED]", masked)
    return masked
