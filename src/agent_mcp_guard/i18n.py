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
        "report_title": "Relatorio de Auditoria agent-mcp-guard",
        "report_subtitle": "Auditoria local sem dependencias de instrucoes de agentes IA, servidores MCP e integridade SHA-256",
        "target_label": "Alvo",
        "files_scanned": "Arquivos Analisados",
        "total_findings": "Achados",
        "risk_score": "Nivel de Risco",
        "lockfile_status": "Verificacao de Lockfile",
        "lockfile_verified": "Verificado",
        "lockfile_missing": "Nao Informado",
        "clean_status": "Limpo: nenhum problema de seguranca encontrado.",
        "severity": "Gravidade",
        "rule": "Regra",
        "location": "Localizacao",
        "owasp_mapping": "OWASP Agentic / CWE",
        "evidence": "Evidencia",
        "remediation": "Como Corrigir",
        "summary_heading": "Distribuicao por Gravidade",
        "findings_heading": "Achados Detectados",
        "filter_all": "Todos",
        "critical": "Critico",
        "high": "Alto",
        "medium": "Medio",
        "low": "Baixo",
        "lock_written": "Lockfile SHA-256 gerado com sucesso",
        "lock_ok": "Todos os servidores MCP e schemas de tools batem com o lockfile SHA-256.",
        "lock_drift": "Alteracao silenciosa (rug pull) ou desvio de schema detectado no MCP.",
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
            "title": "Caracteres invisiveis (zero-width ou Unicode Tags)",
            "description": "Caracteres Unicode ocultos passam despercebidos na revisao humana, mas continuam sendo lidos pelo modelo de IA como parte do prompt ou descricao da tool.",
            "remediation": "Remova todos os caracteres Unicode invisiveis ou de tag e revise o diff em bytes antes de aprovar o arquivo.",
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
            "remediation": "Exclua todos os caracteres de controle bidirecional e bloqueie esse padrao no CI do repositorio.",
        },
    },
    "AMG003": {
        "en": {
            "title": "Obfuscated Base64 or Hex payload in agent context",
            "description": "Long encoded blobs that decode into executable shell verbs, URLs, or override instructions are frequently used to bypass naive keyword filters.",
            "remediation": "Decode and verify the payload manually; never leave opaque Base64/Hex instruction blobs inside prompt rules or tool descriptions.",
        },
        "pt": {
            "title": "Payload ofuscado em Base64 ou Hex nas instrucoes",
            "description": "Blocos longos codificados que decodificam comandos de shell, URLs ou ordens de sobrescrita costumam burlar revisoes manuais.",
            "remediation": "Decodifique e valide o conteudo; nao mantenha blobs ofuscados em regras de agentes ou descricoes MCP.",
        },
    },
    "AMG004": {
        "en": {
            "title": "Prompt injection or stealth override directive",
            "description": "Text instructs the agent to ignore prior safety boundaries, conceal actions from the user, or abuse <IMPORTANT> / hidden HTML comment blocks inside context files or MCP schemas.",
            "remediation": "Remove stealth or boundary-override clauses immediately and treat external rules or MCP schemas as untrusted code inputs.",
        },
        "pt": {
            "title": "Diretiva de prompt injection ou ocultacao de acoes",
            "description": "O texto manda o agente ignorar regras anteriores, agir sem avisar o usuario ou usa blocos <IMPORTANT> / comentarios HTML ocultos para sequestrar o comportamento.",
            "remediation": "Remova essas clausulas imediatamente e trate regras de terceiros e schemas MCP como entrada nao confiavel.",
        },
    },
    "AMG005": {
        "en": {
            "title": "Sensitive file or credential exfiltration instruction",
            "description": "Combines high-value credential paths (~/.ssh, ~/.aws, .env, id_rsa, kubeconfig) with exfiltration verbs (curl, webhook, send, upload, pass via tool arguments).",
            "remediation": "Remove credential read/exfiltration instructions and isolate agent execution away from developer home secrets.",
        },
        "pt": {
            "title": "Instrucao de leitura e exfiltracao de credenciais",
            "description": "Combina caminhos criticos (~/.ssh, ~/.aws, .env, id_rsa) com comandos ou verbos para enviar, fazer upload ou passar o conteudo via tool.",
            "remediation": "Elimine instrucoes que acessem cofres ou arquivos locais sensiveis e isole o ambiente do agente.",
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
            "description": "A descricao de uma tool MCP tenta interferir no uso de outra tool (por exemplo, redirecionando destinatarios, commits ou comandos).",
            "remediation": "Desative o servidor MCP suspeito, audite todo o manifesto de tools e exija aprovacao humana.",
        },
    },
    "AMG007": {
        "en": {
            "title": "Remote execution bootstrap or download-and-execute pattern",
            "description": "Piping remote downloads straight into a shell (curl|sh, wget|bash, PowerShell IEX / -enc) enables unverified code execution during agent workflows.",
            "remediation": "Pin signed artifacts with checksum verification instead of piping remote scripts into a shell.",
        },
        "pt": {
            "title": "Execucao remota direta (curl|sh, iex, powershell -enc)",
            "description": "Baixar e executar scripts direto na linha de comando abre caminho para execucao arbitraria sem verificacao de integridade.",
            "remediation": "Substitua por pacotes com versao travada e conferencia de hash antes da execucao.",
        },
    },
    "AMG008": {
        "en": {
            "title": "Wildcard permission bypass or auto-approve flag",
            "description": "Wildcard approvals (autoApprove: ['*'], alwaysAllow: ['*'], --dangerously-skip-permissions, --yolo) disable human-in-the-loop safety gates.",
            "remediation": "Replace wildcard approvals with an explicit allowlist of read-only tools and require confirmation for state-changing actions.",
        },
        "pt": {
            "title": "Liberacao total de permissoes sem confirmacao humana",
            "description": "Flags como autoApprove ['*'], alwaysAllow ['*'] ou --dangerously-skip-permissions desligam a aprovacao humana do agente.",
            "remediation": "Troque o curinga por uma lista enxuta de tools seguras e mantenha confirmacao para acoes de escrita.",
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
            "description": "O comando do servidor MCP ou a descricao/schema de uma tool mudou em relacao ao mcp-guard.lock.json apos a aprovacao inicial.",
            "remediation": "Interrompa o uso, revise o diff do schema alterado e gere um novo lockfile apenas apos validar a mudanca.",
        },
    },
    "AMG010": {
        "en": {
            "title": "Unpinned dynamic MCP runner package or container tag",
            "description": "Running npx -y, uvx, or docker run :latest without an exact immutable version allows upstream package updates to inject malicious code on the next launch.",
            "remediation": "Pin exact versions (package@1.2.3, pkg==1.2.3, or container digest @sha256:...) in MCP server definitions.",
        },
        "pt": {
            "title": "Pacote ou container MCP sem versao fixa (unpinned)",
            "description": "Usar npx -y, uvx ou docker :latest sem versao travada permite que uma atualizacao externa altere o servidor MCP na proxima execucao.",
            "remediation": "Fixe versoes exatas (pacote@1.2.3, pacote==1.2.3 ou digest @sha256) na configuracao do servidor.",
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
            "description": "Endpoints http:// externos deixam tokens e payloads trafegando em claro; bind em 0.0.0.0 expoe o servidor MCP para a rede local.",
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
            "title": "Endpoint MCP remoto sem autenticacao configurada",
            "description": "Um servidor MCP remoto em https:// foi declarado sem headers de autenticacao (Authorization/X-API-Key) nem configuracao OAuth.",
            "remediation": "Defina autenticacao explicita via referencia a variavel de ambiente protegida.",
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
            "description": "Liberar raiz (/, C:\\), pasta do usuario (~ / $HOME) ou traversal (..) expoe chaves SSH, sessoes e arquivos fora do projeto.",
            "remediation": "Restrinja os caminhos do servidor MCP apenas ao diretorio estrito do projeto.",
        },
    },
    "AMG014": {
        "en": {
            "title": "Sensitive environment variable block passed to MCP server",
            "description": "Broad env blocks or high-privilege variables (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, DATABASE_URL) attached directly inside MCP configs widen blast radius.",
            "remediation": "Inject only minimally scoped runtime variables per server via a secret manager instead of sharing admin tokens.",
        },
        "pt": {
            "title": "Variaveis de ambiente sensiveis expostas na config do MCP",
            "description": "Passar tokens amplos (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, DATABASE_URL) no mcp.json aumenta o impacto em caso de comprometimento.",
            "remediation": "Use credenciais de privilegio minimo injetadas por cofre seguro em tempo de execucao.",
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
            "description": "Credenciais gravadas direto em arquivos de regras ou mcp.json acabam vazando no repositorio Git e no contexto enviado ao modelo.",
            "remediation": "Revogue e rotacione a credencial imediatamente e substitua por referencia a variavel de ambiente (${VAR}).",
        },
    },
    "AMG016": {
        "en": {
            "title": "Oversized MCP tool description (> 1500 chars)",
            "description": "Unusually long tool descriptions are commonly used to push hidden prompt-injection instructions below visible UI scroll limits.",
            "remediation": "Keep tool descriptions concise and audit any lengthy documentation before granting tool access.",
        },
        "pt": {
            "title": "Descricao de tool MCP longa demais (> 1500 caracteres)",
            "description": "Descricoes gigantes sao usadas para esconder instrucoes maliciosas depois da dobra de rolagem da interface.",
            "remediation": "Mantenha descricoes objetivas e revise integralmente qualquer texto extenso antes de aprovar a tool.",
        },
    },
    "AMG017": {
        "en": {
            "title": "Dynamic external instruction loading from remote URL",
            "description": "Instructing the agent to fetch live rules or markdown instructions from remote URLs allows remote attackers to alter agent behavior at any time.",
            "remediation": "Vendor reviewed rule files locally in git rather than pulling unpinned remote instructions dynamically.",
        },
        "pt": {
            "title": "Carregamento dinamico de instrucoes via URL externa",
            "description": "Mandar o agente buscar regras em uma URL remota permite que terceiros alterem o comportamento do agente a qualquer momento.",
            "remediation": "Versione as regras localmente no repositorio apos revisao, sem busca dinamica em runtime.",
        },
    },
    "AMG018": {
        "en": {
            "title": "MCP configuration present without a SHA-256 lockfile",
            "description": "Without a committed mcp-guard.lock.json baseline, silent post-install modifications to MCP servers or tool schemas go undetected.",
            "remediation": "Run `agent-mcp-guard lock` after reviewing your MCP config and verify with `--lockfile mcp-guard.lock.json` in CI.",
        },
        "pt": {
            "title": "Configuracao MCP sem lockfile SHA-256 de integridade",
            "description": "Sem um mcp-guard.lock.json versionado, mudancas silenciosas nos servidores MCP ou schemas de tools passam sem alerta.",
            "remediation": "Execute `agent-mcp-guard lock` apos auditar a configuracao e valide com `--lockfile` no CI.",
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
            "description": "Argumentos com ;, &&, ||, pipe, crase ou $() na inicializacao do servidor MCP facilitam injecao de comandos.",
            "remediation": "Execute o binario diretamente com argumentos separados, evitando passar comandos por shell intermediario.",
        },
    },
    "AMG020": {
        "en": {
            "title": "Markdown image or hyperlink exfiltration vector",
            "description": "Markdown image tags or URL templates containing query-string placeholders can silently leak conversation state or secrets when rendered by chat UIs.",
            "remediation": "Remove untrusted external markdown image embeds and disable dynamic URL interpolation inside agent instructions.",
        },
        "pt": {
            "title": "Vetor de exfiltracao via imagem ou link Markdown",
            "description": "Imagens Markdown com parametros de query dinamicos podem vazar dados da sessao automaticamente quando a interface renderiza a resposta.",
            "remediation": "Remova embeds externos nao confiaveis e bloqueie URLs com interpolacao de variaveis nas instrucoes.",
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
