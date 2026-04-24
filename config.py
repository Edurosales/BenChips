"""
config.py — Toda la data: firmas, wordlists, payloads, constantes.
"""

VERSION = "4.0"
UA      = "Mozilla/5.0 (X11; Linux x86_64) VulnScanner-Pro/4.0"

# ─── Security Headers ──────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity":    "HIGH",
        "description": "Sin HSTS el navegador puede conectarse por HTTP. Un atacante en la misma red puede interceptar la sesión entera (MitM).",
        "impact":      "Robo de sesión, credenciales en texto plano, inyección de contenido.",
        "fix":         "max-age=31536000; includeSubDomains; preload",
        "ref":         "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "cvss":        7.4,
    },
    "Content-Security-Policy": {
        "severity":    "HIGH",
        "description": "Sin CSP el navegador ejecuta cualquier script incluyendo los inyectados por XSS.",
        "impact":      "Ataques XSS, robo de datos, inyección de malware.",
        "fix":         "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "ref":         "https://developer.mozilla.org/es/docs/Web/HTTP/CSP",
        "cvss":        7.2,
    },
    "X-Frame-Options": {
        "severity":    "MEDIUM",
        "description": "Sin este header tu página puede embeberse en un iframe invisible (clickjacking).",
        "impact":      "Clickjacking, robo de clics, acciones no autorizadas.",
        "fix":         "DENY",
        "ref":         "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/X-Frame-Options",
        "cvss":        6.1,
    },
    "X-Content-Type-Options": {
        "severity":    "MEDIUM",
        "description": "El navegador puede 'adivinar' el tipo de archivo y ejecutarlo (MIME sniffing).",
        "impact":      "XSS a través de archivos subidos.",
        "fix":         "nosniff",
        "ref":         "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/X-Content-Type-Options",
        "cvss":        5.3,
    },
    "Referrer-Policy": {
        "severity":    "LOW",
        "description": "Sin política de referrer se envía la URL completa con tokens o parámetros sensibles.",
        "impact":      "Filtración de URLs internas, tokens en logs externos.",
        "fix":         "strict-origin-when-cross-origin",
        "ref":         "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Referrer-Policy",
        "cvss":        3.1,
    },
    "Permissions-Policy": {
        "severity":    "LOW",
        "description": "Sin esta política cualquier script puede solicitar acceso a cámara, micrófono o geolocalización.",
        "impact":      "Acceso no autorizado a hardware si hay XSS.",
        "fix":         "camera=(), microphone=(), geolocation=(), payment=()",
        "ref":         "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        "cvss":        3.4,
    },
    "Cross-Origin-Opener-Policy": {
        "severity":    "LOW",
        "description": "Sin COOP páginas de otros orígenes pueden obtener referencia al window (ataques Spectre).",
        "impact":      "Ataques de canal lateral, robo de información cross-origin.",
        "fix":         "same-origin",
        "ref":         "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        "cvss":        3.7,
    },
    "Cross-Origin-Resource-Policy": {
        "severity":    "LOW",
        "description": "Recursos como imágenes o scripts pueden ser incluidos por sitios de terceros.",
        "impact":      "Hotlinking, ataques de timing cross-origin.",
        "fix":         "same-origin",
        "ref":         "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
        "cvss":        3.1,
    },
}

# ─── EOL Software ──────────────────────────────────────────────────────────────
EOL_SIGNATURES = {
    "IIS/5":      ("CRITICAL", 9.8, "Windows 2000/XP, sin soporte desde 2010"),
    "IIS/6":      ("CRITICAL", 9.8, "Windows Server 2003, EOL 2015, CVE-2017-7269 crítico"),
    "IIS/7":      ("HIGH",     7.5, "Windows Server 2008, EOL 2020"),
    "IIS/8":      ("HIGH",     7.5, "Windows Server 2012, EOL 2023"),
    "Apache/1":   ("CRITICAL", 9.8, "Apache 1.x, EOL desde 2010"),
    "Apache/2.0": ("HIGH",     7.5, "Apache 2.0, EOL desde 2013"),
    "Apache/2.2": ("HIGH",     7.5, "Apache 2.2, EOL desde 2017"),
    "nginx/0":    ("HIGH",     7.5, "Nginx 0.x, EOL y sin parches"),
    "nginx/1.0":  ("HIGH",     7.0, "Nginx 1.0.x, EOL"),
    "nginx/1.2":  ("HIGH",     7.0, "Nginx 1.2.x, EOL"),
    "nginx/1.4":  ("HIGH",     7.0, "Nginx 1.4.x, EOL"),
    "PHP/5":      ("CRITICAL", 9.8, "PHP 5.x, EOL desde 2018, múltiples CVEs críticos"),
    "PHP/7.0":    ("HIGH",     7.5, "PHP 7.0, EOL desde 2019"),
    "PHP/7.1":    ("HIGH",     7.5, "PHP 7.1, EOL desde 2019"),
    "PHP/7.2":    ("HIGH",     7.5, "PHP 7.2, EOL desde 2020"),
    "PHP/7.3":    ("MEDIUM",   5.3, "PHP 7.3, EOL desde 2021"),
}

# ─── Sensitive Paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    ("/.env",                    "CRITICAL", 9.8, "Variables de entorno — DB passwords, API keys"),
    ("/.env.local",              "CRITICAL", 9.8, "Variables entorno locales"),
    ("/.env.production",         "CRITICAL", 9.8, "Variables entorno producción"),
    ("/.env.backup",             "CRITICAL", 9.8, "Backup de variables de entorno"),
    ("/config.php",              "CRITICAL", 9.8, "Config PHP con credenciales"),
    ("/wp-config.php",           "CRITICAL", 9.8, "Config WordPress con credenciales DB"),
    ("/configuration.php",       "CRITICAL", 9.8, "Config Joomla con credenciales"),
    ("/settings.py",             "HIGH",     7.5, "Settings Django — posible SECRET_KEY"),
    ("/config/database.yml",     "CRITICAL", 9.8, "Config DB Rails"),
    ("/database.yml",            "CRITICAL", 9.8, "Config base de datos"),
    ("/app/config/parameters.yml","HIGH",    7.5, "Parámetros Symfony"),
    ("/web.config",              "HIGH",     7.5, "Config IIS — puede tener credenciales"),
    ("/appsettings.json",        "HIGH",     7.5, "Config .NET Core"),
    ("/.git/config",             "CRITICAL", 9.8, "Repositorio Git expuesto — credenciales remotas"),
    ("/.git/HEAD",               "HIGH",     7.5, "Git HEAD expuesto"),
    ("/.git/COMMIT_EDITMSG",     "MEDIUM",   5.3, "Último mensaje commit de Git"),
    ("/.gitignore",              "LOW",      3.1, "Lista de archivos ignorados — revela estructura"),
    ("/.svn/entries",            "HIGH",     7.5, "Repositorio SVN expuesto"),
    ("/admin/",                  "HIGH",     7.5, "Panel de administración"),
    ("/admin/login",             "HIGH",     7.5, "Login panel admin"),
    ("/administrator/",          "HIGH",     7.5, "Panel administrador alternativo"),
    ("/wp-admin/",               "MEDIUM",   5.3, "Panel admin WordPress"),
    ("/wp-login.php",            "MEDIUM",   5.3, "Login WordPress"),
    ("/phpmyadmin/",             "CRITICAL", 9.8, "phpMyAdmin — acceso directo a BD"),
    ("/pma/",                    "CRITICAL", 9.8, "phpMyAdmin alias"),
    ("/adminer.php",             "CRITICAL", 9.8, "Adminer — DB admin tool"),
    ("/console",                 "CRITICAL", 9.8, "Consola de administración"),
    ("/debug",                   "CRITICAL", 9.8, "Endpoint debug activo en producción"),
    ("/_profiler",               "HIGH",     7.5, "Symfony profiler expuesto"),
    ("/__debugbar",              "HIGH",     7.5, "Laravel Debugbar expuesto"),
    ("/telescope",               "HIGH",     7.5, "Laravel Telescope expuesto"),
    ("/horizon",                 "HIGH",     7.5, "Laravel Horizon expuesto"),
    ("/swagger/",                "MEDIUM",   5.3, "Swagger UI — docs API expuestas"),
    ("/swagger-ui.html",         "MEDIUM",   5.3, "Swagger UI HTML"),
    ("/v2/api-docs",             "MEDIUM",   5.3, "OpenAPI/Swagger spec JSON"),
    ("/v3/api-docs",             "MEDIUM",   5.3, "OpenAPI 3 spec JSON"),
    ("/openapi.json",            "MEDIUM",   5.3, "OpenAPI spec"),
    ("/graphql",                 "MEDIUM",   5.3, "GraphQL endpoint — posible introspección"),
    ("/graphiql",                "HIGH",     7.5, "GraphiQL IDE expuesto"),
    ("/backup/",                 "CRITICAL", 9.8, "Directorio backups accesible"),
    ("/backups/",                "CRITICAL", 9.8, "Directorio backups accesible"),
    ("/backup.sql",              "CRITICAL", 9.8, "Dump SQL de base de datos"),
    ("/backup.zip",              "CRITICAL", 9.8, "Backup ZIP del sitio"),
    ("/db.sql",                  "CRITICAL", 9.8, "Archivo SQL expuesto"),
    ("/dump.sql",                "CRITICAL", 9.8, "Dump SQL expuesto"),
    ("/.htaccess",               "MEDIUM",   5.3, "Reglas servidor Apache expuestas"),
    ("/.htpasswd",               "CRITICAL", 9.8, "Archivo contraseñas HTTP Basic Auth"),
    ("/.bash_history",           "CRITICAL", 9.8, "Historial comandos del servidor"),
    ("/.ssh/id_rsa",             "CRITICAL", 9.8, "Clave privada SSH"),
    ("/.DS_Store",               "LOW",      3.1, "Metadata macOS — revela estructura"),
    ("/server-status",           "HIGH",     7.5, "Apache mod_status — info interna"),
    ("/server-info",             "HIGH",     7.5, "Apache mod_info — config módulos"),
    ("/actuator",                "CRITICAL", 9.8, "Spring Boot Actuator — control total"),
    ("/actuator/env",            "CRITICAL", 9.8, "Spring Actuator env — variables entorno"),
    ("/actuator/heapdump",       "CRITICAL", 9.8, "Spring Actuator heap dump — memoria"),
    ("/actuator/health",         "LOW",      3.1, "Spring Actuator health"),
    ("/metrics",                 "MEDIUM",   5.3, "Endpoint métricas"),
    ("/robots.txt",              "LOW",      3.1, "Puede revelar rutas ocultas"),
    ("/sitemap.xml",             "LOW",      3.1, "Revela estructura del sitio"),
    ("/crossdomain.xml",         "MEDIUM",   5.3, "Flash crossdomain policy"),
    ("/logs/",                   "HIGH",     7.5, "Directorio logs accesible"),
    ("/error.log",               "HIGH",     7.5, "Log de errores expuesto"),
    ("/access.log",              "HIGH",     7.5, "Log de acceso expuesto"),
]

# ─── Common Ports ──────────────────────────────────────────────────────────────
PORTS = [
    (21,    "FTP",           "MEDIUM",   5.9,  "FTP sin cifrado — credenciales en texto plano"),
    (22,    "SSH",           "LOW",      3.7,  "SSH abierto — verificar versión y configuración"),
    (23,    "Telnet",        "CRITICAL", 9.8,  "Telnet — protocolo sin cifrado, EOL"),
    (25,    "SMTP",          "MEDIUM",   5.3,  "SMTP abierto — posible open relay"),
    (80,    "HTTP",          "LOW",      3.1,  "Puerto HTTP estándar"),
    (443,   "HTTPS",         "LOW",      3.1,  "Puerto HTTPS estándar"),
    (445,   "SMB",           "HIGH",     8.1,  "SMB expuesto — riesgo EternalBlue/ransomware"),
    (1433,  "MSSQL",         "CRITICAL", 9.8,  "SQL Server expuesto a internet"),
    (1521,  "Oracle DB",     "CRITICAL", 9.8,  "Oracle DB expuesto a internet"),
    (3000,  "Dev Server",    "HIGH",     7.5,  "Puerto de desarrollo expuesto"),
    (3306,  "MySQL",         "CRITICAL", 9.8,  "MySQL expuesto a internet"),
    (3389,  "RDP",           "HIGH",     8.1,  "RDP expuesto — riesgo BlueKeep/fuerza bruta"),
    (4200,  "Angular Dev",   "HIGH",     7.5,  "Servidor de desarrollo Angular expuesto"),
    (5000,  "Flask/Dev",     "HIGH",     7.5,  "Servidor Flask/dev expuesto"),
    (5432,  "PostgreSQL",    "CRITICAL", 9.8,  "PostgreSQL expuesto a internet"),
    (5900,  "VNC",           "CRITICAL", 9.8,  "VNC expuesto — control remoto sin auth fuerte"),
    (6379,  "Redis",         "CRITICAL", 9.8,  "Redis expuesto — sin auth por defecto"),
    (8080,  "HTTP Alt",      "MEDIUM",   5.3,  "Puerto HTTP alternativo — posible panel admin"),
    (8443,  "HTTPS Alt",     "MEDIUM",   5.3,  "Puerto HTTPS alternativo"),
    (8888,  "Jupyter/Dev",   "HIGH",     8.1,  "Jupyter Notebook o servidor dev expuesto"),
    (9200,  "Elasticsearch", "CRITICAL", 9.8,  "Elasticsearch sin auth — acceso total a datos"),
    (27017, "MongoDB",       "CRITICAL", 9.8,  "MongoDB expuesto — sin auth por defecto"),
]

# ─── HTTP Methods ──────────────────────────────────────────────────────────────
DANGEROUS_METHODS = [
    ("TRACE",   "HIGH",   8.1, "Permite XST (Cross-Site Tracing) — robo de cookies HttpOnly"),
    ("PUT",     "HIGH",   8.1, "Puede permitir subir archivos al servidor"),
    ("DELETE",  "HIGH",   8.1, "Puede eliminar recursos del servidor"),
    ("OPTIONS", "MEDIUM", 5.3, "Revela métodos permitidos — info para el atacante"),
    ("PATCH",   "MEDIUM", 5.3, "Modificación parcial de recursos sin control adecuado"),
    ("CONNECT", "MEDIUM", 5.3, "Puede usarse para proxying y túneles"),
]

# ─── CSP Insecure Directives ───────────────────────────────────────────────────
CSP_INSECURE = [
    ("unsafe-inline",  "HIGH",   8.1, "Permite scripts inline — anula protección XSS"),
    ("unsafe-eval",    "HIGH",   8.1, "Permite eval() — ejecutar strings como código"),
    ("*",              "HIGH",   7.5, "Wildcard — permite cargar recursos de cualquier dominio"),
    ("http:",          "MEDIUM", 5.3, "Permite cargar recursos por HTTP sin cifrado"),
    ("data:",          "MEDIUM", 5.3, "Permite URIs data: — puede usarse para XSS"),
    ("blob:",          "LOW",    3.1, "Permite URLs blob — puede usarse en ciertos ataques"),
]

# ─── WAF Signatures ────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":  ["cf-ray", "cf-cache-status", "server:cloudflare"],
    "AWS WAF":     ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
    "Akamai":      ["x-check-cacheable", "akamai-cache-status", "x-akamai"],
    "Imperva":     ["x-iinfo", "x-cdn", "incap_ses"],
    "Sucuri":      ["x-sucuri-id", "x-sucuri-cache"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 BIG-IP":   ["bigip", "x-wa-info", "x-cnection"],
    "Fastly":      ["x-fastly", "fastly-restarts", "x-served-by"],
    "Varnish":     ["x-varnish", "via:.*varnish"],
    "Barracuda":   ["barra_counter_session"],
}

# ─── Open Redirect Params ──────────────────────────────────────────────────────
REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "return_url",
    "redirect_uri", "redirect_url", "goto", "destination", "dest",
    "redir", "target", "to", "ref", "location", "continue", "forward",
    "back", "success", "exit", "out", "view", "path",
]

# ─── Content Leakage Patterns ──────────────────────────────────────────────────
LEAKAGE_PATTERNS = [
    (r"stack\s+trace",                   "HIGH",    7.5, "Stack trace expuesto — revela arquitectura interna"),
    (r"exception\s+in\s+thread",         "HIGH",    7.5, "Excepción Java expuesta"),
    (r"traceback\s+\(most\s+recent",     "HIGH",    7.5, "Traceback Python expuesto — rutas del servidor"),
    (r"fatal\s+error.*php",              "HIGH",    7.5, "Error fatal PHP — rutas de archivos"),
    (r"warning.*mysql",                  "CRITICAL", 9.1, "Credenciales/estructura MySQL expuesta"),
    (r"sql\s+syntax.*mysql",             "HIGH",    7.5, "Error SQL MySQL — estructura de BD"),
    (r"pg_query\(\).*error",             "HIGH",    7.5, "Error SQL PostgreSQL expuesto"),
    (r"microsoft\s+ole\s+db.*error",     "HIGH",    7.5, "Error MSSQL expuesto"),
    (r"access\s+denied\s+for\s+user",    "CRITICAL", 9.1, "Credenciales DB en HTML"),
    (r"password\s*=\s*['\"][^'\"]{3,}",  "CRITICAL", 9.8, "Contraseña hardcodeada en HTML"),
    (r"api[_\-]?key\s*[:=]\s*['\"][a-z0-9\-_]{16,}", "CRITICAL", 9.8, "API key visible en HTML"),
    (r"secret[_\-]?key\s*[:=]\s*['\"][^'\"]{8,}",    "CRITICAL", 9.8, "Secret key expuesto"),
    (r"aws_access_key_id",               "CRITICAL", 9.8, "AWS access key expuesta"),
    (r"debug\s*[=:]\s*(true|1|on)",      "MEDIUM",   5.3, "Modo debug activo en producción"),
    (r"index\s+of\s+/",                  "MEDIUM",   5.3, "Directory listing habilitado"),
    (r"directory\s+listing",             "MEDIUM",   5.3, "Directory listing detectado"),
    (r"root:x:0:0",                      "CRITICAL", 9.8, "Contenido /etc/passwd expuesto"),
    (r"-----begin\s+(rsa\s+)?private\s+key",         "CRITICAL", 9.8, "Clave privada expuesta"),
]

# ─── Active Scan Payloads ──────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    ("'",           r"(sql syntax|mysql_fetch|ORA-\d+|pg_query|sqlite3|SQLSTATE)"),
    ("\"",          r"(sql syntax|mysql_fetch|ORA-\d+|pg_query|sqlite3|SQLSTATE)"),
    ("1' OR '1'='1", r"(sql syntax|mysql_fetch|ORA-\d+)"),
    ("1 OR 1=1--",  r"(sql syntax|mysql_fetch|ORA-\d+)"),
    ("' OR 1=1--",  r"(sql syntax|mysql_fetch|ORA-\d+|pg_query)"),
    ("1; DROP TABLE", r"(sql syntax|mysql_fetch|error)"),
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"mysql_fetch_array",
    r"mysql_num_rows",
    r"ORA-\d{5}",
    r"pg_query\(\)",
    r"SQLite3::query",
    r"SQLSTATE\[\w+\]",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"syntax error.*near",
]

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    '";alert(1);//',
    "javascript:alert(1)",
]

TRAVERSAL_PAYLOADS = [
    ("../../../../etc/passwd",           r"root:x:0:0"),
    ("..%2F..%2F..%2F..%2Fetc%2Fpasswd", r"root:x:0:0"),
    ("....//....//....//etc/passwd",      r"root:x:0:0"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", r"root:x:0:0"),
    ("..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]"),
]

# ─── Subdomain Wordlist ────────────────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh",
    "dev", "test", "staging", "beta", "alpha", "qa", "uat",
    "api", "api2", "api-v2", "v1", "v2", "graphql",
    "admin", "administrator", "cpanel", "whm", "webmail", "portal",
    "dashboard", "manage", "management", "panel",
    "app", "apps", "application", "web", "www2", "secure",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "vpn", "remote", "gateway", "proxy", "firewall",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
    "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence",
    "monitor", "monitoring", "metrics", "grafana", "kibana",
    "docs", "documentation", "wiki", "help", "support",
    "blog", "news", "shop", "store", "pay", "payment",
    "ns1", "ns2", "mx", "mx1", "mx2",
    "backup", "old", "legacy", "archive",
    "internal", "intranet", "corp", "private",
    "mobile", "m", "wap",
    "auth", "login", "sso", "oauth", "id",
    "status", "health", "ping",
]

# ─── Technology Detection Patterns ────────────────────────────────────────────
TECH_PATTERNS = {
    "WordPress":    [r"wp-content/", r"wp-includes/", r"wordpress"],
    "Joomla":       [r"joomla", r"/components/com_"],
    "Drupal":       [r"drupal", r"sites/default/files"],
    "Laravel":      [r"laravel_session", r"X-Powered-By.*PHP"],
    "Django":       [r"csrfmiddlewaretoken", r"django"],
    "Rails":        [r"_rails_", r"X-Runtime"],
    "Next.js":      [r"__NEXT_DATA__", r"/_next/"],
    "React":        [r"react-dom", r"__react"],
    "Angular":      [r"ng-version", r"angular"],
    "Vue.js":       [r"vue", r"__vue_"],
    "jQuery":       [r"jquery"],
    "Bootstrap":    [r"bootstrap"],
    "Nginx":        [r"server:\s*nginx"],
    "Apache":       [r"server:\s*apache"],
    "IIS":          [r"server:\s*microsoft-iis"],
    "Cloudflare":   [r"cf-ray"],
    "PHP":          [r"x-powered-by:\s*php", r"\.php"],
    "ASP.NET":      [r"x-aspnet-version", r"aspnetcore"],
    "Spring Boot":  [r"x-application-context"],
    "Express.js":   [r"x-powered-by:\s*express"],
}
