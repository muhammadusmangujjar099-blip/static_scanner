"""
Scanner rules & constants – patterns, audit rules, vulnerable packages, etc.
No scanning logic here.
"""

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
LANGUAGE_EXTENSIONS = {
    ".py": "Python", ".pyw": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
    ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".cpp": "C++", ".cxx": "C++", ".cc": "C++",
    ".c": "C", ".h": "C/C++ Header", ".hpp": "C++ Header",
    ".swift": "Swift", ".m": "Objective-C", ".scala": "Scala",
    ".r": "R", ".R": "R", ".sql": "SQL",
    ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell",
    ".html": "HTML", ".htm": "HTML", ".css": "CSS",
    ".scss": "SCSS", ".sass": "Sass", ".json": "JSON",
    ".yaml": "YAML", ".yml": "YAML", ".xml": "XML",
    ".md": "Markdown", ".dockerfile": "Dockerfile",
    ".tf": "Terraform", ".vue": "Vue", ".dart": "Dart",
    ".lua": "Lua", ".pl": "Perl", ".pm": "Perl",
}

LANGUAGE_SIGNATURES = [
    (r"^#!.*python", "Python"),
    (r"^#!.*node", "JavaScript"),
    (r"^#!.*bash|#!/bin/sh", "Shell"),
    (r"^package\s+\w+;", "Java"),
    (r"^using\s+System;", "C#"),
    (r"^package\s+main", "Go"),
    (r"^fn\s+main\s*\(", "Rust"),
    (r"^<\?php", "PHP"),
    (r"^import\s+Foundation", "Swift"),
]


# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "API Key"),
    (r"(?i)(secret[_-]?key|secretkey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "Secret Key"),
    (r"(?i)(access[_-]?token|accesstoken)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Access Token"),
    (r"(?i)(auth[_-]?token|authtoken)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "Auth Token"),
    (r"(?i)(private[_-]?key|privatekey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-/+=]{20,})", "Private Key"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]", "Password"),
    (r"(?i)(db[_-]?password|database[_-]?password)\s*[=:]\s*['\"]?([^\s'\"]{4,})", "DB Password"),
    (r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{30,})", "AWS Secret"),
    (r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*['\"]?(AKIA[0-9A-Z]{16})", "AWS Access Key"),
    (r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{20,})", "Bearer Token"),
    (r"(?i)(jwt[_-]?secret|token[_-]?secret)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "JWT Secret"),
    (r"(?i)(mongodb(\+srv)?://[^:]+:)([^@\s]+)@", "MongoDB Credentials"),
    (r"(?i)(postgres(ql)?://[^:]+:)([^@\s]+)@", "PostgreSQL Credentials"),
    (r"(?i)(mysql://[^:]+:)([^@\s]+)@", "MySQL Credentials"),
    (r"(?i)(redis://[^:]+:)([^@\s]+)@", "Redis Credentials"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key Block"),
    (r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", "OpenSSH Private Key"),
    (r"(?i)(slack[_-]?token|xox[baprs]-)[0-9a-zA-Z-]{10,}", "Slack Token"),
    (r"(?i)(github[_-]?token|gh[pousr]_)[0-9a-zA-Z]{20,}", "GitHub Token"),
    (r"(?i)(stripe[_-]?(secret|live|test)[_-]?key)\s*[=:]\s*['\"]?(sk_(live|test)_[0-9a-zA-Z]{20,})", "Stripe Key"),
    (r"(?i)(azure[_-]?storage[_-]?key|accountkey=)([A-Za-z0-9+/=]{40,})", "Azure Storage Key"),
    (r"(?i)(AIza[0-9A-Za-z\-_]{35})", "Google API Key"),
    (r"(?i)(SK[0-9a-fA-F]{32})", "Twilio API Key"),
    (r"(?i)(SG\.[a-zA-Z0-9_\-\.]{22}\.[a-zA-Z0-9_\-\.]{43})", "SendGrid API Key"),
    (r"(?i)(firebase[_-]?(api[_-]?key|config))\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "Firebase Config"),
]


# ---------------------------------------------------------------------------
# Static audit rules
# ---------------------------------------------------------------------------
AUDIT_RULES = [
    {"id": "SA001", "severity": "high", "pattern": r"\beval\s*\(", "message": "Use of eval() – code injection risk", "languages": ["Python", "JavaScript", "PHP"]},
    {"id": "SA002", "severity": "high", "pattern": r"\bexec\s*\(", "message": "Use of exec() – command/code injection risk", "languages": ["Python", "PHP"]},
    {"id": "SA003", "severity": "high", "pattern": r"\bos\.system\s*\(", "message": "os.system() – command injection risk", "languages": ["Python"]},
    {"id": "SA004", "severity": "high", "pattern": r"\bsubprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True", "message": "subprocess with shell=True – command injection risk", "languages": ["Python"]},
    {"id": "SA005", "severity": "high", "pattern": r"\bpickle\.loads?\s*\(", "message": "pickle.load/loads – arbitrary code execution risk", "languages": ["Python"]},
    {"id": "SA006", "severity": "medium", "pattern": r"\byaml\.load\s*\(", "message": "yaml.load – prefer yaml.safe_load", "languages": ["Python"]},
    {"id": "SA007", "severity": "high", "pattern": r"\b__import__\s*\(", "message": "Dynamic __import__ – potential code injection", "languages": ["Python"]},
    {"id": "SA008", "severity": "medium", "pattern": r"(?i)verify\s*=\s*False", "message": "SSL/TLS verification disabled", "languages": ["Python", "JavaScript"]},
    {"id": "SA009", "severity": "high", "pattern": r"\binnerHTML\s*=", "message": "innerHTML assignment – XSS risk", "languages": ["JavaScript", "TypeScript"]},
    {"id": "SA010", "severity": "high", "pattern": r"\bdocument\.write\s*\(", "message": "document.write – XSS risk", "languages": ["JavaScript", "TypeScript"]},
    {"id": "SA011", "severity": "high", "pattern": r"\b(dangerouslySetInnerHTML)", "message": "dangerouslySetInnerHTML – XSS risk", "languages": ["JavaScript", "TypeScript"]},
    {"id": "SA012", "severity": "medium", "pattern": r"(?i)\b(md5|sha1)\s*\(", "message": "Weak hash algorithm (MD5/SHA1)", "languages": ["Python", "JavaScript", "Java", "PHP", "Go"]},
    {"id": "SA013", "severity": "high", "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*['\"]", "message": "Possible SQL string concatenation – injection risk", "languages": ["Python", "JavaScript", "PHP", "Java", "C#"]},
    {"id": "SA014", "severity": "low", "pattern": r"(?i)https?://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9.\-]+", "message": "Hardcoded external URL", "languages": ["*"]},
    {"id": "SA015", "severity": "low", "pattern": r"(?i)\b(TODO|FIXME|HACK|XXX)\b", "message": "TODO/FIXME/HACK comment found", "languages": ["*"]},
    {"id": "SA016", "severity": "high", "pattern": r"\bchild_process\.(exec|execSync|spawn)\s*\(", "message": "child_process execution – command injection risk", "languages": ["JavaScript", "TypeScript"]},
    {"id": "SA017", "severity": "medium", "pattern": r"(?i)(DEBUG\s*=\s*True|debug\s*=\s*true)", "message": "Debug mode enabled", "languages": ["Python", "JavaScript"]},
    {"id": "SA018", "severity": "high", "pattern": r"\bRuntime\.getRuntime\(\)\.exec\s*\(", "message": "Runtime.exec – command injection risk", "languages": ["Java"]},
    {"id": "SA019", "severity": "medium", "pattern": r"(?i)(ALLOW_ALL|Access-Control-Allow-Origin:\s*\*)", "message": "Permissive CORS configuration", "languages": ["*"]},
    {"id": "SA020", "severity": "high", "pattern": r"\bsystem\s*\(", "message": "system() call – command injection risk", "languages": ["PHP", "C", "C++"]},
    {"id": "SA021", "severity": "high", "pattern": r"(?i)assert\s+False|assert\s+0", "message": "Hardcoded assert False – may hide errors", "languages": ["Python"]},
    {"id": "SA022", "severity": "medium", "pattern": r"(?i)random\.random\s*\(|Math\.random\s*\(", "message": "Weak PRNG for security-sensitive use", "languages": ["Python", "JavaScript"]},
    {"id": "SA023", "severity": "high", "pattern": r"(?i)DES|RC4|md5crypt", "message": "Weak/obsolete cryptography algorithm", "languages": ["*"]},
    {"id": "SA024", "severity": "medium", "pattern": r"(?i)chmod\s*\(\s*['\"]?777", "message": "World-writable permissions (777)", "languages": ["Python", "Shell"]},
    {"id": "SA025", "severity": "high", "pattern": r"(?i)disable[_-]?ssl|ssl[_-]?verify\s*=\s*0", "message": "SSL verification disabled", "languages": ["*"]},
]


# ---------------------------------------------------------------------------
# Dependency vulnerabilities (local knowledge base)
# ---------------------------------------------------------------------------
VULNERABLE_PACKAGES = {
    "requests": [
        {"below": "2.20.0", "severity": "high", "cve": "CVE-2018-18074", "note": "Credentials over HTTP"},
        {"below": "2.31.0", "severity": "medium", "cve": "CVE-2023-32681", "note": "Proxy leak"},
    ],
    "urllib3": [
        {"below": "1.26.5", "severity": "high", "cve": "CVE-2021-33503", "note": "Catastrophic backtracking"},
        {"below": "2.0.0", "severity": "medium", "cve": "CVE-2023-43804", "note": "Cookie header injection"},
    ],
    "django": [
        {"below": "3.2.0", "severity": "high", "cve": "Multiple", "note": "EOL / many CVEs"},
        {"below": "4.2.0", "severity": "medium", "cve": "Multiple", "note": "Missing security fixes"},
    ],
    "flask": [{"below": "2.0.0", "severity": "medium", "cve": "CVE-2023-30861", "note": "Cookie handling"}],
    "pillow": [
        {"below": "9.0.0", "severity": "high", "cve": "CVE-2022-22817", "note": "Arbitrary code execution"},
        {"below": "10.0.1", "severity": "high", "cve": "CVE-2023-4863", "note": "Heap buffer overflow"},
    ],
    "pyyaml": [{"below": "5.4", "severity": "high", "cve": "CVE-2020-14343", "note": "Arbitrary code execution"}],
    "jinja2": [{"below": "2.11.3", "severity": "high", "cve": "CVE-2020-28493", "note": "ReDoS"}],
    "cryptography": [{"below": "41.0.0", "severity": "medium", "cve": "Multiple", "note": "Update recommended"}],
    "paramiko": [{"below": "2.10.1", "severity": "high", "cve": "CVE-2022-24302", "note": "Race condition"}],
    "sqlalchemy": [{"below": "1.4.0", "severity": "medium", "cve": "Multiple", "note": "Old major version"}],
    "werkzeug": [{"below": "2.2.3", "severity": "high", "cve": "CVE-2023-25577", "note": "High severity"}],
    "aiohttp": [{"below": "3.8.0", "severity": "high", "cve": "CVE-2023-37276", "note": "HTTP request smuggling"}],
    "lodash": [{"below": "4.17.21", "severity": "high", "cve": "CVE-2021-23337", "note": "Command injection / prototype pollution"}],
    "jquery": [{"below": "3.5.0", "severity": "high", "cve": "CVE-2020-11022", "note": "XSS"}],
    "express": [{"below": "4.17.3", "severity": "medium", "cve": "Multiple", "note": "Security patches"}],
    "axios": [
        {"below": "0.21.2", "severity": "high", "cve": "CVE-2021-3749", "note": "SSRF"},
        {"below": "1.6.0", "severity": "medium", "cve": "CVE-2023-45857", "note": "CSRF"},
    ],
    "minimist": [{"below": "1.2.6", "severity": "high", "cve": "CVE-2021-44906", "note": "Prototype pollution"}],
    "node-fetch": [{"below": "2.6.7", "severity": "high", "cve": "CVE-2022-0235", "note": "Sensitive info exposure"}],
    "ws": [{"below": "7.4.6", "severity": "high", "cve": "CVE-2021-32640", "note": "ReDoS"}],
    "handlebars": [{"below": "4.7.7", "severity": "high", "cve": "CVE-2021-23369", "note": "RCE"}],
    "serialize-javascript": [{"below": "3.1.0", "severity": "high", "cve": "CVE-2020-7660", "note": "RCE"}],
    "moment": [{"below": "2.29.4", "severity": "medium", "cve": "CVE-2022-24785", "note": "Path traversal / ReDoS"}],
    "jsonwebtoken": [{"below": "9.0.0", "severity": "high", "cve": "CVE-2022-23529", "note": "Unrestricted key type"}],
}


# ---------------------------------------------------------------------------
# Sensitive filenames
# ---------------------------------------------------------------------------
SENSITIVE_FILE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "credentials.json", "service-account.json", "serviceAccount.json",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "secrets.yaml", "secrets.yml", "secrets.json",
    "wp-config.php", "settings.local.php",
    "application-prod.properties", "application-secret.yml",
}
SENSITIVE_EXTENSIONS = {".pem", ".p12", ".pfx", ".key", ".keystore", ".jks"}
SENSITIVE_NAME_PATTERNS = [
    r"(?i).*secret.*",
    r"(?i).*credential.*",
    r"(?i).*password.*",
    r"(?i).*\.bak$",
    r"(?i).*\.sql\.gz$",
    r"(?i).*dump.*\.sql$",
    r"(?i).*backup.*",
]


# ---------------------------------------------------------------------------
# Hardcoded IP / internal URL patterns
# ---------------------------------------------------------------------------
IP_URL_PATTERNS = [
    (r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", "Private IP (10.x)"),
    (r"\b(192\.168\.\d{1,3}\.\d{1,3})\b", "Private IP (192.168.x)"),
    (r"\b(172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b", "Private IP (172.16-31.x)"),
    (r"(?i)https?://(?:dev|staging|stage|qa|test|internal|intranet)[.\-]", "Internal/staging URL"),
]


# ---------------------------------------------------------------------------
# License detection
# ---------------------------------------------------------------------------
LICENSE_MARKERS = {
    "MIT License": "MIT",
    "Apache License": "Apache-2.0",
    "GNU GENERAL PUBLIC LICENSE": "GPL",
    "BSD 3-Clause": "BSD-3-Clause",
    "BSD 2-Clause": "BSD-2-Clause",
    "Mozilla Public License": "MPL-2.0",
    "ISC License": "ISC",
    "Unlicense": "Unlicense",
    "Creative Commons": "CC",
    "Proprietary": "Proprietary",
}


SKIP_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", "node_modules", "venv", ".venv",
    "env", "dist", "build", "target", ".idea", ".vscode",
    "vendor", "bower_components", ".tox", ".mypy_cache", ".pytest_cache",
    "coverage", "htmlcov", ".eggs",
}

SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".o", ".a",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".pdf", ".zip", ".tar",
    ".gz", ".rar", ".7z", ".woff", ".woff2", ".ttf", ".eot",
    ".class", ".jar", ".war", ".min.js", ".min.css",
}

MAX_FILE_SIZE = 2 * 1024 * 1024


