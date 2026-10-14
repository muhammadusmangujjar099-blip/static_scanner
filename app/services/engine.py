"""
StaticScanner engine – all analysis methods.
"""

import os
import re
from pathlib import Path
from collections import defaultdict
from typing import Any

from app.services.rules import (
    LANGUAGE_EXTENSIONS,
    LANGUAGE_SIGNATURES,
    SECRET_PATTERNS,
    AUDIT_RULES,
    VULNERABLE_PACKAGES,
    SENSITIVE_FILE_NAMES,
    SENSITIVE_EXTENSIONS,
    SENSITIVE_NAME_PATTERNS,
    IP_URL_PATTERNS,
    LICENSE_MARKERS,
    SKIP_DIRS,
    SKIP_EXTENSIONS,
    MAX_FILE_SIZE,
)

def _parse_version(v: str) -> tuple:
    parts = []
    for p in re.split(r"[^\d]+", str(v).strip()):
        if p.isdigit():
            parts.append(int(p))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def _version_below(current: str, threshold: str) -> bool:
    try:
        return _parse_version(current) < _parse_version(threshold)
    except Exception:
        return False


def _is_pattern_definition_line(line: str) -> bool:
    """Skip lines that are regex/rule definitions (reduces self-scan false positives)."""
    s = line.strip()
    if s.startswith("#") or s.startswith("//"):
        return True
    if re.search(r"""(r['\"]|pattern\s*[=:]|SECRET_PATTERNS|AUDIT_RULES|VULNERABLE)""", line):
        return True
    if "message" in line and ("risk" in line or "injection" in line):
        return True
    return False


class StaticScanner:
    def __init__(self, extract_dir: str):
        self.root = Path(extract_dir)
        self.files: list[Path] = []
        self.languages: dict[str, int] = defaultdict(int)
        self.total_lines = 0
        self.secrets: list[dict] = []
        self.audit_findings: list[dict] = []
        self.dependency_vulns: list[dict] = []
        self.sensitive_files: list[dict] = []
        self.hardcoded_ips: list[dict] = []
        self.quality_metrics: dict[str, Any] = {}
        self.licenses: list[str] = []
        self.system_info: dict[str, Any] = {}

    def collect_files(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in filenames:
                fp = Path(dirpath) / fname
                if fp.suffix.lower() in SKIP_EXTENSIONS:
                    continue
                try:
                    if fp.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                self.files.append(fp)

    def detect_language(self, filepath: Path, content: str | None = None) -> str:
        ext = filepath.suffix.lower()
        if ext in LANGUAGE_EXTENSIONS:
            return LANGUAGE_EXTENSIONS[ext]
        if filepath.name.lower() in ("dockerfile", "makefile", "cmakelists.txt"):
            return filepath.name.capitalize()
        if content:
            first_lines = "\n".join(content.splitlines()[:5])
            for pattern, lang in LANGUAGE_SIGNATURES:
                if re.search(pattern, first_lines, re.MULTILINE | re.IGNORECASE):
                    return lang
        return "Unknown"

    def analyze_languages(self) -> dict:
        for fp in self.files:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                content = ""
            lang = self.detect_language(fp, content)
            self.languages[lang] += 1
            self.total_lines += content.count("\n") + (1 if content else 0)
        sorted_langs = dict(sorted(self.languages.items(), key=lambda x: -x[1]))
        primary = next(iter(sorted_langs), "Unknown")
        return {
            "languages": sorted_langs,
            "primary_language": primary,
            "total_files": len(self.files),
            "total_lines": self.total_lines,
        }

    def analyze_system(self) -> dict:
        structure = {
            "root_files": [],
            "directories": [],
            "dependency_files": [],
            "config_files": [],
            "entry_points": [],
            "has_tests": False,
            "has_docs": False,
            "has_ci": False,
            "has_docker": False,
            "framework_hints": [],
        }
        dep_names = {
            "requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
            "pom.xml", "build.gradle", "build.gradle.kts", "composer.json",
            "Gemfile", "Gemfile.lock", "Podfile", "pubspec.yaml",
        }
        config_names = {
            ".env", ".env.example", ".env.local", "config.json", "config.yaml",
            "config.yml", "settings.py", "application.properties", "application.yml",
            "web.config", "appsettings.json", "tsconfig.json", "webpack.config.js",
            "vite.config.js", "vite.config.ts", "next.config.js",
        }
        entry_hints = {
            "main.py", "app.py", "manage.py", "wsgi.py", "asgi.py",
            "index.js", "index.ts", "main.js", "main.ts", "server.js",
            "Main.java", "main.go", "main.rs", "Program.cs", "index.php",
        }
        for fp in self.files:
            rel = str(fp.relative_to(self.root))
            name = fp.name.lower()
            parent = fp.parent.name.lower()
            if fp.parent == self.root:
                structure["root_files"].append(rel)
            if name in dep_names or name.endswith(".csproj") or name.endswith(".sln"):
                structure["dependency_files"].append(rel)
            if name in config_names or name.startswith(".env"):
                structure["config_files"].append(rel)
            if name in entry_hints:
                structure["entry_points"].append(rel)
            if "test" in name or "spec" in name or parent in ("tests", "test", "__tests__", "spec"):
                structure["has_tests"] = True
            if name in ("readme.md", "readme.rst", "readme.txt") or parent in ("docs", "doc"):
                structure["has_docs"] = True
            if ".github" in rel or ".gitlab-ci" in rel or name == "jenkinsfile":
                structure["has_ci"] = True
            if name in ("dockerfile", "docker-compose.yml", "docker-compose.yaml"):
                structure["has_docker"] = True

        for dep in structure["dependency_files"]:
            try:
                content = (self.root / dep).read_text(encoding="utf-8", errors="ignore").lower()
                for fw, key in [
                    ("FastAPI", "fastapi"), ("Django", "django"), ("Flask", "flask"),
                    ("Express", "express"), ("React", "react"), ("Next.js", "next"),
                    ("Spring", "spring"), ("Laravel", "laravel"), ("Vue", "vue"),
                ]:
                    if key in content:
                        structure["framework_hints"].append(fw)
            except Exception:
                pass
        structure["framework_hints"] = list(set(structure["framework_hints"]))
        structure["directories"] = sorted(
            {str(p.relative_to(self.root).parent) for p in self.files if p.parent != self.root}
        )[:50]
        self.system_info = structure
        return structure

    def find_secrets(self) -> list[dict]:
        findings = []
        for fp in self.files:
            # skip pure docs for password-in-docs noise (still scan .env etc.)
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lines = content.splitlines()
            for lineno, line in enumerate(lines, 1):
                if _is_pattern_definition_line(line):
                    continue
                stripped = line.strip()
                if stripped.startswith("#") and "example" in stripped.lower():
                    continue
                for pattern, secret_type in SECRET_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        redacted = line
                        if match.lastindex and match.lastindex >= 2:
                            val = match.group(match.lastindex)
                            if len(val) > 8:
                                redacted = line.replace(val, val[:4] + "****" + val[-2:])
                            else:
                                redacted = line.replace(val, "****")
                        findings.append({
                            "file": str(fp.relative_to(self.root)),
                            "line": lineno,
                            "type": secret_type,
                            "snippet": redacted.strip()[:200],
                        })
                        break
        self.secrets = findings
        return findings

    def static_audit(self) -> list[dict]:
        findings = []
        for fp in self.files:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lang = self.detect_language(fp, content)
            lines = content.splitlines()
            for lineno, line in enumerate(lines, 1):
                if _is_pattern_definition_line(line):
                    continue
                for rule in AUDIT_RULES:
                    if rule["languages"] != ["*"] and lang not in rule["languages"]:
                        continue
                    if re.search(rule["pattern"], line):
                        findings.append({
                            "id": rule["id"],
                            "severity": rule["severity"],
                            "file": str(fp.relative_to(self.root)),
                            "line": lineno,
                            "message": rule["message"],
                            "snippet": line.strip()[:200],
                        })
        self.audit_findings = findings
        return findings

    def check_dependencies(self) -> list[dict]:
        findings = []
        for fp in self.files:
            name = fp.name.lower()
            if name not in (
                "requirements.txt", "package.json", "pipfile",
                "pyproject.toml", "go.mod", "composer.json", "gemfile",
            ):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(fp.relative_to(self.root))
            packages = []

            if name == "requirements.txt":
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = re.match(
                        r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<)\s*([0-9][0-9A-Za-z.\-+]*)",
                        line,
                    )
                    if m:
                        packages.append((m.group(1).lower().replace("_", "-"), m.group(3)))

            elif name == "package.json":
                for section in ("dependencies", "devDependencies"):
                    block = re.search(rf'"{section}"\s*:\s*\{{([^}}]+)\}}', content, re.DOTALL)
                    if not block:
                        continue
                    for m in re.finditer(
                        r'"([^"]+)"\s*:\s*"[\^~>=<]*([0-9][0-9A-Za-z.\-]*)"',
                        block.group(1),
                    ):
                        packages.append((m.group(1).lower(), m.group(2)))

            elif name == "pipfile":
                for m in re.finditer(
                    r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"[=<>~]*([0-9][0-9A-Za-z.\-]*)"',
                    content,
                    re.MULTILINE,
                ):
                    packages.append((m.group(1).lower().replace("_", "-"), m.group(2)))

            for pkg, version in packages:
                key = pkg.lower().replace("_", "-")
                rules = VULNERABLE_PACKAGES.get(key) or VULNERABLE_PACKAGES.get(pkg.lower())
                if not rules:
                    continue
                for rule in rules:
                    if _version_below(version, rule["below"]):
                        findings.append({
                            "package": pkg,
                            "version": version,
                            "file": rel,
                            "severity": rule["severity"],
                            "cve": rule.get("cve", ""),
                            "note": rule.get("note", ""),
                            "fix_version": rule["below"],
                        })
                        break
        self.dependency_vulns = findings
        return findings

    def find_sensitive_files(self) -> list[dict]:
        findings = []
        for fp in self.files:
            rel = str(fp.relative_to(self.root))
            name = fp.name
            name_l = name.lower()
            reason = None
            if name_l in SENSITIVE_FILE_NAMES or name in SENSITIVE_FILE_NAMES:
                reason = "Known sensitive filename"
            elif fp.suffix.lower() in SENSITIVE_EXTENSIONS:
                reason = f"Sensitive extension ({fp.suffix})"
            else:
                for pat in SENSITIVE_NAME_PATTERNS:
                    if re.match(pat, name_l) or re.match(pat, name):
                        reason = "Filename matches sensitive pattern"
                        break
            if reason:
                try:
                    size = fp.stat().st_size
                except OSError:
                    size = 0
                findings.append({
                    "file": rel,
                    "reason": reason,
                    "size_bytes": size,
                    "severity": "high" if name_l in SENSITIVE_FILE_NAMES or fp.suffix.lower() in SENSITIVE_EXTENSIONS else "medium",
                })
        self.sensitive_files = findings
        return findings

    def find_hardcoded_ips(self) -> list[dict]:
        findings = []
        for fp in self.files:
            if fp.suffix.lower() in (".md", ".txt", ".rst"):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for lineno, line in enumerate(content.splitlines(), 1):
                if _is_pattern_definition_line(line):
                    continue
                for pattern, label in IP_URL_PATTERNS:
                    m = re.search(pattern, line)
                    if m:
                        findings.append({
                            "file": str(fp.relative_to(self.root)),
                            "line": lineno,
                            "type": label,
                            "value": m.group(0)[:80],
                            "snippet": line.strip()[:200],
                        })
                        break
        self.hardcoded_ips = findings
        return findings

    def analyze_quality(self) -> dict:
        large_files = []
        total_funcs = 0
        long_funcs = 0
        deep_nest = 0
        for fp in self.files:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lines = content.splitlines()
            n = len(lines)
            if n > 500:
                large_files.append({
                    "file": str(fp.relative_to(self.root)),
                    "lines": n,
                })
            # simple function count / long functions (Python/JS style)
            func_starts = [i for i, l in enumerate(lines) if re.match(r"^\s*(def |function |async def |async function )", l)]
            total_funcs += len(func_starts)
            for i, start in enumerate(func_starts):
                end = func_starts[i + 1] if i + 1 < len(func_starts) else n
                if end - start > 80:
                    long_funcs += 1
            # deep nesting heuristic
            for line in lines:
                leading = len(line) - len(line.lstrip(" \t"))
                if leading >= 24:  # ~6 levels of 4-space indent
                    deep_nest += 1
                    break
        metrics = {
            "large_files_count": len(large_files),
            "large_files": large_files[:20],
            "approx_functions": total_funcs,
            "long_functions": long_funcs,
            "files_with_deep_nesting": deep_nest,
        }
        self.quality_metrics = metrics
        return metrics

    def detect_licenses(self) -> list[str]:
        found = set()
        for fp in self.files:
            name = fp.name.lower()
            if name not in ("license", "license.md", "license.txt", "copying", "licence"):
                if "license" not in name:
                    continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")[:3000]
            except Exception:
                continue
            for marker, lic in LICENSE_MARKERS.items():
                if marker.lower() in content.lower():
                    found.add(lic)
            if not found and content.strip():
                found.add("Unknown (LICENSE file present)")
        # package.json license field
        for fp in self.files:
            if fp.name.lower() == "package.json":
                try:
                    content = fp.read_text(encoding="utf-8", errors="ignore")
                    m = re.search(r'"license"\s*:\s*"([^"]+)"', content)
                    if m:
                        found.add(m.group(1))
                except Exception:
                    pass
        self.licenses = sorted(found)
        return self.licenses

    def compute_score(self) -> float:
        score = 100.0
        for f in self.audit_findings:
            if f["severity"] == "high":
                score -= 5
            elif f["severity"] == "medium":
                score -= 2
            else:
                score -= 0.5
        score -= min(len(self.secrets) * 3, 30)
        for v in self.dependency_vulns:
            if v["severity"] == "high":
                score -= 4
            elif v["severity"] == "medium":
                score -= 2
            else:
                score -= 0.5
        score -= min(len(self.sensitive_files) * 2, 15)
        score -= min(len(self.hardcoded_ips) * 0.5, 5)
        return max(0.0, min(100.0, round(score, 1)))

    def risk_level(self, score: float) -> str:
        if score >= 80:
            return "Low"
        if score >= 50:
            return "Medium"
        return "High"

    def run(self) -> dict:
        self.collect_files()
        lang_info = self.analyze_languages()
        system = self.analyze_system()
        secrets = self.find_secrets()
        deps = self.check_dependencies()
        sensitive = self.find_sensitive_files()
        ips = self.find_hardcoded_ips()
        quality = self.analyze_quality()
        licenses = self.detect_licenses()
        audit = self.static_audit()
        score = self.compute_score()
        risk = self.risk_level(score)

        severity_counts = defaultdict(int)
        for f in audit:
            severity_counts[f["severity"]] += 1

        system["dependency_vulnerabilities"] = deps
        system["sensitive_files"] = sensitive
        system["hardcoded_ips"] = ips
        system["quality_metrics"] = quality
        system["licenses"] = licenses
        system["risk_level"] = risk

        summary = {
            "primary_language": lang_info["primary_language"],
            "languages_detected": list(lang_info["languages"].keys()),
            "total_files_scanned": lang_info["total_files"],
            "total_lines": lang_info["total_lines"],
            "secrets_count": len(secrets),
            "audit_findings_count": len(audit),
            "severity_breakdown": dict(severity_counts),
            "audit_score": score,
            "risk_level": risk,
            "has_tests": system.get("has_tests"),
            "has_docker": system.get("has_docker"),
            "frameworks": system.get("framework_hints", []),
            "dependency_vulns_count": len(deps),
            "sensitive_files_count": len(sensitive),
            "hardcoded_ips_count": len(ips),
            "licenses": licenses,
            "quality_metrics": quality,
        }

        return {
            "languages": lang_info["languages"],
            "primary_language": lang_info["primary_language"],
            "system_info": system,
            "secrets_found": secrets,
            "secrets_count": len(secrets),
            "dependency_vulnerabilities": deps,
            "sensitive_files": sensitive,
            "hardcoded_ips": ips,
            "quality_metrics": quality,
            "licenses": licenses,
            "static_audit": audit,
            "audit_score": score,
            "risk_level": risk,
            "total_files": lang_info["total_files"],
            "total_lines": lang_info["total_lines"],
            "summary": summary,
        }


