"""Web application testing modules."""
import json
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

from . import BaseModule, Finding, ModuleResult, Severity

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Nuclei ────────────────────────────────────────────────────────────────────

class NucleiModule(BaseModule):
    name = "nuclei"
    description = "Nuclei — template-based vulnerability scanner"
    default_timeout = 600

    _SEV_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "unknown": Severity.INFO,
    }

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("nuclei"):
            return ModuleResult(success=False, error="nuclei not found")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        severity = options.get("severity", "critical,high,medium")
        tags = options.get("tags", "")

        cmd = [
            "nuclei", "-u", target,
            "-severity", severity,
            "-json-export", "/dev/stdout",
            "-silent",
            "-no-color",
        ]
        if tags:
            cmd += ["-tags", tags]

        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self.parse_output(stdout)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            template_id = d.get("template-id", "unknown")
            name = d.get("info", {}).get("name", template_id)
            severity_raw = d.get("info", {}).get("severity", "info").lower()
            matched_at = d.get("matched-at", "")
            description = d.get("info", {}).get("description", "")
            extractor_data = d.get("extracted-results", [])
            evidence = matched_at
            if extractor_data:
                evidence += "\nExtracted: " + ", ".join(str(x) for x in extractor_data[:10])

            findings.append(Finding(
                title=f"[nuclei] {name}",
                description=description or f"Template: {template_id}",
                severity=self._SEV_MAP.get(severity_raw, Severity.INFO),
                evidence=evidence,
                module=self.name,
                target=matched_at,
            ))
        return findings


# ── FFuf ──────────────────────────────────────────────────────────────────────

class FfufModule(BaseModule):
    name = "ffuf"
    description = "FFuf — web fuzzer for directories, endpoints, VHosts"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("ffuf"):
            return ModuleResult(success=False, error="ffuf not found")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        mc = options.get("mc", "200,204,301,302,307,401,403")
        url_pattern = options.get("url", f"{target.rstrip('/')}/FUZZ")
        tmpfile = tempfile.mktemp(suffix=".json", prefix="reaper_ffuf_")

        cmd = [
            "ffuf",
            "-u", url_pattern,
            "-w", wordlist,
            "-mc", mc,
            "-o", tmpfile,
            "-of", "json",
            "-s",
        ]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self._parse_output_file(tmpfile)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def _parse_output_file(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(Path(path).read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return findings
        for result in data.get("results", []):
            url = result.get("url", "")
            status = result.get("status", 0)
            size = result.get("length", 0)
            sev = Severity.LOW if status in (200, 204) else Severity.INFO
            findings.append(Finding(
                title=f"FFuf: {status} {url}",
                description=f"Status: {status} | Length: {size}",
                severity=sev,
                evidence=f"{status} {url} [{size} bytes]",
                module=self.name,
                target=url,
            ))
        return findings


# ── SQLMap ────────────────────────────────────────────────────────────────────

class SqlmapModule(BaseModule):
    name = "sqlmap"
    description = "SQLMap — automatic SQL injection detection and exploitation"
    default_timeout = 600

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("sqlmap"):
            return ModuleResult(success=False, error="sqlmap not found")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        level = options.get("level", 2)
        risk = options.get("risk", 2)
        forms = options.get("forms", True)

        cmd = [
            "sqlmap", "-u", target,
            "--batch",
            "--level", str(level),
            "--risk", str(risk),
            "--random-agent",
        ]
        if forms:
            cmd.append("--forms")

        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self.parse_output(stdout)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        if "is vulnerable" in output.lower() or "parameter" in output.lower() and "injectable" in output.lower():
            for line in output.splitlines():
                if "is vulnerable" in line.lower() or ("parameter" in line.lower() and "injectable" in line.lower()):
                    findings.append(Finding(
                        title=f"SQL Injection: {line.strip()[:120]}",
                        description="SQLMap detected SQL injection vulnerability",
                        severity=Severity.CRITICAL,
                        evidence=line.strip(),
                        module=self.name,
                    ))
        return findings


# ── Nikto ─────────────────────────────────────────────────────────────────────

class NiktoModule(BaseModule):
    name = "nikto"
    description = "Nikto — web server misconfiguration and vulnerability scanner"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("nikto"):
            return ModuleResult(success=False, error="nikto not found")

        tmpfile = tempfile.mktemp(suffix=".json", prefix="reaper_nikto_")
        cmd = [
            "nikto",
            "-h", target,
            "-Format", "json",
            "-output", tmpfile,
            "-nointeractive",
        ]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self._parse_json(tmpfile) or self.parse_output(stdout)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def _parse_json(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(Path(path).read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return findings
        for vuln in data.get("vulnerabilities", []):
            msg = vuln.get("msg", "")
            url = vuln.get("url", "")
            method = vuln.get("method", "")
            osvdb = vuln.get("OSVDB", "0")
            sev = Severity.HIGH if osvdb != "0" else Severity.MEDIUM
            findings.append(Finding(
                title=f"Nikto: {msg[:100]}",
                description=f"Method: {method} | OSVDB: {osvdb}",
                severity=sev,
                evidence=f"{method} {url}: {msg}",
                module=self.name,
                target=url,
            ))
        return findings

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            if line.startswith("+ "):
                findings.append(Finding(
                    title=f"Nikto: {line[2:100]}",
                    description=line[2:],
                    severity=Severity.MEDIUM,
                    evidence=line,
                    module=self.name,
                ))
        return findings


# ── Dalfox ────────────────────────────────────────────────────────────────────

class DalfoxModule(BaseModule):
    name = "dalfox"
    description = "Dalfox — XSS parameter analysis and scanning"
    default_timeout = 240

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("dalfox"):
            return ModuleResult(success=False, error="dalfox not found")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        cmd = ["dalfox", "url", target, "--no-color", "--format", "json"]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self.parse_output(stdout)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                pass
            else:
                findings.append(Finding(
                    title=f"XSS: {d.get('type', 'unknown')} on {d.get('param', '?')}",
                    description=str(d.get("evidence", "")),
                    severity=Severity.HIGH,
                    evidence=str(d),
                    module=self.name,
                    target=d.get("data", {}).get("url", ""),
                ))
                continue

            # Fallback text parsing
            if "[V]" in line or "[POC]" in line:
                findings.append(Finding(
                    title=f"XSS found: {line[:120]}",
                    description="Dalfox confirmed XSS vulnerability",
                    severity=Severity.HIGH,
                    evidence=line,
                    module=self.name,
                ))
        return findings


# ── Whatweb ───────────────────────────────────────────────────────────────────

class WhatwebModule(BaseModule):
    name = "whatweb"
    description = "WhatWeb — technology fingerprinting for web targets"
    default_timeout = 120

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("whatweb"):
            return ModuleResult(success=False, error="whatweb not found")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        aggression = options.get("aggression", 1)
        tmpfile = tempfile.mktemp(suffix=".json", prefix="reaper_whatweb_")

        cmd = [
            "whatweb",
            target,
            f"--aggression={aggression}",
            f"--log-json={tmpfile}",
            "--no-errors",
            "--quiet",
        ]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self._parse_json(tmpfile, target)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def _parse_json(self, path: str, default_target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            raw = Path(path).read_text()
            # whatweb outputs one JSON object per line or a JSON array
            data_lines = []
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("["):
                    data_lines.extend(json.loads(line))
                elif line.startswith("{"):
                    data_lines.append(json.loads(line))
        except (json.JSONDecodeError, FileNotFoundError):
            return findings

        for entry in data_lines:
            target_url = entry.get("target", default_target)
            plugins = entry.get("plugins", {})
            techs: list[str] = []
            for plugin_name, plugin_data in plugins.items():
                if plugin_name in ("Status", "RedirectLocation"):
                    continue
                versions = plugin_data.get("version", [])
                if versions:
                    techs.append(f"{plugin_name}/{versions[0]}")
                else:
                    techs.append(plugin_name)

            if techs:
                findings.append(Finding(
                    title=f"WhatWeb: {len(techs)} technologies on {target_url}",
                    description=", ".join(techs),
                    severity=Severity.INFO,
                    evidence="\n".join(techs),
                    module=self.name,
                    target=target_url,
                ))

            # Flag known vulnerable/interesting components
            interesting = ["WordPress", "Joomla", "Drupal", "phpMyAdmin", "Jenkins",
                           "Apache Tomcat", "WebLogic", "JBoss", "Struts"]
            for tech in interesting:
                if tech.lower() in " ".join(techs).lower():
                    findings.append(Finding(
                        title=f"WhatWeb: {tech} detected — check for known CVEs",
                        description=f"Known high-value target technology: {tech}",
                        severity=Severity.MEDIUM,
                        evidence=", ".join(t for t in techs if tech.lower() in t.lower()),
                        module=self.name,
                        target=target_url,
                    ))
        return findings


# ── CORS Checker ──────────────────────────────────────────────────────────────

class CorsModule(BaseModule):
    name = "cors"
    description = "CORS misconfiguration checker — pure Python, no external tools"
    default_timeout = 60

    _EVIL_ORIGINS = [
        "https://evil.example.com",
        "null",
        "https://attacker.com",
        "https://evil-site.com",
    ]

    def run(self, target: str, options: dict) -> ModuleResult:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self._emit(f"[*] Checking CORS misconfigurations on {target}")
        findings: list[Finding] = []
        output_lines: list[str] = []

        for origin in self._EVIL_ORIGINS:
            result = self._check(target, origin)
            output_lines.append(result["line"])
            self._emit(result["line"])
            if result["finding"]:
                findings.append(result["finding"])

        # Remove duplicates by title
        seen: set[str] = set()
        deduped: list[Finding] = []
        for f in findings:
            if f.title not in seen:
                seen.add(f.title)
                deduped.append(f)

        return ModuleResult(
            success=True,
            findings=deduped,
            raw_output="\n".join(output_lines),
            command=f"cors-check {target}",
        )

    def _check(self, url: str, origin: str) -> dict:
        headers = {
            "Origin": origin,
            "User-Agent": "Mozilla/5.0 (REAPER Security Scanner)",
        }
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            acam = resp.headers.get("Access-Control-Allow-Methods", "")
            line = f"Origin={origin!r:40s} → ACAO={acao!r:30s} ACAC={acac!r}"
            finding: Finding | None = None

            if acao == "*" and acac == "true":
                finding = Finding(
                    title=f"CORS: Wildcard + credentials on {url}",
                    description=(
                        "Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true. "
                        "Browsers block this per spec but it indicates misconfiguration."
                    ),
                    severity=Severity.HIGH,
                    evidence=line,
                    module=self.name,
                    target=url,
                )
            elif acao and acao == origin and origin != "null" and acac == "true":
                finding = Finding(
                    title=f"CORS: Arbitrary origin reflected with credentials on {url}",
                    description=(
                        "Server reflects the attacker-controlled Origin header and allows "
                        "credentials — classic CORS misconfiguration enabling cross-origin data theft."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=line,
                    module=self.name,
                    target=url,
                )
            elif acao and acao == origin and origin != "null":
                finding = Finding(
                    title=f"CORS: Arbitrary origin reflected (no credentials) on {url}",
                    description="Server reflects arbitrary Origin. Without credentials impact is limited.",
                    severity=Severity.MEDIUM,
                    evidence=line,
                    module=self.name,
                    target=url,
                )
            elif acao == "null":
                finding = Finding(
                    title=f"CORS: Null origin allowed on {url}",
                    description=(
                        "Server accepts null origin, which can be triggered via sandboxed iframes "
                        "— can lead to CSRF or data theft."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=line,
                    module=self.name,
                    target=url,
                )

            return {"line": line, "finding": finding}

        except requests.RequestException as exc:
            line = f"[!] Connection error checking CORS ({origin}): {exc}"
            return {"line": line, "finding": None}
