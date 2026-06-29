"""Reconnaissance modules."""
import json
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import requests

from . import BaseModule, Finding, ModuleResult, Severity


# ── Nmap ──────────────────────────────────────────────────────────────────────

class NmapModule(BaseModule):
    name = "nmap"
    description = "Nmap — service/version detection, OS fingerprinting"
    default_timeout = 600

    # Ports/services that escalate severity
    _DANGEROUS = {"ftp", "telnet", "rsh", "rlogin", "finger", "tftp", "rexec"}
    _NOTABLE = {"smtp", "smb", "msrpc", "netbios-ssn", "microsoft-ds", "ms-wbt-server"}

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("nmap"):
            return ModuleResult(success=False, error="nmap not found")

        ports = options.get("ports", "1-65535")
        extra_flags = options.get("flags", "-sV -sC -O --open")
        tmpdir = tempfile.mkdtemp(prefix="reaper_nmap_")
        xml_out = Path(tmpdir) / "scan.xml"

        cmd = (
            ["nmap", "-p", ports, "-oX", str(xml_out), "--stats-every", "10s"]
            + extra_flags.split()
            + [target]
        )

        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd, timeout=self.default_timeout)

        findings = self._parse_xml(str(xml_out), target)
        if not findings:
            findings = self.parse_output(stdout)

        return ModuleResult(
            success=rc in (0, 1),
            findings=findings,
            raw_output=stdout + ("\n" + stderr if stderr else ""),
            command=" ".join(cmd),
        )

    def _parse_xml(self, path: str, default_target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            tree = ET.parse(path)
        except (ET.ParseError, FileNotFoundError):
            return findings

        for host in tree.getroot().findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
            ip = addr_el.get("addr", default_target) if addr_el is not None else default_target

            for port in host.findall(".//port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_id = port.get("portid", "?")
                proto = port.get("protocol", "tcp")
                svc_el = port.find("service")
                svc = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                svc_str = " ".join(filter(None, [svc, product, version])) or "unknown"

                if svc in self._DANGEROUS:
                    severity = Severity.HIGH
                    desc = f"Cleartext/dangerous service exposed: {svc_str}"
                elif svc in self._NOTABLE:
                    severity = Severity.MEDIUM
                    desc = f"Notable network service: {svc_str}"
                else:
                    severity = Severity.INFO
                    desc = f"Service: {svc_str}"

                findings.append(Finding(
                    title=f"Open {port_id}/{proto} on {ip}",
                    description=desc,
                    severity=severity,
                    evidence=f"{ip}:{port_id}/{proto}  {svc_str}",
                    module=self.name,
                    target=ip,
                ))
        return findings

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            m = re.search(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
            if m:
                port, proto, svc = m.groups()
                findings.append(Finding(
                    title=f"Open port {port}/{proto}",
                    description=f"Service: {svc}",
                    severity=Severity.HIGH if svc in self._DANGEROUS else Severity.INFO,
                    evidence=line.strip(),
                    module=self.name,
                ))
        return findings


# ── Masscan ───────────────────────────────────────────────────────────────────

class MasscanModule(BaseModule):
    name = "masscan"
    description = "Masscan — ultra-fast port scan for large IP ranges"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("masscan"):
            return ModuleResult(success=False, error="masscan not found")

        ports = options.get("ports", "0-65535")
        rate = options.get("rate", "10000")
        tmpfile = tempfile.mktemp(suffix=".json", prefix="reaper_masscan_")

        cmd = [
            "masscan", target,
            "-p", ports,
            "--rate", str(rate),
            "-oJ", tmpfile,
        ]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self._parse_json(tmpfile, target)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout + ("\n" + stderr if stderr else ""),
            command=" ".join(cmd),
        )

    def _parse_json(self, path: str, default_target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(Path(path).read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return findings
        for host in data:
            ip = host.get("ip", default_target)
            for p in host.get("ports", []):
                port = p.get("port", "?")
                proto = p.get("proto", "tcp")
                if p.get("status") == "open":
                    findings.append(Finding(
                        title=f"Masscan: open {port}/{proto} on {ip}",
                        description="Port found open via masscan",
                        severity=Severity.INFO,
                        evidence=f"{ip}:{port}/{proto}",
                        module=self.name,
                        target=ip,
                    ))
        return findings


# ── Subfinder ─────────────────────────────────────────────────────────────────

class SubfinderModule(BaseModule):
    name = "subfinder"
    description = "Subfinder — passive subdomain enumeration"
    default_timeout = 180

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("subfinder"):
            return ModuleResult(success=False, error="subfinder not found")

        domain = re.sub(r"^https?://", "", target).split("/")[0]
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        subdomains = [l.strip() for l in stdout.splitlines() if l.strip()]
        findings: list[Finding] = []
        if subdomains:
            findings.append(Finding(
                title=f"Subfinder: {len(subdomains)} subdomains for {domain}",
                description="\n".join(subdomains[:100]),
                severity=Severity.INFO,
                evidence="\n".join(subdomains),
                module=self.name,
                target=domain,
            ))
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )


# ── httpx ─────────────────────────────────────────────────────────────────────

class HttpxModule(BaseModule):
    name = "httpx"
    description = "httpx — fast HTTP probing with status codes, titles, tech detection"
    default_timeout = 120

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("httpx"):
            return ModuleResult(success=False, error="httpx not found")

        if not target.startswith(("http://", "https://")):
            target_url = f"https://{target}"
        else:
            target_url = target

        cmd = [
            "httpx", "-u", target_url,
            "-status-code", "-title", "-tech-detect",
            "-follow-redirects", "-json", "-silent",
        ]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self._parse_json_lines(stdout, target)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def _parse_json_lines(self, output: str, default_target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = data.get("url", default_target)
            status = data.get("status-code", 0)
            title = data.get("title", "")
            techs = data.get("tech", [])
            tech_str = ", ".join(techs) if techs else "unknown"

            sev = Severity.INFO
            if status in (401, 403):
                sev = Severity.LOW
            elif status == 200:
                sev = Severity.INFO

            findings.append(Finding(
                title=f"HTTP {status}: {url}",
                description=f"Title: {title} | Tech: {tech_str}",
                severity=sev,
                evidence=json.dumps(data, ensure_ascii=False),
                module=self.name,
                target=url,
            ))
        return findings


# ── theHarvester ──────────────────────────────────────────────────────────────

class TheHarvesterModule(BaseModule):
    name = "theharvester"
    description = "theHarvester — OSINT: emails, subdomains, hosts, IPs"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        tool = "theHarvester"
        if not self.tool_check_emit(tool):
            return ModuleResult(success=False, error="theHarvester not found")

        domain = re.sub(r"^https?://", "", target).split("/")[0]
        sources = options.get("sources", "all")
        limit = options.get("limit", 200)

        cmd = [tool, "-d", domain, "-l", str(limit), "-b", sources]
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
        emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", output)
        hosts = re.findall(r"[\w\-]+\.[\w\-]+\.[\w\-]+", output)
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)

        if emails:
            findings.append(Finding(
                title=f"theHarvester: {len(set(emails))} email addresses found",
                description="Emails: " + ", ".join(sorted(set(emails))[:50]),
                severity=Severity.MEDIUM,
                evidence="\n".join(sorted(set(emails))),
                module=self.name,
            ))
        if hosts:
            findings.append(Finding(
                title=f"theHarvester: {len(set(hosts))} hostnames discovered",
                description="First 30: " + ", ".join(sorted(set(hosts))[:30]),
                severity=Severity.INFO,
                evidence="\n".join(sorted(set(hosts))),
                module=self.name,
            ))
        if ips:
            findings.append(Finding(
                title=f"theHarvester: {len(set(ips))} IPs discovered",
                description=", ".join(sorted(set(ips))[:30]),
                severity=Severity.INFO,
                evidence="\n".join(sorted(set(ips))),
                module=self.name,
            ))
        return findings


# ── TruffleHog ────────────────────────────────────────────────────────────────

class TruffleHogModule(BaseModule):
    name = "trufflehog"
    description = "TruffleHog — scan git repos/filesystems for leaked secrets"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("trufflehog"):
            return ModuleResult(success=False, error="trufflehog not found")

        # target can be git URL or filesystem path
        if target.startswith(("http://", "https://", "git@")):
            cmd = ["trufflehog", "git", target, "--json", "--no-update"]
        else:
            cmd = ["trufflehog", "filesystem", target, "--json", "--no-update"]

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
            det = d.get("DetectorName", "Unknown")
            raw = d.get("Raw", "")[:200]
            source_meta = d.get("SourceMetadata", {}).get("Data", {})
            file_path = ""
            for v in source_meta.values():
                if isinstance(v, dict):
                    file_path = v.get("file", "") or v.get("link", "")

            findings.append(Finding(
                title=f"Secret found: {det}",
                description=f"Detector: {det}\nFile: {file_path}",
                severity=Severity.CRITICAL,
                evidence=raw,
                module=self.name,
                target=file_path or "unknown",
            ))
        return findings


# ── Katana ────────────────────────────────────────────────────────────────────

class KatanaModule(BaseModule):
    name = "katana"
    description = "Katana — next-gen web crawler (ProjectDiscovery)"
    default_timeout = 180

    _SENSITIVE_PATTERNS = re.compile(
        r"(admin|backup|config|\.env|\.git|\.sql|api/|secret|token|cred)", re.IGNORECASE
    )

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("katana"):
            return ModuleResult(success=False, error="katana not found")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        depth = options.get("depth", 3)
        cmd = [
            "katana", "-u", target,
            "-d", str(depth),
            "-silent",
            "-jc",  # JavaScript crawling
        ]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        urls = [l.strip() for l in stdout.splitlines() if l.strip().startswith("http")]
        findings: list[Finding] = []

        interesting = [u for u in urls if self._SENSITIVE_PATTERNS.search(u)]
        if interesting:
            for u in interesting:
                findings.append(Finding(
                    title=f"Interesting URL: {u}",
                    description="URL contains potentially sensitive path component",
                    severity=Severity.LOW,
                    evidence=u,
                    module=self.name,
                    target=target,
                ))
        if urls:
            findings.append(Finding(
                title=f"Katana: {len(urls)} URLs crawled on {target}",
                description=f"Total crawled URLs: {len(urls)}",
                severity=Severity.INFO,
                evidence="\n".join(urls[:200]),
                module=self.name,
                target=target,
            ))
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )


# ── Wayback Machine ───────────────────────────────────────────────────────────

class WaybackModule(BaseModule):
    name = "wayback"
    description = "Wayback Machine — fetch historical URLs from CDX API (pure Python)"
    default_timeout = 60

    _INTERESTING = re.compile(
        r"(admin|backup|config|\.sql|\.env|password|secret|api|token|key|\.git|\.svn|wp-config|cred)",
        re.IGNORECASE,
    )

    def run(self, target: str, options: dict) -> ModuleResult:
        domain = re.sub(r"^https?://", "", target).rstrip("/").split("/")[0]
        limit = int(options.get("limit", 500))

        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&collapse=urlkey"
            f"&fl=original&limit={limit}"
        )
        self._emit(f"[*] Querying Wayback CDX API for: {domain}")

        try:
            resp = requests.get(cdx_url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            return ModuleResult(success=False, error=str(exc), command=cdx_url)
        except (ValueError, TypeError) as exc:
            return ModuleResult(success=False, error=f"JSON parse error: {exc}", command=cdx_url)

        urls = [row[0] for row in data[1:] if row]  # row 0 is header
        self._emit(f"[+] {len(urls)} URLs found")

        findings: list[Finding] = []
        for url in urls:
            if self._INTERESTING.search(url):
                findings.append(Finding(
                    title=f"Wayback: sensitive URL — {url[:120]}",
                    description="Historical URL with potentially sensitive path found in Wayback archive",
                    severity=Severity.LOW,
                    evidence=url,
                    module=self.name,
                    target=domain,
                ))

        if urls:
            findings.append(Finding(
                title=f"Wayback: {len(urls)} historical URLs for {domain}",
                description=f"Retrieved from Wayback Machine CDX API",
                severity=Severity.INFO,
                evidence="\n".join(urls[:300]),
                module=self.name,
                target=domain,
            ))

        return ModuleResult(
            success=True,
            findings=findings,
            raw_output="\n".join(urls),
            command=cdx_url,
        )
