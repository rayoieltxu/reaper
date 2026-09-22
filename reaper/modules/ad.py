"""Active Directory / Windows network modules."""
import re
import json
import tempfile
from pathlib import Path

from . import BaseModule, Finding, ModuleResult, Severity, redact_command


# ── NetExec (formerly CrackMapExec) ───────────────────────────────────────────

class NetExecModule(BaseModule):
    name = "netexec"
    description = "NetExec — SMB/LDAP/WinRM enumeration and spraying (formerly CrackMapExec)"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        tool = "netexec" if self.tool_available("netexec") else "crackmapexec"
        if not self.tool_check_emit(tool):
            return ModuleResult(success=False, error="netexec/crackmapexec not found")

        protocol = options.get("protocol", "smb")
        username = options.get("username", "")
        password = options.get("password", "")
        domain = options.get("domain", "")

        cmd = [tool, protocol, target]
        if domain:
            cmd += ["-d", domain]
        if username:
            cmd += ["-u", username]
        if password:
            cmd += ["-p", password]
        else:
            cmd.append("--no-bruteforce")

        cmd_str = redact_command(cmd, password)
        self._emit(f"[*] {cmd_str}")
        rc, stdout, stderr = self.run_command(cmd)
        findings = self.parse_output(stdout)

        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout + ("\n" + stderr if stderr else ""),
            command=cmd_str,
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            # Detect successful authentication
            if "[+]" in line and ("Pwn3d" in line or "Win" in line):
                findings.append(Finding(
                    title=f"NetExec: Admin access — {line.strip()[:120]}",
                    description="Local administrator or Domain Admin access confirmed",
                    severity=Severity.CRITICAL,
                    evidence=line.strip(),
                    module=self.name,
                ))
            elif "[+]" in line:
                findings.append(Finding(
                    title=f"NetExec: Successful auth — {line.strip()[:100]}",
                    description="Valid credentials or anonymous access",
                    severity=Severity.HIGH,
                    evidence=line.strip(),
                    module=self.name,
                ))
            elif "SMB" in line and ("signing" in line.lower() or "disabled" in line.lower()):
                sev = Severity.MEDIUM if "disabled" in line.lower() else Severity.INFO
                findings.append(Finding(
                    title=f"NetExec: SMB signing — {line.strip()[:80]}",
                    description="SMB signing disabled enables relay attacks (NTLM relay)",
                    severity=sev,
                    evidence=line.strip(),
                    module=self.name,
                ))
        return findings


# ── Kerbrute ──────────────────────────────────────────────────────────────────

class KerbruteModule(BaseModule):
    name = "kerbrute"
    description = "Kerbrute — Kerberos user enumeration and password spraying"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("kerbrute"):
            return ModuleResult(success=False, error="kerbrute not found")

        domain = options.get("domain", target)
        dc = options.get("dc", target)
        wordlist = options.get("wordlist", "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt")
        action = options.get("action", "userenum")
        password = options.get("password", "")

        if action == "userenum":
            cmd = ["kerbrute", "userenum", "--dc", dc, "-d", domain, wordlist, "--no-color"]
        elif action == "passwordspray":
            cmd = ["kerbrute", "passwordspray", "--dc", dc, "-d", domain, wordlist, password, "--no-color"]
        else:
            cmd = ["kerbrute", action, "--dc", dc, "-d", domain, wordlist, "--no-color"]

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
        valid_users: list[str] = []
        valid_creds: list[str] = []

        for line in output.splitlines():
            if "VALID USERNAME" in line or "VALID LOGIN" in line:
                user = re.search(r"VALID (?:USERNAME|LOGIN):\s+(\S+)", line)
                if user:
                    if "@" in line and "VALID LOGIN" in line:
                        valid_creds.append(user.group(1))
                    else:
                        valid_users.append(user.group(1))

        if valid_users:
            findings.append(Finding(
                title=f"Kerbrute: {len(valid_users)} valid Kerberos usernames",
                description="Valid usernames can be used for further attacks",
                severity=Severity.MEDIUM,
                evidence="\n".join(valid_users),
                module=self.name,
            ))
        if valid_creds:
            findings.append(Finding(
                title=f"Kerbrute: {len(valid_creds)} valid credentials found",
                description="Valid AD credentials — immediate risk of lateral movement",
                severity=Severity.CRITICAL,
                evidence="\n".join(valid_creds),
                module=self.name,
            ))
        return findings


# ── BloodHound.py ─────────────────────────────────────────────────────────────

class BloodhoundModule(BaseModule):
    name = "bloodhound"
    description = "BloodHound.py — Active Directory attack path collector"
    default_timeout = 600

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("bloodhound-python"):
            return ModuleResult(success=False, error="bloodhound-python not found (pip install bloodhound)")

        username = options.get("username", "")
        password = options.get("password", "")
        domain = options.get("domain", "")
        dc_ip = options.get("dc_ip", target)
        collection_method = options.get("collection", "All")
        output_dir = options.get("output_dir", tempfile.mkdtemp(prefix="reaper_bh_"))

        if not all([username, password, domain]):
            self._emit("[!] bloodhound requires: username, password, domain (pass via --opts)")
            return ModuleResult(
                success=False,
                error="Missing required options: username, password, domain",
                command="bloodhound-python ...",
            )

        cmd = [
            "bloodhound-python",
            "-u", username,
            "-p", password,
            "-d", domain,
            "-ns", dc_ip,
            "-c", collection_method,
            "--zip",
            "--disable-pooling",
            "-op", output_dir,
        ]
        cmd_str = redact_command(cmd, password)
        self._emit(f"[*] {cmd_str}")
        rc, stdout, stderr = self.run_command(cmd)

        zip_files = list(Path(output_dir).glob("*.zip"))
        zip_str = str(zip_files[0]) if zip_files else "none"

        findings: list[Finding] = []
        if rc == 0 or zip_files:
            findings.append(Finding(
                title=f"BloodHound collection complete — {zip_str}",
                description=(
                    f"AD data collected via bloodhound-python\n"
                    f"Import {zip_str} into BloodHound GUI to visualise attack paths."
                ),
                severity=Severity.INFO,
                evidence=f"Output: {output_dir}\nZip: {zip_str}",
                module=self.name,
                target=domain,
            ))

        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout + ("\n" + stderr if stderr else ""),
            command=cmd_str,
        )


# ── Certipy ───────────────────────────────────────────────────────────────────

class CertipyModule(BaseModule):
    name = "certipy"
    description = "Certipy — Active Directory Certificate Services (AD CS) attack tool"
    default_timeout = 300

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("certipy"):
            return ModuleResult(success=False, error="certipy not found (pip install certipy-ad)")

        username = options.get("username", "")
        password = options.get("password", "")
        domain = options.get("domain", "")
        dc_ip = options.get("dc_ip", target)
        action = options.get("action", "find")

        if not all([username, password, domain]):
            return ModuleResult(
                success=False,
                error="certipy requires: username, password, domain",
            )

        cmd = [
            "certipy", action,
            "-u", f"{username}@{domain}",
            "-p", password,
            "-dc-ip", dc_ip,
        ]
        if action == "find":
            cmd.append("-vulnerable")

        cmd_str = redact_command(cmd, password)
        self._emit(f"[*] {cmd_str}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self.parse_output(stdout + stderr)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=cmd_str,
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        # ESC1, ESC2... patterns
        esc_pattern = re.compile(r"(ESC\d+)", re.IGNORECASE)
        for line in output.splitlines():
            m = esc_pattern.search(line)
            if m:
                findings.append(Finding(
                    title=f"AD CS Vulnerability: {m.group(1)} — {line.strip()[:100]}",
                    description=f"Certipy detected AD CS misconfiguration: {m.group(1)}",
                    severity=Severity.CRITICAL,
                    evidence=line.strip(),
                    module=self.name,
                ))
        return findings


# ── Responder ─────────────────────────────────────────────────────────────────

class ResponderModule(BaseModule):
    name = "responder"
    description = "Responder — LLMNR/NBT-NS/mDNS poisoner for credential capture"
    default_timeout = 120

    def run(self, target: str, options: dict) -> ModuleResult:
        if not self.tool_check_emit("responder"):
            return ModuleResult(success=False, error="responder not found")

        interface = options.get("interface", "eth0")
        duration_raw = options.get("duration", 60)
        try:
            duration = int(duration_raw)
        except (TypeError, ValueError):
            self._emit(f"[!] Invalid duration {duration_raw!r} — falling back to 60s")
            duration = 60

        cmd = ["responder", "-I", interface, "-dwv", "--no-color"]
        self._emit(f"[*] Running Responder for {duration}s on {interface} (requires root)")
        self._emit(f"[*] {' '.join(cmd)}")

        rc, stdout, stderr = self.run_command(cmd, timeout=duration)

        findings = self.parse_output(stdout)
        # rc stays at run_command's -1 sentinel only if the process never
        # actually completed its lifecycle (e.g. an unhandled exception in
        # run_command); a timeout-kill (the expected way to stop Responder)
        # still yields a real (usually negative/signal) returncode.
        success = rc != -1
        if not success:
            self._emit("[!] Responder did not run correctly — check interface/duration/permissions")
        return ModuleResult(
            success=success,
            findings=findings,
            raw_output=stdout,
            command=" ".join(cmd),
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        # NTLMv2 hash pattern
        for line in output.splitlines():
            if "::" in line and "NTLMv" in output:
                # Try to detect captured hashes
                parts = line.split("::")
                if len(parts) >= 2:
                    user = parts[0].strip()
                    findings.append(Finding(
                        title=f"Responder: NTLMv2 hash captured for {user}",
                        description="NTLMv2 hash captured — crack with hashcat -m 5600",
                        severity=Severity.CRITICAL,
                        evidence=line.strip(),
                        module=self.name,
                    ))
        return findings


# ── LinWinPwn ─────────────────────────────────────────────────────────────────

class LinWinPwnModule(BaseModule):
    name = "linwinpwn"
    description = "linWinPwn — automated AD enumeration and exploitation script"
    default_timeout = 1800

    def run(self, target: str, options: dict) -> ModuleResult:
        script = options.get("script_path", "/opt/linWinPwn/linWinPwn.sh")

        if not Path(script).exists():
            self._emit(f"[!] linWinPwn not found at {script}")
            self._emit("[*] Install: git clone https://github.com/lefayjey/linWinPwn /opt/linWinPwn")
            return ModuleResult(
                success=False,
                error=f"linWinPwn.sh not found at {script}",
                command=script,
            )

        domain = options.get("domain", "")
        username = options.get("username", "")
        password = options.get("password", "")

        cmd = ["bash", script, "-t", target]
        if domain:
            cmd += ["-d", domain]
        if username:
            cmd += ["-u", username]
        if password:
            cmd += ["-p", password]

        cmd_str = redact_command(cmd, password)
        self._emit(f"[*] {cmd_str}")
        rc, stdout, stderr = self.run_command(cmd)

        findings = self.parse_output(stdout + stderr)
        return ModuleResult(
            success=rc == 0,
            findings=findings,
            raw_output=stdout,
            command=cmd_str,
        )

    def parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        patterns = [
            (r"(Kerberoastable|AS-REP Roastable) user:\s*(\S+)", Severity.HIGH, "Roastable account"),
            (r"DCSync.*?(\S+@\S+)", Severity.CRITICAL, "DCSync right"),
            (r"(Pass-the-Hash|PTH).*?(\S+)", Severity.CRITICAL, "PTH opportunity"),
            (r"Unconstrained delegation.*?(\S+)", Severity.HIGH, "Unconstrained delegation"),
        ]
        for pattern, sev, tag in patterns:
            for m in re.finditer(pattern, output, re.IGNORECASE):
                findings.append(Finding(
                    title=f"linWinPwn: {tag} — {m.group(0)[:80]}",
                    description=f"Detected via linWinPwn automated scan: {tag}",
                    severity=sev,
                    evidence=m.group(0),
                    module=self.name,
                ))
        return findings
