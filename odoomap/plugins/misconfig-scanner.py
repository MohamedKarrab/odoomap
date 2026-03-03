import re
import time
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import MINIMAL, ROUNDED, HEAVY
from rich.columns import Columns
from .plugin_base import BasePlugin, PluginMetadata, PluginCategory

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold magenta",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
}


class Finding:
    def __init__(self, name, severity, status, detail, reference="", sub_findings=None):
        self.name = name
        self.severity = severity
        self.status = status
        self.detail = detail
        self.reference = reference
        self.sub_findings = sub_findings or []


class Plugin(BasePlugin):
    """Checks for known Odoo misconfigurations documented in public security resources"""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Misconfiguration Scanner",
            description="Checks for known Odoo misconfigurations based on public documentation",
            author="unclej4ck",
            version="1.2.0",
            category=PluginCategory.SECURITY,
            requires_auth=False,
            requires_connection=True,
            external_dependencies=["requests", "rich"]
        )

    def run(self, target_url, database=None, username=None, password=None, connection=None):
        if not connection:
            console.print("[red][-] Connection required")
            return "Error: Connection required"

        host = connection.host
        console.print()
        console.print(Panel(
            f"[bold]Target:[/bold] {host}\n"
            f"[bold]Database:[/bold] {database or 'not specified'}\n"
            f"[bold]Auth:[/bold] {'provided' if username else 'none'}",
            title="[bold blue]Misconfiguration Scanner[/bold blue]",
            border_style="blue"
        ))

        findings = []

        findings.append(self._check_version_leak(connection))
        findings.append(self._check_db_listing(connection))
        findings.append(self._check_db_manager(connection))
        findings.append(self._check_default_master_password(connection))
        findings.append(self._check_registration(connection))
        findings.append(self._check_xmlrpc_exposed(connection))
        findings.append(self._check_default_creds(connection, database))
        findings.append(self._check_demo_user(connection, database))

        if database and username and password:
            uid = connection.authenticate(database, username, password, verbose=False)
            if uid:
                findings.append(self._check_mail_template_access(connection))

        findings = [f for f in findings if f is not None]
        self._display_findings(findings)

        vuln_count = sum(1 for f in findings if f.status == "FINDING")
        info_count = sum(1 for f in findings if f.status == "INFO")
        return f"Scan complete. {vuln_count} finding(s), {info_count} info item(s)"

    def _check_version_leak(self, connection):
        try:
            result = connection.jsonrpc("/web/webclient/version_info")
            if result:
                ver = result.get("server_version", "unknown")
                serie = result.get("server_serie", "")
                return Finding(
                    "Version Information Disclosure",
                    "LOW",
                    "FINDING",
                    f"Server version: {ver} (serie: {serie}) exposed via /web/webclient/version_info",
                    "https://www.odoo.com/documentation/19.0/developer/reference/backend/security.html"
                )
        except Exception:
            pass
        return Finding("Version Information Disclosure", "LOW", "OK", "Version endpoint not accessible")

    def _check_db_listing(self, connection):
        try:
            dbs = connection.get_databases()
            if dbs:
                db_str = ", ".join(dbs[:5])
                extra = f" (+{len(dbs)-5} more)" if len(dbs) > 5 else ""
                return Finding(
                    "Database Listing Enabled",
                    "MEDIUM",
                    "FINDING",
                    f"Databases exposed: {db_str}{extra}",
                    "Odoo docs: set list_db=False in odoo.conf"
                )
        except Exception:
            pass
        return Finding("Database Listing Enabled", "MEDIUM", "OK", "Database listing is disabled or blocked")

    def _check_db_manager(self, connection):
        try:
            url = f"{connection.host}/web/database/manager"
            resp = connection.session.get(url, timeout=10)
            if resp.status_code == 200 and ("database" in resp.text.lower() and "manager" in resp.text.lower()):
                return Finding(
                    "Database Manager Exposed",
                    "HIGH",
                    "FINDING",
                    f"Database manager accessible — allows backup/restore/delete operations",
                    "CVE-2018-14885, Odoo docs: disable with list_db=False or block at reverse proxy"
                )
        except Exception:
            pass
        return Finding("Database Manager Exposed", "HIGH", "OK", "Database manager not accessible")

    def _check_default_master_password(self, connection):
        """Test common master passwords using the dump() RPC method.

        Calls dump(password, "fake_db_name") on /xmlrpc/2/db.
        - Wrong password → "Access Denied" / "Wrong master password" error
        - Correct password → different error (e.g. database doesn't exist)
        This is the same technique used by bruteforce_master_password in actions.py.
        """
        candidates = ["admin", "odoo", "master", ""]
        for pwd in candidates:
            try:
                connection.master.dump(pwd, "odoomap_fake_db_test_83712")
                # No exception = password valid
                pwd_display = f"'{pwd}'" if pwd else "(empty)"
                return Finding(
                    "Default/Weak Master Password",
                    "CRITICAL",
                    "FINDING",
                    f"Master password accepted: {pwd_display}",
                    "Odoo docs: set strong admin_passwd in odoo.conf"
                )
            except (ConnectionRefusedError, TimeoutError, OSError):
                # Network error — can't test, move on
                break
            except Exception as e:
                err = str(e)
                if "Fault 3:" in err or "Access Denied" in err or "Wrong master password" in err:
                    continue  # Wrong password, try next
                else:
                    # Different error = password was accepted (e.g. DB doesn't exist)
                    pwd_display = f"'{pwd}'" if pwd else "(empty)"
                    return Finding(
                        "Default/Weak Master Password",
                        "CRITICAL",
                        "FINDING",
                        f"Master password accepted: {pwd_display}",
                        "Odoo docs: set strong admin_passwd in odoo.conf"
                    )

        return Finding("Default/Weak Master Password", "CRITICAL", "OK",
                       "Default master passwords rejected or DB manager not accessible")

    def _check_registration(self, connection):
        try:
            url = f"{connection.host}/web/signup"
            resp = connection.session.get(url, timeout=10)
            if resp.status_code == 200 and "name=\"login\"" in resp.text:
                return Finding(
                    "Open User Registration",
                    "MEDIUM",
                    "FINDING",
                    "Self-registration enabled — anyone can create portal accounts",
                    "auth_signup module: restrict or disable if not needed"
                )
        except Exception:
            pass
        return Finding("Open User Registration", "MEDIUM", "OK", "Self-registration not detected")

    def _check_xmlrpc_exposed(self, connection):
        try:
            version = connection.common.version()
            if version:
                return Finding(
                    "XML-RPC Externally Accessible",
                    "LOW",
                    "INFO",
                    "XML-RPC /xmlrpc/2/common responds — consider blocking at reverse proxy",
                    "Odoo deployment docs: restrict RPC access via reverse proxy"
                )
        except Exception:
            pass
        return Finding("XML-RPC Externally Accessible", "LOW", "OK", "XML-RPC not accessible")

    def _check_default_creds(self, connection, database):
        if not database:
            return Finding("Default Credentials", "HIGH", "OK", "No database specified, skipping")

        default_pairs = [
            ("admin", "admin"),
            ("admin", "odoo"),
            ("demo", "demo"),
            ("admin", "1234"),
        ]
        found = []
        for user, pwd in default_pairs:
            try:
                uid = connection.common.authenticate(database, user, pwd, {})
                if uid:
                    found.append(f"{user}:{pwd} (uid:{uid})")
            except Exception:
                continue

        if found:
            return Finding(
                "Default Credentials Found",
                "CRITICAL",
                "FINDING",
                f"Valid default credentials: {', '.join(found)}",
                "Odoo security: change default passwords after installation"
            )
        return Finding("Default Credentials Found", "CRITICAL", "OK",
                       "No default credentials accepted")

    def _check_demo_user(self, connection, database):
        if not database:
            return None
        try:
            uid = connection.common.authenticate(database, "demo", "demo", {})
            if uid:
                return Finding(
                    "Demo Data Loaded",
                    "MEDIUM",
                    "FINDING",
                    f"demo:demo account exists (uid:{uid}) — demo data loaded in production",
                    "CVE-2021-45111: demo data can be triggered by any authenticated user on Odoo <=15"
                )
        except Exception:
            pass
        return None

    def _check_mail_template_access(self, connection):
        try:
            result = connection.models.execute_kw(
                connection.db, connection.uid, connection.password,
                'mail.template', 'check_access_rights', ['write'], {'raise_exception': False}
            )
            if result:
                tpl_count = 0
                try:
                    tpl_count = connection.models.execute_kw(
                        connection.db, connection.uid, connection.password,
                        'mail.template', 'search_count', [[]]
                    )
                except Exception:
                    pass
                detail = "Current user can write to mail.template"
                if tpl_count:
                    detail += f" ({tpl_count} templates available)"
                detail += " — relevant to SSTI on Odoo <=14 and Odoo 18"
                return Finding(
                    "mail.template Write Access",
                    "LOW",
                    "INFO",
                    detail,
                    "Orange Cyberdefense / vycioha SSTI research"
                )
        except Exception:
            pass
        return None

    def _display_findings(self, findings):
        console.print()

        vuln_findings = [f for f in findings if f.status == "FINDING"]
        info_findings = [f for f in findings if f.status == "INFO"]
        ok_findings = [f for f in findings if f.status == "OK"]

        if vuln_findings:
            console.print("[bold red]FINDINGS[/bold red]")
            console.print()
            for f in vuln_findings:
                sev_style = SEVERITY_STYLES.get(f.severity, "white")
                content = Text()
                content.append("Severity: ", style="bold")
                content.append(f.severity, style=sev_style)
                content.append("\n")
                content.append(f.detail)
                if f.reference:
                    content.append(f"\nRef: {f.reference}", style="dim")
                if f.sub_findings:
                    content.append("\n")
                    for sf in f.sub_findings:
                        content.append(f"\n{sf}", style="cyan")

                console.print(Panel(
                    content,
                    title=f"[bold red]!! {f.name}[/bold red]",
                    border_style="red",
                ))

        if info_findings:
            console.print("[bold cyan]INFORMATIONAL[/bold cyan]")
            console.print()
            for f in info_findings:
                sev_style = SEVERITY_STYLES.get(f.severity, "white")
                content = Text()
                content.append("Severity: ", style="bold")
                content.append(f.severity, style=sev_style)
                content.append(f"\n{f.detail}")
                if f.reference:
                    content.append(f"\nRef: {f.reference}", style="dim")

                console.print(Panel(
                    content,
                    title=f"[cyan]{f.name}[/cyan]",
                    border_style="cyan",
                ))

        if ok_findings:
            console.print("[bold green]PASSED[/bold green]")
            ok_table = Table(box=MINIMAL, show_header=False, padding=(0, 1))
            ok_table.add_column("Check", style="green", width=40)
            ok_table.add_column("Detail", style="dim")
            for f in ok_findings:
                ok_table.add_row(f.name, f.detail)
            console.print(ok_table)

        console.print()
        summary = Table(title="Summary", box=ROUNDED, show_lines=False, title_style="bold")
        summary.add_column("", width=3, justify="center")
        summary.add_column("Category", style="bold")
        summary.add_column("Count", justify="right", width=5)
        summary.add_row(Text("!!", style="bold red"), Text("FINDINGS", style="bold red"), str(len(vuln_findings)))
        summary.add_row(Text("i", style="cyan"), Text("INFO", style="cyan"), str(len(info_findings)))
        summary.add_row(Text("ok", style="green"), Text("PASSED", style="green"), str(len(ok_findings)))
        console.print(summary)
        console.print()
