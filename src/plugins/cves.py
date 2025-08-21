#!/usr/bin/env python3
import requests
from colorama import Fore, Style, init

# Init colorama (Windows/Linux)
init(autoreset=True)

def search_nvd(version):
    """Query NVD for Odoo CVEs for a given version"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": f"odoo {version}"}
    resp = requests.get(url, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()

def format_score(cve):
    """Extract CVSS score if available"""
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    if "cvssMetricV30" in metrics:
        return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    if "cvssMetricV2" in metrics:
        return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    return "N/A"

def format_references(cve):
    """Extract first 2 references"""
    refs = [r["url"] for r in cve.get("references", [])]
    return refs[:2] if refs else ["No references"]

class Plugin:
    """Plugin to search for Odoo CVEs using detected version"""
    
    def run(self, target_url, database=None, username=None, password=None, connection=None):
        # Use connection to get version
        if connection:
            version_info = connection.get_version()
            if not version_info:
                print(Fore.YELLOW + "[-] Could not detect Odoo version, defaulting to 15")
                version = "15"
            else:
                version = version_info.get("server_version", "15")
                print(Fore.GREEN + f"[+] Detected Odoo version: {version}")
        else:
            version = "15"
            print(Fore.YELLOW + "[!] No connection provided, defaulting to Odoo 15")

        # Query NVD
        try:
            data = search_nvd(version)
        except Exception as e:
            print(Fore.RED + f"[-] Error querying NVD: {e}")
            return

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(Fore.YELLOW + f"[-] No CVEs found for Odoo {version}")
            return

        print(Fore.GREEN + f"[+] Found {len(vulns)} CVEs for Odoo {version}:\n")

        for vuln in vulns:
            cve = vuln["cve"]
            cve_id = cve["id"]
            desc = cve["descriptions"][0]["value"]
            score = format_score(cve)
            refs = format_references(cve)

            # Color severity
            if score == "N/A":
                sev_color = Fore.WHITE
            elif float(score) >= 9:
                sev_color = Fore.RED + Style.BRIGHT
            elif float(score) >= 7:
                sev_color = Fore.MAGENTA
            elif float(score) >= 4:
                sev_color = Fore.YELLOW
            else:
                sev_color = Fore.GREEN

            print(sev_color + f"[{cve_id}] CVSS: {score}")
            print(Fore.CYAN + f"  Description: {desc}")
            print(Fore.BLUE + "  References:")
            for r in refs:
                print(Fore.WHITE + f"    - {r}")
            print("-" * 80)

        return "Plugin completed"
