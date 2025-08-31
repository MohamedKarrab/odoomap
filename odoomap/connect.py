import sys
import xmlrpc.client
import requests
import ssl
import urllib3
import os
from bs4 import BeautifulSoup
from odoomap.utils.colors import Colors
from urllib.parse import urljoin
from importlib.resources import files
import json
from .utils.brute_display import BruteDisplay

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Connection:
    def __init__(self, host, ssl_verify=False):
        self.host = host if host.startswith(('http://', 'https://')) else f"https://{host}"
        self.ssl_verify = ssl_verify
        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.common_endpoint = f"{self.host}/xmlrpc/2/common"
        self.object_endpoint = f"{self.host}/xmlrpc/2/object"
        self.master_password_endpoint = f"{self.host}/xmlrpc/2/db"
        
        # For authenticated operations
        self.uid = None
        self.password = None
        self.db = None
        
        # Setup XML-RPC with context for SSL verification
        if not ssl_verify:
            ssl_context = ssl._create_unverified_context()
            self.common = xmlrpc.client.ServerProxy(self.common_endpoint, context=ssl_context)
            self.master = xmlrpc.client.ServerProxy(self.master_password_endpoint, context=ssl_context)
            self.models = None  # Will be initialized after authentication
        else:
            self.common = xmlrpc.client.ServerProxy(self.common_endpoint)
            self.models = None
    
    def get_version(self):
        """Get Odoo version information"""
        try:
            version_info = self.common.version()
            return version_info
        except Exception as e:
            print(f"{Colors.e} Error getting version: {str(e)}")
            return None
    
    def get_databases(self):
        """List available databases"""
        try:
            db_endpoint = f"{self.host}/xmlrpc/2/db"
            db_service = xmlrpc.client.ServerProxy(db_endpoint, 
                                                context=ssl._create_unverified_context() if not self.ssl_verify else None)
            databases = db_service.list()
            return databases
        except Exception as e:
            print(f"{Colors.e} Error listing databases: {str(e)}")
            print(f"{Colors.i} Falling back to JSON-RPC method...")
        
        try:
            jsonrpc_endpoint = f"{self.host}/web/database/list"
            headers = {"Content-Type": "application/json"}
            payload = {
                "jsonrpc": "2.0",
                "method": "call",
                "params": {}
            }

            verify_ssl = self.ssl_verify
            response = requests.post(
                jsonrpc_endpoint,
                headers=headers,
                data=json.dumps(payload),
                verify=verify_ssl
            )

            if response.status_code == 200:
                result = response.json().get("result")
                if isinstance(result, list) and result:
                    return result
        except Exception as e:
            print(f"{Colors.e} JSON-RPC DB listing failed: {e}")
            
        return []
    
    def authenticate(self, db, username, password, verbose=True):
        """Authenticate to Odoo"""
        if verbose:
            print(f"{Colors.i} Authenticating as {username} on {db}...")
        try:
            uid = self.common.authenticate(db, username, password, {})
            if uid:
                self.uid = uid
                self.password = password
                self.db = db
                self.models = xmlrpc.client.ServerProxy(self.object_endpoint, 
                                                     context=ssl._create_unverified_context() if not self.ssl_verify else None)
                if verbose:
                    print(f"{Colors.s} Authentication successful (uid: {uid})")
                return uid
            
            else:
                if verbose:
                    print(f"{Colors.e} Authentication failed")
            return None
        
        except Exception as e:
            if "failed: FATAL:  database" in str(e) and "does not exist" in str(e):
                if verbose:
                    print(f"{Colors.e} Authentication failed: database {Colors.FAIL}{db}{Colors.ENDC} does not exist")
            else:
                if verbose:
                    print(f"{Colors.e} Authentication error: {str(e)}")
            return None
    
    def sanitize_for_xmlrpc(self, text):
        """Sanitize text to be used in XML-RPC calls."""
        if not isinstance(text, str):
            return text
        return ''.join(c for c in text if c != '\x00' and ord(c) < 128 and c.isprintable())

    def bruteforce_database_names(self, db_names_file):
        """Bruteforce database names using a wordlist file"""
        
        try:
            with open(db_names_file, 'r', encoding='utf-8', errors='ignore') as f:
                databases = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.e} Error reading database names file: {str(e)}")
            return False

        print(f"{Colors.s} Loaded {len(databases)} database names from {db_names_file}")
        print(f"{Colors.i} Starting database name bruteforce with {len(databases)} candidates")

        total = len(databases)
        display = BruteDisplay(total)
        found_databases = []

        print("")
        for db in databases:
            display.update(f"{Colors.t} {db}")
            try:
                uid = self.common.authenticate(db, "test_user", "test_pass", {})
                if uid == False:
                    display.add_success(f"{db}")
                    found_databases.append(db)
            except Exception as e:
                if "FATAL:  database" in str(e) and "does not exist" in str(e):
                    pass
                else:
                    display.add_error(f"{db} -> {str(e)}")

        display.stop()

        return found_databases

    def bruteforce_login(self, db, wordlist_file=None, usernames_file=None, passwords_file=None):
        if not db:
            print(f"{Colors.e} No database specified for bruteforce")
            return False

        usernames, passwords, user_pass_pairs = [], [], []

        try:
            usernames_text = files("odoomap.data").joinpath("default_usernames.txt").read_text(encoding='utf-8', errors='ignore')
            usernames = [line.strip() for line in usernames_text.splitlines() if line.strip()]

            passwords_text = files("odoomap.data").joinpath("default_passwords.txt").read_text(encoding='utf-8', errors='ignore')
            passwords = [line.strip() for line in passwords_text.splitlines() if line.strip()]
        except Exception as e:
            print(f"{Colors.e} Error reading default credentials files: {str(e)}")
            sys.exit(1)

        if usernames_file:
            try:
                with open(usernames_file, 'r', encoding='utf-8', errors='ignore') as f:
                    usernames = [line.strip() for line in f if line.strip()]
                #print(f"{Colors.s} Loaded {len(usernames)} usernames from {usernames_file}")
            except Exception as e:
                print(f"{Colors.e} Error reading usernames file: {str(e)}")
                sys.exit(1)

        if passwords_file:
            try:
                with open(passwords_file, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                #print(f"{Colors.s} Loaded {len(passwords)} passwords from {passwords_file}")
            except Exception as e:
                print(f"{Colors.e} Error reading passwords file: {str(e)}")
                sys.exit(1)

        if wordlist_file:
            try:
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [line.strip() for line in f if line.strip()]
                    # Check if this is in user:pass format
                    for line in lines:
                        if ':' in line:
                            user, pwd = line.split(':', 1)
                            user_pass_pairs.append((user, pwd))
            except Exception as e:
                print(f"{Colors.e} Error reading wordlist file: {str(e)}")
                sys.exit(1)

            if not user_pass_pairs:
                print(f"{Colors.e} No valid user:pass pairs found in {wordlist_file}, Exiting...")
                sys.exit(1)

        # sanitize & unique
        usernames = list(dict.fromkeys(self.sanitize_for_xmlrpc(u).strip() for u in usernames if u.strip()))
        passwords = list(dict.fromkeys(self.sanitize_for_xmlrpc(p).strip() for p in passwords if p.strip()))
        user_pass_pairs = list(dict.fromkeys(
            (self.sanitize_for_xmlrpc(u).strip(), self.sanitize_for_xmlrpc(p).strip())
            for u, p in user_pass_pairs if u.strip() and p.strip()
        ))

        # Remove any empty username/password pairs after sanitization
        usernames = [u for u in usernames if u]
        passwords = [p for p in passwords if p]
        user_pass_pairs = [(u, p) for u, p in user_pass_pairs if u and p]

        # If no user-pass pairs were provided, generate them from sanitized usernames and passwords
        if not user_pass_pairs:
            if usernames_file:
                print(f"{Colors.s} Loaded {len(usernames)} unique usernames from {usernames_file}")
            else:
                print(f"{Colors.s} Using {len(usernames)} default usernames")
            if passwords_file:
                print(f"{Colors.s} Loaded {len(passwords)} unique passwords from {passwords_file}")
            else:
                print(f"{Colors.s} Using {len(passwords)} default passwords")

            user_pass_pairs = list(dict.fromkeys(
                (self.sanitize_for_xmlrpc(u).strip(), self.sanitize_for_xmlrpc(p).strip())
                for u in usernames for p in passwords if u and p
            ))
        else:
            print(f"{Colors.s} Loaded {len(user_pass_pairs)} unique user:pass pairs from {wordlist_file}")

        print(f"{Colors.i} Starting bruteforce with {len(user_pass_pairs)} credential pairs")

        total = len(user_pass_pairs)
        display = BruteDisplay(total)

        print("")
        for username, password in user_pass_pairs:
            display.update(f"{Colors.t} {username}:{password}")
            try:
                uid = self.authenticate(db, username, password, verbose=False)
                if uid:
                    display.add_success(f"{username}:{password} (uid: {uid})\n")
                        
            except Exception as e:
                display.add_error(f"{username}:{password} -> {e}")

        display.stop()
        return len(display.successes) > 0

    def registration_check(self):
        """
        Detect whether self‑host exposes any anonymous signup page.
        Returns True at the first positive match, otherwise False.
        """
        candidate_paths = [
            "/web/signup",             # default (>= v10)
            "/auth_signup/sign_up",    # auth_signup controller
            "/web/portal/register",    # older portal module
            "/web/register",           # some community themes
            "/website/signup",         # website module alias
            "/portal/signup",          # portal frontend alias
            "/signup",                 # catch‑all shortcut
            "/web/login/signup"        # Sometimes a redirect from /web/login
        ]

        portal_found = False
        base = self.host.rstrip("/") + "/"        # ensure base ends with exactly one /
        for p in candidate_paths:
            url = urljoin(base, p.lstrip("/"))
            try:
                response = self.session.get(url, verify=self.ssl_verify, timeout=10)
            except Exception as exc:
                print(f"{Colors.e} error requesting {url}: {exc}")
                continue

            if response.status_code == 200 and "name=\"login\"" in response.text:
                print(f"{Colors.s} Portal registration is enabled: {Colors.FAIL}{url}{Colors.ENDC}")
                portal_found = True
                
            
            elif response.status_code == 200:
                print(f"{Colors.s} Public signup found at {Colors.FAIL}{url}{Colors.ENDC}")
                portal_found = True
                continue
            
        if portal_found:
            return True
        else:
            print(f"{Colors.w} Portal registration is disabled / not detected")
            return portal_found

    
    def default_apps_check(self):
        """Get information about default apps"""
        try:
            login_url = urljoin(self.host, '/web/login')
            response = self.session.get(login_url, verify=self.ssl_verify)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                app_info = {}

                if soup.title:
                    app_info["title"] = soup.title.string

                paths = [
                    "/web", "/shop", "/forum", "/contactus",
                    "/website/info", "/blog", "/events",
                    "/jobs", "/slides"
                ]
                for path in paths:
                    try:
                        full_url = urljoin(self.host, path)
                        path_response = self.session.get(full_url, verify=self.ssl_verify)
                        if path_response.status_code == 200:
                            print(f"    - {path}: Available ({full_url})")
                        app_info[path] = path_response.status_code
                    except:
                        app_info[path] = None

                return app_info
            return None
        except Exception as e:
            print(f"{Colors.e} Error getting apps info: {str(e)}")
            return None