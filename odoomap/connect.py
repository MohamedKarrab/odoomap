import sys
import xmlrpc.client
import requests
import ssl
import urllib3
import json
import time
import random
from bs4 import BeautifulSoup
from odoomap.utils.colors import Colors
from urllib.parse import urljoin
from importlib.resources import files
from .utils.brute_display import BruteDisplay, console



# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ThrottledServerProxy:
    def __init__(self, uri, context, throttle_func):
        self._proxy = xmlrpc.client.ServerProxy(uri, context=context)
        self._throttle = throttle_func
    
    def __getattr__(self, name):
        attr = getattr(self._proxy, name)
        if callable(attr):
            def wrapped(*args, **kwargs):
                self._throttle()
                return attr(*args, **kwargs)
            return wrapped
        return attr

class ThrottledSession(requests.Session):
    def __init__(self, throttle_func):
        super().__init__()
        self._throttle = throttle_func
    
    def request(self, method, url, **kwargs):
        self._throttle()
        return super().request(method, url, **kwargs)

class Connection:
    def __init__(self, host, ssl_verify=False, rate_limit=None, jitter=None):
        self.host = host if host.startswith(('http://', 'https://')) else f"https://{host}"
        self.ssl_verify = ssl_verify
        
        self.rate_limit = rate_limit
        self.jitter = jitter
        self.last_request_time = 0

        self.session = ThrottledSession(self._throttle)
        self.session.verify = ssl_verify
        
        self.common_endpoint = f"{self.host}/xmlrpc/2/common"
        self.object_endpoint = f"{self.host}/xmlrpc/2/object"
        self.master_password_endpoint = f"{self.host}/xmlrpc/2/db"
        
        # For authenticated operations
        self.uid = None
        self.login = None
        self.password = None
        self.db = None
        
        # Setup XML-RPC with throttled wrappers
        ssl_context = ssl._create_unverified_context() if not ssl_verify else None
        self.common = ThrottledServerProxy(self.common_endpoint, ssl_context, self._throttle)
        self.master = ThrottledServerProxy(self.master_password_endpoint, ssl_context, self._throttle)
        self.models = None  # Will be initialized after authentication
    
    def _throttle(self):
        """Apply rate limiting before making requests"""
        if self.rate_limit and self.rate_limit > 0:
            current_time = time.time()
            
            # Skip throttling on first request
            if self.last_request_time == 0:
                self.last_request_time = current_time
                return
            
            time_since_last = current_time - self.last_request_time
            min_interval = 1.0 / self.rate_limit
            
            # Add jitter to avoid pattern detection
            if self.jitter and self.jitter > 0:
                jitter_factor = 1.0 + (random.uniform(-self.jitter, self.jitter) / 100.0)
                min_interval *= jitter_factor
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()
    
    def jsonrpc(self, endpoint, params=None):
        url = f"{self.host}{endpoint}"
        payload = {
            "jsonrpc": "2.0",
            "method": "call",
            "id": random.randint(1, 1_000_000),
            "params": params or {},
        }
        resp = self.session.post(url, json=payload, timeout=15)
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            err = body["error"]
            msg = err.get("data", {}).get("message") or err.get("message", str(err))
            raise Exception(f"JSON-RPC error: {msg}")
        return body.get("result")

    def json_authenticate(self, db, login, password):
        try:
            result = self.jsonrpc("/web/session/authenticate", {
                "db": db,
                "login": login,
                "password": password,
            })
            if result and result.get("uid"):
                return result
            return None
        except Exception:
            return None

    def json_call_kw(self, model, method, args=None, kwargs=None):
        return self.jsonrpc("/web/dataset/call_kw", {
            "model": model,
            "method": method,
            "args": args or [],
            "kwargs": kwargs or {},
        })

    def json_search_count(self, model, domain=None):
        return self.json_call_kw(model, "search_count", [domain or []])

    def json_search_read(self, model, domain=None, fields=None, limit=0):
        return self.json_call_kw(model, "search_read", [domain or []], {
            "fields": fields or [],
            "limit": limit,
        })

    def enumerate_users_via_timing_attack(self, db, usernames, samples=3):
        def measure(login):
            times = []
            for _ in range(samples):
                start = time.time()
                try:
                    self.jsonrpc("/web/session/authenticate", {
                        "db": db, "login": login,
                        "password": "odoomap_timing_probe_" + str(random.randint(0, 99999)),
                    })
                except Exception:
                    pass
                times.append(time.time() - start)
            return sorted(times)[len(times) // 2]

        print(f"{Colors.i} Calibrating with known-invalid username...")
        baseline = measure(f"definitely_nonexistent_{random.randint(100000,999999)}@invalid.test")
        threshold_multiplier = 2
        threshold = baseline * threshold_multiplier
        print(f"{Colors.i} Baseline: {baseline*1000:.0f}ms, threshold: {threshold*1000:.0f}ms ({threshold_multiplier}x)")

        found = []
        total = len(usernames)
        display = BruteDisplay(total)
        console.print("")
        for username in usernames:
            display.update(f"{Colors.t} {username}")
            median_time = measure(username)
            if median_time >= threshold:
                display.add_success(f"{username} ({median_time*1000:.0f}ms vs {baseline*1000:.0f}ms baseline)\n")
                found.append(username)

        display.stop()
        if found:
            print(f"{Colors.s} {len(found)} likely valid account(s) found")
        else:
            print(f"{Colors.w} No valid accounts detected via timing")
        return found

    def get_version(self):
        """Get Odoo version information. Tries XML-RPC first, falls back to JSON-RPC."""
        try:
            version_info = self.common.version()
            return version_info
        except Exception:
            pass

        try:
            result = self.jsonrpc("/web/webclient/version_info")
            if result:
                return result
        except Exception:
            pass

        print(f"{Colors.e} Error getting version via XML-RPC and JSON-RPC")
        return None

    def get_major_version(self):
        """Get the major Odoo version as an integer (e.g. 18).

        Uses server_version_info array when available for accuracy,
        falls back to regex on the version string.
        """
        version_info = self.get_version()
        if not version_info:
            return None

        # Prefer the array form
        info_arr = version_info.get("server_version_info")
        if info_arr and isinstance(info_arr, (list, tuple)) and len(info_arr) > 0:
            try:
                return int(info_arr[0])
            except (ValueError, TypeError):
                pass

        # Fallback to regex
        import re
        raw = version_info.get("server_version", "")
        match = re.search(r'(\d+)', str(raw))
        return int(match.group(1)) if match else None

    def get_session_info(self):
        """Fetch pre-auth session info via /web/session/get_session_info.

        Returns dict with database name, server version, and session metadata
        even without authentication. Returns None on failure.
        """
        try:
            result = self.jsonrpc("/web/session/get_session_info")
            return result
        except Exception:
            return None
    
    def get_databases(self):
        """List available databases"""
        try:
            db_endpoint = f"{self.host}/xmlrpc/2/db"
            ssl_context = ssl._create_unverified_context() if not self.ssl_verify else None
            db_service = ThrottledServerProxy(db_endpoint, ssl_context, self._throttle)
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
        """Authenticate to Odoo. Tries XML-RPC first, falls back to JSON-RPC."""
        if verbose:
            print(f"{Colors.i} Authenticating as {username} on {db}...")

        # Try XML-RPC first
        try:
            uid = self.common.authenticate(db, username, password, {})
            if uid:
                self._set_auth(db, username, password, uid)
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
                return None
            # XML-RPC failed for other reason — try JSON-RPC
            if verbose:
                print(f"{Colors.i} XML-RPC auth failed, trying JSON-RPC...")

        # Fallback to JSON-RPC
        result = self.json_authenticate(db, username, password)
        if result and result.get("uid"):
            uid = result["uid"]
            self._set_auth(db, username, password, uid)
            if verbose:
                print(f"{Colors.s} Authentication successful via JSON-RPC (uid: {uid})")
            return uid

        if verbose:
            print(f"{Colors.e} Authentication failed")
        return None

    def _set_auth(self, db, username, password, uid):
        """Store auth state and initialize model proxy."""
        self.uid = uid
        self.login = username
        self.password = password
        self.db = db
        ssl_context = ssl._create_unverified_context() if not self.ssl_verify else None
        self.models = ThrottledServerProxy(self.object_endpoint, ssl_context, self._throttle)

    def execute_kw(self, model, method, args=None, kwargs=None):
        """Execute an ORM method with XML-RPC, falling back to JSON-RPC.

        Requires prior authentication (self.uid must be set).
        """
        if not self.uid:
            raise Exception("Not authenticated")

        # Try XML-RPC first
        if self.models:
            try:
                return self.models.execute_kw(
                    self.db, self.uid, self.password,
                    model, method, args or [], kwargs or {}
                )
            except Exception:
                pass

        # Fallback to JSON-RPC (establish session if needed)
        try:
            return self.json_call_kw(model, method, args, kwargs)
        except Exception as e:
            if "Session expired" in str(e) or "session" in str(e).lower():
                # No JSON-RPC session — create one and retry
                self.json_authenticate(self.db, self.login, self.password)
                return self.json_call_kw(model, method, args, kwargs)
            raise
    
    def sanitize_for_xmlrpc(self, text):
        """Sanitize text to be used in XML-RPC calls."""
        if not isinstance(text, str):
            return text
        return ''.join(c for c in text if c != '\x00' and ord(c) < 128 and c.isprintable())

    def bruteforce_database_names(self, databases):
        """Bruteforce database names using a list of candidates"""

        print(f"{Colors.i} Starting database name bruteforce with {len(databases)} candidates")

        total = len(databases)
        display = BruteDisplay(total)
        found_databases = []

        console.print("")
        for db in databases:
            display.update(f"{Colors.t} {db}")
            try:
                uid = self.common.authenticate(db, "test_user", "test_pass", {})
                if uid == False:
                    display.add_success(f"{db}\n")
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

        console.print()
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
                    "/web/database/manager", "/web/database/selector", "/web", "/shop", "/forum", "/contactus",
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