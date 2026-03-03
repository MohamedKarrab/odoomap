import os
import sys
from importlib.resources import files
from odoomap.utils.colors import Colors
from .utils.brute_display import BruteDisplay, console

directory = os.getcwd()      

def get_models(connection, limit=100, with_permissions=False, bruteforce=False, model_file=None):
    """Get list of accessible models with optional limit, 
    falls back to bruteforcing if listing fails"""
    print(f"{Colors.i} Enumerating models...")
    if not connection.uid:
        print(f"{Colors.e} Not authenticated. Please authenticate first.")
        return []
    
    try:
        if not bruteforce:
            # Try standard model listing first
            batch_size = 100  # Increased batch size for efficiency
            offset = 0
            total_models = []
            model_count = 0
            
            if batch_size > limit:
                batch_size = limit

            # First, get the total count for progress reporting
            try:
                count = connection.models.execute_kw(
                    connection.db, connection.uid, connection.password,
                    'ir.model', 'search_count', [[]])
                
                print(f"{Colors.i} Found {count} models total, retrieving in batches...")
                
                # Retrieve models in batches with offset
                while True:
                    # Fetch a batch of models directly with search_read
                    batch_models = connection.models.execute_kw(
                        connection.db, connection.uid, connection.password,
                        'ir.model', 'search_read',
                        [[]], {'fields': ['model', 'name'], 'limit': batch_size, 'offset': offset})
                    
                    if not batch_models:
                        break  # No more models to retrieve
                    
                    # Display models as they're retrieved
                    for j, model in enumerate(batch_models):
                        model_num = offset + j + 1
                        print(f"{Colors.s} [{model_num}/{count}] {model['model']} - {model['name']}")
                    
                    total_models.extend(batch_models)
                    offset += batch_size
                    
                    # Break if we've reached the limit
                    if limit and offset >= limit:
                        break
                
                models = total_models
            except Exception as e:
                print(f"{Colors.e} Error listing models: {str(e)}")
                response = input(f"{Colors.i} Fall back to bruteforce method? [y/N]: ").strip().lower()
                if response == 'y' or response == 'yes':
                    print(f"{Colors.i} Falling back to bruteforce method...")
                    bruteforce = True
                else:
                    print(f"{Colors.e} Aborting model enumeration.")
                    sys.exit(1)
        
        # If bruteforce is enabled or standard listing failed
        if bruteforce:
            return bruteforce_models(connection, model_file, limit, with_permissions)
        
        if not with_permissions:
            print(f"\n{Colors.i} Retrieved {len(models)} models total (limit: {limit if limit else 'none'}, -l to change limit)")
        else:
            print(f"\n{Colors.i} Permissions: r=read, w=write, c=create, d=delete")
            
        # Process models and check permissions
        result = []
        for i, model in enumerate(models):
            model_info = model['model']
            
            # Print progress regardless of permission checking
            if with_permissions:
                try:
                    print(f"{Colors.i} Checking permissions for {model_info}...", end="\r")
                    
                    # Check each permission type individually
                    read_access = connection.models.execute_kw(
                        connection.db, connection.uid, connection.password,
                        model['model'], 'check_access_rights', 
                        ['read'], {'raise_exception': False})
                    
                    write_access = connection.models.execute_kw(
                        connection.db, connection.uid, connection.password,
                        model['model'], 'check_access_rights', 
                        ['write'], {'raise_exception': False})
                    
                    create_access = connection.models.execute_kw(
                        connection.db, connection.uid, connection.password,
                        model['model'], 'check_access_rights', 
                        ['create'], {'raise_exception': False})
                    
                    unlink_access = connection.models.execute_kw(
                        connection.db, connection.uid, connection.password,
                        model['model'], 'check_access_rights', 
                        ['unlink'], {'raise_exception': False})
                    
                    perms = []
                    if read_access: perms.append('r')
                    if write_access: perms.append('w')
                    if create_access: perms.append('c')
                    if unlink_access: perms.append('d')
                    
                    perm_str = ','.join(perms) if perms else 'none'
                    model_info_with_perms = f"{model_info} [{perm_str}]"
                    
                    print(f"{Colors.s} {model_info_with_perms}".ljust(80))
                    
                    model_info = model_info_with_perms
                except Exception as e:
                    model_info += " [ERROR]"
                    print(f"{Colors.e} Error checking permissions for {model['model']}: {str(e)}")
            
            result.append(model_info)

        return result
    except Exception as e:
        print(f"{Colors.e} Error in model discovery: {str(e)}")
        return []


def bruteforce_models(connection, model_file, limit=100, with_permissions=False):
    """Bruteforce models from a list and check permissions"""
    print(f"{Colors.i} Using bruteforce method to discover models")
    # Use provided model file, or select default based on version
    if model_file and os.path.exists(model_file):
        print(f"{Colors.i} Loading models from file: {model_file}")
        with open(model_file, 'r') as f:
            model_list = [line.strip() for line in f if line.strip()]
    else:
        print(f"{Colors.i} Using default model list for bruteforce")
        try:
            models_text = files("odoomap.data").joinpath("default_models.txt").read_text(encoding="utf-8")
            model_list = [line.strip() for line in models_text.splitlines() if line.strip()]
        except Exception as e:
            print(f"{Colors.e} Error reading default models file: {str(e)}")
            sys.exit(1)
    
    print(f"{Colors.i} Bruteforcing {len(model_list)} potential models...")
    
    if not connection.uid:
        print(f"{Colors.e} Not authenticated. Please authenticate first.")
        return []
    
    discovered_models = []
    count = 0
    
    # Limit the model list if needed
    if limit and limit < len(model_list):
        model_list = model_list[:limit]
    
    total = len(model_list)
    print(f"\n{Colors.i} Testing access to {total} models... (change limit with -l limit)")
    if with_permissions:
        print(f"{Colors.i} Permissions: r=read, w=write, c=create, d=delete")
    
    for i, model_name in enumerate(model_list):                
        try:
            print(f"\r{Colors.i} Testing model {i+1}/{total}: {model_name}".ljust(80), end="\r")
            
            model_exists = False
            try:
                connection.models.execute_kw(
                    connection.db, connection.uid, connection.password,
                    model_name, 'search', [[]], {'limit': 1})
                model_exists = True
            except Exception:
                pass
            
            if model_exists:
                count += 1
                model_info = model_name
                
                if with_permissions:
                    try:
                        read_access = connection.models.execute_kw(
                            connection.db, connection.uid, connection.password,
                            model_name, 'check_access_rights', 
                            ['read'], {'raise_exception': False})
                        
                        write_access = connection.models.execute_kw(
                            connection.db, connection.uid, connection.password,
                            model_name, 'check_access_rights', 
                            ['write'], {'raise_exception': False})
                        
                        create_access = connection.models.execute_kw(
                            connection.db, connection.uid, connection.password,
                            model_name, 'check_access_rights', 
                            ['create'], {'raise_exception': False})
                        
                        unlink_access = connection.models.execute_kw(
                            connection.db, connection.uid, connection.password,
                            model_name, 'check_access_rights', 
                            ['unlink'], {'raise_exception': False})
                        
                        perms = []
                        if read_access: perms.append('r')
                        if write_access: perms.append('w')
                        if create_access: perms.append('c')
                        if unlink_access: perms.append('d')
                        
                        perm_str = ','.join(perms) if perms else 'none'
                        model_info = f"{model_name} [{perm_str}]"
                    except Exception:
                        model_info = f"{model_name} [ERROR]"
                
                print(f"{Colors.s} Found accessible model: {model_info}".ljust(80))
                discovered_models.append(model_info)
        except Exception as e:
            print(f"{Colors.e} Error testing model {model_name}: {str(e)}".ljust(80))
    
    print(f"\n{Colors.s} Found {count} accessible models out of {total} tested")
    return discovered_models
    
    
def dump_model(connection, model_name, limit=100, output_file=None):
    """Dump data from a model"""
    if not connection.uid:
        print(f"{Colors.e} Not authenticated. Please authenticate first.")
        return None
    
    try:
        count = connection.models.execute_kw(
            connection.db, connection.uid, connection.password,
            model_name, 'search_count', [[]])
        
        print(f"{Colors.i} Total records in {model_name}: {count}")
        
        record_ids = connection.models.execute_kw(
            connection.db, connection.uid, connection.password,
            model_name, 'search', [[]], {'limit': limit})
        
        if not record_ids:
            print(f"{Colors.w} No records found in {model_name}")
            return None
        
        fields_info = connection.models.execute_kw(
            connection.db, connection.uid, connection.password,
            model_name, 'fields_get', [], {'attributes': ['string', 'type']})
        
        field_names = list(fields_info.keys())
        
        records = connection.models.execute_kw(
            connection.db, connection.uid, connection.password,
            model_name, 'read', [record_ids], {'fields': field_names})
        
        print(f"{Colors.s} Retrieved {len(records)} records from {model_name} (Change limit with -l limit)")
        
        if output_file:
            import json
            with open(output_file, 'w') as f:
                json.dump(records, f, indent=4)
            print(f"{Colors.s} Data saved to {output_file}\n")
        
        return records
    except Exception as e:
        print(f"{Colors.e} Error dumping data from {model_name}: {str(e)}")
        return None

def bruteforce_master_password(connection, wordlist_file=None):
    """
    Attempt to bruteforce the Odoo database master password.
    This works by trying to dump an unexisting database with each password.
    Even if the password is correct, it will raise an exception about unspecified
    format, so we check for specific error messages to confirm success.
    """

    passwords = []

    if wordlist_file:
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"{Colors.s} Loaded {len(passwords)} passwords from {wordlist_file}")
        except Exception as e:
            print(f"{Colors.e} Error reading wordlist file: {e}")
            return None

    if not passwords:
        print(f"{Colors.e} Please provide a passwords file with -p <file>.")
        return None

    display = BruteDisplay(total=len(passwords))

    console.print()
    for pwd in passwords:
        display.update(f"{Colors.t} {pwd}")
        try:
            proxy = connection.master
            proxy.dump(pwd, "fake_db_73189")

            # If no exception: password is valid
            display.add_success(f"{pwd}\n")
            return pwd

        except (ConnectionRefusedError, TimeoutError, OSError) as net_err:
            display.add_error(f"{net_err}")

        except Exception as e:
            if "Fault 3:" in str(e) or "Access Denied" in str(e) or "Wrong master password" in str(e):
                pass
            else:
                # If it's a different exception: password is valid
                display.add_success(f"{pwd}\n")
                display.stop()
                return pwd

    display.stop()
    return None


def enumerate_modules(connection):
    print(f"{Colors.i} Enumerating installed modules...")

    module_paths_text = files("odoomap.data").joinpath("module_paths.txt").read_text(encoding="utf-8")
    path_map = {}
    for line in module_paths_text.splitlines():
        line = line.strip()
        if "=" in line:
            path, module = line.split("=", 1)
            path_map[path.strip()] = module.strip()

    detected = []
    print(f"{Colors.i} Pre-auth path probing ({len(path_map)} paths)...")
    from urllib.parse import urljoin
    for path, module in path_map.items():
        try:
            url = urljoin(connection.host.rstrip("/") + "/", path.lstrip("/"))
            resp = connection.session.get(url, timeout=10, allow_redirects=False)
            if resp.status_code in range(200, 300) or resp.status_code in (301, 302, 303, 307, 308, 400, 401, 403, 405, 415, 500):
                print(f"{Colors.s} {path} -> {module} (HTTP {resp.status_code})")
                detected.append(module)
            else:
                pass
        except Exception:
            pass

    if not connection.uid:
        print(f"{Colors.w} Not authenticated, provide -D, -U, -P to enable post-auth module enumeration")

    if connection.uid:
        print(f"{Colors.i} Querying ir.module.module (authenticated)...")
        try:
            modules = connection.models.execute_kw(
                connection.db, connection.uid, connection.password,
                'ir.module.module', 'search_read',
                [[['state', '=', 'installed']]],
                {'fields': ['name', 'shortdesc', 'state'], 'limit': 0})
            for mod in modules:
                name = mod['name']
                if name not in detected:
                    detected.append(name)
                print(f"{Colors.s} {name} - {mod.get('shortdesc', '')}")
            print(f"{Colors.i} {len(modules)} installed modules found via ORM")
        except Exception as e:
            print(f"{Colors.e} ir.module.module query failed: {e}")

    if not detected:
        print(f"{Colors.w} No modules detected")
    else:
        print(f"{Colors.s} {len(detected)} unique module(s) detected total")
    return detected


def check_backup_endpoint(connection):
    """Check if /web/database/backup is accessible (more dangerous than manager page)."""
    try:
        url = f"{connection.host}/web/database/backup"
        resp = connection.session.get(url, timeout=10)
        if resp.status_code == 200 and "backup" in resp.text.lower():
            print(f"{Colors.s} Database backup endpoint accessible: {Colors.FAIL}{url}{Colors.ENDC}")
            return True
        else:
            print(f"{Colors.w} Database backup endpoint not accessible")
            return False
    except Exception as e:
        print(f"{Colors.e} Error checking backup endpoint: {e}")
        return False


def enumerate_fields(connection, model_name):
    if not connection.uid:
        print(f"{Colors.e} Not authenticated. Please authenticate first.")
        return {}

    print(f"{Colors.i} Enumerating fields on {model_name}...")
    try:
        fields_info = connection.models.execute_kw(
            connection.db, connection.uid, connection.password,
            model_name, 'fields_get', [],
            {'attributes': ['string', 'type', 'relation', 'store', 'groups']})

        for fname, fdata in sorted(fields_info.items()):
            ftype = fdata.get('type', '?')
            label = fdata.get('string', '')
            stored = 'stored' if fdata.get('store') else 'computed'
            groups = fdata.get('groups', '')
            relation = fdata.get('relation', '')

            extra = []
            if relation:
                extra.append(f"-> {relation}")
            if groups:
                extra.append(f"groups={groups}")
            extra.append(stored)

            print(f"{Colors.s} {fname} ({ftype}) {label} [{', '.join(extra)}]")

        print(f"{Colors.i} {len(fields_info)} fields found on {model_name}")
        return fields_info
    except Exception as e:
        print(f"{Colors.e} fields_get failed on {model_name}: {e}")
        return {}
