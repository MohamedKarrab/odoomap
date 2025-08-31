import argparse
import sys
import os
from . import connect
from . import actions
from . import __version__
from .utils.colors import Colors
from .plugin_manager import load_specific_plugin, list_available_plugins, get_plugin_info
from urllib.parse import urljoin, urlparse, urlunparse
import signal

def _on_sigint(signum, frame):
    print(f"\n{Colors.w} Interrupted by user. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, _on_sigint)

def banner():
    return Colors.HEADER + r'''
_______________________________________________________________
                   _                                   
          ___   __| | ___   ___  _ __ ___   __ _ _ __  
         / _ \ / _` |/ _ \ / _ \| '_ ` _ \ / _` | '_ \ 
        | (_) | (_| | (_) | (_) | | | | | | (_| | |_) |
         \___/ \__,_|\___/ \___/|_| |_| |_|\__,_| .__/ 
                                                |_|  
_______________________________________________________________
''' + Colors.ENDC + f'''
        Odoo Security Scanner by Mohamed Karrab @_karrab
        Version {__version__}
    ''' 

def parse_arguments():
    parser = argparse.ArgumentParser(description='Odoo Security Assessment Tool')
    
    # Target specification
    parser.add_argument('-u', '--url', help='Target Odoo server URL')
    
    # Authentication
    parser.add_argument('-D', '--database', help='Target database name')
    parser.add_argument('-U', '--username', help='Username for authentication')
    parser.add_argument('-P', '--password', help='Password for authentication')
    
    # Operation modes
    parser.add_argument('-r', '--recon', action='store_true', help='Perform initial reconnaissance')
    parser.add_argument('-e', '--enumerate', action='store_true', help='Enumerate available model names')
    parser.add_argument('-pe', '--permissions', action='store_true', help='Enumerate model permissions (requires -e)')
    parser.add_argument('-l', '--limit', type=int, default=100, help='Limit results for enumeration or dump operations')
    parser.add_argument('-o', '--output', help='Output file for results')
    
    # Dump options
    parser.add_argument('-d', '--dump', help='Dump data from specified model(s); accepts a comma-separated list or a file path containing model names (one per line)')
    
    # Model enumeration options
    parser.add_argument('-B', '--bruteforce-models', action='store_true', help='Bruteforce model names instead of listing them (default if listing fails)')
    parser.add_argument('--model-file', help='File containing model names for bruteforcing (one per line)')
    
    # Other operations
    parser.add_argument('-b', '--bruteforce', action='store_true', help='Bruteforce login credentials (requires -D)')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for bruteforcing in user:pass format')
    parser.add_argument('--usernames', help='File containing usernames for bruteforcing (one per line)')
    parser.add_argument('--passwords', help='File containing passwords for bruteforcing (one per line)')
    parser.add_argument('-M', '--bruteforce-master', action='store_true', help="Bruteforce the database's master password")
    parser.add_argument('-p','--master-pass', help='Wordlist file for master password bruteforcing (one password per line)')

    # bruteforce database names
    parser.add_argument('-n','--brute-db-names', action='store_true', help='Bruteforce database names')
    parser.add_argument('-N','--db-names-file', help='File containing database names for bruteforcing (case-sensitive)')

    # plugin execution
    parser.add_argument('--plugin', help='Run a specific plugin by name (from odoomap/plugins/)')
    parser.add_argument('--list-plugins', action='store_true', help='List all available plugins with metadata')

    args = parser.parse_args()
    
    # Validate URL requirement (not needed for --list-plugins)
    if not args.list_plugins and not args.url:
        parser.error("the following arguments are required: -u/--url (except when using --list-plugins)")
    
    # Validate argument combinations
    if args.permissions and not args.enumerate:
        parser.error("--permissions requires --enumerate")
    
    if args.bruteforce and not args.database:
        parser.error("--bruteforce requires --database")

    return args

def main():
    args = parse_arguments()

    # Handle --list-plugins early (no connection needed)
    if args.list_plugins:
        plugins_info = get_plugin_info()
        if not plugins_info:
            print(f"{Colors.w} No plugins found in odoomap/plugins/")
            return
        
        print(f"{Colors.s} Available Plugins:\n")
        for plugin_name, info in plugins_info.items():
            print(f"{Colors.i} {info['name']} ({plugin_name}) v{info['version']}")
            print(f"    Author: {info['author']}")
            print(f"    Category: {info['category']}")
            print(f"    Description: {info['description']}")
            print(f"    Requires Auth: {'Yes' if info['requires_auth'] else 'No'}")
            print(f"    Requires Connection: {'Yes' if info['requires_connection'] else 'No'}")
            if info['external_dependencies']:
                print(f"    Dependencies: {', '.join(info['external_dependencies'])}")
            if 'error' in info:
                print(f"    {Colors.e} Error: {info['error']}")
            print()
        return

    # Check if we have all authentication parameters
    has_auth_params = args.username and args.password and args.database
    auth_required_ops = args.enumerate or args.dump or args.permissions or args.bruteforce_models

    # Check if any action is specified (besides recon)
    any_action = args.enumerate or args.dump or args.bruteforce or args.permissions or args.bruteforce_models or args.bruteforce_master or args.brute_db_names or args.plugin or args.list_plugins

    # Determine if recon should be performed
    do_recon = args.recon or not any_action

    print(banner())
    print(f"{Colors.i} Target: {Colors.FAIL}{args.url}{Colors.ENDC}")

    # Initialize connection
    connection = connect.Connection(host=args.url)

    # --- Odoo check before authentication ---
    connection = connect.Connection(host=args.url)
    version = connection.get_version()
    if not version:
        # Try base URL if the given one fails
        parsed = urlparse(args.url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, '/', '', '', ''))
        if base_url.endswith('//'):
            base_url = base_url[:-1]
        print(f"{Colors.w} No Odoo detected at {args.url}, trying base URL: {base_url}")
        connection = connect.Connection(host=base_url)
        version = connection.get_version()
        if version:
            print(f"{Colors.s} Odoo detected at base URL!")
            response = input(f"{Colors.i} Use {base_url} as target? (y/n): ").strip().lower()
            if response == 'y' or response == 'yes':
                print(f"{Colors.i} Updated target {Colors.FAIL}{base_url}{Colors.ENDC}")
                args.url = base_url  # Update target for rest of script
            else:
                print(f"{Colors.e} Aborting, please provide a valid Odoo URL.")
                sys.exit(1)
        else:
            print(f"{Colors.e} The target does not appear to be running Odoo or is unreachable.")
            sys.exit(1)
    else:
        print(f"{Colors.s} Odoo detected (version: {version})")

    # --- Master password bruteforce ---
    if args.bruteforce_master:
        wordlist = args.master_pass
        actions.bruteforce_master_password(connection, wordlist)
        # If only master bruteforce was requested, exit after
        if not (args.bruteforce or args.enumerate or args.dump or args.permissions or args.recon):
            sys.exit(0)

    # Authenticate if needed for further operations
    if auth_required_ops and has_auth_params:
        uid = connection.authenticate(args.database, args.username, args.password)
        
    elif auth_required_ops and not has_auth_params:
        print(f"{Colors.e} Authentication required for the requested operation")
        print(f"{Colors.e} Please provide -U username, -P password, and -D database")
        if not args.bruteforce:
            sys.exit(1)

    # Perform recon if requested or if no other action is specified
    if do_recon:
        print(f"{Colors.i} Performing reconnaissance...")
        """
        version = connection.get_version()
        if not version:
            print(f"{Colors.e} Failed to connect to Odoo server or determine version")
            sys.exit(1)

        print(f"{Colors.s} Detected Odoo version: {version}")
        """
        
        # List databases
        dbs = connection.get_databases()
        if dbs:
            print(f"{Colors.s} Found {len(dbs)} database(s):")
            for db in dbs:
                print(f"{Colors.i}    - {db}{Colors.ENDC}")
        else:
            print(f"{Colors.w} No databases found or listing is disabled")

        # Check portal
        portal = connection.registration_check()

        # Check default apps
        apps = connection.default_apps_check()

    # --- Bruteforce database names if requested ---
    if args.brute_db_names:
        if not args.db_names_file:
            print(f"{Colors.e} Use -N <file> to specify a file containing database names (case-sensitive).")
            sys.exit(1)
        print(f"{Colors.i} Bruteforcing database names using file: {args.db_names_file}")
        connection.bruteforce_database_names(args.db_names_file)
    
    # Bruteforce
    if args.bruteforce:
        print(f"{Colors.i} Starting bruteforce login...")
        if not (args.wordlist or args.usernames or args.passwords):
            print(f"{Colors.w} Warning: No wordlist, usernames, or passwords provided. Using default values.")
        connection.bruteforce_login(args.database, wordlist_file=args.wordlist,
                                usernames_file=args.usernames, passwords_file=args.passwords)

    # Enumerate models
    if args.enumerate and connection.uid:
        models = actions.get_models(connection, limit=args.limit, 
                               with_permissions=args.permissions, 
                               bruteforce=args.bruteforce_models,
                               model_file=args.model_file)
        if models:
            if args.output:
                with open(args.output, 'w') as f:
                    for model in models:
                        f.write(f"{model}\n")
                print(f"\n{Colors.s} Model list saved to {args.output}")
                
    elif args.bruteforce_models and connection.uid:
        models = actions.bruteforce_models(connection, limit=args.limit, 
                                           with_permissions=args.permissions, 
                                           model_file=args.model_file)
        if models:
            if args.output:
                output_file = args.output if os.path.isdir(args.output) else os.path.dirname(args.output)
                output_file = os.path.join(output_file, 'bruteforced_models.txt')
                with open(output_file, 'w') as f:
                    for model in models:
                        f.write(f"{model}\n")
                print(f"\n{Colors.s} Bruteforced model list saved to {output_file}")

    # Dump model data
    if args.dump and connection.uid:
        models_to_dump = []

        # Check if the dump argument is a file path
        if os.path.isfile(args.dump):
            print(f"\n{Colors.i} Reading model list from file: {args.dump}")
            try:
                with open(args.dump, 'r') as f:
                    models_to_dump = [line.strip() for line in f if line.strip()]
                print(f"{Colors.i} Dumping data from {len(models_to_dump)} model(s) listed in file: {args.dump}")
            except Exception as e:
                print(f"{Colors.e} Error reading model list file: {str(e)}")
                sys.exit(1)
        else:
            models_to_dump = [model.strip() for model in args.dump.split(',')]
            print(f"{Colors.i} Dumping data from {len(models_to_dump)} model(s)")

        output_dir = args.output or "./dump"
        os.makedirs(output_dir, exist_ok=True)

        for model_name in models_to_dump:
            output_file = os.path.join(output_dir, f"{model_name}.json")
            print(f"{Colors.i} Dumping {model_name} to {output_file}")
            actions.dump_model(connection, model_name, limit=args.limit, output_file=output_file)


    if args.plugin:
        try:
            plugin_instance = load_specific_plugin(args.plugin)
        except ValueError as e:
            print(f"{Colors.e} {e}")
            available = list_available_plugins()
            print(f"{Colors.i} Available plugins: {', '.join(available)}")
            sys.exit(1)

        try:
            result = plugin_instance.run(
            # Passing all the necessary connection/auth information.
                args.url, 
                database=args.database,
                username=args.username,
                password=args.password,
                connection=connection
                # add args that plugins might need.
            )
            print(f"{Colors.s} Plugin '{args.plugin}' finished. Result:\n{result}")

        except Exception as e:
            print(f"{Colors.e} Error running plugin '{args.plugin}': {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()