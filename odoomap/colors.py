class Colors:
    HEADER = '\033[92m'      # Bright Green
    OKGREEN = '\033[32m'     # Green
    OKCYAN = '\033[36m'      # Cyan
    WARNING = '\033[93m'     # Yellow
    FAIL = '\033[91m'        # Red
    ENDC = '\033[0m'         # Reset
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Status prefixes (short aliases)
    i = INFO = f"{OKCYAN}[*]{ENDC}"
    s = SUCCESS = f"{OKGREEN}[+]{ENDC}"
    e = ERROR = f"{FAIL}[-]{ENDC}"
    w = WARN = f"{WARNING}[!]{ENDC}"