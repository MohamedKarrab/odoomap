# Just a wrapper for core.py
from odoomap.core import main
from odoomap.colors import Colors
import sys

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.w} Interrupted by user. Exiting...")
        sys.exit(0)

