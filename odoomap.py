# Just a wrapper for core.py
from src.core import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting..")
