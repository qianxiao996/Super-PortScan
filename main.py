import os
import sys

from modules import scan


def main():
    scan.click_main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)